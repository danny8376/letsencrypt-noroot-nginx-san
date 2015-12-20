#!/usr/bin/env ruby
require 'json/jwt'
require 'net/http'

# load config
load 'CONFIG.rb'



SUPPORT_CHALLENGES = ["http-01"]
SERVER_SOCKFILE = '/tmp/acme-challenge.sock'



ngx_options = `nginx -V 2>&1`
NGINX_CONF = ngx_options.scan(/--conf-path=([^\s]+)/).last[0]
NGINX_CONF_PREFIX = NGINX_CONF[/^\/?([^\/]+\/)+/]
# get all used nginx confs
def get_nginx_confs(conf = NGINX_CONF)
  conf = "#{NGINX_CONF_PREFIX}#{conf}" unless conf[0] == "/"
  if conf.include? "*"
    begin
      Dir[conf].collect{|c| get_nginx_confs c}.flatten
    rescue Errno::EACCES
      print "#{conf} permission denied\n"
      []
    end
  else
    begin
      ([conf] +
      File.read(conf).scan(/[^#]\s*include\s+([^;]+);/).flatten.collect{|c| get_nginx_confs c}.flatten).uniq
    rescue Errno::EACCES
      print "#{conf} permission denied\n"
      []
    end
  end
end
STATIC_DOMAIN_PATTERN = /^[a-zA-Z0-9.-]+$/
# list domains from nginx confs
def get_domains
  domains = []
  pending = []
  get_nginx_confs.each do |conf|
    next unless File.file? conf
    File.open(conf, 'r') do |file|
      file.each_line do |line|
        case line
        when /^\s*server_name/
          pending = line.split(/[\s;]/).reject{|c| c.empty? or not c.include? "."}
        when /include includes\/acme-challenge.conf;/
          domains += pending
        end
      end
    end
  end
  domains.uniq!
  domains.reject! do |domain|
    EXCLUDE_DOMAIN.any? do |exclude|
      if exclude.start_with? "~"
        domain.end_with? exclude[1..-1]
      else
        domain == exclude
      end
    end
  end
  static, wildcard = [], []
  domains.each{|d| (d[STATIC_DOMAIN_PATTERN] ? static : wildcard).push d}
  WILDCARD_PROCESSING.call(wildcard, static) unless wildcard.empty?
  wildcard.flatten!
  wildcard.select!{|d| String === d}
  wildcard_check = []
  wildcard.each{|d| wildcard_check.push d unless d[STATIC_DOMAIN_PATTERN]}
  raise "Wildcard domains not precceed:#{wildcard_check.join " "}" unless wildcard_check.empty?
  static + wildcard
end

$domains = get_domains

unless FileTest.exist? 'data'
  Dir.mkdir 'data'
  File.chmod 0700, 'data'
end

unless FileTest.exist? 'data/acc.key'
  print "Generate account keypair with: \n\nopenssl genrsa 4096 > data/acc.key\n\n"
  exit
end
unless FileTest.exist? 'data/server.key'
  print "Generate server keypair with: \n\nopenssl genrsa 2048 > data/server.key\n\n"
  exit
end


# load keys (private keys are just used locally, which can be easily audited)
$acc_priv = OpenSSL::PKey::RSA.new File.read('data/acc.key')
$acc_pub = $acc_priv.public_key

$acc_jwk = JSON::JWK.new $acc_pub # account public key as jwk (for request header)
$acc_thumbprint = $acc_jwk.thumbprint # thumbprint for domain challenge

$server_priv = OpenSSL::PKey::RSA.new File.read('data/server.key') # key for ssl server; used for sign csr
$server_pub = $server_priv.public_key

# method to send request to acme server
def ca_request(path, method = :get, data = nil)
  uri = URI(CA)
  data = data.to_s if JSON::JWS === data
  Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
    http.send method, path, data
    # get, head, ... has no data, but has initheader.
    # Thus, it won't be any exception here ;P
  end
end

# method to gen jws
def jws(hash)
  jws = JSON::JWS.new hash
  jws.alg = :RS256
  jws.jwk = $acc_jwk
  jws.header[:nonce] = ca_request('/directory')['Replay-Nonce'] # token for preventing replay attack
  jws.sign!($acc_priv)
end


print "Generating CSR\n"

# Gen CSR
# As default, email of cert will be that of your account
# You can modify it if you don't like
csr = OpenSSL::X509::Request.new
csr.subject = OpenSSL::X509::Name.new([
  ['CN',           CN,   OpenSSL::ASN1::UTF8STRING],
  ['emailAddress', MAIL, OpenSSL::ASN1::UTF8STRING]
])
csr.public_key = $server_pub
# SAN ext
exts = []
ext_factory = OpenSSL::X509::ExtensionFactory.new
exts.push ext_factory.create_extension("subjectAltName", $domains.map{|n| "DNS:#{n}"}.join(", "), false)
ext_req = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(exts)])
csr.add_attribute(OpenSSL::X509::Attribute.new("extReq", ext_req))
csr.add_attribute(OpenSSL::X509::Attribute.new("msExtReq", ext_req))

csr.sign($server_priv, OpenSSL::Digest::SHA256.new)


print "Registering account\n"


# Reg account
res = ca_request('/acme/new-reg', :post, jws({
  resource: "new-reg",
  contact: ["mailto:#{MAIL}"],
  agreement: TERMS
}))

case res.code
when '201'
  # normal
  print "Registered!\n"
when '409'
  print "Alread registered, skipping\n"
else
  raise "Error registering\n"
end


print "Starting domain auth\n"

# The unix socket server for nginx to pass, which used for auth domain
$auth_server = UNIXServer.new(SERVER_SOCKFILE)
File.chmod(0777, SERVER_SOCKFILE)

at_exit do
  $auth_server.close if $auth_server and not $auth_server.closed?
  FileUtils.rm SERVER_SOCKFILE
end

# The whole auth process as follow
# 1) request challenge from acme server
# 2) accept incoming connections
# 3) check the path is correct, then response with keyAuth
# 4) polling acme server to check validation status

# The part process accepting conns
def wait_auth(auth)
  loop do
    sock = $auth_server.accept
    req = sock.gets
    if req.start_with?("GET /.well-known/acme-challenge/#{auth[/[^.]+/]} HTTP/")
      sock.print "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n#{auth}"
      sock.close
      break
    else
      sock.print "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"
      sock.close
    end
  end
end

# Polling status. We try 10 at most.
def check_status(uri, depth = 0)
  return :timeout if depth > 9 # too much times, maybe it's not accessed by acme server
  res = ca_request(uri)
  res = JSON.parse(res.body)
  case res['status']
  when "pending" # maybe too fast
    sleep 1
    check_status(uri, depth + 1)
  when "valid"
    return :valid, res
  else
    raise "Challenge failed"
  end
end

# Auth domain OwO
def auth_domain(uri, auth)
  ca_request(uri) # This status shuold be pending

  wait_auth(auth) # blocking here OwO
  sleep 1 # wait acme server for processing

  # when goes to here, it's authed
  status, res = check_status(uri)
  case status
  when :timeout
    raise "Challenge retry too much"
  when :valid
    return res
  else # uh?
  end
end

# Auth with all domains
$domains.each do |domain|
  print "Auth for domain #{domain}\n"

  # checking for available challanges
  res = ca_request('/acme/new-authz', :post, jws({
    resource: "new-authz",
    identifier: {
      type: "dns",
      value: domain,
    }
  }))

  res = JSON.parse(res.body)
  challenge = nil
  supported = res['challenges'].any? do |c|
    challenge = c
    SUPPORT_CHALLENGES.include? c['type']
  end
  raise 'No supported challenge' unless supported

  # CHALLENGE!
  uri = challenge['uri']
  uri[CA] = ''
  res = ca_request(uri, :post, jws({
    resource: "challenge",
    type: challenge['type'],
    keyAuthorization: "#{challenge['token']}.#{$acc_thumbprint}"
  }))

  res = JSON.parse(res.body)
  uri = res['uri']
  uri[CA] = ''
  auth = res['keyAuthorization']
  res = auth_domain(uri, auth)

  # check auth status
  uri[/\/\d+$/] = ''
  res = ca_request(uri)

  print "#{domain} authed, expires: #{res['expires']}\n"
end


print "Request for cert\n"

def ca_bundle
  chain = []
  chain << Net::HTTP.get(URI("https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem"))

  web = Net::HTTP.get(URI("https://www.identrust.com/certificates/trustid/root-download-x3.html"))
  str = /<textarea[^>]*>([^<]+)<\/textarea>/.match(web)[1].gsub(/(\r|[ \t]*$)/){}
  chain << "-----BEGIN CERTIFICATE-----#{str}-----END CERTIFICATE-----\n"

  chain.join
end

# Write cert
def cert_out(res, uri)
  print "Cert saved to output.pem & could download from:\n#{uri}"
  cert = OpenSSL::X509::Certificate.new(res.body).to_pem
  File.open("data/output.pem", "w") {|f| f.write cert}
  File.open("data/ca-bundle.pem", "w") {|f| f.write ca_bundle}
  File.open("data/full-chain.pem", "w") {|f| f.write cert + ca_bundle}
end


res = ca_request("/acme/new-cert", :post, jws({
  resource: "new-cert",
  csr: UrlSafeBase64.encode64(csr.to_der)
}))


if res.code == "201"
  uri = res['location']
  if res.body.empty?
    loop do
      res = ca_request(uri)
      case res.code
      when "200"
        cert_out(res, uri)
        break
      when "202"
        time = res['retry-after']
        time = (Time.parse(time) - Time.now).ceil unless time =~ /^\d+$/
        print "Cert unavailable now, retry after #{time} sec later"
        sleep time.to_i
      else
      end
    end
  else
    cert_out(res, uri)
  end
else
  raise "Cert failed"
end
