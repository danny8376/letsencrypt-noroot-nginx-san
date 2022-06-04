#!/usr/bin/env ruby
# exit 0=> new cert, 1=> ruby err, 2=> no renewal, 5=> auth err, 10=> no key
require 'socket'
require 'acme-client'

# load config
load 'CONFIG.rb'

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
STATIC_DOMAIN_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9.-]+$/
WILDCARD_DOMAIN_PATTERN = /^\*\.[a-zA-Z0-9][a-zA-Z0-9.-]+$/
# list domains from nginx confs
def get_domains
  domains = [CN]
  pending = []
  get_nginx_confs.each do |conf|
    next unless File.file? conf
    File.open(conf, 'r') do |file|
      file.each_line do |line|
        case line
        when /[^#]\s*server_name/
          pending = line.split(/[\s;]/).reject{|c| c.empty? or not c.include? "."}
        when /[^#]\s*include includes\/acme-challenge.conf;/
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
  wildcard.each{|d|
    if d[STATIC_DOMAIN_PATTERN]
      # nothing
    elsif d[WILDCARD_DOMAIN_PATTERN]
      print "!!!NOTICE!!! wildcard SAN #{d}\n"
    else
      wildcard_check.push d
    end
  }
  raise "Domains not precceed:#{wildcard_check.join " "}" unless wildcard_check.empty?
  static + wildcard + CUSTOM_DOMAIN
end

$domains = get_domains

unless FileTest.exist? 'data'
  Dir.mkdir 'data'
  File.chmod 0700, 'data'
end

unless FileTest.exist? 'data/acc.key'
  print "Generate account keypair with: \n\nopenssl genrsa 4096 > data/acc.key\n\n"
  exit 10
end
unless FileTest.exist? 'data/server.key'
  print "Generate server keypair with: \n\nopenssl genrsa 2048 > data/server.key\n\n"
  exit 10
end

# check existing cert
if FileTest.exist? 'data/output.pem' and (['force', '-f', '-force', '--force'] & ARGV).empty?
  domains = []
  $cert = OpenSSL::X509::Certificate.new File.read('data/output.pem')
  $cert.subject.to_a.each do |name|
    if name[0] == 'CN'
      domains.push name[1]
    end
  end
  $cert.extensions.select {|ext| ext.oid == 'subjectAltName'}.each do |ext|
    domains.concat(ext.value.split(', ').map {|v| v[4..-1]})
  end
  # skip only if no domain change
  if domains.uniq.sort == $domains.uniq.sort
    due = $cert.not_after
    now = Time.now
    if due - now > RENEWAL_THRESHOLD * 24 * 60 * 60
      print "Cert is still valid for more than #{RENEWAL_THRESHOLD} days, skip renewal, or use force to force renew.\n"
      exit 2
    end
  end
end

# load keys (private keys are just used locally, which can be easily audited)
$acc_priv = OpenSSL::PKey::RSA.new File.read('data/acc.key')

$server_priv = OpenSSL::PKey::RSA.new File.read('data/server.key') # key for ssl server; used for sign csr
$server_pub = $server_priv.public_key

if FileTest.exist? 'data/kid.txt'
  $kid = File.read('data/kid.txt')
  $acme = Acme::Client.new(private_key: $acc_priv, directory: CA, kid: $kid)
else
  $acme = Acme::Client.new(private_key: $acc_priv, directory: CA)
  acc = $acme.new_account(contact: "mailto:#{MAIL}", terms_of_service_agreed: true)
  File.write('data/kid.txt', acc.kid)
end

print "Start domain auth\n"

$auth_server = UNIXServer.new(ACME_SOCK)
$authes = {} # [auth, challenge, delayed]
File.chmod(0777, ACME_SOCK)
at_exit do
  $auth_server.close if $auth_server and not $auth_server.closed?
  File.unlink ACME_SOCK
end

# The part process accepting conns
Thread.new do
  while $auth_server and not $auth_server.closed?
    sock = $auth_server.accept
    req = sock.gets
    method, path, ver = req.split(" ")
    auth_pair = $authes[path]
    if auth_pair
      auth, challenge = *auth_pair
      sock.print "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n#{challenge.file_content}"
      print "Domain #{auth.domain} responsed\n"
      sock.close
    else
      sock.print "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n" rescue
      sock.close
    end
  end
rescue IOError
  # ignore
end

$order = $acme.new_order(identifiers: $domains)

$order.authorizations.each do |auth|
  print "Auth for domain #{auth.domain}\n"
  dns01 = auth.dns
  http01 = auth.http
  requested = false
  if dns01 # try dns first
    n = $authes.keys.collect{|k| k.start_with? auth.domain}.size + 1
    $authes["#{auth.domain}-#{n}"] = [auth, dns01, true]
    result = DNS_UPDATE.call(auth.domain, dns01.record_name, dns01.record_type, dns01.record_content, n)
    if result.nil?
      # nothing, continue
    elsif result
      requested = true
    else
      print "Domain #{auth.domain} dns update failed\n"
      exit 5
    end
  end
  if not requested and http01
    $authes["/#{http01.filename}"] = [auth, http01]
    http01.request_validation
    requested = true
  end
  if requested
    print "#{auth.domain} auth requested, expires: #{auth.expires}\n"
  else
    print "Domain #{auth.domain} no auth method available\n"
    exit 5
  end
end

$authes.each {|k, v| v[1].request_validation if v[2]}

while $authes.any? {|k, v| v[1].status == 'pending'}
  sleep 5
  $authes.each do |path, auth_pair|
    auth, challenge = *auth_pair
    challenge.reload
    if challenge.status != 'pending'
      print "#{auth.domain} done, result: #{challenge.status}\n"
      if challenge.status != 'valid'
        print "Error: #{challenge.error}\n"
      end
    end
  end
end

if $authes.any? {|k, v| v[1].status != 'valid'}
  print "!!! Some domain auth failed !!!\n"
  $authes.each do |path, auth_pair|
    auth, challenge = *auth_pair
    if challenge.status != 'valid'
      print "Domain: #{auth.domain}\n"
      print "Error: #{challenge.error}\n"
    end
  end
  exit 5
end

# Gen CSR
# As default, email of cert will be that of your account
# You can modify it if you don't like
csr = OpenSSL::X509::Request.new
csr.version = 1 # just make it not zero :P
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

$order.finalize(csr: csr)
while $order.status == 'processing'
  sleep 1
  $order.reload
end

File.write('data/output.pem', $order.certificate)
File.open('data/history.txt', 'a') {|f| f.write "#{Time.now}:#{$order.certificate_url}\n"}

print "Cert saved\n"

