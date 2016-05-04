require 'json/jwt'
require 'net/http'

def ca_request(path, method = :get, data = nil)
  uri = URI(CA)
  data = data.to_s if JSON::JWS === data
  Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
    http.send method, path, data
    # get, head, ... has no data, but has initheader.
    # Thus, it won't be any exception here ;P
  end
end

def jws_raw(hash, jwk, priv)
  jws = JSON::JWS.new hash
  jws.alg = :RS256
  jws.jwk = jwk
  jws.header[:nonce] = ca_request('/directory')['Replay-Nonce']
  jws.sign!(priv)
end

def ca_bundle
  chain = []
  chain << Net::HTTP.get(URI("https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"))

  web = Net::HTTP.get(URI("https://www.identrust.com/certificates/trustid/root-download-x3.html"))
  str = /<textarea[^>]*>([^<]+)<\/textarea>/.match(web)[1].gsub(/(\r|[ \t]*$)/){}
  chain << "-----BEGIN CERTIFICATE-----#{str}-----END CERTIFICATE-----\n"

  chain.join
end

# Write cert
def cert_out(res, uri=nil, new_cert=true)
  res = res.body if Net::HTTPResponse === res
  print "Cert saved to output.pem & could download from:\n#{uri}"
  cert = OpenSSL::X509::Certificate.new(res).to_pem
  File.open("data/output.pem", "w") {|f| f.write cert}
  File.open("data/ca-bundle.pem", "w") {|f| f.write ca_bundle}
  File.open("data/full-chain.pem", "w") {|f| f.write cert + ca_bundle}
  File.open("data/history.txt", "a") {|f| f.write "#{Time.now}:#{uri}\n"} if new_cert
end
