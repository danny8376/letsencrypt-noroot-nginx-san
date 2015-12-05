#!/usr/bin/env ruby
require 'json/jwt'
require 'net/http'

# load config
load 'CONFIG.rb'



$priv = OpenSSL::PKey::RSA.new File.read(Dir['data/acc.key', 'data/domain.key'].first)
$pub = $priv.public_key
$jwk = JSON::JWK.new $pub

$cert = OpenSSL::X509::Certificate.new File.read(ARGV[0] ? ARGV[0] : 'data/output.pem')

def ca_request(path, method = :get, data = nil)
  uri = URI(CA)
  data = data.to_s if JSON::JWS === data
  Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
    http.send method, path, data
    # get, head, ... has no data, but has initheader.
    # Thus, it won't be any exception here ;P
  end
end

def jws(hash)
  jws = JSON::JWS.new hash
  jws.alg = :RS256
  jws.jwk = $jwk
  jws.header[:nonce] = ca_request('/directory')['Replay-Nonce']
  jws.sign!($priv)
end

res = ca_request('/acme/revoke-cert', :post, jws({
  resource: "revoke-cert",
  certificate: UrlSafeBase64.encode64($cert.to_der)
}))

if res.code == "200"
  print "Succeed"
else
  p res, res.body
  print "Failed"
end
