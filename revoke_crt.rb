#!/usr/bin/env ruby
require 'open-uri'

require_relative 'lib/common'

# load config
load 'CONFIG.rb'



$priv = OpenSSL::PKey::RSA.new File.read(Dir['data/acc.key', 'data/domain.key'].first)
$pub = $priv.public_key
$jwk = JSON::JWK.new $pub

def jws(hash)
  jws_raw(hash, $jwk, $priv)
end

$cert = OpenSSL::X509::Certificate.new open(ARGV[0] ? ARGV[0] : 'data/output.pem'){|f| f.read}

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
