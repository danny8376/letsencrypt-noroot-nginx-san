#!/usr/bin/env ruby
require 'open-uri'
require 'acme-client'

# load config
load 'CONFIG.rb'

if not FileTest.exist? 'data/acc.key' or not FileTest.exist? 'data/kid.txt'
  print "There's no account.\n"
  exit
end

$priv = OpenSSL::PKey::RSA.new File.read('data/acc.key')
$kid = File.read('data/kid.txt')

$acme = Acme::Client.new(private_key: $priv, directory: CA, kid: $kid)

$cert = OpenSSL::X509::Certificate.new open(ARGV[0] ? ARGV[0] : 'data/output.pem'){|f| f.read}

begin
  $acme.revoke(certificate: $cert)
  print "Succeed\n"
rescue Acme::Client::Error => err
  print "Failed : #{err.message}\n"
end
