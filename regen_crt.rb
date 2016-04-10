#!/usr/bin/env ruby
require 'open-uri'

require_relative 'lib/common'

# load config
load 'CONFIG.rb'



$priv = OpenSSL::PKey::RSA.new File.read(Dir['data/acc.key', 'data/domain.key'].first)
$pub = $priv.public_key
$jwk = JSON::JWK.new $pub

history = File.readlines("data/history.txt")[-1].chomp
uri = history[/https?:.*/]

cert = open(uri) {|f| f.read}
cert_out(cert, nil, false)
