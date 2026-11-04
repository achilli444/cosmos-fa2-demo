# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/utilities/transport_security'

module OpenC3
  describe TransportSecurity do
    around(:each) do |example|
      saved = ENV.to_h.slice('OPENC3_PLAINTEXT_TRANSPORT', 'OPENC3_TLS_CA_FILE')
      ENV.delete('OPENC3_PLAINTEXT_TRANSPORT')
      ENV.delete('OPENC3_TLS_CA_FILE')
      example.run
    ensure
      ENV.delete('OPENC3_PLAINTEXT_TRANSPORT')
      ENV.delete('OPENC3_TLS_CA_FILE')
      ENV.update(saved)
    end

    it "defaults every client to TLS" do
      expect(TransportSecurity.plaintext?).to be false
      expect(TransportSecurity.http_scheme).to eq 'https'
      expect(TransportSecurity.redis_scheme).to eq 'rediss'
      expect(TransportSecurity.pg_sslmode).to eq 'verify-full'
      expect(TransportSecurity.redis_ssl_params).to eq({ verify_mode: OpenSSL::SSL::VERIFY_PEER })
    end

    it "only opts into plaintext for an explicit truthy OPENC3_PLAINTEXT_TRANSPORT" do
      %w(1 true TRUE yes on).each do |value|
        ENV['OPENC3_PLAINTEXT_TRANSPORT'] = value
        expect(TransportSecurity.plaintext?).to be(true), "expected #{value.inspect} to enable plaintext"
      end
      %w(0 false no off).each do |value|
        ENV['OPENC3_PLAINTEXT_TRANSPORT'] = value
        expect(TransportSecurity.plaintext?).to be(false), "expected #{value.inspect} to keep TLS"
      end
      ENV['OPENC3_PLAINTEXT_TRANSPORT'] = ''
      expect(TransportSecurity.plaintext?).to be false
    end

    it "falls back to the historical plaintext transports when opted out" do
      ENV['OPENC3_PLAINTEXT_TRANSPORT'] = '1'
      expect(TransportSecurity.http_scheme).to eq 'http'
      expect(TransportSecurity.redis_scheme).to eq 'redis'
      expect(TransportSecurity.pg_sslmode).to eq 'prefer'
      expect(TransportSecurity.redis_ssl_params).to be_nil
    end

    it "pins the CA bundle from OPENC3_TLS_CA_FILE" do
      expect(TransportSecurity.ca_file).to be_nil
      ENV['OPENC3_TLS_CA_FILE'] = ' '
      expect(TransportSecurity.ca_file).to be_nil
      ENV['OPENC3_TLS_CA_FILE'] = '/etc/openc3/ca.pem'
      expect(TransportSecurity.ca_file).to eq '/etc/openc3/ca.pem'
      expect(TransportSecurity.redis_ssl_params).to eq({ verify_mode: OpenSSL::SSL::VERIFY_PEER, ca_file: '/etc/openc3/ca.pem' })
    end
  end
end
