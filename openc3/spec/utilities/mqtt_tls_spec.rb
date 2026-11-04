# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/utilities/mqtt_tls'
require 'mqtt'

module OpenC3
  describe MqttTls do
    before(:all) do
      @key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse('/CN=mqtt_tls_spec')
      cert.issuer = cert.subject
      cert.public_key = @key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      cert.sign(@key, OpenSSL::Digest.new('SHA256'))
      @cert = cert
    end

    describe "configure" do
      it "loads the cert, key and CA into the client without touching the filesystem" do
        expect(Tempfile).not_to receive(:new)
        expect(File).not_to receive(:write)
        client = MQTT::Client.new
        MqttTls.configure(client, cert: @cert.to_pem, key: @key.to_pem, ca_file: @cert.to_pem)
        expect(client.ssl).to be true
        expect(client.ssl_context.cert.to_pem).to eql @cert.to_pem
        expect(client.ssl_context.key.to_pem).to eql @key.to_pem
        expect(client.ssl_context.verify_mode).to eql OpenSSL::SSL::VERIFY_PEER
        expect(client.ssl_context.ca_file).to be_nil
        expect(client.ssl_context.cert_store.verify(@cert)).to be true
      end

      it "loads every certificate in a CA bundle" do
        client = MQTT::Client.new
        MqttTls.configure(client, ca_file: @cert.to_pem + "\n" + @cert.to_pem)
        expect(client.ssl).to be true
        expect(client.ssl_context.key).to be_nil
        expect(client.ssl_context.cert_store.verify(@cert)).to be true
      end

      it "raises if the CA_FILE has no PEM certificate" do
        client = MQTT::Client.new
        expect { MqttTls.configure(client, ca_file: 'ca_file_content') }.to raise_error(/CA_FILE does not contain a PEM certificate/)
      end

      it "leaves the client alone without options" do
        client = MQTT::Client.new
        MqttTls.configure(client)
        expect(client.ssl).to be false
        expect(client.ssl_context.key).to be_nil
      end
    end
  end
end
