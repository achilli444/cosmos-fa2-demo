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
require 'openc3/utilities/mqtt_client'

module OpenC3
  describe MqttClient do
    describe "resolve_ssl" do
      it "defaults to TLS unless explicitly disabled" do
        expect(MqttClient.resolve_ssl(nil)).to be true
        expect(MqttClient.resolve_ssl('nil')).to be true
        expect(MqttClient.resolve_ssl('true')).to be true
        expect(MqttClient.resolve_ssl(false)).to be false
        expect(MqttClient.resolve_ssl('FALSE')).to be false
      end
    end

    describe "resolve_port" do
      it "defaults to 8883 with TLS and 1883 without" do
        expect(MqttClient.resolve_port(nil, true)).to eql 8883
        expect(MqttClient.resolve_port('nil', true)).to eql 8883
        expect(MqttClient.resolve_port(nil, false)).to eql 1883
        expect(MqttClient.resolve_port('1883', true)).to eql 1883
        expect(MqttClient.resolve_port(9000, false)).to eql 9000
      end
    end

    describe "build" do
      let(:args) { { name: 'TEST', hostname: 'broker.example.com', port: 8883, ack_timeout: 5.0 } }

      it "enables TLS with peer and hostname verification by default" do
        expect_any_instance_of(OpenSSL::SSL::SSLContext).to receive(:min_version=).with(OpenSSL::SSL::TLS1_2_VERSION).and_call_original
        client = MqttClient.build(ssl: true, **args)
        expect(client.ssl).to be true
        expect(client.verify_host).to be true
        context = client.ssl_context
        expect(context.verify_mode).to eql OpenSSL::SSL::VERIFY_PEER
        expect(context.verify_hostname).to be true
        expect(context.cert_store).to be_a(OpenSSL::X509::Store)
        expect(context.ca_file).to be_nil
      end

      it "verifies against CA_FILE when given" do
        ca = Tempfile.new('ca')
        client = MqttClient.build(ssl: true, ca_file: ca, **args)
        expect(client.ssl).to be true
        expect(client.ssl_context.verify_mode).to eql OpenSSL::SSL::VERIFY_PEER
        expect(client.ssl_context.ca_file).to eql ca.path
        expect(client.ssl_context.verify_hostname).to be true
        ca.close
        ca.unlink
      end

      it "forces TLS when a client cert and key are given" do
        rsa = OpenSSL::PKey::RSA.new(2048)
        x509 = OpenSSL::X509::Certificate.new
        x509.version = 2
        x509.serial = 1
        x509.subject = x509.issuer = OpenSSL::X509::Name.parse('/CN=test')
        x509.public_key = rsa.public_key
        x509.not_before = Time.now
        x509.not_after = Time.now + 3600
        x509.sign(rsa, OpenSSL::Digest.new('SHA256'))
        cert = Tempfile.new('cert')
        cert.write(x509.to_pem)
        cert.flush
        key = Tempfile.new('key')
        key.write(rsa.to_pem)
        key.flush

        client = MqttClient.build(ssl: false, cert: cert, key: key, **args)
        expect(client.ssl).to be true
        expect(client.ssl_context.verify_mode).to eql OpenSSL::SSL::VERIFY_PEER
        expect(client.ssl_context.cert.subject.to_s).to eql '/CN=test'
        cert.close
        cert.unlink
        key.close
        key.unlink
      end

      it "never leaves the context at VERIFY_NONE when TLS is on" do
        client = MqttClient.build(ssl: true, **args)
        expect(client.ssl_context.verify_mode).not_to eql OpenSSL::SSL::VERIFY_NONE
      end

      it "allows plaintext only as an explicit opt-in and warns" do
        expect(Logger).to receive(:warn).with(/TEST: TLS disabled.*broker.example.com:1883.*plaintext.*credentials/)
        client = MqttClient.build(ssl: false, username: 'u', password: 'p', **args.merge(port: 1883))
        expect(client.ssl).to be false
        expect(client.port).to eql 1883
        expect(client.username).to eql 'u'
      end
    end
  end
end
