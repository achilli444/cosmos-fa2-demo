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

require 'openssl'

module OpenC3
  # Configures client certificate authentication on an MQTT::Client from PEM
  # text held in memory. Nothing is written to disk, so the client private key
  # never lands in the shared temp directory.
  module MqttTls
    PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m

    # @param client [MQTT::Client]
    # @param cert [String, nil] PEM client certificate
    # @param key [String, nil] PEM client private key
    # @param ca_file [String, nil] PEM certificate(s) used to verify the broker
    def self.configure(client, cert: nil, key: nil, ca_file: nil)
      if cert and key
        client.ssl = true
        client.cert = cert
        client.key = key
      end
      if ca_file
        client.ssl = true
        store = OpenSSL::X509::Store.new
        certs = ca_file.scan(PEM_CERTIFICATE)
        raise "CA_FILE does not contain a PEM certificate" if certs.empty?

        certs.each { |pem| store.add_cert(OpenSSL::X509::Certificate.new(pem)) }
        client.ssl_context.cert_store = store
        client.ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end
    end
  end
end
