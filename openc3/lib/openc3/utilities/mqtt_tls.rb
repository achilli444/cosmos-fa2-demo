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
        ca_certificates(ca_file).each { |ca_cert| store.add_cert(ca_cert) }
        client.ssl_context.cert_store = store
        client.ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end
    end

    # Parses every certificate in a PEM bundle without regex scanning the text
    # (OpenSSL walks the bundle linearly).
    def self.ca_certificates(ca_file)
      OpenSSL::X509::Certificate.load(ca_file)
    rescue OpenSSL::X509::CertificateError => e
      raise "CA_FILE does not contain a PEM certificate: #{e.message}"
    end
  end
end
