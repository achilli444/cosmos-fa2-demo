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
require 'mqtt'
require 'openc3/utilities/logger'
require 'openc3/config/config_parser'

module OpenC3
  # Shared MQTT::Client construction for MqttInterface and MqttStream.
  # TLS is on by default and the broker certificate is always verified
  # (VERIFY_PEER, TLS 1.2+, hostname check) against either the CA_FILE option
  # or the system certificate store. Plaintext is an explicit opt-in (ssl false)
  # and is logged as a warning because commands, telemetry and credentials
  # would otherwise cross the network unprotected.
  module MqttClient
    DEFAULT_PORT = 1883
    DEFAULT_SSL_PORT = 8883

    # @param ssl [Boolean] Whether TLS is enabled
    # @return [Integer] The conventional MQTT port for the given TLS setting
    def self.default_port(ssl)
      ssl ? DEFAULT_SSL_PORT : DEFAULT_PORT
    end

    # @param ssl [Boolean, String, nil] ssl given in the interface definition (nil to use the default)
    # @return [Boolean] true unless TLS was explicitly disabled
    def self.resolve_ssl(ssl)
      ssl = ConfigParser.handle_nil(ssl)
      ssl.nil? ? true : ConfigParser.handle_true_false(ssl)
    end

    # @param port [Integer, String, nil] Port given in the interface definition (nil to use the default)
    # @param ssl [Boolean] Whether TLS is enabled
    # @return [Integer] Resolved port
    def self.resolve_port(port, ssl)
      port = ConfigParser.handle_nil(port)
      port.nil? ? default_port(ssl) : Integer(port)
    end

    # Builds a configured (but not yet connected) MQTT::Client
    #
    # @param name [String] Name used in log messages
    # @param hostname [String] MQTT broker hostname
    # @param port [Integer] MQTT broker port
    # @param ssl [Boolean] Whether to use TLS (forced true when cert/key or ca_file are given)
    # @param ack_timeout [Float] Connection ack timeout
    # @param username [String, nil] Broker username
    # @param password [String, nil] Broker password
    # @param cert [File, nil] PEM client certificate for mutual TLS
    # @param key [File, nil] PEM client private key for mutual TLS
    # @param ca_file [File, nil] PEM CA certificate(s) to trust instead of the system store
    def self.build(name:, hostname:, port:, ssl:, ack_timeout:, username: nil, password: nil, cert: nil, key: nil, ca_file: nil)
      client = MQTT::Client.new
      client.ack_timeout = ack_timeout
      client.host = hostname
      client.port = port
      client.username = username if username
      client.password = password if password

      ssl = true if (cert and key) or ca_file
      if ssl
        configure_tls(client, cert: cert, key: key, ca_file: ca_file)
      else
        client.ssl = false
        message = "#{name}: TLS disabled, connecting to #{hostname}:#{port} in plaintext"
        message += " (MQTT credentials will be sent unencrypted)" if username or password
        Logger.warn message
      end
      client
    end

    def self.configure_tls(client, cert: nil, key: nil, ca_file: nil)
      client.ssl = true
      client.verify_host = true # post_connection_check(host) after the handshake
      context = client.ssl_context
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      context.verify_hostname = true
      context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      if cert and key
        client.cert_file = cert.path
        client.key_file = key.path
      end
      if ca_file
        client.ca_file = ca_file.path
      else
        store = OpenSSL::X509::Store.new
        store.set_default_paths
        context.cert_store = store
      end
      client
    end
  end
end
