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

require 'openc3/interfaces/mqtt_interface' # For MQTT patches
require 'openc3/streams/stream'
require 'openc3/config/config_parser'
require 'openc3/utilities/mqtt_client'

module OpenC3
  class MqttStream < Stream
    attr_reader :hostname
    attr_reader :port
    attr_reader :ssl
    attr_reader :write_topic
    attr_reader :read_topic
    attr_accessor :username
    attr_accessor :password
    attr_accessor :cert
    attr_accessor :key
    attr_accessor :ca_file

    # @param port [Integer] MQTT port (defaults to 8883 with ssl, 1883 without)
    # @param ssl [Boolean] Whether to use TLS (default true, broker certificate always verified)
    def initialize(hostname, port = nil, ssl = true, write_topic = nil, read_topic = nil, ack_timeout = 5)
      super()

      @hostname = hostname
      @ssl = MqttClient.resolve_ssl(ssl)
      @port = MqttClient.resolve_port(port, @ssl)
      @write_topic = ConfigParser.handle_nil(write_topic)
      @read_topic = ConfigParser.handle_nil(read_topic)
      @ack_timeout = Float(ack_timeout)

      @username = nil
      @password = nil
      @cert = nil
      @key = nil
      @ca_file = nil

      # Mutex on write is needed to protect from commands coming in from more than one tool
      @write_mutex = Mutex.new
    end

    # Connect the stream
    def connect
      @client = MqttClient.build(name: self.class.name, hostname: @hostname, port: @port, ssl: @ssl,
                                 ack_timeout: @ack_timeout, username: @username, password: @password,
                                 cert: @cert, key: @key, ca_file: @ca_file)
      @client.connect
      @client.subscribe(@read_topic) if @read_topic
    end

    def connected?
      if @client
        return @client.connected?
      else
        return false
      end
    end

    def disconnect
      if @client
        @client.disconnect
        @client = nil
      end
    end

    # @return [String] Returns a binary string of data from the read_topic
    def read
      raise "Attempt to read from write only stream" unless @read_topic

      # No read mutex is needed because reads happen serially
      _, data = @client.get
      if data.nil? or data.length <= 0
        Logger.info "MqttStream: read returned nil" if data.nil?
        Logger.info "MqttStream: read returned 0 bytes" if not data.nil? and data.length <= 0
        return nil
      end

      return data
    end

    # @param data [String] A binary string of data to write to the write_topic
    def write(data)
      raise "Attempt to write to read only stream" unless @write_topic

      @write_mutex.synchronize do
        @client.publish(@write_topic, data)
      end
    end
  end
end
