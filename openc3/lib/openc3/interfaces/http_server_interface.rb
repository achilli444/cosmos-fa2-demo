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

require 'openc3/interfaces/interface'
require 'openc3/config/config_parser'
require 'openc3/accessors/http_accessor'
require 'webrick'
require 'webrick/https'
require 'openssl'

module OpenC3
  class HttpServerInterface < Interface
    # Only accept connections from the local host unless LISTEN_ADDRESS is explicitly widened
    DEFAULT_LISTEN_ADDRESS = '127.0.0.1'
    # Maximum number of requests buffered before read_interface drains them
    DEFAULT_MAX_QUEUE_SIZE = 1000
    # Reject SSLv2/SSLv3/TLS1.0/TLS1.1 so only TLS 1.2+ is negotiated
    SSL_OPTIONS = OpenSSL::SSL::OP_NO_SSLv2 | OpenSSL::SSL::OP_NO_SSLv3 | OpenSSL::SSL::OP_NO_TLSv1 | OpenSSL::SSL::OP_NO_TLSv1_1

    # @param port [Integer] HTTP port
    def initialize(port = 80)
      super()
      @listen_address = DEFAULT_LISTEN_ADDRESS
      @port = Integer(port)
      @server = nil
      @server_thread = nil
      @max_queue_size = DEFAULT_MAX_QUEUE_SIZE
      @request_queue = SizedQueue.new(@max_queue_size)
      @cert = nil
      @key = nil
      @ca_file = nil
      @auth_token = nil
    end

    # Supported Options
    # LISTEN_ADDRESS - Ip address of the interface to accept connections on (default 127.0.0.1)
    # MAX_QUEUE_SIZE - Maximum number of buffered requests before new requests are rejected with 503
    # CERT - PEM encoded server certificate (contents or filename). Enables HTTPS when given with KEY.
    # KEY - PEM encoded server private key (contents or filename)
    # CA_FILE - PEM encoded CA bundle (contents or filename). Requires and verifies client certificates.
    # AUTH_TOKEN - Shared secret clients must send as 'Authorization: Bearer <token>'
    # (see Interface#set_option)
    def set_option(option_name, option_values)
      super(option_name, option_values)
      case option_name.upcase
      when 'LISTEN_ADDRESS'
        @listen_address = option_values[0]
      when 'MAX_QUEUE_SIZE'
        @max_queue_size = Integer(option_values[0])
        raise "MAX_QUEUE_SIZE must be greater than 0" if @max_queue_size <= 0

        @request_queue = SizedQueue.new(@max_queue_size)
      when 'CERT'
        @cert = read_pem_option(option_values[0])
      when 'KEY'
        @key = read_pem_option(option_values[0])
      when 'CA_FILE'
        @ca_file = read_pem_option(option_values[0])
      when 'AUTH_TOKEN'
        @auth_token = option_values[0].to_s
        raise "AUTH_TOKEN must not be empty" if @auth_token.empty?
      end
    end

    def ssl?
      return !!(@cert and @key)
    end

    def connection_string
      return "listening on #{@listen_address}:#{@port}"
    end

    # Connects the interface to its target(s)
    def connect
      @server = WEBrick::HTTPServer.new(server_config)
      @request_queue = SizedQueue.new(@max_queue_size)

      # Create a response hook for every command packet
      @target_names.each do |target_name|
        System.commands.packets(target_name).each do |packet_name, packet|
          packet.restore_defaults
          path = nil
          begin
            path = packet.read('HTTP_PATH')
          rescue => e
            # No HTTP_PATH is an error
            Logger.error("HttpServerInterface Packet #{target_name} #{packet_name} unable to read HTTP_PATH\n#{e.formatted}")
          end
          if path
            @server.mount_proc path do |req, res|
              unless authorized?(req)
                res.status = 401
                res['WWW-Authenticate'] = 'Bearer'
                res.body = ''
                next
              end

              # Build the Response
              begin
                status = packet.read('HTTP_STATUS')
                if status
                  res.status = status
                end
              rescue
                # No HTTP_STATUS - Leave at default
              end

              # http_accessor stores all the pseudo-derived HTTP configuration in extra
              if packet.extra
                headers = packet.extra['HTTP_HEADERS']
                if headers
                  headers.each do |key, value|
                    res[key] = value
                  end
                end
              end

              res.body = packet.buffer

              # Save the Request
              packet_name = nil
              begin
                packet_name = packet.read('HTTP_PACKET')
              rescue
                # No packet name means dont save the request as telemetry
              end
              if packet_name
                data = req.body.to_s.dup # Dup to remove frozen
                extra = {}
                extra['HTTP_REQUEST_TARGET_NAME'] = target_name
                extra['HTTP_REQUEST_PACKET_NAME'] = packet_name

                headers = req.header
                if headers
                  extra['HTTP_HEADERS'] = {}
                  headers.each do |key, value|
                    extra['HTTP_HEADERS'][key.downcase] = value
                  end
                end

                queries = req.query
                if queries
                  extra['HTTP_QUERIES'] = {}
                  queries.each do |key, value|
                    extra['HTTP_QUERIES'][key] = value
                  end
                end

                begin
                  @request_queue.push([data, extra], true)
                rescue ThreadError
                  # Queue is full - shed load rather than grow memory without bound
                  Logger.warn("#{@name}: request queue full (#{@max_queue_size}), rejecting #{req.request_method} #{req.path}")
                  res.status = 503
                  res['Retry-After'] = '1'
                  res.body = ''
                end
              end
            end
          end
        end
      end

      super()

      @server_thread = Thread.new do
        # This blocks, but will be unblocked by server.shutdown called in disconnect()
        @server.start
      end
    end

    def connected?
      if @server
        return true
      else
        return false
      end
    end

    # Disconnects the interface from its target(s)
    def disconnect
      @server.shutdown if @server
      # Wait for the listener sockets to be released
      @server_thread.join(5) if @server_thread
      @server_thread = nil
      @server = nil
      while @request_queue.length > 0
        @request_queue.pop
      end
      super()
      @request_queue.push(nil)
    end

    def read_interface
      # Get the Faraday Response
      data, extra = @request_queue.pop
      return nil if data.nil?

      read_interface_base(data, extra)
      return data, extra
    end

    def write_interface(_data, _extra = nil)
      raise "Commands cannot be sent to HttpServerInterface"
    end

    # Called to convert the read data into a OpenC3 Packet object
    #
    # @param data [String] Raw packet data
    # @return [Packet] OpenC3 Packet with buffer filled with data
    def convert_data_to_packet(data, extra = nil)
      packet = Packet.new(nil, nil, :BIG_ENDIAN, nil, data.to_s)
      packet.accessor = HttpAccessor.new(packet)
      if extra
        # Identify the response
        request_target_name = extra['HTTP_REQUEST_TARGET_NAME']
        request_packet_name = extra['HTTP_REQUEST_PACKET_NAME']
        if request_target_name and request_packet_name
          packet.target_name = request_target_name.to_s.upcase
          packet.packet_name = request_packet_name.to_s.upcase
        end
        extra.delete("HTTP_REQUEST_TARGET_NAME")
        extra.delete("HTTP_REQUEST_PACKET_NAME")
        packet.extra = extra
      end

      return packet
    end

    def convert_packet_to_data(_packet)
      raise "Commands cannot be sent to HttpServerInterface"
    end

    def details
      result = super()
      result['listen_address'] = @listen_address
      result['port'] = @port
      result['ssl'] = ssl?
      result['client_cert_required'] = !@ca_file.nil?
      result['auth_token_required'] = !@auth_token.nil?
      result['max_queue_size'] = @max_queue_size
      result['request_queue_length'] = @request_queue.length
      return result
    end

    protected

    # Option values may be the PEM text itself (e.g. injected from a SECRET) or a filename
    def read_pem_option(value)
      value = value.to_s
      return value if value.lstrip.start_with?('-----BEGIN')

      raise "PEM file not found: #{value}" unless File.file?(value)

      return File.read(value)
    end

    def server_config
      config = { :BindAddress => @listen_address, :Port => @port }
      if ssl?
        config[:SSLEnable] = true
        config[:SSLCertificate] = OpenSSL::X509::Certificate.new(@cert)
        config[:SSLPrivateKey] = OpenSSL::PKey.read(@key)
        config[:SSLOptions] = SSL_OPTIONS
        if @ca_file
          store = OpenSSL::X509::Store.new
          @ca_file.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).each do |pem|
            store.add_cert(OpenSSL::X509::Certificate.new(pem))
          end
          config[:SSLCertificateStore] = store
          config[:SSLVerifyClient] = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
        end
      elsif @cert or @key
        raise "HttpServerInterface requires both CERT and KEY options to enable HTTPS"
      elsif @ca_file
        raise "HttpServerInterface CA_FILE option requires CERT and KEY"
      end
      if @listen_address == '0.0.0.0' and !ssl? and !@auth_token
        Logger.warn("#{@name}: accepting unauthenticated plain HTTP from any address on port #{@port}. Set CERT/KEY, AUTH_TOKEN or LISTEN_ADDRESS to restrict access.")
      end
      return config
    end

    def authorized?(req)
      return true unless @auth_token

      header = req['Authorization'].to_s
      return false unless header.start_with?('Bearer ')

      token = header[7..-1].to_s
      return false unless token.bytesize == @auth_token.bytesize

      return OpenSSL.fixed_length_secure_compare(token, @auth_token)
    end
  end
end
