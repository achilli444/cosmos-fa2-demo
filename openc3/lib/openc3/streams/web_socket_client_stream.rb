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
require 'openc3/streams/tcpip_client_stream'
require 'websocket'
require 'uri'

module OpenC3
  class WebSocketClientStream < TcpipClientStream
    attr_accessor :headers
    # Optional path to a PEM bundle of CA certificates to trust for wss/https
    # instead of the system store (same semantics as MqttStream#ca_file)
    attr_accessor :ca_file

    # @param url [String] The host to connect to
    # @param write_timeout [Float] Seconds to wait before aborting writes
    # @param read_timeout [Float|nil] Seconds to wait before aborting reads.
    #   Pass nil to block until the read is complete.
    # @param connect_timeout [Float|nil] Seconds to wait before aborting connect.
    #   Pass nil to block until the connection is complete.
    def initialize(url, write_timeout, read_timeout, connect_timeout = 5.0)
      @url = url
      @uri = URI.parse @url
      @ssl = ['https', 'wss'].include?(@uri.scheme)
      port = (@ssl ? 443 : 80)
      port = @uri.port if @uri.port
      super(@uri.host, port, port, write_timeout, read_timeout, connect_timeout)
      @headers = {}
      @ca_file = nil
    end

    def connect
      super()
      ssl_connect() if @ssl
      @handshake = ::WebSocket::Handshake::Client.new(:url => @url, :headers => @headers)
      @frame = ::WebSocket::Frame::Incoming::Client.new
      @handshaked = false
      @write_socket.write(@handshake.to_s)
      read() # This should wait for the handshake
      return true
    end

    def read
      while true
        if @handshaked
          msg = @frame.next
          return msg.data if msg
        end

        data = super()
        return data if data.length <= 0

        if @handshaked
          @frame << data
          msg = @frame.next
          return msg.data if msg
        else
          index = 0
          chars = ""
          data.each_char do |char|
            @handshake << char
            chars << char
            index += 1
            if @handshake.finished?
              @handshaked = true
              break
            end
          end
          if @handshaked
            data = data[index..-1]
            @frame << data
            return
          end
        end
      end
    end

    def write(data, type: :text)
      frame = ::WebSocket::Frame::Outgoing::Client.new(:data => data, :type => type, :version => @handshake.version)
      super(frame.to_s)
    end

    # Builds the context used for wss/https connections. The server certificate
    # must chain to a trusted CA (the system store, honoring SSL_CERT_FILE and
    # SSL_CERT_DIR, or #ca_file when set) and match the URL hostname.
    def ssl_context
      context = ::OpenSSL::SSL::SSLContext.new
      context.ca_file = @ca_file if @ca_file
      context.set_params(verify_mode: ::OpenSSL::SSL::VERIFY_PEER, verify_hostname: true)
      context
    end

    protected

    # Wraps the connected TCP socket in a verifying SSLSocket and completes the
    # TLS handshake, honoring @connect_timeout. Raises OpenSSL::SSL::SSLError
    # if the server certificate does not verify or does not match the host.
    def ssl_connect
      socket = ::OpenSSL::SSL::SSLSocket.new(@write_socket, ssl_context())
      socket.sync_close = true
      socket.hostname = @uri.host
      # Reassign before the handshake so disconnect() closes the socket if it fails
      @write_socket = socket
      @read_socket = socket
      loop do
        case socket.connect_nonblock(exception: false)
        when :wait_readable
          raise "Connect timeout" unless socket.wait_readable(@connect_timeout)
        when :wait_writable
          raise "Connect timeout" unless socket.wait_writable(@connect_timeout)
        else
          break
        end
      end
      socket.post_connection_check(@uri.host)
    end
  end
end
