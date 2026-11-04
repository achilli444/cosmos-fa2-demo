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
    attr_reader :ssl_context

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
      @ssl_context = build_ssl_context() if @ssl
      @headers = {}
    end

    def connect
      super()
      start_tls() if @ssl
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

    protected

    # The server certificate must chain to a CA in the system store
    # (SSL_CERT_FILE / SSL_CERT_DIR are honored, see cacert.pem in compose.yaml)
    # and must match the hostname in the URL.
    def build_ssl_context
      context = ::OpenSSL::SSL::SSLContext.new
      context.min_version = ::OpenSSL::SSL::TLS1_2_VERSION
      context.verify_mode = ::OpenSSL::SSL::VERIFY_PEER
      context.verify_hostname = true
      store = ::OpenSSL::X509::Store.new
      store.set_default_paths
      context.cert_store = store
      context
    end

    # Wrap the connected TCP socket in TLS and verify the server before any
    # application data (handshake headers, token, telemetry) is sent.
    def start_tls
      socket = ::OpenSSL::SSL::SSLSocket.new(@write_socket, @ssl_context)
      socket.sync_close = true
      socket.hostname = @uri.host
      begin
        ssl_connect_nonblock(socket)
        socket.post_connection_check(@uri.host)
      rescue => e
        OpenC3.close_socket(socket)
        @connected = false
        raise e
      end
      @write_socket = socket
      @read_socket = socket
    end

    def ssl_connect_nonblock(socket)
      loop do
        case socket.connect_nonblock(exception: false)
        when :wait_readable
          socket.to_io.wait_readable(@connect_timeout) or raise "Connect timeout"
        when :wait_writable
          socket.to_io.wait_writable(@connect_timeout) or raise "Connect timeout"
        else
          return
        end
      end
    rescue IOError, Errno::ENOTSOCK
      raise "Connect canceled"
    end
  end
end
