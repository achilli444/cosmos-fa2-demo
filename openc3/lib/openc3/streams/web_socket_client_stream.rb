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

    # @param url [String] The host to connect to
    # @param write_timeout [Float] Seconds to wait before aborting writes
    # @param read_timeout [Float|nil] Seconds to wait before aborting reads.
    #   Pass nil to block until the read is complete.
    # @param connect_timeout [Float|nil] Seconds to wait before aborting connect.
    #   Pass nil to block until the connection is complete.
    # @param tls [Hash] TLS options (:ca_file, :cert, :key, :verify) applied
    #   to wss / https URLs. See {TcpipClientStream.build_ssl_context}. The
    #   server certificate is verified against the CA store and checked
    #   against the URL host unless verify: false is given.
    def initialize(url, write_timeout, read_timeout, connect_timeout = 5.0, tls: {})
      @url = url
      @uri = URI.parse @url
      secure = ['https', 'wss'].include?(@uri.scheme)
      port = (secure ? 443 : 80)
      port = @uri.port if @uri.port
      # TLS is negotiated in connect (after the TCP connect) by TcpipClientStream,
      # which verifies the certificate and calls post_connection_check(host)
      super(@uri.host, port, port, write_timeout, read_timeout, connect_timeout, tls: (secure ? { hostname: @uri.host }.merge(tls) : nil))
      @headers = {}
    end

    def connect
      super()
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
  end
end
