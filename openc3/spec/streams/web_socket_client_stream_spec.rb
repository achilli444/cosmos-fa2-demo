# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

require 'spec_helper'
require 'openc3/streams/web_socket_client_stream'
require_relative '../support/tls_test_server'

module OpenC3
  describe WebSocketClientStream do
    # Reads the HTTP upgrade request from the socket and answers with a
    # websocket handshake (the Sec-WebSocket-Accept value is not checked
    # by the client).
    def websocket_handshake(socket)
      request = ''
      request << socket.readpartial(4096) until request.include?("\r\n\r\n")
      socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n")
      socket.flush
      request
    end

    describe "initialize" do
      it "defaults to port 80 without TLS for ws" do
        ss = WebSocketClientStream.new('ws://localhost/path', 10.0, 10.0)
        expect(ss.tls?).to be false
      end

      it "defaults to port 443 with TLS for wss" do
        ss = WebSocketClientStream.new('wss://localhost/path', 10.0, 10.0)
        expect(ss.tls?).to be true
      end

      it "enables TLS for https" do
        ss = WebSocketClientStream.new('https://localhost:8443/path', 10.0, 10.0)
        expect(ss.tls?).to be true
      end
    end

    describe "connect" do
      before(:each) do
        @server = TlsTestServer.new
      end

      after(:each) do
        @server.close
      end

      it "rejects a wss server with an untrusted certificate" do
        @server.accept_once
        ss = WebSocketClientStream.new("wss://localhost:#{@server.port}/cable", 10.0, 10.0)
        expect { ss.connect }.to raise_error(OpenSSL::SSL::SSLError, /certificate verify failed/)
        expect(@server.server_error).to be_a OpenSSL::SSL::SSLError
      end

      it "rejects a wss server whose certificate does not match the host" do
        @server.close
        @server = TlsTestServer.new(hostnames: ['other.example.com'], ip: nil)
        @server.accept_once
        ss = WebSocketClientStream.new("wss://localhost:#{@server.port}/cable", 10.0, 10.0, 5.0, tls: { ca_file: @server.ca_file })
        expect { ss.connect }.to raise_error(OpenSSL::SSL::SSLError, /hostname|verify failed/)
      end

      it "connects over wss when the CA is trusted and exchanges frames" do
        request = nil
        @server.accept_once do |socket|
          request = websocket_handshake(socket)
          # Unmasked text frame "pong" from the server
          socket.write(["\x81".b, [4].pack('C'), "pong"].join)
          socket.flush
          socket.readpartial(4096) # client frame
        end
        ss = WebSocketClientStream.new("wss://localhost:#{@server.port}/cable?token=x", 10.0, 10.0, 5.0, tls: { ca_file: @server.ca_file })
        ss.connect
        expect(ss.connected?).to be true
        expect(request).to match(%r{GET /cable\?token=x HTTP/1.1})
        expect(request).to match(/Upgrade: websocket/i)
        expect(ss.read).to eq "pong"
        ss.write("ping")
        ss.disconnect
        expect(@server.server_error).to be_nil
      end

      it "connects over plaintext ws" do
        tcp_server = TCPServer.new('127.0.0.1', 0)
        thread = Thread.new do
          socket = tcp_server.accept
          websocket_handshake(socket)
          socket.write(["\x81".b, [2].pack('C'), "ok"].join)
          socket.flush
          sleep 0.5
          socket.close
        end
        ss = WebSocketClientStream.new("ws://localhost:#{tcp_server.addr[1]}/cable", 10.0, 10.0)
        expect(ss.tls?).to be false
        ss.connect
        expect(ss.connected?).to be true
        expect(ss.read).to eq "ok"
        ss.disconnect
        thread.join
        tcp_server.close
      end
    end
  end
end
