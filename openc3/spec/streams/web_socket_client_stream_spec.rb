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
require 'openc3/streams/web_socket_client_stream'
require 'openssl'
require 'socket'
require 'tempfile'

module OpenC3
  describe WebSocketClientStream do
    before(:all) do
      @key = OpenSSL::PKey::RSA.new(2048)
      @cert = OpenSSL::X509::Certificate.new
      @cert.version = 2
      @cert.serial = 1
      @cert.subject = OpenSSL::X509::Name.parse('/CN=localhost')
      @cert.issuer = @cert.subject
      @cert.public_key = @key.public_key
      @cert.not_before = Time.now - 60
      @cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new(@cert, @cert)
      @cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
      @cert.add_extension(ef.create_extension('subjectAltName', 'DNS:localhost'))
      @cert.sign(@key, OpenSSL::Digest.new('SHA256'))
      @ca_file = Tempfile.new(['ca', '.pem'])
      @ca_file.write(@cert.to_pem)
      @ca_file.close
    end

    after(:all) do
      @ca_file.unlink
    end

    # Minimal WebSocket server: answers the opening handshake then holds the
    # connection open until the client disconnects.
    def serve_websocket(io)
      handshake = ::WebSocket::Handshake::Server.new
      handshake << io.readpartial(4096) until handshake.finished?
      io.write(handshake.to_s)
      loop { io.readpartial(4096) }
    rescue StandardError
      # Client went away
    ensure
      io.close rescue nil
    end

    # Serves a single connection (plain or TLS) on an ephemeral port and
    # yields the port. The server thread is joined before returning so the
    # spec_helper thread-leak check passes.
    def with_server(tls: false)
      server = TCPServer.new('127.0.0.1', 0)
      context = nil
      if tls
        context = OpenSSL::SSL::SSLContext.new
        context.cert = @cert
        context.key = @key
      end
      thread = Thread.new do
        client = server.accept
        if context
          client = OpenSSL::SSL::SSLSocket.new(client, context)
          client.sync_close = true
          begin
            client.accept
          rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
            client.close rescue nil
            next
          end
        end
        serve_websocket(client)
      rescue IOError, SystemCallError
        # Server closed before a client connected
      end
      yield server.addr[1]
    ensure
      server.close
      thread.kill unless thread.join(2)
    end

    describe "ssl_context" do
      it "requires peer certificate and hostname verification" do
        stream = WebSocketClientStream.new("wss://localhost:443/cable", 5.0, 5.0, 5.0)
        context = stream.ssl_context
        expect(context.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
        expect(context.verify_hostname).to be true
        expect(context.ca_file).to be_nil
      end

      it "trusts the configured ca_file" do
        stream = WebSocketClientStream.new("wss://localhost:443/cable", 5.0, 5.0, 5.0)
        stream.ca_file = @ca_file.path
        context = stream.ssl_context
        expect(context.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
        expect(context.ca_file).to eq(@ca_file.path)
      end
    end

    describe "connect" do
      it "completes the handshake over plain ws" do
        with_server do |port|
          stream = WebSocketClientStream.new("ws://localhost:#{port}/cable", 5.0, 5.0, 5.0)
          expect(stream.connect).to be true
          expect(stream.connected?).to be true
          expect(stream.instance_variable_get(:@handshaked)).to be true
          expect(stream.instance_variable_get(:@write_socket)).not_to be_a(OpenSSL::SSL::SSLSocket)
          stream.disconnect
        end
      end

      it "rejects a wss server whose certificate is not trusted" do
        with_server(tls: true) do |port|
          stream = WebSocketClientStream.new("wss://localhost:#{port}/cable", 5.0, 5.0, 5.0)
          expect { stream.connect }.to raise_error(OpenSSL::SSL::SSLError, /certificate verify failed/)
          stream.disconnect
        end
      end

      it "rejects a trusted certificate that does not match the URL host" do
        with_server(tls: true) do |port|
          stream = WebSocketClientStream.new("wss://127.0.0.1:#{port}/cable", 5.0, 5.0, 5.0)
          stream.ca_file = @ca_file.path
          expect { stream.connect }.to raise_error(OpenSSL::SSL::SSLError, /certificate verify failed|hostname/)
          stream.disconnect
        end
      end

      it "completes the handshake over wss when the certificate is trusted and matches the host" do
        with_server(tls: true) do |port|
          stream = WebSocketClientStream.new("wss://localhost:#{port}/cable", 5.0, 5.0, 5.0)
          stream.ca_file = @ca_file.path
          expect(stream.connect).to be true
          expect(stream.connected?).to be true
          expect(stream.instance_variable_get(:@handshaked)).to be true
          socket = stream.instance_variable_get(:@write_socket)
          expect(socket).to be_a(OpenSSL::SSL::SSLSocket)
          expect(socket.context.verify_mode).to eq(OpenSSL::SSL::VERIFY_PEER)
          expect(socket.peer_cert.subject.to_s).to include('CN=localhost')
          stream.disconnect
        end
      end
    end
  end
end
