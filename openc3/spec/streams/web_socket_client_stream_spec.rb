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
    def self_signed_cert(common_name)
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = rand(1..(2**31))
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{common_name}")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = cert
      cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(ef.create_extension("subjectAltName", "DNS:#{common_name}"))
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      [cert, key]
    end

    # Minimal wss server: TLS accept then answer the WebSocket handshake
    def start_tls_server(cert, key)
      ssl_context = OpenSSL::SSL::SSLContext.new
      ssl_context.cert = cert
      ssl_context.key = key
      tcp_server = TCPServer.new('127.0.0.1', 0)
      port = tcp_server.addr[1]
      ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, ssl_context)
      ssl_server.start_immediately = false
      request = +""
      thread = Thread.new do
        begin
          client = ssl_server.accept
          client.accept
          handshake = WebSocket::Handshake::Server.new
          until handshake.finished?
            char = client.read(1)
            break unless char

            request << char
            handshake << char
          end
          client.write(handshake.to_s) if handshake.finished?
          client.close
        rescue OpenSSL::SSL::SSLError, IOError, Errno::ECONNRESET
          # Client rejected us, which is what several tests verify
        end
      end
      [port, thread, request, tcp_server]
    end

    def with_trusted_cert(cert)
      file = Tempfile.new(['ca', '.pem'])
      file.write(cert.to_pem)
      file.close
      original = ENV['SSL_CERT_FILE']
      ENV['SSL_CERT_FILE'] = file.path
      yield
    ensure
      ENV['SSL_CERT_FILE'] = original
      file.unlink
    end

    describe "initialize" do
      it "does not build an ssl context for ws" do
        stream = WebSocketClientStream.new("ws://localhost:1234/cable", 10.0, 10.0)
        expect(stream.ssl_context).to be_nil
      end

      it "builds a verifying ssl context for wss" do
        stream = WebSocketClientStream.new("wss://localhost:1234/cable", 10.0, 10.0)
        expect(stream.ssl_context.verify_mode).to eq OpenSSL::SSL::VERIFY_PEER
        expect(stream.ssl_context.verify_hostname).to be true
        expect(stream.ssl_context.cert_store).to be_a(OpenSSL::X509::Store)
      end
    end

    describe "connect" do
      it "rejects a server certificate not signed by a trusted CA" do
        cert, key = self_signed_cert('localhost')
        port, thread, request, server = start_tls_server(cert, key)
        begin
          stream = WebSocketClientStream.new("wss://localhost:#{port}/cable", 10.0, 10.0)
          expect { stream.connect }.to raise_error(OpenSSL::SSL::SSLError, /certificate verify failed/)
          expect(stream.connected?).to be false
          thread.join(5)
          expect(request).to eq ""
        ensure
          server.close
        end
      end

      it "rejects a trusted certificate issued for another hostname" do
        cert, key = self_signed_cert('other.example.com')
        port, thread, request, server = start_tls_server(cert, key)
        begin
          with_trusted_cert(cert) do
            stream = WebSocketClientStream.new("wss://localhost:#{port}/cable", 10.0, 10.0)
            expect { stream.connect }.to raise_error(OpenSSL::SSL::SSLError, /hostname|verify failed/)
            expect(stream.connected?).to be false
          end
          thread.join(5)
          expect(request).to eq ""
        ensure
          server.close
        end
      end

      it "completes the handshake over TLS when the certificate is trusted and matches" do
        cert, key = self_signed_cert('localhost')
        port, thread, request, server = start_tls_server(cert, key)
        begin
          with_trusted_cert(cert) do
            stream = WebSocketClientStream.new("wss://localhost:#{port}/cable", 10.0, 10.0)
            expect(stream.connect).to be true
            expect(stream.connected?).to be true
            expect(stream.write_socket).to be_a(OpenSSL::SSL::SSLSocket)
            expect(stream.write_socket.peer_cert.to_pem).to eq cert.to_pem
            stream.disconnect
          end
          thread.join(5)
          expect(request).to start_with("GET /cable HTTP/1.1")
        ensure
          server.close
        end
      end
    end
  end
end
