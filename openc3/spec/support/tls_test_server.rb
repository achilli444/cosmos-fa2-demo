# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

require 'openssl'
require 'socket'
require 'tempfile'

module OpenC3
  # Minimal TLS server used by the stream specs to exercise certificate
  # verification. Issues its own CA and a server certificate valid for
  # localhost / 127.0.0.1 (or a mismatched name when asked).
  class TlsTestServer
    attr_reader :port, :ca_file, :ca_pem

    def initialize(hostnames: ['localhost'], ip: '127.0.0.1')
      @ca_key = OpenSSL::PKey::RSA.new(2048)
      @ca_cert = build_cert(@ca_key, @ca_key, "/CN=OpenC3 Spec CA #{Random.rand(1 << 32)}", ca: true)
      @server_key = OpenSSL::PKey::RSA.new(2048)
      sans = hostnames.map { |h| "DNS:#{h}" }
      sans << "IP:#{ip}" if ip
      @server_cert = build_cert(@server_key, @ca_key, "/CN=#{hostnames.first}", issuer: @ca_cert, sans: sans)
      @ca_pem = @ca_cert.to_pem
      @ca_tempfile = Tempfile.new(['spec_ca', '.pem'])
      @ca_tempfile.write(@ca_pem)
      @ca_tempfile.close
      @ca_file = @ca_tempfile.path

      context = OpenSSL::SSL::SSLContext.new
      context.cert = @server_cert
      context.key = @server_key
      @tcp_server = TCPServer.new('127.0.0.1', 0)
      @port = @tcp_server.addr[1]
      @ssl_server = OpenSSL::SSL::SSLServer.new(@tcp_server, context)
      @ssl_server.start_immediately = true
      @errors = Queue.new
    end

    # Accept one TLS connection on a thread and yield the SSLSocket to the block
    def accept_once(&block)
      @thread = Thread.new do
        begin
          socket = @ssl_server.accept
          block.call(socket) if block
          socket.close unless socket.closed?
        rescue => e
          @errors << e
        end
      end
    end

    # @return [Exception|nil] The first error the server thread hit (e.g. handshake failure)
    def server_error(timeout = 2.0)
      @thread.join(timeout) if @thread
      @errors.empty? ? nil : @errors.pop
    end

    def close
      if @thread
        @thread.kill if @thread.alive?
        @thread.join(2.0)
      end
      @ssl_server.close rescue nil
      @ca_tempfile.unlink
    end

    private

    def build_cert(key, signing_key, subject, ca: false, issuer: nil, sans: [])
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = Random.rand(1 << 48)
      cert.subject = OpenSSL::X509::Name.parse(subject)
      cert.issuer = issuer ? issuer.subject : cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      factory.issuer_certificate = issuer || cert
      if ca
        cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
        cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign, cRLSign', true))
      else
        cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
        cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature, keyEncipherment', true))
        cert.add_extension(factory.create_extension('extendedKeyUsage', 'serverAuth', false))
        cert.add_extension(factory.create_extension('subjectAltName', sans.join(','), false)) unless sans.empty?
      end
      cert.sign(signing_key, OpenSSL::Digest.new('SHA256'))
      cert
    end
  end
end
