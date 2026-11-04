# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/streams/tcpip_client_stream'

module OpenC3
  describe TcpipClientStream do
    before(:all) do
      addr = Socket.pack_sockaddr_in(8888, "0.0.0.0")
      if RUBY_ENGINE == 'ruby'
        @listen_socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      else
        @listen_socket = ServerSocket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
      end
      @listen_socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1) unless Kernel.is_windows?
      if RUBY_ENGINE == 'ruby'
        @listen_socket.bind(addr)
        @listen_socket.listen(5)
      else
        @listen_socket.bind(addr, 5)
      end
    end

    after(:all) do
      @listen_socket.close
    end

    describe "initialize" do
      it "complains if the host is bad" do
        expect { TcpipClientStream.new('asdf', 8888, 8888, 10.0, nil) }.to raise_error(/Invalid hostname/)
      end

      it "uses the same socket if read_port == write_port" do
        ss = TcpipClientStream.new('localhost', 8888, 8888, 10.0, nil)
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end

      it "creates the write socket" do
        ss = TcpipClientStream.new('localhost', 8888, nil, 10.0, nil)
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end

      it "creates the read socket" do
        ss = TcpipClientStream.new('localhost', nil, 8888, 10.0, nil)
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end
    end
  end
end

module OpenC3
  describe TcpipClientStream, "with TLS" do
    def self_signed(name)
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new(cert, cert)
      cert.add_extension(ef.create_extension("subjectAltName", "DNS:#{name},IP:127.0.0.1"))
      cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      return cert, key
    end

    before(:each) do
      @cert, @key = self_signed('localhost')
      context = OpenSSL::SSL::SSLContext.new
      context.cert = @cert
      context.key = @key
      context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      @tcp_server = TCPServer.new('127.0.0.1', 8890)
      @ssl_server = OpenSSL::SSL::SSLServer.new(@tcp_server, context)
      @server_thread = Thread.new do
        loop do
          begin
            client = @ssl_server.accept
            data = client.readpartial(1024)
            client.write(data.upcase)
            client.close
          rescue StandardError
            break if @tcp_server.closed?
          end
        end
      end
    end

    after(:each) do
      @tcp_server.close
      @server_thread.kill
      @server_thread.join
    end

    it "reports ssl? false until an SSL option is set" do
      ss = TcpipClientStream.new('localhost', 8890, 8890, 10.0, 5.0)
      expect(ss.ssl?).to be false
      ss.set_option('SSL', ['true'])
      expect(ss.ssl?).to be true
    end

    it "round trips data over TLS when the CA is trusted" do
      ss = TcpipClientStream.new('localhost', 8890, 8890, 10.0, 5.0)
      ss.set_option('SSL_CA_FILE', [@cert.to_pem])
      ss.set_option('SSL_HOSTNAME', ['localhost'])
      ss.connect
      expect(ss.connected?).to be true
      expect(ss.write_socket).to be_a(OpenSSL::SSL::SSLSocket)
      ss.write("hello")
      expect(ss.read).to eql "HELLO"
      ss.disconnect
    end

    it "refuses an untrusted server certificate" do
      ss = TcpipClientStream.new('localhost', 8890, 8890, 10.0, 5.0)
      ss.set_option('SSL', ['true'])
      ss.set_option('SSL_HOSTNAME', ['localhost'])
      expect { ss.connect }.to raise_error(OpenSSL::SSL::SSLError)
    end

    it "connects to an untrusted certificate only when SSL_VERIFY is false" do
      expect(Logger).to receive(:warn).with(/SSL_VERIFY false/)
      ss = TcpipClientStream.new('localhost', 8890, 8890, 10.0, 5.0)
      ss.set_option('SSL', ['true'])
      ss.set_option('SSL_VERIFY', ['false'])
      ss.connect
      ss.write("abc")
      expect(ss.read).to eql "ABC"
      ss.disconnect
    end
  end
end
