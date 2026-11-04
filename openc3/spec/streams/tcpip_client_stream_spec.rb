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
require_relative '../support/tls_test_server'

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
    describe "build_ssl_context" do
      it "verifies the peer with the default store by default" do
        context = TcpipClientStream.build_ssl_context
        expect(context.verify_mode).to eq OpenSSL::SSL::VERIFY_PEER
        expect(context.verify_hostname).to be true
      end

      it "loads a custom ca_file into the store" do
        server = TlsTestServer.new
        context = TcpipClientStream.build_ssl_context(ca_file: server.ca_file)
        expect(context.verify_mode).to eq OpenSSL::SSL::VERIFY_PEER
        expect(context.cert_store).to be_a OpenSSL::X509::Store
        expect(context.cert_store.verify(OpenSSL::X509::Certificate.new(server.ca_pem))).to be true
        server.close
      end

      it "requires both cert and key for mutual TLS" do
        expect { TcpipClientStream.build_ssl_context(cert: 'cert.pem') }.to raise_error(ArgumentError, /cert and key/)
        expect { TcpipClientStream.build_ssl_context(key: 'key.pem') }.to raise_error(ArgumentError, /cert and key/)
      end

      it "only disables verification when verify is explicitly false" do
        expect(Logger).to receive(:warn).with(/verification disabled/)
        context = TcpipClientStream.build_ssl_context(verify: 'FALSE')
        expect(context.verify_mode).to eq OpenSSL::SSL::VERIFY_NONE
      end
    end

    describe "tls" do
      before(:each) do
        @server = TlsTestServer.new
      end

      after(:each) do
        @server.close
      end

      it "is disabled by default" do
        ss = TcpipClientStream.new('localhost', 8888, 8888, 10.0, nil)
        expect(ss.tls?).to be false
      end

      it "rejects a server certificate not signed by a trusted CA" do
        @server.accept_once
        ss = TcpipClientStream.new('localhost', @server.port, @server.port, 10.0, nil, 5.0, tls: true)
        expect(ss.tls?).to be true
        expect { ss.connect }.to raise_error(OpenSSL::SSL::SSLError, /certificate verify failed/)
        expect(ss.connected?).to be false
        expect(@server.server_error).to be_a OpenSSL::SSL::SSLError
      end

      it "connects when the CA is trusted via ca_file and exchanges data" do
        @server.accept_once do |socket|
          data = socket.readpartial(100)
          socket.write(data.upcase)
          socket.flush
        end
        ss = TcpipClientStream.new('localhost', @server.port, @server.port, 10.0, 5.0, 5.0, tls: { ca_file: @server.ca_file })
        ss.connect
        expect(ss.connected?).to be true
        ss.write("hello")
        expect(ss.read).to eq "HELLO"
        ss.disconnect
        expect(ss.connected?).to be false
        expect(@server.server_error).to be_nil
      end

      it "accepts inline PEM for ca_file" do
        @server.accept_once
        ss = TcpipClientStream.new('localhost', @server.port, @server.port, 10.0, nil, 5.0, tls: { ca_file: @server.ca_pem })
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end

      it "verifies the certificate against an IP address hostname" do
        @server.accept_once
        ss = TcpipClientStream.new('127.0.0.1', @server.port, @server.port, 10.0, nil, 5.0, tls: { ca_file: @server.ca_file })
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end

      it "rejects a certificate whose hostname does not match" do
        @server.close
        @server = TlsTestServer.new(hostnames: ['other.example.com'], ip: nil)
        @server.accept_once
        ss = TcpipClientStream.new('localhost', @server.port, @server.port, 10.0, nil, 5.0, tls: { ca_file: @server.ca_file })
        expect { ss.connect }.to raise_error(OpenSSL::SSL::SSLError, /hostname|verify failed/)
        expect(ss.connected?).to be false
      end

      it "allows overriding the hostname used for verification" do
        @server.close
        @server = TlsTestServer.new(hostnames: ['other.example.com'], ip: nil)
        @server.accept_once
        ss = TcpipClientStream.new('localhost', @server.port, @server.port, 10.0, nil, 5.0, tls: { ca_file: @server.ca_file, hostname: 'other.example.com' })
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end

      it "wraps separate read and write sockets" do
        read_server = TlsTestServer.new
        @server.accept_once { |socket| socket.readpartial(100) }
        read_server.accept_once do |socket|
          socket.write("from read")
          socket.flush
        end
        ca = @server.ca_pem + read_server.ca_pem
        ss = TcpipClientStream.new('localhost', @server.port, read_server.port, 10.0, 5.0, 5.0, tls: { ca_file: ca })
        ss.connect
        expect(ss.connected?).to be true
        ss.write("to write")
        expect(ss.read).to eq "from read"
        ss.disconnect
        expect(@server.server_error).to be_nil
        expect(read_server.server_error).to be_nil
        read_server.close
      end

      it "is configured through set_option like an interface OPTION" do
        @server.accept_once
        ss = TcpipClientStream.new('localhost', @server.port, @server.port, 10.0, nil)
        expect(ss.tls?).to be false
        ss.set_option('TLS', ['TRUE'])
        ss.set_option('TLS_CA_FILE', [@server.ca_file])
        expect(ss.tls?).to be true
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end

      it "still connects to a plain TCP server when TLS is not enabled" do
        ss = TcpipClientStream.new('localhost', 8888, 8888, 10.0, nil)
        ss.connect
        expect(ss.connected?).to be true
        ss.disconnect
      end
    end
  end
end
