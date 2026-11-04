# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/interfaces/http_server_interface'
require 'openc3/packets/packet'
require 'openc3/system/system'
require 'net/http'
require 'openssl'
require 'socket'

module OpenC3
  describe HttpServerInterface do
    before(:all) do
      setup_system()
      @localhost = '127.0.0.1'
      @socket_80 = 80 # make desktop spec not collide with dev/CI env where Cosmos is already running
      begin
        sock = Socket.new(Socket::Constants::AF_INET, Socket::Constants::SOCK_STREAM, 0)
        sock.bind(Socket.pack_sockaddr_in(80,  @localhost )) #raise if listening
        sock.close
      rescue Errno::EACCES => e;
        Logger.info("Found listener on port 80; presumably in CI\n#{e.message}")
        @socket_80 = 81
      end
    end

    before(:each) do
      @interface = HttpServerInterface.new(8000 + @socket_80)
    end

    after(:each) do
      kill_leftover_threads()
    end

    # Self-signed CA plus a server (and client) certificate signed by it
    def make_ca
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse("/CN=Test CA")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new(cert, cert)
      cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(ef.create_extension("keyUsage", "keyCertSign, cRLSign", true))
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      return cert, key
    end

    def make_cert(cn, ca_cert, ca_key, serial)
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = serial
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{cn}")
      cert.issuer = ca_cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new(ca_cert, cert)
      cert.add_extension(ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false))
      cert.sign(ca_key, OpenSSL::Digest.new('SHA256'))
      return cert, key
    end

    def free_port
      server = TCPServer.new(@localhost, 0)
      port = server.addr[1]
      server.close
      return port
    end

    # Mounts /test for every INST command and stores requests as REQUEST telemetry
    def start_server(interface)
      allow_any_instance_of(Packet).to receive(:read).with('HTTP_PATH').and_return('/test')
      allow_any_instance_of(Packet).to receive(:read).with('HTTP_STATUS').and_return(200)
      allow_any_instance_of(Packet).to receive(:read).with('HTTP_PACKET').and_return('REQUEST')
      interface.target_names = ['INST']
      capture_io { interface.connect }
      sleep 0.2
    end

    def http(port, ssl: false, token: nil, client_cert: nil, client_key: nil)
      http = Net::HTTP.new(@localhost, port)
      if ssl
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.cert = client_cert if client_cert
        http.key = client_key if client_key
      end
      http.open_timeout = 2
      http.read_timeout = 2
      request = Net::HTTP::Get.new('/test?temp=1')
      request['Authorization'] = "Bearer #{token}" if token
      request['Cookie'] = 'session=abc'
      request['X-Custom'] = 'kept'
      return http.request(request)
    end

    describe "#initialize" do
      it "initializes with default port" do # above the privileged port range
        expect(@interface.instance_variable_get(:@port)).to eq(8000 + @socket_80)
      end

      it "defaults the listen address to loopback" do
        expect(@interface.instance_variable_get(:@listen_address)).to eq('127.0.0.1')
      end

      it "initializes with custom port" do
        interface = HttpServerInterface.new(8000 + @socket_80)
        expect(interface.instance_variable_get(:@port)).to eq(8000 + @socket_80)
      end
    end

    describe "#set_option" do
      it "sets the listen address" do
        @interface.set_option("LISTEN_ADDRESS", [ '0.0.0.0' ])
        expect(@interface.instance_variable_get(:@listen_address)).to eq('0.0.0.0')
      end

      it "sets the auth token and ignores a blank one" do
        @interface.set_option("AUTH_TOKEN", [ 'secret' ])
        expect(@interface.instance_variable_get(:@auth_token)).to eq('secret')
        @interface.set_option("AUTH_TOKEN", [ '' ])
        expect(@interface.instance_variable_get(:@auth_token)).to be_nil
      end

      it "accepts SSL_CERT and SSL_KEY as PEM contents or a file path" do
        ca_cert, ca_key = make_ca()
        cert, key = make_cert('localhost', ca_cert, ca_key, 2)
        @interface.set_option("SSL_CERT", [ cert.to_pem ])
        expect(@interface.instance_variable_get(:@ssl_cert)).to eq(cert.to_pem)
        Tempfile.create('key') do |file|
          file.write(key.to_pem)
          file.flush
          @interface.set_option("SSL_KEY", [ file.path ])
        end
        expect(@interface.instance_variable_get(:@ssl_key)).to eq(key.to_pem)
        expect(@interface.ssl?).to be true
      end
    end

    describe "#connection_string" do
      it "returns the correct connection string" do
        expect(@interface.connection_string).to eq("listening on 127.0.0.1:#{8000 + @socket_80}")
      end

      it "flags ssl" do
        @interface.set_option("SSL_CERT", [ 'cert' ])
        expect(@interface.connection_string).to eq("listening on 127.0.0.1:#{8000 + @socket_80} (ssl)")
      end
    end

    describe "#connect" do
      it "connects to a web server and mounts routes" do
        allow_any_instance_of(Packet).to receive(:read).with('HTTP_PATH').and_return('/test')
        allow_any_instance_of(Packet).to receive(:read).with('HTTP_STATUS').and_return(200)
        @interface.instance_variable_set(:@port, 8000 + @socket_80)
        @interface.connect
        expect(@interface.instance_variable_get(:@server)).to_not be_nil
      end

      it "creates a response hook for every command packet" do
        @interface.target_names = ['INST']
        server_double = double
        allow(WEBrick::HTTPServer).to receive(:new).and_return(server_double)
        request = OpenStruct.new(header: { alpha: "bet" }, query: { what: "is" }, status: nil, body: nil)
        response = OpenStruct.new(status: nil, body: nil)
        allow(server_double).to receive(:mount_proc).with('/test').and_yield(request, response)
        expect(server_double).to receive(:start) do
          sleep(0.1)
        end
        @interface.instance_variable_set(:@port, 8000 + @socket_80)
        @interface.connect
        sleep 0.2
      end

      it "warns when exposed without authentication" do
        allow(WEBrick::HTTPServer).to receive(:new).and_return(double(start: nil))
        @interface.set_option("LISTEN_ADDRESS", [ '0.0.0.0' ])
        expect(Logger).to receive(:warn).with(/without AUTH_TOKEN or SSL_CA_FILE/)
        @interface.connect
      end

      it "does not warn on loopback or when AUTH_TOKEN is set" do
        allow(WEBrick::HTTPServer).to receive(:new).and_return(double(start: nil))
        expect(Logger).not_to receive(:warn)
        @interface.connect
        @interface.set_option("LISTEN_ADDRESS", [ '0.0.0.0' ])
        @interface.set_option("AUTH_TOKEN", [ 'secret' ])
        @interface.connect
      end

      it "raises if only one of SSL_CERT / SSL_KEY is set" do
        @interface.set_option("SSL_CERT", [ 'cert' ])
        expect { @interface.connect }.to raise_error(/SSL_CERT and SSL_KEY must both be set/)
      end
    end

    describe "request handling" do
      before(:each) do
        @port = free_port()
        @interface = HttpServerInterface.new(@port)
      end

      after(:each) do
        @interface.disconnect
      end

      it "accepts requests and redacts credential headers from the telemetry" do
        start_server(@interface)
        response = http(@port)
        expect(response.code).to eq('200')
        _, extra = @interface.read_interface
        expect(extra['HTTP_QUERIES']).to eq({ 'temp' => '1' })
        expect(extra['HTTP_HEADERS']['x-custom']).to eq(['kept'])
        expect(extra['HTTP_HEADERS']).not_to have_key('cookie')
        expect(extra['HTTP_HEADERS']).not_to have_key('authorization')
      end

      it "rejects requests without the AUTH_TOKEN and does not queue them" do
        @interface.set_option("AUTH_TOKEN", [ 'secret' ])
        start_server(@interface)
        expect(Logger).to receive(:warn).with(/rejected unauthenticated request for \/test from 127.0.0.1/).twice

        response = http(@port)
        expect(response.code).to eq('401')
        expect(response['WWW-Authenticate']).to eq('Bearer')
        expect(response.body.to_s).to eq('')

        response = http(@port, token: 'wrong')
        expect(response.code).to eq('401')
        expect(@interface.instance_variable_get(:@request_queue).length).to eq(0)

        response = http(@port, token: 'secret')
        expect(response.code).to eq('200')
        _, extra = @interface.read_interface
        expect(extra['HTTP_HEADERS']).not_to have_key('authorization')
      end

      it "serves HTTPS with SSL_CERT / SSL_KEY and refuses plaintext" do
        ca_cert, ca_key = make_ca()
        cert, key = make_cert('localhost', ca_cert, ca_key, 2)
        @interface.set_option("SSL_CERT", [ cert.to_pem ])
        @interface.set_option("SSL_KEY", [ key.to_pem ])
        start_server(@interface)

        response = http(@port, ssl: true)
        expect(response.code).to eq('200')
        expect(@interface.details['ssl']).to be true

        expect { http(@port) }.to raise_error(StandardError)
      end

      it "requires a client certificate signed by SSL_CA_FILE" do
        ca_cert, ca_key = make_ca()
        cert, key = make_cert('localhost', ca_cert, ca_key, 2)
        client_cert, client_key = make_cert('client', ca_cert, ca_key, 3)
        other_ca_cert, other_ca_key = make_ca()
        bad_cert, bad_key = make_cert('client', other_ca_cert, other_ca_key, 4)
        @interface.set_option("SSL_CERT", [ cert.to_pem ])
        @interface.set_option("SSL_KEY", [ key.to_pem ])
        @interface.set_option("SSL_CA_FILE", [ ca_cert.to_pem ])
        start_server(@interface)
        expect(@interface.details['client_cert_required']).to be true

        expect { http(@port, ssl: true) }.to raise_error(OpenSSL::SSL::SSLError)
        expect { http(@port, ssl: true, client_cert: bad_cert, client_key: bad_key) }.to raise_error(OpenSSL::SSL::SSLError)
        response = http(@port, ssl: true, client_cert: client_cert, client_key: client_key)
        expect(response.code).to eq('200')
      end
    end

    describe "#connected?" do
      it "returns true when server is present" do
        @interface.instance_variable_set(:@server, double('server'))
        expect(@interface.connected?).to be true
      end

      it "returns false when server is not present" do
        expect(@interface.connected?).to be false
      end
    end

    describe "#disconnect" do
      it "shuts down the server and clears the queue" do
        server = double('server')
        expect(server).to receive(:shutdown)
        @interface.instance_variable_set(:@server, server)
        @interface.instance_variable_set(:@request_queue, Queue.new)
        @interface.instance_variable_get(:@request_queue).push("test")
        @interface.disconnect
        expect(@interface.instance_variable_get(:@server)).to be_nil
        expect(@interface.instance_variable_get(:@request_queue).size).to eq(1)
        expect(@interface.instance_variable_get(:@request_queue).pop).to be_nil
      end
    end

    describe "#read_interface" do
      it "reads from the request queue" do
        @interface.instance_variable_set(:@request_queue, Queue.new)
        @interface.instance_variable_get(:@request_queue).push(["data", {}])
        expect(@interface).to receive(:read_interface_base).with("data", {})
        data, extra = @interface.read_interface
        expect(data).to eq("data")
        expect(extra).to eq({})
      end
    end

    describe "#write_interface" do
      it "raises an error" do
        expect { @interface.write_interface({}) }.to raise_error(RuntimeError, "Commands cannot be sent to HttpServerInterface")
      end
    end

    describe "#convert_data_to_packet" do
      it "converts data to a packet" do
        data = "test data"
        extra = {
          'HTTP_REQUEST_TARGET_NAME' => 'TARGET',
          'HTTP_REQUEST_PACKET_NAME' => 'PACKET',
          'EXTRA_INFO' => 'value'
        }
        packet = @interface.convert_data_to_packet(data, extra)
        expect(packet.target_name).to eq('TARGET')
        expect(packet.packet_name).to eq('PACKET')
        expect(packet.buffer).to eq(data)
        expect(packet.extra).to eq({ 'EXTRA_INFO' => 'value' })
      end
    end

    describe "#convert_packet_to_data" do
      it "raises an error" do
        expect { @interface.convert_packet_to_data(Packet.new('TGT', 'PKT')) }.to raise_error(RuntimeError, "Commands cannot be sent to HttpServerInterface")
      end
    end

    describe "details" do
      it "returns detailed interface information" do
        i = HttpServerInterface.new(8080)
        i.instance_variable_set(:@listen_address, '192.168.1.100')
        i.instance_variable_set(:@request_queue, Queue.new)

        details = i.details

        expect(details).to be_a(Hash)
        expect(details['listen_address']).to eql('192.168.1.100')
        expect(details['port']).to eql(8080)
        expect(details['request_queue_length']).to eql(0)

        # Check that base interface details are included
        expect(details['name']).to eql('HttpServerInterface')
        expect(details).to have_key('read_allowed')
        expect(details).to have_key('write_allowed')
        expect(details).to have_key('options')
      end

      it "shows current request queue length" do
        i = HttpServerInterface.new(8080)
        request_queue = Queue.new
        request_queue.push(['test1', {}])
        request_queue.push(['test2', {}])
        i.instance_variable_set(:@request_queue, request_queue)

        details = i.details

        expect(details['request_queue_length']).to eql(2)
      end

      it "handles default listen address" do
        i = HttpServerInterface.new(8080)
        i.instance_variable_set(:@request_queue, Queue.new)

        details = i.details

        expect(details['listen_address']).to eql('127.0.0.1')
        expect(details['port']).to eql(8080)
        expect(details['ssl']).to be false
        expect(details['client_cert_required']).to be false
        expect(details['auth_token_required']).to be false
      end
    end
  end
end
