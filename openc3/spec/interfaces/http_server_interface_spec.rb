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
      @interface = HttpServerInterface.new(8000+@socket_80)
    end

    after(:each) do
      # Release the listener socket so the next example can bind the same port
      @interface.disconnect if @interface.instance_variable_get(:@server).is_a?(WEBrick::HTTPServer)
      kill_leftover_threads()
    end

    describe "#initialize" do
      it "initializes with default port" do # above the privileged port range
        expect(@interface.instance_variable_get(:@port)).to eq(8000+@socket_80)
      end

      it "initializes with custom port" do
        interface = HttpServerInterface.new(8000+@socket_80)
        expect(interface.instance_variable_get(:@port)).to eq(8000+@socket_80)
      end
    end

    describe "#set_option" do
      it "sets the listen address" do
        @interface.set_option("LISTEN_ADDRESS", [ '0.0.0.0' ])
        expect(@interface.instance_variable_get(:@listen_address)).to eq('0.0.0.0')
      end

      it "defaults the listen address to localhost" do
        expect(@interface.instance_variable_get(:@listen_address)).to eq('127.0.0.1')
      end

      it "defaults to a bounded request queue" do
        queue = @interface.instance_variable_get(:@request_queue)
        expect(queue).to be_a(SizedQueue)
        expect(queue.max).to eq(HttpServerInterface::DEFAULT_MAX_QUEUE_SIZE)
      end

      it "sets the max queue size" do
        @interface.set_option("MAX_QUEUE_SIZE", ['5'])
        expect(@interface.instance_variable_get(:@request_queue).max).to eq(5)
      end

      it "rejects a non-positive max queue size" do
        expect { @interface.set_option("MAX_QUEUE_SIZE", ['0']) }.to raise_error(/MAX_QUEUE_SIZE/)
      end

      it "rejects an empty auth token" do
        expect { @interface.set_option("AUTH_TOKEN", ['']) }.to raise_error(/AUTH_TOKEN/)
      end

      it "accepts PEM contents or a PEM filename" do
        cert, key = self_signed_cert()
        @interface.set_option("CERT", [cert.to_pem])
        Tempfile.create('key') do |file|
          file.write(key.to_pem)
          file.flush
          @interface.set_option("KEY", [file.path])
        end
        expect(@interface.instance_variable_get(:@cert)).to eq(cert.to_pem)
        expect(@interface.instance_variable_get(:@key)).to eq(key.to_pem)
        expect(@interface.ssl?).to be true
      end

      it "rejects a missing PEM filename" do
        expect { @interface.set_option("CERT", ['/nonexistent/server.crt']) }.to raise_error(/PEM file not found/)
      end
    end

    describe "#connection_string" do
      it "returns the correct connection string" do
        expect(@interface.connection_string).to eq("listening on 127.0.0.1:#{8000 + @socket_80}")
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

      it "requires both CERT and KEY to enable HTTPS" do
        cert, _key = self_signed_cert()
        @interface.set_option("CERT", [cert.to_pem])
        expect { @interface.connect }.to raise_error(/both CERT and KEY/)
      end

      it "requires CERT and KEY when CA_FILE is given" do
        cert, _key = self_signed_cert()
        @interface.set_option("CA_FILE", [cert.to_pem])
        expect { @interface.connect }.to raise_error(/CA_FILE option requires CERT and KEY/)
      end

      it "warns when exposed on all addresses without TLS or auth" do
        allow_any_instance_of(Packet).to receive(:read).with('HTTP_PATH').and_return('/test')
        @interface.set_option("LISTEN_ADDRESS", ['0.0.0.0'])
        expect(Logger).to receive(:warn).with(/unauthenticated plain HTTP from any address/)
        @interface.connect
        @interface.disconnect
      end

      it "does not warn when bound to localhost" do
        allow_any_instance_of(Packet).to receive(:read).with('HTTP_PATH').and_return('/test')
        expect(Logger).not_to receive(:warn)
        @interface.connect
        @interface.disconnect
      end

      it "creates a response hook for every command packet" do
        @interface.target_names = ['INST']
        server_double = double
        allow(WEBrick::HTTPServer).to receive(:new).and_return(server_double)
        request = OpenStruct.new(header: {alpha: "bet"}, query: {what: "is"}, status: nil, body: nil)
        response = OpenStruct.new(status: nil, body: nil)
        allow(server_double).to receive(:mount_proc).with('/test').and_yield(request, response)
        expect(server_double).to receive(:start) do
          sleep(0.1)
        end
        @interface.instance_variable_set(:@port, 8000 + @socket_80)
        @interface.connect
        sleep 0.2
      end
    end

    describe "request handling" do
      before(:each) do
        allow_any_instance_of(Packet).to receive(:read).with('HTTP_PATH').and_return('/test')
        allow_any_instance_of(Packet).to receive(:read).with('HTTP_STATUS').and_return(200)
        allow_any_instance_of(Packet).to receive(:read).with('HTTP_PACKET').and_return('REQUEST')
        @interface.target_names = ['INST']
        @uri = URI("http://#{@localhost}:#{8000 + @socket_80}/test")
      end

      after(:each) do
        @interface.disconnect
      end

      def post(body, headers = {}, uri = @uri, ssl = false)
        Net::HTTP.start(uri.host, uri.port, use_ssl: ssl, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
          http.request(Net::HTTP::Post.new(uri, headers), body)
        end
      end

      it "queues requests as telemetry" do
        @interface.connect
        response = post('{"a":1}')
        expect(response.code).to eq('200')
        data, extra = @interface.read_interface
        expect(data).to eq('{"a":1}')
        expect(extra['HTTP_REQUEST_TARGET_NAME']).to eq('INST')
        expect(extra['HTTP_REQUEST_PACKET_NAME']).to eq('REQUEST')
      end

      it "rejects requests without the AUTH_TOKEN bearer header" do
        @interface.set_option("AUTH_TOKEN", ['s3cret'])
        @interface.connect
        expect(post('{"a":1}').code).to eq('401')
        expect(post('{"a":1}', { 'Authorization' => 'Bearer wrong' }).code).to eq('401')
        expect(post('{"a":1}', { 'Authorization' => 's3cret' }).code).to eq('401')
        expect(@interface.instance_variable_get(:@request_queue).length).to eq(0)
      end

      it "accepts requests with the AUTH_TOKEN bearer header" do
        @interface.set_option("AUTH_TOKEN", ['s3cret'])
        @interface.connect
        expect(post('{"a":1}', { 'Authorization' => 'Bearer s3cret' }).code).to eq('200')
        data, _extra = @interface.read_interface
        expect(data).to eq('{"a":1}')
      end

      it "rejects requests with 503 once the queue is full" do
        @interface.set_option("MAX_QUEUE_SIZE", ['2'])
        @interface.connect
        expect(post('1').code).to eq('200')
        expect(post('2').code).to eq('200')
        expect(Logger).to receive(:warn).with(/request queue full \(2\)/)
        response = post('3')
        expect(response.code).to eq('503')
        expect(response['Retry-After']).to eq('1')
        expect(@interface.instance_variable_get(:@request_queue).length).to eq(2)
      end

      it "serves HTTPS with TLS 1.2+ when CERT and KEY are given" do
        cert, key = self_signed_cert()
        @interface.set_option("CERT", [cert.to_pem])
        @interface.set_option("KEY", [key.to_pem])
        @interface.connect
        server = @interface.instance_variable_get(:@server)
        expect(server.config[:SSLEnable]).to be true
        expect(server.config[:SSLOptions] & OpenSSL::SSL::OP_NO_TLSv1_1).to_not eq(0)
        expect(server.config[:SSLVerifyClient]).to eq(OpenSSL::SSL::VERIFY_NONE)
        uri = URI("https://#{@localhost}:#{8000 + @socket_80}/test")
        expect(post('{"a":1}', {}, uri, true).code).to eq('200')
        data, _extra = @interface.read_interface
        expect(data).to eq('{"a":1}')
        expect { post('{"a":1}') }.to raise_error(StandardError)
      end

      it "requires a client certificate when CA_FILE is given" do
        cert, key = self_signed_cert()
        @interface.set_option("CERT", [cert.to_pem])
        @interface.set_option("KEY", [key.to_pem])
        @interface.set_option("CA_FILE", [cert.to_pem])
        @interface.connect
        server = @interface.instance_variable_get(:@server)
        expect(server.config[:SSLVerifyClient]).to eq(OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT)
        uri = URI("https://#{@localhost}:#{8000 + @socket_80}/test")
        expect { post('{"a":1}', {}, uri, true) }.to raise_error(StandardError)
        Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE, cert: cert, key: key) do |http|
          expect(http.request(Net::HTTP::Post.new(uri), '{"a":1}').code).to eq('200')
        end
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
        expect(packet.extra).to eq({'EXTRA_INFO' => 'value'})
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
        expect(details['ssl']).to be false
        expect(details['client_cert_required']).to be false
        expect(details['auth_token_required']).to be false
        expect(details['max_queue_size']).to eql(HttpServerInterface::DEFAULT_MAX_QUEUE_SIZE)
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
      end
    end

    def self_signed_cert
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = cert
      cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
      cert.add_extension(ef.create_extension("keyUsage", "keyCertSign,digitalSignature,keyEncipherment", true))
      cert.add_extension(ef.create_extension("subjectAltName", "IP:127.0.0.1,DNS:localhost", false))
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      return cert, key
    end
  end
end
