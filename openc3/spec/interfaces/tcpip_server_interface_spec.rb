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
require 'openc3/interfaces/tcpip_server_interface'
require 'openc3/streams/tcpip_client_stream'
require 'openc3/interfaces/protocols/burst_protocol'

module OpenC3
  describe TcpipServerInterface do
    describe "initialize" do
      it "initializes the instance variables" do
        i = TcpipServerInterface.new('8888', '8889', '5', '5', 'burst')
        expect(i.name).to eql "TcpipServerInterface"
      end

      it "is not writeable if no write port given" do
        i = TcpipServerInterface.new('nil', '8889', 'nil', '5', 'burst')
        expect(i.write_allowed?).to be false
        expect(i.write_raw_allowed?).to be false
        expect(i.read_allowed?).to be true
      end

      it "is not readable if no read port given" do
        i = TcpipServerInterface.new('8888', 'nil', '5', 'nil', 'burst')
        expect(i.write_allowed?).to be true
        expect(i.write_raw_allowed?).to be true
        expect(i.read_allowed?).to be false
      end
    end

    describe "connection_string" do
      it "builds a human readable connection string" do
        i = TcpipServerInterface.new('8889', '8889', 'nil', '5', 'burst')
        expect(i.connection_string).to eql "listening on 0.0.0.0:8889 (R/W)"

        i = TcpipServerInterface.new('8889', '8890', 'nil', '5', 'burst')
        expect(i.connection_string).to eql "listening on 0.0.0.0:8889 (write) 0.0.0.0:8890 (read)"

        i = TcpipServerInterface.new('8889', 'nil', 'nil', '5', 'burst')
        expect(i.connection_string).to eql "listening on 0.0.0.0:8889 (write)"

        i = TcpipServerInterface.new('nil', '8889', 'nil', '5', 'burst')
        expect(i.connection_string).to eql "listening on 0.0.0.0:8889 (read)"
      end
    end

    describe "read" do
      it "counts the packets received" do
        i = TcpipServerInterface.new('8888', '8889', '5', '5', 'burst')
        class << i
          def connected?; true; end
        end

        read_queue = i.instance_variable_get(:@read_queue)
        2.times { read_queue << Packet.new(nil, nil) }

        expect(i.read_count).to eql 0
        i.read
        expect(i.read_count).to eql 1
        i.read
        expect(i.read_count).to eql 2
      end

      it "does not count nil packets" do
        i = TcpipServerInterface.new('8888', '8889', '5', '5', 'burst')
        class << i
          def connected?; true; end
        end

        read_queue = i.instance_variable_get(:@read_queue)
        2.times { read_queue << nil }

        expect(i.read_count).to eql 0
        i.read
        expect(i.read_count).to eql 0
        i.read
        expect(i.read_count).to eql 0
      end
    end

    describe "write" do
      it "complains if the server is not connected" do
        i = TcpipServerInterface.new('8888', '8889', '5', '5', 'burst')
        class << i
          def connected?; false; end
        end
        expect { i.write(Packet.new('', '')) }.to raise_error(/Interface not connected/)
      end

      it "counts the packets written" do
        i = TcpipServerInterface.new('8888', '8889', '5', '5', 'burst')
        class << i
          def connected?; true; end
        end
        expect(i.write_count).to eql 0
        i.write(Packet.new('', ''))
        expect(i.write_count).to eql 1
        i.write(Packet.new('', ''))
        expect(i.write_count).to eql 2
      end
    end

    describe "write_raw" do
      it "complains if the server is not connected" do
        i = TcpipServerInterface.new('8888', '8889', '5', '5', 'burst')
        class << i
          def connected?; false; end
        end
        expect { i.write_raw("\x00") }.to raise_error(/Interface not connected/)
      end

      it "counts the bytes written" do
        i = TcpipServerInterface.new('8888', '8889', '5', '5', 'burst')
        i.connect
        sleep(1)
        write_interface_infos = i.instance_variable_get(:@write_interface_infos)
        wii = TcpipServerInterface::InterfaceInfo.new(StreamInterface.new, nil, nil, nil)
        interface = wii.interface
        class << interface
          def connected?; true; end

          def write_interface(data, extra = nil); write_interface_base(data, extra); end

          def stream
            a = Object.new
            class << a
              def write_socket
                b = Object.new
                class << b
                  def recvfrom_nonblock(_amount)
                    raise Errno::EWOULDBLOCK
                  end
                end
                b
              end
            end
            a
          end
        end
        write_interface_infos << wii
        begin
          expect(i.write_count).to eql 0
          expect(i.bytes_written).to eql 0
          i.write_raw("\x00\x01")
          sleep(1)
          expect(i.write_count).to eql 0
          expect(i.bytes_written).to eql 2
          i.write_raw("\x02")
          sleep(1)
          expect(i.write_count).to eql 0
          expect(i.bytes_written).to eql 3
        ensure
          i.disconnect
        end
      end
    end

    describe "set_option" do
      it "sets the listen address for the tcpip_server" do
        i = TcpipServerInterface.new('8888', '8888', '5', '5', 'burst')
        i.set_option('LISTEN_ADDRESS', ['127.0.0.1'])
        expect(i.instance_variable_get(:@listen_address)).to eq '127.0.0.1'
        expect(i.connection_string).to eql "listening on 127.0.0.1:8888 (R/W)"
      end
    end

    describe "details" do
      it "returns detailed interface information" do
        i = TcpipServerInterface.new('8888', '8889', '5.0', '10.0', 'burst')
        i.set_option('LISTEN_ADDRESS', ['127.0.0.1'])

        details = i.details

        expect(details).to be_a(Hash)
        expect(details['write_port']).to eql(8888)
        expect(details['read_port']).to eql(8889)
        expect(details['write_timeout']).to eql(5.0)
        expect(details['read_timeout']).to eql(10.0)
        expect(details['listen_address']).to eql('127.0.0.1')

        # Check that base interface details are included
        expect(details['name']).to eql('TcpipServerInterface')
        expect(details).to have_key('read_allowed')
        expect(details).to have_key('write_allowed')
        expect(details).to have_key('options')
      end

      it "handles default listen address" do
        i = TcpipServerInterface.new('8888', '8889', '5.0', '10.0', 'burst')

        details = i.details

        expect(details['write_port']).to eql(8888)
        expect(details['read_port']).to eql(8889)
        expect(details['listen_address']).to eql('0.0.0.0')
      end

      it "handles nil values correctly" do
        i = TcpipServerInterface.new('8888', 'nil', 'nil', '10.0', 'burst')

        details = i.details

        expect(details['write_port']).to eql(8888)
        expect(details['read_port']).to be_nil
        expect(details['write_timeout']).to be_nil
        expect(details['read_timeout']).to eql(10.0)
      end
    end
  end
end

module OpenC3
  describe TcpipServerInterface, "link encryption" do
    before(:each) do
      @saved = ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS']
    end

    after(:each) do
      if @saved
        ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = @saved
      else
        ENV.delete('OPENC3_REQUIRE_ENCRYPTED_LINKS')
      end
    end

    it "warns when accepting plaintext connections" do
      ENV.delete('OPENC3_REQUIRE_ENCRYPTED_LINKS')
      i = TcpipServerInterface.new('8891', '8891', '5', '5', 'burst')
      allow(Logger).to receive(:warn)
      expect(Logger).to receive(:warn).with(/plaintext link listening on 0.0.0.0:8891/)
      i.connect
      i.disconnect
    end

    it "refuses plaintext connections when OPENC3_REQUIRE_ENCRYPTED_LINKS is set" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      i = TcpipServerInterface.new('8892', '8892', '5', '5', 'burst')
      expect { i.connect }.to raise_error(PlaintextLinkError)
      expect(i.connected?).to be false
    end

    it "accepts an approved ALLOW_PLAINTEXT bypass" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      i = TcpipServerInterface.new('8893', '8893', '5', '5', 'burst')
      i.set_option('ALLOW_PLAINTEXT', ['true'])
      allow(Logger).to receive(:warn)
      expect(Logger).to receive(:warn).with(/permitted by ALLOW_PLAINTEXT/)
      i.connect
      i.disconnect
    end

    it "serves TLS to clients when SSL_CERT and SSL_KEY are set" do
      ENV['OPENC3_REQUIRE_ENCRYPTED_LINKS'] = 'true'
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2
      cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      ef = OpenSSL::X509::ExtensionFactory.new(cert, cert)
      cert.add_extension(ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1"))
      cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
      cert.sign(key, OpenSSL::Digest.new('SHA256'))

      i = TcpipServerInterface.new('8894', '8894', '5', '5', 'burst')
      i.set_option('SSL_CERT', [cert.to_pem])
      i.set_option('SSL_KEY', [key.to_pem])
      expect(i.ssl?).to be true
      expect(i.connection_string).to eql "listening on 0.0.0.0:8894 (R/W) (TLS)"
      expect(i.details['options']).not_to have_key('SSL_KEY')
      expect(Logger).not_to receive(:warn).with(/plaintext/)
      i.connect
      sleep 0.2

      client = TcpipClientStream.new('localhost', 8894, 8894, 5.0, 5.0)
      client.set_option('SSL_CA_FILE', [cert.to_pem])
      client.set_option('SSL_HOSTNAME', ['localhost'])
      client.connect
      client.write("\x01\x02\x03")
      sleep 0.2
      packet = i.read
      expect(packet.buffer).to eql "\x01\x02\x03"
      expect(i.num_clients).to eql 1
      client.disconnect
      i.disconnect
    end

    it "rejects a plaintext client when TLS is configured" do
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 3
      cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      cert.sign(key, OpenSSL::Digest.new('SHA256'))

      i = TcpipServerInterface.new('8895', '8895', '5', '5', 'burst')
      i.set_option('SSL_CERT', [cert.to_pem])
      i.set_option('SSL_KEY', [key.to_pem])
      i.connect
      sleep 0.2
      expect(Logger).to receive(:error).with(/TLS handshake failed/)
      client = TcpipClientStream.new('localhost', 8895, 8895, 5.0, 5.0)
      client.connect
      client.write("plaintext")
      sleep 0.5
      expect(i.num_clients).to eql 0
      client.disconnect
      i.disconnect
    end
  end
end
