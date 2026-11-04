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
require 'openc3/interfaces'
require 'openc3/interfaces/tcpip_server_interface'

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

      it "accepts any client by default" do
        i = TcpipServerInterface.new('8888', '8888', '5', '5', 'burst')
        expect(i.allowed_clients).to be_nil
        expect(i.max_clients).to be_nil
        expect(i.client_allowed?('203.0.113.7')).to be true
      end

      it "parses ALLOWED_CLIENTS as a list of addresses and CIDR ranges" do
        i = TcpipServerInterface.new('8888', '8888', '5', '5', 'burst')
        i.set_option('ALLOWED_CLIENTS', ['10.1.2.3', '192.168.0.0/16'])
        expect(i.allowed_clients.length).to eql 2
        expect(i.client_allowed?('10.1.2.3')).to be true
        expect(i.client_allowed?('10.1.2.4')).to be false
        expect(i.client_allowed?('192.168.200.1')).to be true
        expect(i.client_allowed?('192.169.0.1')).to be false
        expect(i.client_allowed?('not an ip')).to be false
      end

      it "parses a single space or comma separated ALLOWED_CLIENTS value" do
        i = TcpipServerInterface.new('8888', '8888', '5', '5', 'burst')
        i.set_option('ALLOWED_CLIENTS', ['127.0.0.1, 172.16.0.0/12'])
        expect(i.client_allowed?('127.0.0.1')).to be true
        expect(i.client_allowed?('172.20.1.1')).to be true
        expect(i.client_allowed?('10.0.0.1')).to be false
      end

      it "rejects invalid ALLOWED_CLIENTS values" do
        i = TcpipServerInterface.new('8888', '8888', '5', '5', 'burst')
        expect { i.set_option('ALLOWED_CLIENTS', ['300.1.1.1']) }.to raise_error(ArgumentError, /ALLOWED_CLIENTS invalid/)
        expect { i.set_option('ALLOWED_CLIENTS', ['10.0.0.0/33']) }.to raise_error(ArgumentError, /ALLOWED_CLIENTS invalid/)
        expect { i.set_option('ALLOWED_CLIENTS', ['']) }.to raise_error(ArgumentError, /at least one/)
        expect(i.allowed_clients).to be_nil
      end

      it "parses MAX_CLIENTS as a positive integer" do
        i = TcpipServerInterface.new('8888', '8888', '5', '5', 'burst')
        i.set_option('MAX_CLIENTS', ['3'])
        expect(i.max_clients).to eql 3
        expect { i.set_option('MAX_CLIENTS', ['0']) }.to raise_error(ArgumentError, /positive integer/)
        expect { i.set_option('MAX_CLIENTS', ['-1']) }.to raise_error(ArgumentError, /positive integer/)
        expect { i.set_option('MAX_CLIENTS', ['many']) }.to raise_error(ArgumentError, /positive integer/)
        expect(i.max_clients).to eql 3
      end
    end

    describe "listen_thread_body" do
      # Poll until the block returns true or the timeout expires
      def wait_for(timeout = 5)
        start = Time.now
        until yield
          raise "Timeout waiting for condition" if Time.now - start > timeout

          sleep 0.05
        end
      end

      # Returns true if the server closed the connection (EOF or reset)
      def closed_by_server?(client)
        client.read_nonblock(1).nil?
      rescue EOFError, Errno::ECONNRESET, Errno::EPIPE
        true
      rescue IO::WaitReadable
        false
      end

      def server(port, options = {})
        i = TcpipServerInterface.new(port.to_s, port.to_s, '5', '5', 'burst')
        i.set_option('LISTEN_ADDRESS', ['127.0.0.1'])
        options.each { |name, values| i.set_option(name, values) }
        i.connect
        i
      end

      it "closes and logs connections from clients not in ALLOWED_CLIENTS" do
        allow(Logger).to receive(:info)
        expect(Logger).to receive(:warn).with(/rejected connection from 127\.0\.0\.1:\d+ \(not in ALLOWED_CLIENTS\)/)
        i = server(8892, 'ALLOWED_CLIENTS' => ['10.0.0.0/8'])
        begin
          client = TCPSocket.new('127.0.0.1', 8892)
          wait_for { closed_by_server?(client) }
          expect(i.num_clients).to eql 0
          client.close
        ensure
          i.disconnect
        end
      end

      it "accepts connections from clients in ALLOWED_CLIENTS" do
        allow(Logger).to receive(:info)
        expect(Logger).not_to receive(:warn)
        i = server(8893, 'ALLOWED_CLIENTS' => ['192.0.2.1', '127.0.0.0/8'])
        begin
          client = TCPSocket.new('127.0.0.1', 8893)
          wait_for { i.num_clients == 1 }
          expect(closed_by_server?(client)).to be false
          client.close
        ensure
          i.disconnect
        end
      end

      it "closes and logs connections beyond MAX_CLIENTS" do
        allow(Logger).to receive(:info)
        expect(Logger).to receive(:warn).with(/rejected connection from 127\.0\.0\.1:\d+ \(MAX_CLIENTS 1 reached\)/)
        i = server(8894, 'MAX_CLIENTS' => ['1'])
        begin
          first = TCPSocket.new('127.0.0.1', 8894)
          wait_for { i.num_clients == 1 }
          second = TCPSocket.new('127.0.0.1', 8894)
          wait_for { closed_by_server?(second) }
          expect(i.num_clients).to eql 1
          expect(closed_by_server?(first)).to be false
          first.close
          second.close
        ensure
          i.disconnect
        end
      end

      it "accepts every client when neither option is set" do
        allow(Logger).to receive(:info)
        expect(Logger).not_to receive(:warn)
        i = server(8895)
        begin
          clients = 3.times.map { TCPSocket.new('127.0.0.1', 8895) }
          wait_for { i.num_clients == 3 }
          clients.each { |client| expect(closed_by_server?(client)).to be false }
          clients.each(&:close)
        ensure
          i.disconnect
        end
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
        expect(details['allowed_clients']).to be_nil
        expect(details['max_clients']).to be_nil

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

      it "includes the client allow list and connection cap" do
        i = TcpipServerInterface.new('8888', '8889', '5.0', '10.0', 'burst')
        i.set_option('ALLOWED_CLIENTS', ['10.1.2.3', '192.168.0.0/16'])
        i.set_option('MAX_CLIENTS', ['2'])

        details = i.details

        expect(details['allowed_clients']).to eql(['10.1.2.3/32', '192.168.0.0/16'])
        expect(details['max_clients']).to eql(2)
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
