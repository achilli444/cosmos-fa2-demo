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
require 'openc3/interfaces/protocols/aead_protocol'
require 'openc3/interfaces/stream_interface'
require 'openc3/streams/stream'
require 'openc3/packets/packet'

module OpenC3
  describe AeadProtocol do
    KEY_HEX = ('ab' * 32)

    class AeadStream < Stream
      def connect; end
      def connected?; true; end
      def disconnect; end
      def read; $aead_buffer; end
      def write(data); $aead_buffer = data; end
    end

    before(:each) do
      @interface = StreamInterface.new
      allow(@interface).to receive(:connected?) { true }
      mock_redis()
      ENV['OPENC3_SCOPE'] ||= 'DEFAULT'
      set_key(KEY_HEX)
      @interface.instance_variable_set(:@stream, AeadStream.new)
      $aead_buffer = ''
    end

    def set_key(value)
      @interface.secrets.set('LINK_KEY', value, scope: ENV['OPENC3_SCOPE'])
    end

    def add(args = ['LINK_KEY'])
      @interface.add_protocol(AeadProtocol, args, :READ_WRITE)
      @interface.read_protocols[0].connect_reset
      @interface.read_protocols[0]
    end

    describe "initialize" do
      it "requires a key secret name" do
        expect { add(['nil']) }.to raise_error(/Key secret name is required/)
      end

      it "only allows AEAD ciphers" do
        expect { add(['LINK_KEY', 'AES-256-CBC']) }.to raise_error(/Invalid cipher/)
      end

      it "complains about a bad strategy" do
        expect { add(['LINK_KEY', 'AES-256-GCM', 'OTHER']) }.to raise_error(/Invalid bad strategy/)
      end

      it "advertises authenticated encryption" do
        expect(add().authenticated_encryption?).to be true
      end
    end

    describe "connect_reset" do
      it "loads a hex encoded key from the interface secrets" do
        expect(add().instance_variable_get(:@key)).to eql ["ab" * 32].pack('H*')
      end

      it "loads a raw key from the interface secrets" do
        set_key("\x01" * 16)
        protocol = add(['LINK_KEY', 'AES-128-GCM'])
        expect(protocol.instance_variable_get(:@key)).to eql "\x01" * 16
      end

      it "complains if the secret is missing" do
        expect { add(['MISSING']) }.to raise_error(/secret 'MISSING' not found/)
      end

      it "complains if the key is the wrong size" do
        set_key('abcd')
        expect { add() }.to raise_error(/must be 32 bytes or 64 hex characters/)
      end
    end

    describe "write and read" do
      it "round trips data through an authenticated record" do
        add()
        packet = Packet.new(nil, nil, :BIG_ENDIAN, nil, "\x01\x02\x03\x04")
        @interface.write(packet)
        expect($aead_buffer.length).to eql 4 + 12 + 4 + 16
        expect($aead_buffer[0, 4].unpack1('N')).to eql 12 + 4 + 16
        expect($aead_buffer).not_to include("\x01\x02\x03\x04")
        expect(@interface.read.buffer).to eql "\x01\x02\x03\x04"
      end

      it "uses a fresh nonce for every record" do
        add()
        packet = Packet.new(nil, nil, :BIG_ENDIAN, nil, "\x01\x02\x03\x04")
        @interface.write(packet)
        first = $aead_buffer.dup
        @interface.write(packet)
        expect($aead_buffer[4, 12]).not_to eql first[4, 12]
        expect($aead_buffer).not_to eql first
      end

      it "reassembles records delivered in fragments and back to back" do
        add()
        @interface.write(Packet.new(nil, nil, :BIG_ENDIAN, nil, "AAAA"))
        first = $aead_buffer.dup
        @interface.write(Packet.new(nil, nil, :BIG_ENDIAN, nil, "BB"))
        second = $aead_buffer.dup
        chunks = [first[0, 7], first[7..-1] + second[0, 3], second[3..-1]]
        $aead_buffer = chunks.shift
        allow_any_instance_of(AeadStream).to receive(:read) { chunks.empty? ? '' : chunks.shift }
        protocol = @interface.read_protocols[0]
        expect(protocol.read_data($aead_buffer)).to eql :STOP
        expect(protocol.read_data(chunks.shift)[0]).to eql "AAAA"
        expect(protocol.read_data(chunks.shift)[0]).to eql "BB"
      end

      it "drops a tampered record with ERROR strategy" do
        add()
        @interface.write(Packet.new(nil, nil, :BIG_ENDIAN, nil, "\x01\x02\x03\x04"))
        tampered = $aead_buffer.dup
        tampered[20] = (tampered[20].ord ^ 0xFF).chr
        protocol = @interface.read_protocols[0]
        expect(Logger).to receive(:error).with(/authentication failed/)
        expect(protocol.read_data(tampered)).to eql :STOP
      end

      it "drops a record encrypted under a different key" do
        add()
        @interface.write(Packet.new(nil, nil, :BIG_ENDIAN, nil, "\x01\x02\x03\x04"))
        record = $aead_buffer.dup
        set_key('cd' * 32)
        protocol = @interface.read_protocols[0]
        protocol.connect_reset
        expect(Logger).to receive(:error).with(/authentication failed/)
        expect(protocol.read_data(record)).to eql :STOP
      end

      it "disconnects on a tampered record with DISCONNECT strategy" do
        add(['LINK_KEY', 'AES-256-GCM', 'DISCONNECT'])
        @interface.write(Packet.new(nil, nil, :BIG_ENDIAN, nil, "\x01\x02\x03\x04"))
        tampered = $aead_buffer.dup
        tampered[-1] = (tampered[-1].ord ^ 0x01).chr
        expect(Logger).to receive(:error).with(/authentication failed/)
        expect(@interface.read_protocols[0].read_data(tampered)).to eql :DISCONNECT
      end

      it "rejects a record shorter than nonce plus tag" do
        add()
        expect(Logger).to receive(:error).with(/shorter than nonce/)
        expect(@interface.read_protocols[0].read_data([3].pack('N') + "abc")).to eql :STOP
      end

      it "refuses to exceed the per key record limit" do
        protocol = add()
        protocol.instance_variable_set(:@records_written, AeadProtocol::MAX_RECORDS_PER_KEY)
        expect { protocol.write_data("data") }.to raise_error(/rotate the key/)
      end

      it "reports the cipher in write_details" do
        protocol = add()
        protocol.write_data("data")
        details = protocol.write_details
        expect(details['cipher']).to eql 'AES-256-GCM'
        expect(details['key_secret_name']).to eql 'LINK_KEY'
        expect(details['records_written']).to eql 1
      end
    end
  end
end
