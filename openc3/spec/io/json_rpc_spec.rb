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
require 'openc3/io/json_rpc'

module OpenC3
  describe as_json do
    describe "string as_json" do
      it "converts utf8 bytes" do
        bytes = 'ab' # Valid ASCII
        expect(bytes.as_json).to eql("ab")
        bytes = "\xc3\xb1" # Valid 2 Octet Sequence
        expect(bytes.as_json).to eql("ñ")
        bytes = "\xc3\x28" # Invalid 2 Octet Sequence
        expect(bytes.as_json).to eql({"json_class" => "String", "raw" => bytes.unpack("C*")})
        bytes = "\xe2\x28\xa1" # Invalid 3 Octet Sequence
        expect(bytes.as_json).to eql({"json_class" => "String", "raw" => bytes.unpack("C*")})
        bytes = "\xf0\x28\x8c\x28" # Invalid 4 Octet Sequence
        expect(bytes.as_json).to eql({"json_class" => "String", "raw" => bytes.unpack("C*")})
      end

      it "encodes binary data with high bytes as json_class format" do
        # Test binary string with bytes > 127 (even if valid UTF-8)
        # This simulates data from hex_to_byte_string like 0xDEAD
        bytes = "\xDE\xAD\xBE\xEF".b
        result = bytes.as_json
        expect(result).to eql({"json_class" => "String", "raw" => [222, 173, 190, 239]})

        # Verify round-trip encoding/decoding
        json_str = JSON.generate(result, allow_nan: true)
        decoded = JSON.parse(json_str, allow_nan: true, create_additions: true)
        expect(decoded).to eq(bytes)
        expect(decoded.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it "does not encode plain ASCII strings even if ASCII-8BIT encoding" do
        # Plain ASCII text should not be encoded as binary even if marked ASCII-8BIT
        bytes = "NORMAL".force_encoding(Encoding::ASCII_8BIT)
        expect(bytes.as_json).to eql("NORMAL")
      end

      it "preserves Unicode characters that are valid UTF-8 even in ASCII-8BIT strings" do
        # This simulates the MECH packet CURRENT units "micro-Ampères µA"
        # The micro sign µ (U+00B5) is encoded as \xC2\xB5 in UTF-8
        # When read from ASCII-8BIT encoded files, the string has ASCII-8BIT encoding
        # but the bytes are valid UTF-8 and should be preserved as readable text
        micro_amperes = "0.5 µA".force_encoding(Encoding::ASCII_8BIT)
        result = micro_amperes.as_json
        # Should return the readable UTF-8 string, not a json_class raw object
        expect(result).to eql("0.5 µA")
        expect(result).not_to be_a(Hash)

        # Test just the micro sign character
        micro = "\xC2\xB5".force_encoding(Encoding::ASCII_8BIT) # µ in UTF-8 bytes
        expect(micro.as_json).to eql("µ")

        # Test other common Unicode characters that might appear in units
        degree_celsius = "25 \xC2\xB0C".force_encoding(Encoding::ASCII_8BIT) # ° is U+00B0
        expect(degree_celsius.as_json).to eql("25 °C")

        # Test accented characters like in "Ampères"
        amperes = "Amp\xC3\xA8res".force_encoding(Encoding::ASCII_8BIT) # è is U+00E8
        expect(amperes.as_json).to eql("Ampères")
      end

      it "correctly distinguishes binary data from UTF-8 text in ASCII-8BIT strings" do
        # True binary data that happens to have bytes > 127 should be encoded as raw
        binary = "\xDE\xAD\xBE\xEF".force_encoding(Encoding::ASCII_8BIT)
        expect(binary.as_json).to be_a(Hash)
        expect(binary.as_json["json_class"]).to eq("String")

        # But valid UTF-8 bytes in ASCII-8BIT should be treated as text
        utf8_text = "Test µ value".force_encoding(Encoding::ASCII_8BIT)
        expect(utf8_text.as_json).to eql("Test µ value")
        expect(utf8_text.as_json).not_to be_a(Hash)
      end

      it "treats 2-byte binary data that happens to be valid UTF-8 as binary" do
        # This is a regression test for the issue where 0xDEAD (2 bytes) was being
        # interpreted as valid UTF-8 text instead of binary data.
        # \xDE\xAD happens to be a valid 2-byte UTF-8 sequence (decodes to U+07AD, Thaana script)
        # but should be treated as binary since Thaana characters are not expected in command data.
        # See: https://github.com/OpenC3/cosmos/issues/XXXX
        bytes = "\xDE\xAD".force_encoding(Encoding::ASCII_8BIT)
        result = bytes.as_json
        expect(result).to be_a(Hash)
        expect(result["json_class"]).to eq("String")
        expect(result["raw"]).to eq([222, 173]) # 0xDE = 222, 0xAD = 173

        # Verify round-trip encoding/decoding
        json_str = JSON.generate(result, allow_nan: true)
        decoded = JSON.parse(json_str, allow_nan: true, create_additions: true)
        expect(decoded).to eq(bytes)
        expect(decoded.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it "treats bytes that decode to C1 control characters as binary" do
        # C1 control characters (U+0080-U+009F) should be treated as binary
        # U+0080 is encoded as \xC2\x80 in UTF-8
        c1_control = "\xC2\x80".force_encoding(Encoding::ASCII_8BIT)
        result = c1_control.as_json
        expect(result).to be_a(Hash)
        expect(result["json_class"]).to eq("String")
      end
    end
  end

  # A class with a json_create hook that must never be reachable from
  # untrusted JSON via "json_class"
  class JsonRpcSpecGadget
    @@created = 0
    def self.created
      @@created
    end

    def self.json_create(_object)
      @@created += 1
      new
    end
  end

  describe JsonRpcRequest do
    describe "from_json" do
      it "parses a request" do
        json = JSON.generate({ 'jsonrpc' => '2.0', 'method' => 'tlm', 'params' => ['INST HEALTH_STATUS TEMP1'],
                               'keyword_params' => { 'scope' => 'DEFAULT' }, 'id' => 7 })
        request = JsonRpcRequest.from_json(json, { 'HTTP_AUTHORIZATION' => 'token' })
        expect(request.method).to eql('tlm')
        expect(request.params).to eql(['INST HEALTH_STATUS TEMP1'])
        expect(request.keyword_params).to eql({ scope: 'DEFAULT', token: 'token' })
        expect(request.id).to eql(7)
      end

      it "restores Float and binary String typed values" do
        binary = "\xDE\xAD\xBE\xEF".force_encoding(Encoding::ASCII_8BIT)
        json = JSON.generate({ 'jsonrpc' => '2.0', 'method' => 'cmd', 'id' => 1,
                               'params' => [Float::INFINITY.as_json, (-Float::INFINITY).as_json, Float::NAN.as_json, binary.as_json],
                               'keyword_params' => { 'nested' => { 'data' => [binary.as_json] } } })
        request = JsonRpcRequest.from_json(json, {})
        expect(request.params[0]).to eql(Float::INFINITY)
        expect(request.params[1]).to eql(-Float::INFINITY)
        expect(request.params[2]).to be_nan
        expect(request.params[3]).to eql(binary)
        expect(request.params[3].encoding).to eql(Encoding::ASCII_8BIT)
        expect(request.keyword_params[:nested]['data'][0]).to eql(binary)
      end

      it "leaves unrecognized json_class hashes as plain hashes" do
        json = JSON.generate({ 'jsonrpc' => '2.0', 'method' => 'cmd', 'id' => 1,
                               'params' => [{ 'json_class' => 'Float', 'raw' => 'bogus' },
                                            { 'json_class' => 'String', 'raw' => 'not bytes' },
                                            { 'json_class' => 'String', 'raw' => [1, 'a'] }] })
        request = JsonRpcRequest.from_json(json, {})
        expect(request.params[0]).to eql({ 'json_class' => 'Float', 'raw' => 'bogus' })
        expect(request.params[1]).to eql({ 'json_class' => 'String', 'raw' => 'not bytes' })
        expect(request.params[2]).to eql({ 'json_class' => 'String', 'raw' => [1, 'a'] })
      end

      it "does not instantiate arbitrary classes named by json_class" do
        json = JSON.generate({ 'jsonrpc' => '2.0', 'method' => 'cmd', 'id' => 1,
                               'params' => [{ 'json_class' => 'OpenC3::JsonRpcSpecGadget', 'raw' => [] }],
                               'keyword_params' => { 'json_class' => 'OpenC3::JsonRpcSpecGadget', 'raw' => [] } })
        request = JsonRpcRequest.from_json(json, {})
        expect(JsonRpcSpecGadget.created).to eql(0)
        expect(request.params[0]).to eql({ 'json_class' => 'OpenC3::JsonRpcSpecGadget', 'raw' => [] })
        expect(request.keyword_params).to eql({ json_class: 'OpenC3::JsonRpcSpecGadget', raw: [] })
      end

      it "rejects malformed requests" do
        ['not json', '[]', '"string"',
         JSON.generate({ 'jsonrpc' => '1.0', 'method' => 'cmd', 'id' => 1 }),
         JSON.generate({ 'jsonrpc' => '2.0', 'id' => 1 }),
         JSON.generate({ 'jsonrpc' => '2.0', 'method' => 'cmd' }),
         JSON.generate({ 'jsonrpc' => '2.0', 'method' => ['cmd'], 'id' => 1 }),
         JSON.generate({ 'jsonrpc' => '2.0', 'method' => 'cmd', 'params' => 'x', 'id' => 1 }),
         JSON.generate({ 'jsonrpc' => '2.0', 'method' => 'cmd', 'keyword_params' => [], 'id' => 1 })].each do |json|
          expect { JsonRpcRequest.from_json(json, {}) }.to raise_error(/Invalid JSON-RPC 2.0 Request/), json
        end
      end
    end
  end

  describe JsonRpcResponse do
    describe "from_json" do
      it "restores typed values without create_additions" do
        json = JSON.generate({ 'jsonrpc' => '2.0', 'id' => 1,
                               'result' => [Float::NAN.as_json, { 'json_class' => 'OpenC3::JsonRpcSpecGadget', 'raw' => [] }] })
        response = JsonRpcResponse.from_json(json)
        expect(response).to be_a(JsonRpcSuccessResponse)
        expect(response.result[0]).to be_nan
        expect(response.result[1]).to eql({ 'json_class' => 'OpenC3::JsonRpcSpecGadget', 'raw' => [] })
        expect(JsonRpcSpecGadget.created).to eql(0)
      end

      it "parses an error response" do
        json = JSON.generate({ 'jsonrpc' => '2.0', 'id' => 1, 'error' => { 'code' => -1, 'message' => 'boom' } })
        response = JsonRpcResponse.from_json(json)
        expect(response).to be_a(JsonRpcErrorResponse)
        expect(response.error.message).to eql('boom')
      end
    end
  end

  describe Exception do
    describe "from_hash" do
      it "rebuilds a namespaced exception" do
        error = Exception.from_hash({ 'class' => 'OpenC3::JsonDRbUnknownError', 'message' => 'msg', 'backtrace' => [],
                                      'instance_variables' => { '@extra' => 1 } })
        expect(error).to be_a(JsonDRbUnknownError)
        expect(error.message).to eql('msg')
        expect(error.instance_variable_get(:@extra)).to eql(1)
      end

      it "raises JsonDRbUnknownError for classes that are not exceptions" do
        ['OpenC3::JsonRpcSpecGadget', 'String', 'Does::Not::Exist'].each do |name|
          expect do
            Exception.from_hash({ 'class' => name, 'message' => 'msg', 'backtrace' => [], 'instance_variables' => {} })
          end.to raise_error(JsonDRbUnknownError, 'msg')
        end
      end
    end
  end
end
