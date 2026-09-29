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

  describe JsonRpc do
    describe "self.parse" do
      it "restores Float NaN and Infinity encodings" do
        json = { "a" => Float::NAN, "b" => Float::INFINITY, "c" => -Float::INFINITY, "d" => 1.5 }.as_json.to_json(allow_nan: true)
        result = JsonRpc.parse(json)
        expect(result["a"]).to be_nan
        expect(result["b"]).to eql Float::INFINITY
        expect(result["c"]).to eql(-Float::INFINITY)
        expect(result["d"]).to eql 1.5
      end

      it "restores binary String encodings nested in arrays and hashes" do
        bytes = "\xDE\xAD\xBE\xEF".b
        json = { "list" => [bytes, { "inner" => bytes }] }.as_json.to_json(allow_nan: true)
        result = JsonRpc.parse(json)
        expect(result["list"][0]).to eql bytes
        expect(result["list"][0].encoding).to eql Encoding::ASCII_8BIT
        expect(result["list"][1]["inner"]).to eql bytes
      end

      it "leaves malformed String raw values as plain hashes" do
        result = JsonRpc.parse('{"json_class":"String","raw":[1,"x",300]}')
        expect(result).to eql({ "json_class" => "String", "raw" => [1, "x", 300] })
        result = JsonRpc.parse('{"json_class":"String","raw":"text"}')
        expect(result).to eql({ "json_class" => "String", "raw" => "text" })
      end

      it "never instantiates classes named by json_class" do
        klass = Class.new do
          def self.json_create(_object)
            raise "json_create must not be called"
          end
        end
        stub_const("SpecJsonCreateTarget", klass)
        result = JsonRpc.parse('{"json_class":"SpecJsonCreateTarget","raw":{"a":1}}')
        expect(result).to eql({ "json_class" => "SpecJsonCreateTarget", "raw" => { "a" => 1 } })
        result = JsonRpc.parse('{"json_class":"Time","s":0,"n":0}')
        expect(result).to eql({ "json_class" => "Time", "s" => 0, "n" => 0 })
        expect(JsonRpc.parse('[{"json_class":"Range","a":[0,1,false]}]')).to eql([{ "json_class" => "Range", "a" => [0, 1, false] }])
      end
    end
  end

  describe JsonRpcRequest do
    describe "self.from_json" do
      it "parses a request with typed params" do
        json = { "jsonrpc" => "2.0", "method" => "cmd", "params" => ["INST", "\xDE\xAD".b, Float::NAN], "keyword_params" => { "scope" => "DEFAULT" }, "id" => 1 }.as_json.to_json(allow_nan: true)
        request = JsonRpcRequest.from_json(json, { 'HTTP_AUTHORIZATION' => 'token' })
        expect(request.method).to eql 'cmd'
        expect(request.params[0]).to eql 'INST'
        expect(request.params[1]).to eql "\xDE\xAD".b
        expect(request.params[2]).to be_nan
        expect(request.keyword_params).to eql({ scope: 'DEFAULT', token: 'token' })
        expect(request.id).to eql 1
      end

      it "does not instantiate classes named by json_class" do
        klass = Class.new do
          def self.json_create(_object)
            raise "json_create must not be called"
          end
        end
        stub_const("SpecJsonCreateTarget", klass)
        json = '{"jsonrpc":"2.0","method":"cmd","params":[{"json_class":"SpecJsonCreateTarget","raw":1}],"id":1}'
        request = JsonRpcRequest.from_json(json, {})
        expect(request.params[0]).to eql({ "json_class" => "SpecJsonCreateTarget", "raw" => 1 })
      end

      it "rejects requests with the wrong shape" do
        expect { JsonRpcRequest.from_json('[]', {}) }.to raise_error(/Invalid JSON-RPC 2.0 Request/)
        expect { JsonRpcRequest.from_json('{"jsonrpc":"2.0","method":["cmd"],"id":1}', {}) }.to raise_error(/Invalid JSON-RPC 2.0 Request/)
        expect { JsonRpcRequest.from_json('{"jsonrpc":"2.0","method":"cmd","params":{},"id":1}', {}) }.to raise_error(/Invalid JSON-RPC 2.0 Request/)
        expect { JsonRpcRequest.from_json('{"jsonrpc":"2.0","method":"cmd","keyword_params":[],"id":1}', {}) }.to raise_error(/Invalid JSON-RPC 2.0 Request/)
      end
    end
  end

  describe JsonRpcResponse do
    describe "self.from_json" do
      it "parses a success response with typed result" do
        json = JsonRpcSuccessResponse.new({ "value" => Float::INFINITY, "raw" => "\xDE\xAD".b }, 5).to_json(allow_nan: true)
        response = JsonRpcResponse.from_json(json)
        expect(response).to be_a JsonRpcSuccessResponse
        expect(response.result["value"]).to eql Float::INFINITY
        expect(response.result["raw"]).to eql "\xDE\xAD".b
      end

      it "does not instantiate classes named by json_class" do
        klass = Class.new do
          def self.json_create(_object)
            raise "json_create must not be called"
          end
        end
        stub_const("SpecJsonCreateTarget", klass)
        response = JsonRpcResponse.from_json('{"jsonrpc":"2.0","result":{"json_class":"SpecJsonCreateTarget","raw":1},"id":1}')
        expect(response.result).to eql({ "json_class" => "SpecJsonCreateTarget", "raw" => 1 })
      end

      it "rejects responses that are not objects" do
        expect { JsonRpcResponse.from_json('[1]') }.to raise_error(/Invalid JSON-RPC 2.0 Response/)
      end
    end
  end

  describe Exception do
    describe "self.from_hash" do
      it "only instantiates Exception subclasses" do
        expect { Exception.from_hash({ 'class' => 'OpenC3::JsonRpcRequest', 'message' => 'msg', 'backtrace' => [], 'instance_variables' => {} }) }.to raise_error(JsonDRbUnknownError, 'msg')
        error = Exception.from_hash({ 'class' => 'RuntimeError', 'message' => 'msg', 'backtrace' => [], 'instance_variables' => {} })
        expect(error).to be_a RuntimeError
      end
    end
  end
end
