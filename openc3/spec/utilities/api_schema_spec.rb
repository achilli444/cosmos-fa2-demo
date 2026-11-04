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
require 'openc3/utilities/api_schema'
require 'openc3/utilities/authentication'
require 'openc3/script'

module OpenC3
  describe ApiSchema do
    schema_vars = %w(OPENC3_API_SCHEMA OPENC3_SCRIPT_API_SCHEMA OPENC3_ALLOW_PLAINTEXT_API)

    before(:each) do
      @saved = schema_vars.to_h { |v| [v, ENV[v]] }
      schema_vars.each { |v| ENV.delete(v) }
      ApiSchema.reset_warnings
    end

    after(:each) do
      @saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    end

    describe "resolve" do
      it "defaults to https when the variable is unset or blank" do
        expect(ApiSchema.resolve('OPENC3_API_SCHEMA')).to eql 'https'
        ENV['OPENC3_API_SCHEMA'] = '  '
        expect(ApiSchema.resolve('OPENC3_API_SCHEMA')).to eql 'https'
      end

      it "accepts https and wss without an override" do
        ENV['OPENC3_API_SCHEMA'] = 'HTTPS'
        expect(ApiSchema.resolve('OPENC3_API_SCHEMA')).to eql 'https'
        ENV['OPENC3_SCRIPT_API_SCHEMA'] = 'wss'
        expect(ApiSchema.resolve('OPENC3_SCRIPT_API_SCHEMA')).to eql 'wss'
      end

      it "refuses http unless OPENC3_ALLOW_PLAINTEXT_API is set" do
        ENV['OPENC3_API_SCHEMA'] = 'http'
        expect { ApiSchema.resolve('OPENC3_API_SCHEMA') }.to raise_error(OpenC3PlaintextApiError, /OPENC3_API_SCHEMA=http.*OPENC3_ALLOW_PLAINTEXT_API/)
        ENV['OPENC3_ALLOW_PLAINTEXT_API'] = 'false'
        expect { ApiSchema.resolve('OPENC3_API_SCHEMA') }.to raise_error(OpenC3PlaintextApiError)
      end

      it "allows http with OPENC3_ALLOW_PLAINTEXT_API and warns once per variable" do
        ENV['OPENC3_API_SCHEMA'] = 'http'
        ENV['OPENC3_ALLOW_PLAINTEXT_API'] = 'true'
        expect(STDOUT).to receive(:puts).with(/OPENC3_API_SCHEMA=http sends credentials and data unencrypted/).once
        expect(ApiSchema.resolve('OPENC3_API_SCHEMA')).to eql 'http'
        expect(ApiSchema.resolve('OPENC3_API_SCHEMA')).to eql 'http'
      end
    end

    describe "resolve_websocket" do
      it "maps https to wss by default" do
        expect(ApiSchema.resolve_websocket('OPENC3_API_SCHEMA')).to eql 'wss'
      end

      it "maps an allowed http to ws" do
        ENV['OPENC3_SCRIPT_API_SCHEMA'] = 'http'
        ENV['OPENC3_ALLOW_PLAINTEXT_API'] = '1'
        allow(STDOUT).to receive(:puts)
        expect(ApiSchema.resolve_websocket('OPENC3_SCRIPT_API_SCHEMA')).to eql 'ws'
      end

      it "refuses ws without the override" do
        ENV['OPENC3_API_SCHEMA'] = 'ws'
        expect { ApiSchema.resolve_websocket('OPENC3_API_SCHEMA') }.to raise_error(OpenC3PlaintextApiError)
      end
    end

    describe "URL builders" do
      it "OpenC3Authentication posts the password to https by default" do
        ENV['OPENC3_API_PASSWORD'] = 'password'
        auth = OpenC3Authentication.new
        expect(auth._generate_auth_url).to eql 'https://openc3-cosmos-cmd-tlm-api:2901/openc3-api/auth/verify'
        expect(auth._generate_auth_url('/auth/otp')).to start_with 'https://'
      end

      it "OpenC3Authentication refuses to send the password over http without the override" do
        ENV['OPENC3_API_PASSWORD'] = 'password'
        auth = OpenC3Authentication.new # spec_helper mocks the request itself
        ENV['OPENC3_API_SCHEMA'] = 'http'
        expect { auth._generate_auth_url }.to raise_error(OpenC3PlaintextApiError)
      end

      it "ServerProxy and ScriptServerProxy default to https" do
        expect(ServerProxy.allocate.generate_url).to eql 'https://openc3-cosmos-cmd-tlm-api:2901'
        expect(ScriptServerProxy.allocate.generate_url).to eql 'https://openc3-cosmos-script-runner-api:2902'
      end

      it "ServerProxy refuses http without the override" do
        ENV['OPENC3_API_SCHEMA'] = 'http'
        expect { ServerProxy.allocate.generate_url }.to raise_error(OpenC3PlaintextApiError)
      end

      it "cable websockets default to wss" do
        expect(CmdTlmWebSocketApi.allocate.generate_url).to eql 'wss://openc3-cosmos-cmd-tlm-api:3901/openc3-api/cable'
        expect(ScriptWebSocketApi.allocate.generate_url).to eql 'wss://openc3-cosmos-script-runner-api:3902/script-api/cable'
      end

      it "cable websockets refuse ws without the override" do
        ENV['OPENC3_SCRIPT_API_SCHEMA'] = 'http'
        expect { ScriptWebSocketApi.allocate.generate_url }.to raise_error(OpenC3PlaintextApiError)
      end
    end
  end
end
