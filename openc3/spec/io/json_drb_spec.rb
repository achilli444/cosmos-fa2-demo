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
require 'openc3/io/json_drb'

module OpenC3
  describe JsonDRb do
    # Stands in for the object exposed over JSON-RPC. Only #greet is allowed;
    # #secret exists to prove that a real method is still rejected when it is
    # not in the whitelist.
    class JsonDRbSpecTarget
      def greet(name:)
        "hello #{name}"
      end

      def secret
        'unreachable'
      end

      def protected_call(token: nil, scope: nil)
        raise AuthError.new("Token is invalid")
      end
    end

    let(:json_drb) do
      drb = JsonDRb.new(method_whitelist: ['greet', 'protected_call'])
      drb.object = JsonDRbSpecTarget.new
      drb
    end

    # Builds a JSON-RPC request, processes it, and returns the parsed response
    def process(json_drb, method_name, params: [], keyword_params: {})
      request = { 'jsonrpc' => '2.0', 'method' => method_name, 'id' => 1 }
      request['params'] = params unless params.empty?
      request['keyword_params'] = keyword_params unless keyword_params.empty?
      response_data, error_code = json_drb.process_request(
        request_data: JSON.generate(request), request_headers: {}, start_time: Time.now
      )
      return JSON.parse(response_data), error_code
    end

    describe "method_whitelist" do
      it "is required" do
        expect { JsonDRb.new }.to raise_error(ArgumentError, /missing keyword: :method_whitelist/)
      end

      it "rejects a nil or empty whitelist" do
        [nil, [], Set[]].each do |whitelist|
          expect { JsonDRb.new(method_whitelist: whitelist) }.to raise_error(
            ArgumentError, /method_whitelist is required and must not be empty/
          )
        end
      end

      it "downcases the method names into a Set" do
        drb = JsonDRb.new(method_whitelist: ['Tlm', :CMD])
        expect(drb.method_whitelist).to eql(Set['tlm', 'cmd'])
      end

      it "accepts a one-pass Enumerable" do
        drb = JsonDRb.new(method_whitelist: %w[tlm cmd].each)
        expect(drb.method_whitelist).to eql(Set['tlm', 'cmd'])
      end

      it "can be replaced but still cannot be cleared" do
        drb = JsonDRb.new(method_whitelist: ['tlm'])
        drb.method_whitelist = ['cmd']
        expect(drb.method_whitelist).to eql(Set['cmd'])
        expect { drb.method_whitelist = [] }.to raise_error(ArgumentError)
        expect(drb.method_whitelist).to eql(Set['cmd'])
      end
    end

    describe "process_request" do
      it "calls a whitelisted method" do
        response, error_code = process(json_drb, 'greet', keyword_params: { 'name' => 'world' })
        expect(response['result']).to eql('hello world')
        expect(error_code).to be_nil
      end

      it "matches whitelisted methods case insensitively" do
        response, _error_code = process(json_drb, 'GREET', keyword_params: { 'name' => 'world' })
        expect(response['result']).to eql('hello world')
      end

      it "rejects a method that exists on the object but is not whitelisted" do
        response, error_code = process(json_drb, 'secret')
        expect(response['error']['message']).to eql('Cannot call unauthorized methods')
        expect(error_code).to eql(JsonRpcError::ErrorCode::OTHER_ERROR)
      end

      # These are all public methods on Object (several added by ActiveSupport)
      # which allow arbitrary code execution or leak server state. The whitelist
      # is what blocks them; there is no blocklist to keep in sync.
      it "rejects reflection and code evaluation methods" do
        %w[send __send__ public_send try try! instance_eval instance_exec class_eval
           method instance_variable_get instance_variable_set instance_values
           methods public_methods singleton_class extend freeze inspect to_s
           to_yaml to_json as_json].each do |method_name|
          response, _error_code = process(json_drb, method_name, params: ['1+1'])
          expect(response['error']['message']).to eql('Cannot call unauthorized methods'),
                                                  "expected #{method_name} to be rejected"
        end
      end

      it "audits auth failures with the method, caller address and no token" do
        request = { 'jsonrpc' => '2.0', 'method' => 'protected_call', 'id' => 7, 'keyword_params' => { 'scope' => 'DEFAULT' } }
        headers = { 'HTTP_AUTHORIZATION' => 'SECRET_TOKEN', 'HTTP_X_FORWARDED_FOR' => '10.20.30.40, 172.16.0.1' }
        capture_io do |stdout|
          response_data, error_code = json_drb.process_request(
            request_data: JSON.generate(request), request_headers: headers, start_time: Time.now
          )
          expect(error_code).to eql(JsonRpcError::ErrorCode::AUTH_ERROR)
          expect(JSON.parse(response_data)['error']['message']).to eql('Token is invalid')
          record = JSON.parse(stdout.string.lines.last)
          expect(record['level']).to eql 'WARN'
          expect(record['type']).to eql 'security'
          expect(record).to include('event' => 'api_request', 'outcome' => 'failure',
            'reason' => 'AuthError: Token is invalid', 'method' => 'protected_call', 'source' => '10.20.30.40', 'scope' => 'DEFAULT')
          expect(stdout.string).not_to include('SECRET_TOKEN')
        end
      end

      it "exposes the method and caller address to code running inside the call" do
        seen = nil
        allow(json_drb.object).to receive(:greet) { seen = SecurityAudit.context; 'hi' }
        request = { 'jsonrpc' => '2.0', 'method' => 'greet', 'id' => 1, 'keyword_params' => { 'name' => 'x' } }
        json_drb.process_request(
          request_data: JSON.generate(request), request_headers: { 'HTTP_X_REAL_IP' => '10.1.1.1' }, start_time: Time.now
        )
        expect(seen).to eql({ method: 'greet', source: '10.1.1.1' })
        expect(SecurityAudit.context).to eql({})
      end

      it "rejects an unknown method" do
        response, _error_code = process(json_drb, 'does_not_exist')
        expect(response['error']['message']).to eql('Cannot call unauthorized methods')
      end
    end
  end
end
