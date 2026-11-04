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
require 'openc3/io/json_drb_object'
require 'openc3/io/json_api_object'
require 'openc3/utilities/authentication'

module OpenC3
  describe JsonDRbObject do
    def response(status, body)
      instance_double(Faraday::Response, status: status, headers: {}, body: body)
    end

    def ok_body
      JsonRpcSuccessResponse.new('result', 1).to_json
    end

    def auth_error_body
      JsonRpcErrorResponse.new(JsonRpcError.new(JsonRpcError::ErrorCode::AUTH_ERROR, 'Token is invalid', AuthError.new('Token is invalid')), 1).to_json
    end

    before(:each) do
      ENV['OPENC3_API_PASSWORD'] = 'test_password'
      @auth = OpenC3Authentication.new
      @http = double('Faraday')
      allow(Faraday).to receive(:new).and_return(@http)
    end

    after(:each) do
      ENV['OPENC3_API_PASSWORD'] = nil
    end

    it "re-authenticates once and retries when the session token is rejected" do
      tokens = []
      expect(@http).to receive(:post).twice do |_uri, _data, headers|
        tokens << headers['Authorization']
        tokens.length == 1 ? response(401, auth_error_body) : response(200, ok_body)
      end
      mock_response = Object.new
      mock_response.define_singleton_method(:body) { 'fresh_token' }
      expect(@auth).to receive(:_make_auth_request).once.and_return(mock_response)

      drb = JsonDRbObject.new(url: 'http://localhost:2901', authentication: @auth)
      expect(drb.tlm('INST HEALTH_STATUS TEMP1', scope: 'DEFAULT')).to eq('result')
      expect(tokens).to eq([$openc3_mock_token, 'fresh_token'])
    end

    it "raises the AuthError when re-authentication does not help" do
      expect(@http).to receive(:post).twice.and_return(response(401, auth_error_body))
      mock_response = Object.new
      mock_response.define_singleton_method(:body) { 'fresh_token' }
      allow(@auth).to receive(:_make_auth_request).and_return(mock_response)

      drb = JsonDRbObject.new(url: 'http://localhost:2901', authentication: @auth)
      expect { drb.tlm('INST HEALTH_STATUS TEMP1', scope: 'DEFAULT') }.to raise_error(AuthError, /Token is invalid/)
    end

    it "does not re-authenticate when the caller supplied the token" do
      expect(@http).to receive(:post).once.and_return(response(401, auth_error_body))
      expect(@auth).not_to receive(:_make_auth_request)

      drb = JsonDRbObject.new(url: 'http://localhost:2901', authentication: @auth)
      expect { drb.tlm('INST HEALTH_STATUS TEMP1', scope: 'DEFAULT', token: 'explicit') }.to raise_error(AuthError)
    end

    it "does not re-authenticate without an authentication object" do
      expect(@http).to receive(:post).once.and_return(response(401, auth_error_body))
      ENV['OPENC3_API_PASSWORD'] = nil
      drb = JsonDRbObject.new(url: 'http://localhost:2901')
      expect { drb.tlm('INST HEALTH_STATUS TEMP1', scope: 'DEFAULT') }.to raise_error(AuthError)
    end
  end

  describe JsonApiObject do
    before(:each) do
      ENV['OPENC3_API_PASSWORD'] = 'test_password'
      @auth = OpenC3Authentication.new
      @http = double('Faraday')
      allow(Faraday).to receive(:new).and_return(@http)
    end

    after(:each) do
      ENV['OPENC3_API_PASSWORD'] = nil
    end

    it "re-authenticates once and retries when the session token is rejected" do
      tokens = []
      expect(@http).to receive(:get).twice do |_uri, _query, headers|
        tokens << headers['Authorization']
        instance_double(Faraday::Response, status: tokens.length == 1 ? 401 : 200, headers: {}, body: '{}')
      end
      mock_response = Object.new
      mock_response.define_singleton_method(:body) { 'fresh_token' }
      expect(@auth).to receive(:_make_auth_request).once.and_return(mock_response)

      api = JsonApiObject.new(url: 'http://localhost:2901', authentication: @auth)
      resp = api.request('get', '/openc3-api/screens', scope: 'DEFAULT')
      expect(resp.status).to eq(200)
      expect(tokens).to eq([$openc3_mock_token, 'fresh_token'])
    end
  end
end
