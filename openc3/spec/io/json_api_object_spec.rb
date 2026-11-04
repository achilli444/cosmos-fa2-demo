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
require 'openc3/io/json_api_object'
require 'net/http'

module OpenC3
  describe JsonApiObject do
    # Faraday only copies :read_timeout onto the Net::HTTP instance when the value
    # is truthy, so the only way to prove the setting survives is to run the real
    # adapter code against the connection options we actually build. Returns what
    # Net::HTTP would use for the request.
    def net_http_read_timeout(api_object)
      api_object.send(:connect)
      connection = api_object.instance_variable_get(:@http)
      http = Net::HTTP.new('openc3-cosmos-cmd-tlm-api', 2901)
      Faraday::Adapter::NetHttp.new.send(:configure_request, http, connection.options)
      http.read_timeout
    end

    before(:each) do
      ENV.delete('OPENC3_API_READ_TIMEOUT')
    end

    after(:each) do
      ENV.delete('OPENC3_API_READ_TIMEOUT')
    end

    describe "read timeout" do
      it "sets an explicit read timeout on the underlying Net::HTTP connection" do
        api_object = JsonApiObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0)
        # Net::HTTP defaults to 60s. Passing nil through Faraday leaves that default
        # in place, which silently caps any request that legitimately runs longer
        # (e.g. cmd() with timeout: 100 waiting on an interface ack).
        expect(net_http_read_timeout(api_object)).to eq(JsonApiObject::DEFAULT_READ_TIMEOUT_S)
        expect(net_http_read_timeout(api_object)).to be > 60
      end

      it "honors the read_timeout keyword" do
        api_object = JsonApiObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0, read_timeout: 120.0)
        expect(net_http_read_timeout(api_object)).to eq(120.0)
      end

      it "honors the OPENC3_API_READ_TIMEOUT environment variable" do
        ENV['OPENC3_API_READ_TIMEOUT'] = '300'
        api_object = JsonApiObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0)
        expect(net_http_read_timeout(api_object)).to eq(300.0)
      end

      it "prefers the read_timeout keyword over the environment variable" do
        ENV['OPENC3_API_READ_TIMEOUT'] = '300'
        api_object = JsonApiObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0, read_timeout: 120.0)
        expect(net_http_read_timeout(api_object)).to eq(120.0)
      end

      it "does not use the connect timeout as the read timeout" do
        # @timeout is the connection phase limit only. A short one must not cut
        # off a long running response.
        api_object = JsonApiObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0)
        api_object.send(:connect)
        connection = api_object.instance_variable_get(:@http)
        expect(connection.options[:open_timeout]).to eq(1)
        expect(connection.options[:read_timeout]).to eq(JsonApiObject::DEFAULT_READ_TIMEOUT_S)
      end
    end

    describe "JsonDRbObject" do
      it "passes read_timeout through to JsonApiObject" do
        require 'openc3/io/json_drb_object'
        api_object = JsonDRbObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0, read_timeout: 120.0)
        expect(net_http_read_timeout(api_object)).to eq(120.0)
      end

      it "defaults to the long read timeout" do
        require 'openc3/io/json_drb_object'
        api_object = JsonDRbObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0)
        expect(net_http_read_timeout(api_object)).to eq(JsonApiObject::DEFAULT_READ_TIMEOUT_S)
      end
    end

    describe "credential redaction" do
      let(:token) { 'Bearer super-secret-session-token-123' }
      let(:api_object) do
        JsonApiObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0, authentication: double(token: token))
      end

      before(:each) do
        api_object.send(:connect)
        allow(api_object).to receive(:connect)
        allow(api_object).to receive(:sleep)
        allow(Logger).to receive(:debug)
      end

      it "does not include the Authorization token in the raised exception" do
        expect(api_object).to receive(:_http_request).and_raise(Faraday::TimeoutError.new('read timeout'))
        expect { api_object.request('post', '/openc3-api/timeline', scope: 'DEFAULT') }.to raise_error do |error|
          expect(error.message).to match(/Api Exception/)
          expect(error.message).not_to include(token)
          expect(error.message).to match(/"Authorization" ?=?>? ?"\[REDACTED\]"/)
        end
      end

      it "redacts an explicit token keyword" do
        expect(api_object).to receive(:_http_request).and_raise(Faraday::TimeoutError.new('read timeout'))
        expect { api_object.request('get', '/openc3-api/tlm', scope: 'DEFAULT', token: 'explicit-token') }.to raise_error do |error|
          expect(error.message).not_to include('explicit-token')
          expect(error.message).to match(/token:? ?=?>? ?"\[REDACTED\]"/)
        end
      end

      it "redacts a caller supplied authorization header regardless of case" do
        expect(api_object).to receive(:_http_request).and_raise(Faraday::TimeoutError.new('read timeout'))
        headers = { 'authorization' => 'caller-token' }
        expect { api_object.request('get', '/openc3-api/tlm', scope: 'DEFAULT', headers: headers) }.to raise_error do |error|
          expect(error.message).not_to include('caller-token')
        end
      end

      it "keeps the exception class and message but not the backtrace in the raised exception" do
        exception = Faraday::TimeoutError.new('read timeout')
        exception.set_backtrace(['/openc3/lib/openc3/io/json_api_object.rb:1:in `secret_frame`'])
        expect(api_object).to receive(:_http_request).and_raise(exception)
        expect { api_object.request('post', '/openc3-api/timeline', scope: 'DEFAULT') }.to raise_error do |error|
          expect(error.message).to include('Faraday::TimeoutError, read timeout')
          expect(error.message).not_to include('secret_frame')
        end
        expect(Logger).to have_received(:debug).with(/secret_frame/)
      end

      it "does not leak the token after exhausting connection retries" do
        expect(api_object).to receive(:_http_request).exactly(RETRY_COUNT + 1).times
                                                     .and_raise(Faraday::ConnectionFailed.new('connect timeout'))
        expect { api_object.request('post', '/openc3-api/timeline', scope: 'DEFAULT') }.to raise_error do |error|
          expect(error.message).not_to include(token)
        end
      end

      it "does not leak the token when the scope keyword is missing" do
        expect { api_object.request('get', '/openc3-api/tlm', token: 'explicit-token') }.to raise_error(JsonApiError) do |error|
          expect(error.message).to match(/no scope keyword found/)
          expect(error.message).not_to include('explicit-token')
        end
      end

      it "still sends the real token to the server" do
        allow(api_object).to receive(:_http_request) do |**args|
          expect(args[:kwargs][:headers]['Authorization']).to eq(token)
          double(status: 200, headers: {}, body: '{}')
        end
        api_object.request('get', '/openc3-api/tlm', scope: 'DEFAULT')
      end
    end

    describe "timeout retry behavior" do
      let(:api_object) { JsonApiObject.new(url: 'http://openc3-cosmos-cmd-tlm-api:2901', timeout: 1.0) }

      before(:each) do
        api_object.send(:connect)
        # Stub connect and sleep so a retry loops straight back to _http_request.
        allow(api_object).to receive(:connect)
        allow(api_object).to receive(:sleep)
      end

      it "does not retry after a read timeout" do
        # The request was fully sent, so the server may have already acted on it.
        # Retrying a non idempotent POST would duplicate the operation.
        expect(api_object).to receive(:_http_request).once.and_raise(Faraday::TimeoutError.new('read timeout'))
        expect { api_object.request('post', '/openc3-api/timeline', scope: 'DEFAULT') }.to raise_error(/Api Exception/)
      end

      it "retries after a connection failure" do
        # Nothing was successfully sent, so replaying is safe. Net::OpenTimeout
        # arrives here as Faraday::ConnectionFailed.
        expect(api_object).to receive(:_http_request).exactly(RETRY_COUNT + 1).times
                                                     .and_raise(Faraday::ConnectionFailed.new('connect timeout'))
        expect { api_object.request('post', '/openc3-api/timeline', scope: 'DEFAULT') }.to raise_error(/Api Exception/)
      end
    end
  end
end
