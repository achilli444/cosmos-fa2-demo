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

require "spec_helper"
require "openc3/utilities/authentication"

module OpenC3
  describe OpenC3Authentication do
    describe "initialize" do
      it "raises an error if OPENC3_API_PASSWORD is not set" do
        old_password = ENV.fetch('OPENC3_API_PASSWORD', nil)
        ENV.delete('OPENC3_API_PASSWORD')
        expect { OpenC3Authentication.new }.to raise_error(OpenC3AuthenticationError, /Authentication requires environment variable/)
        ENV['OPENC3_API_PASSWORD'] = old_password
      end

      it "initializes with OPENC3_API_PASSWORD" do
        ENV['OPENC3_API_PASSWORD'] = 'test_password'
        auth = OpenC3Authentication.new
        # Initialization calls a method that uses Faraday to get a token from the server.
        # It's mocked to return $openc3_mock_token for unit testing.
        expect(auth.token).to eq($openc3_mock_token)

        # Once initialized, it should be able to get an OTP as well
        expect(auth.get_otp).to eq($openc3_mock_otp)
      end

      it "retries on Faraday::ConnectionFailed" do
        ENV['OPENC3_API_PASSWORD'] = 'test_password'
        call_count = 0
        mock_response = Object.new
        mock_response.define_singleton_method(:body) { 'retry_token' }
        allow_any_instance_of(OpenC3Authentication).to receive(:_make_auth_request) do
          call_count += 1
          if call_count < 3
            raise Faraday::ConnectionFailed, "Hostname not known"
          end
          mock_response
        end
        allow_any_instance_of(OpenC3Authentication).to receive(:sleep)
        auth = OpenC3Authentication.new
        expect(auth.token).to eq('retry_token')
        expect(call_count).to eq(3)
      end

      it "raises after exhausting retries" do
        ENV['OPENC3_API_PASSWORD'] = 'test_password'
        allow_any_instance_of(OpenC3Authentication).to receive(:_make_auth_request).and_raise(Faraday::ConnectionFailed, "Hostname not known")
        allow_any_instance_of(OpenC3Authentication).to receive(:sleep)
        expect { OpenC3Authentication.new }.to raise_error(Faraday::ConnectionFailed)
      end
    end
  end

  describe "credential transport" do
    let(:cleared) do
      { 'OPENC3_API_SCHEMA' => nil, 'OPENC3_API_HOSTNAME' => nil, 'OPENC3_API_PORT' => nil,
        'OPENC3_DEVEL' => nil, 'OPENC3_ALLOW_INSECURE_AUTH' => nil, 'OPENC3_API_PASSWORD' => 'test_password' }
    end
    let(:mock_response) do
      response = Object.new
      response.define_singleton_method(:body) { $openc3_mock_token }
      response
    end

    before(:each) do
      OpenC3.reset_cleartext_auth_warning
      # spec_helper stubs out the whole request; put the URL generation (and thus
      # the transport check) back on the path like the real _make_auth_request
      allow_any_instance_of(OpenC3Authentication).to receive(:_make_auth_request) do |auth, _password|
        auth._generate_auth_url
        mock_response
      end
    end

    it "defaults OPENC3_API_SCHEMA to https" do
      OpenC3.spec_with_env(cleared) do
        expect(OpenC3.api_schema('OPENC3_API_SCHEMA')).to eq('https')
        auth = OpenC3Authentication.new
        expect(auth._generate_auth_url).to eq('https://openc3-cosmos-cmd-tlm-api:2901/openc3-api/auth/verify')
        expect(auth._generate_auth_url('/auth/otp')).to eq('https://openc3-cosmos-cmd-tlm-api:2901/openc3-api//auth/otp')
      end
    end

    it "treats an empty OPENC3_API_SCHEMA as https" do
      OpenC3.spec_with_env(cleared.merge('OPENC3_API_SCHEMA' => '')) do
        expect(OpenC3Authentication.new._generate_auth_url).to start_with('https://')
      end
    end

    it "refuses to post the password over http" do
      OpenC3.spec_with_env(cleared.merge('OPENC3_API_SCHEMA' => 'http')) do
        expect(Logger).not_to receive(:warn)
        expect { OpenC3Authentication.new }.to raise_error(OpenC3AuthenticationError, /Refusing to send credentials over cleartext http.*OPENC3_API_SCHEMA/)
      end
    end

    it "does not treat OPENC3_ALLOW_INSECURE_AUTH=0 as an opt-in" do
      OpenC3.spec_with_env(cleared.merge('OPENC3_API_SCHEMA' => 'http', 'OPENC3_ALLOW_INSECURE_AUTH' => '0')) do
        expect { OpenC3Authentication.new }.to raise_error(OpenC3AuthenticationError, /cleartext http/)
      end
    end

    it "posts over http when OPENC3_ALLOW_INSECURE_AUTH is set and warns once per process" do
      OpenC3.spec_with_env(cleared.merge('OPENC3_API_SCHEMA' => 'http', 'OPENC3_ALLOW_INSECURE_AUTH' => '1')) do
        expect(Logger).to receive(:warn).with(/Sending credentials over cleartext http/).once
        expect(OpenC3Authentication.new.token).to eq($openc3_mock_token)
        expect(OpenC3Authentication.new.token).to eq($openc3_mock_token)
      end
    end

    it "treats OPENC3_DEVEL as the local development opt-in" do
      OpenC3.spec_with_env(cleared.merge('OPENC3_API_SCHEMA' => 'http', 'OPENC3_DEVEL' => '../openc3')) do
        expect(Logger).to receive(:warn).with(/cleartext http/).once
        expect(OpenC3Authentication.new._generate_auth_url).to eq('http://127.0.0.1:2901/openc3-api/auth/verify')
      end
    end

    it "refuses an http Keycloak URL and accepts https" do
      OpenC3.spec_with_env(cleared) do
        expect { OpenC3KeycloakAuthentication.new('http://keycloak:8080') }.to raise_error(OpenC3AuthenticationError, /cleartext http.*OPENC3_KEYCLOAK_URL/)
        expect(OpenC3KeycloakAuthentication.new('https://keycloak:8080')).to be_a(OpenC3KeycloakAuthentication)
      end
    end

    it "leaves https and wss alone" do
      OpenC3.spec_with_env(cleared) do
        expect(Logger).not_to receive(:warn)
        expect(OpenC3.verify_credential_transport('https://x:1')).to eq('https://x:1')
        expect(OpenC3.verify_credential_transport('wss://x:1')).to eq('wss://x:1')
      end
    end
  end

  describe OpenC3KeycloakAuthentication do
    let(:test_url) { "https://test-keycloak.local" }
    let(:mock_http) { instance_double(Faraday::Connection) }
    let(:mock_builder) { instance_double(Faraday::RackBuilder) }

    before(:each) do
      ENV['OPENC3_API_USER'] = 'testuser'
      ENV['OPENC3_API_PASSWORD'] = 'testpassword'
      ENV['OPENC3_KEYCLOAK_REALM'] = 'openc3'
      # Mock Faraday to return our mock connection
      allow(Faraday).to receive(:new).and_return(mock_http)
    end

    after(:each) do
      ENV.delete('OPENC3_API_USER')
      ENV.delete('OPENC3_API_PASSWORD')
      ENV.delete('OPENC3_API_TOKEN')
      ENV.delete('OPENC3_KEYCLOAK_REALM')
      ENV.delete('OPENC3_API_CLIENT')
    end

    describe "initialize" do
      it "initializes with a URL" do
        auth = OpenC3KeycloakAuthentication.new(test_url)
        expect(auth).to be_a(OpenC3KeycloakAuthentication)
      end
    end

    describe "password obfuscation in logs" do
      let(:auth) { OpenC3KeycloakAuthentication.new(test_url) }
      let(:mock_response) do
        instance_double(Faraday::Response,
          status: 401,
          headers: {},
          body: '{"error":"invalid_grant"}'
        )
      end

      before(:each) do
        allow(mock_http).to receive(:post).and_return(mock_response)
      end

      context "when debug mode is disabled" do
        before(:each) do
          allow(JsonDRb).to receive(:debug?).and_return(false)
        end

        it "obfuscates password in error messages" do
          expect {
            auth.token
          }.to raise_error(OpenC3AuthenticationError) do |error|
            # Error message should contain obfuscated password (works with both Ruby 3.2 and 3.3+ inspect formats)
            expect(error.message).to match(/"password"\s*=>\s*"\*\*\*"/)
            # Error message should NOT contain actual password
            expect(error.message).not_to include('testpassword')
          end
        end

        it "obfuscates password in STDOUT logs" do
          stdout = StringIO.new('', 'r+')
          saved_stdout = $stdout
          $stdout = stdout
          saved_stdout_const = Object.const_get(:STDOUT)
          OpenC3.disable_warnings { Object.const_set(:STDOUT, stdout) }

          begin
            expect {
              auth.token
            }.to raise_error(OpenC3AuthenticationError)
          ensure
            $stdout = saved_stdout
            OpenC3.disable_warnings { Object.const_set(:STDOUT, saved_stdout_const) }
          end

          # STDOUT should not contain the actual password
          expect(stdout.string).not_to include('testpassword')
        end

        it "preserves other parameters in logs" do
          expect {
            auth.token
          }.to raise_error(OpenC3AuthenticationError) do |error|
            # Other parameters should still be visible (works with both Ruby 3.2 and 3.3+ inspect formats)
            expect(error.message).to match(/"username"\s*=>\s*"testuser"/)
            expect(error.message).to match(/"grant_type"\s*=>\s*"password"/)
            expect(error.message).to match(/"client_id"\s*=>\s*"api"/)
          end
        end
      end

      context "when debug mode is enabled" do
        before(:each) do
          allow(JsonDRb).to receive(:debug?).and_return(true)
        end

        it "shows actual password in error messages when debug is enabled" do
          stdout = StringIO.new('', 'r+')
          saved_stdout = $stdout
          $stdout = stdout
          saved_stdout_const = Object.const_get(:STDOUT)
          OpenC3.disable_warnings { Object.const_set(:STDOUT, stdout) }

          begin
            expect {
              auth.token
            }.to raise_error(OpenC3AuthenticationError)
          ensure
            $stdout = saved_stdout
            OpenC3.disable_warnings { Object.const_set(:STDOUT, saved_stdout_const) }
          end

          # In debug mode, STDOUT should contain the actual password (works with both Ruby 3.2 and 3.3+ inspect formats)
          expect(stdout.string).to match(/"password"\s*=>\s*"testpassword"/)
        end
      end

      context "with refresh token" do
        let(:auth) { OpenC3KeycloakAuthentication.new(test_url) }

        before(:each) do
          ENV.delete('OPENC3_API_USER')
          ENV.delete('OPENC3_API_PASSWORD')
          ENV['OPENC3_API_TOKEN'] = 'test_refresh_token'
          allow(JsonDRb).to receive(:debug?).and_return(false)
        end

        it "obfuscates refresh_token in normal mode" do
          expect {
            auth.token
          }.to raise_error(OpenC3AuthenticationError) do |error|
            # Refresh token should be obfuscated (works with both Ruby 3.2 and 3.3+ inspect formats)
            expect(error.message).to match(/"refresh_token"\s*=>\s*"\*\*\*"/)
            # Error message should NOT contain actual refresh token
            expect(error.message).not_to include('test_refresh_token')
          end
        end

        it "shows actual refresh_token when debug is enabled" do
          allow(JsonDRb).to receive(:debug?).and_return(true)

          stdout = StringIO.new('', 'r+')
          saved_stdout = $stdout
          $stdout = stdout
          saved_stdout_const = Object.const_get(:STDOUT)
          OpenC3.disable_warnings { Object.const_set(:STDOUT, stdout) }

          begin
            expect {
              auth.token
            }.to raise_error(OpenC3AuthenticationError)
          ensure
            $stdout = saved_stdout
            OpenC3.disable_warnings { Object.const_set(:STDOUT, saved_stdout_const) }
          end

          # In debug mode, STDOUT should contain the actual refresh token (works with both Ruby 3.2 and 3.3+ inspect formats)
          expect(stdout.string).to match(/"refresh_token"\s*=>\s*"test_refresh_token"/)
        end
      end
    end

    describe "successful authentication" do
      let(:auth) { OpenC3KeycloakAuthentication.new(test_url) }
      let(:mock_success_response) do
        instance_double(Faraday::Response,
          status: 200,
          headers: {},
          body: JSON.generate({
            "access_token" => "access_token_123",
            "expires_in" => 600,
            "refresh_expires_in" => 1800,
            "refresh_token" => "refresh_token_123",
            "token_type" => "bearer"
          })
        )
      end

      before(:each) do
        allow(JsonDRb).to receive(:debug?).and_return(false)
        allow(mock_http).to receive(:post).and_return(mock_success_response)
      end

      it "returns token with Bearer prefix by default" do
        token = auth.token
        expect(token).to eq("Bearer access_token_123")
      end

      it "returns token without Bearer prefix when requested" do
        token = auth.token(include_bearer: false)
        expect(token).to eq("access_token_123")
      end
    end

    describe "retryable errors" do
      let(:auth) { OpenC3KeycloakAuthentication.new(test_url) }
      let(:mock_503_response) do
        instance_double(Faraday::Response,
          status: 503,
          headers: {},
          body: '{"error":"service_unavailable"}'
        )
      end

      before(:each) do
        allow(JsonDRb).to receive(:debug?).and_return(false)
        allow(mock_http).to receive(:post).and_return(mock_503_response)
      end

      it "raises retryable error for 5xx status codes" do
        expect {
          auth.token
        }.to raise_error(OpenC3AuthenticationRetryableError)
      end
    end

    describe "URL encoding of special characters" do
      # This test runs without any mocking to verify Faraday's behavior
      context "Faraday middleware verification" do
        after(:each) do
          RSpec::Mocks.space.proxy_for(Faraday).reset if RSpec::Mocks.space.proxies.any?
        end

        it "verifies Faraday URL encodes hash data" do
          RSpec::Mocks.space.proxy_for(Faraday).reset if RSpec::Mocks.space.proxies.any?

          # Simple test to verify Faraday's url_encoded middleware works
          conn = Faraday.new do |f|
            f.request :url_encoded
            f.adapter :test do |stub|
              stub.post('/test') do |env|
                [200, {}, env[:body]]
              end
            end
          end

          response = conn.post('/test', {'password' => 'my&pass=word%'})
          expect(response.body).to eq('password=my%26pass%3Dword%25')

          # Restore the mock for other tests
          allow(mock_builder).to receive(:request)
          allow(Faraday).to receive(:new).and_yield(mock_builder).and_return(mock_http)
        end
      end
    end
  end
end
