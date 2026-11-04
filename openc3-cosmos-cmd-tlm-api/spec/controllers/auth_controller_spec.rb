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

require 'rails_helper'

RSpec.describe AuthController, :type => :controller do
  before(:each) do
    mock_redis()
  end

  describe "token-exists" do
    it "returns false then true when the token is set" do
      get :token_exists
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json).to eql({"result" => false})

      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      get :token_exists
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json).to eql({"result" => true})
    end
  end

  describe "set" do
    it "requires old_password after initial set" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :set, params: { password: 'PASSWORD2' }
      expect(response).to have_http_status(:error)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json["status"]).to eql 'error'
      expect(json["message"]).to eql 'old_password must not be nil or empty'

      post :set, params: { password: 'PASSWORD2', old_password: 'BAD' }
      expect(response).to have_http_status(:error)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json["status"]).to eql 'error'
      expect(json["message"]).to eql 'old_password incorrect'

      post :set, params: { password: 'PASSWORD2', old_password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
    end
  end

  describe "set" do
    it "revokes old sessions and issues a new token on password change" do
      # Set initial password and get a session token
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      old_token = response.body
      expect(old_token).not_to be_empty

      # Change password
      post :set, params: { password: 'PASSWORD2', old_password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      new_token = response.body
      expect(new_token).not_to be_empty
      expect(new_token).not_to eq(old_token)

      # Old token should be invalid
      expect(OpenC3::AuthModel.verify(old_token)).to eq(false)
      # New token should be valid
      expect(OpenC3::AuthModel.verify(new_token)).to eq(true)
    end
  end

  describe "verify" do
    it "requires token" do
      post :verify
      expect(response).to have_http_status(:unauthorized)
    end

    it "validates the set password" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)
    end

    it "validates the service password" do
      post :verify_service, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)

      post :verify_service, params: { password: 'openc3service' }
      expect(response).to have_http_status(:ok)
    end
  end

  describe "security audit" do
    def security_events
      events = []
      allow(OpenC3::SecurityAudit).to receive(:log).and_wrap_original do |m, **kwargs|
        events << m.call(**kwargs)
      end
      events
    end

    it "logs a failed and a successful user login with source address, never the password" do
      events = security_events
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      logins = events.select { |e| e[:event] == 'login' }
      expect(logins.map { |e| e[:outcome] }).to eql ['failure', 'success']
      expect(logins[0]).to include(login_type: 'user', reason: 'Incorrect password', user: 'anonymous', source: '0.0.0.0')
      expect(logins[1]).to include(login_type: 'user', user: 'anonymous', source: '0.0.0.0')
      expect(events.to_s).not_to include('PASSWORD')
      expect(events.to_s).not_to include('BAD')
    end

    it "logs failed and successful service logins" do
      events = security_events
      post :verify_service, params: { password: 'BAD' }
      post :verify_service, params: { password: 'openc3service' }
      logins = events.select { |e| e[:event] == 'login' }
      expect(logins.map { |e| [e[:login_type], e[:outcome]] }).to eql [['service', 'failure'], ['service', 'success']]
      expect(events.to_s).not_to include('openc3service')
    end

    it "logs password change outcomes" do
      events = security_events
      post :set, params: { password: 'PASSWORD' }
      post :set, params: { password: 'PASSWORD2', old_password: 'WRONG' }
      expect(response).to have_http_status(:error)
      changes = events.select { |e| e[:event] == 'password_change' }
      expect(changes.map { |e| e[:outcome] }).to eql ['success', 'failure']
      expect(changes[1][:reason]).to eql 'old_password incorrect'
      expect(events.to_s).not_to include('WRONG')
    end

    it "logs when a client is rate limited" do
      events = security_events
      allow_any_instance_of(AuthController).to receive(:user_rate_limited?).and_return(true)
      allow_any_instance_of(AuthController).to receive(:service_rate_limited?).and_return(true)
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:too_many_requests)
      post :verify_service, params: { password: 'openc3service' }
      expect(response).to have_http_status(:too_many_requests)
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:too_many_requests)
      expect(events.map { |e| [e[:event], e[:outcome]] }).to eql [
        ['login', 'rate_limited'], ['login', 'rate_limited'], ['password_change', 'rate_limited']
      ]
      expect(events[0]).to include(login_type: 'user', source: '0.0.0.0')
      expect(events[1]).to include(login_type: 'service')
    end

    it "emits the records through OpenC3::Logger as type security" do
      captured = []
      post :set, params: { password: 'PASSWORD' }
      allow(OpenC3::Logger).to receive(:warn) { |message, **kwargs| captured << [message, kwargs] }
      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)
      message, kwargs = captured.find { |m, _| m.include?('Security event login failure') }
      expect(message).to include('Incorrect password')
      expect(kwargs).to include(type: 'security', scope: nil, user: 'anonymous')
      expect(kwargs[:other]).to include(event: 'login', outcome: 'failure', source: '0.0.0.0')
      expect(kwargs[:other].values).to all(be_a(String))
    end
  end

  describe "rate limiting" do
    # Actually testing that rate limiting is enforced is done in Playwright
    # because the bad attempt counters in the controller are shared across
    # all requests/tests. But we can ensure that the config is read and that
    # successful attempts don't get rate limited.

    it "uses default rate limit values from environment" do
      expect(ENV['OPENC3_AUTH_RATE_LIMIT_TO']).to eq('10')
      expect(ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN']).to eq('120')
    end

    it "respects custom rate limit values from environment" do
      original_to = ENV.fetch('OPENC3_AUTH_RATE_LIMIT_TO', '10')
      original_within = ENV.fetch('OPENC3_AUTH_RATE_LIMIT_WITHIN', '120')

      begin
        ENV['OPENC3_AUTH_RATE_LIMIT_TO'] = '5'
        ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN'] = '60'

        load Rails.root.join('app', 'controllers', 'auth_controller.rb')

        expect(ENV['OPENC3_AUTH_RATE_LIMIT_TO']).to eq('5')
        expect(ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN']).to eq('60')
      ensure
        ENV['OPENC3_AUTH_RATE_LIMIT_TO'] = original_to
        ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN'] = original_within
        load Rails.root.join('app', 'controllers', 'auth_controller.rb')
      end
    end

    it "does not rate limit successful password attempts" do
      # Note: testing rate limit for bad attempts is done in Playwright
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      20.times do
        post :verify, params: { password: 'PASSWORD' }
        expect(response).to have_http_status(:ok)
      end
    end
  end
end
