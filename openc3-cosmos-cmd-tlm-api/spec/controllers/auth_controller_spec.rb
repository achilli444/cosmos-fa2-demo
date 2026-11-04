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

  describe "verify-token" do
    it "requires a token" do
      post :verify_token
      expect(response).to have_http_status(:unauthorized)
    end

    it "validates a session token" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      token = response.body

      post :verify_token, params: { token: token }
      expect(response).to have_http_status(:ok)

      post :verify_token, params: { token: 'ses_bogus' }
      expect(response).to have_http_status(:unauthorized)
    end

    it "does not accept the password" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :verify_token, params: { token: 'PASSWORD' }
      expect(response).to have_http_status(:unauthorized)
    end

    it "rejects tokens that aren't shaped like a session token without hitting redis" do
      # The endpoint is unauthenticated, so an obviously invalid token must do
      # no Redis work at all. verify_no_service is where the HGET happens, so
      # never reaching it is the invariant. Knowing
      # the session prefix must not be enough to get through, so the full shape
      # is checked rather than just the prefix.
      expect(OpenC3::AuthModel).not_to receive(:verify_no_service)
      [
        '',
        'PASSWORD',
        'otp_something',
        'nope',
        'ses_',
        'ses_AAA',                     # right prefix, too short
        "ses_#{'A' * 21}",             # one character short
        "ses_#{'A' * 23}",             # one character long
        "ses_#{'A' * 21}+",            # not urlsafe base64
        "ses_#{'A' * 22}\n",           # trailing whitespace
        "ses_#{'A' * 22}ses_#{'A' * 22}",
      ].each do |token|
        post :verify_token, params: { token: token }
        expect(response).to have_http_status(:unauthorized)
      end
    end

    it "accepts the shape of every generated session token" do
      100.times do
        expect(OpenC3::AuthModel.session_token?(OpenC3::AuthModel.generate_session())).to be true
      end
      # An OTP token is a valid session token but must not pass this endpoint
      expect(OpenC3::AuthModel.session_token?(OpenC3::AuthModel.generate_session(otp: true))).to be false
    end

    it "does not consume an OTP token" do
      user = 'anonymous'
      otp = OpenC3::Authorization.generate_otp(user)
      post :verify_token, params: { token: otp }
      expect(response).to have_http_status(:unauthorized)
      # Still usable, i.e. verify_no_service never saw it
      expect(OpenC3::AuthModel.verify_no_service(otp, mode: :token)).to be true
    end

    # Mirrors what the login page does (see Login.vue verifyToken): check the
    # token in localStorage on mount, fall back to the password form, then check
    # the new token on the next page load.
    it "accepts a token the moment verify hands it out" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      # Page load with a stale token in localStorage
      stale = "ses_#{'A' * 22}"
      post :verify_token, params: { token: stale }
      expect(response).to have_http_status(:unauthorized)

      # User types the password and gets a fresh token
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      token = response.body

      # Next page load checks that token. The failed check above must not have
      # cached a negative result that makes this 401 and bounce the user back to
      # the login form.
      post :verify_token, params: { token: token }
      expect(response).to have_http_status(:ok)

      post :verify_token, params: { token: stale }
      expect(response).to have_http_status(:unauthorized)
    end

    it "does not read the entire session hash" do
      # Unauthenticated endpoint, so a caller must not be able to make us pull
      # every session ever created on every request. Store goes through
      # method_missing, so the expectation has to go on the redis mock itself.
      redis = mock_redis()
      expect(redis).not_to receive(:hgetall)

      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      token = response.body

      post :verify_token, params: { token: token }
      expect(response).to have_http_status(:ok)

      10.times do
        post :verify_token, params: { token: "ses_#{SecureRandom.urlsafe_base64(nil, false)}" }
        expect(response).to have_http_status(:unauthorized)
      end
    end

    it "does not count a stale token as a bad password attempt" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      # A stale token in localStorage must not eat into the password rate limit
      20.times do
        post :verify_token, params: { token: 'ses_stale' }
        expect(response).to have_http_status(:unauthorized)
      end
      expect(OpenC3::EphemeralStore.get('openc3__auth_bad_attempts__user')).to be_nil

      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
    end
  end

  describe "rate limiting" do
    # Sets the client ip for the next request, either as the connecting address
    # or as the address a proxy forwarded. remote_ip memoizes in both the request
    # instance and the rack env so clear both or later requests keep the old ip.
    def set_client_ip(ip, forwarded: false)
      if forwarded
        request.headers['X-Forwarded-For'] = ip
      else
        request.remote_addr = ip
      end
      request.env.delete('action_dispatch.remote_ip')
      request.instance_variable_set(:@remote_ip, nil)
    end

    it "rate limits bad password attempts from the same client" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      set_client_ip('1.2.3.4')
      10.times do
        post :verify, params: { password: 'BAD' }
        expect(response).to have_http_status(:unauthorized)
      end
      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:too_many_requests)
      # Even the correct password is rejected for this client
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:too_many_requests)
    end

    it "does not rate limit other clients when one client sends bad passwords" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      set_client_ip('1.2.3.4')
      20.times do
        post :verify, params: { password: 'BAD' }
      end
      expect(response).to have_http_status(:too_many_requests)

      # A different client can still log in with the correct password
      set_client_ip('5.6.7.8')
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
    end

    it "rate limits based on X-Forwarded-For when behind a proxy" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      # Simulate traefik forwarding two different browsers from the same proxy
      request.remote_addr = '10.0.0.1'
      set_client_ip('1.2.3.4', forwarded: true)
      20.times do
        post :verify, params: { password: 'BAD' }
      end
      expect(response).to have_http_status(:too_many_requests)

      set_client_ip('5.6.7.8', forwarded: true)
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
    end

    it "clears the bad attempt counter after a successful attempt" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      set_client_ip('1.2.3.4')
      9.times do
        post :verify, params: { password: 'BAD' }
        expect(response).to have_http_status(:unauthorized)
      end
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      # Counter was reset so 9 more bad attempts don't trip the limit
      9.times do
        post :verify, params: { password: 'BAD' }
        expect(response).to have_http_status(:unauthorized)
      end
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
    end

    it "refreshes the window on each bad attempt" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      set_client_ip('1.2.3.4')
      key = "openc3__auth_bad_attempts__user__1.2.3.4"
      post :verify, params: { password: 'BAD' }
      OpenC3::EphemeralStore.expire(key, 5)
      post :verify, params: { password: 'BAD' }
      expect(OpenC3::EphemeralStore.ttl(key)).to be > 5
    end

    it "gives the counter a window if it somehow has no expiration" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      # Simulate incr succeeding but expire failing, which would otherwise lock
      # this client out forever
      key = "openc3__auth_bad_attempts__user__1.2.3.4"
      OpenC3::EphemeralStore.set(key, 100)
      set_client_ip('1.2.3.4')
      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:too_many_requests)
      expect(OpenC3::EphemeralStore.ttl(key)).to be_between(1, 120)
    end

    it "rate limits bad service password attempts per client" do
      set_client_ip('1.2.3.4')
      20.times do
        post :verify_service, params: { password: 'BAD' }
      end
      expect(response).to have_http_status(:too_many_requests)

      set_client_ip('5.6.7.8')
      post :verify_service, params: { password: 'openc3service' }
      expect(response).to have_http_status(:ok)
    end

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

  describe "audit logging" do
    # Every logon outcome must leave a structured record that ties the event
    # to a source address and never contains what the client submitted.
    SECRET = 'S3cretPw!'

    def set_client_ip(ip)
      request.remote_addr = ip
      request.env.delete('action_dispatch.remote_ip')
      request.instance_variable_set(:@remote_ip, nil)
    end

    before(:each) do
      @records = []
      [:info, :warn, :error].each do |level|
        allow(OpenC3::Logger).to receive(level).and_wrap_original do |original, *args, **kwargs, &block|
          if kwargs[:type] == OpenC3::Logger::AUDIT
            @records << { level: level, message: args[0], user: kwargs[:user] }.merge(kwargs[:other] || {})
          end
          original.call(*args, **kwargs, &block)
        end
      end
    end

    after(:each) do
      # Nothing we audit may contain the submitted password
      expect(@records.to_s).not_to include(SECRET)
      expect(@records.to_s).not_to include('BAD')
    end

    def login_records(outcome)
      @records.select { |r| r[:event] == 'login' and r[:outcome] == outcome }
    end

    it "records a successful password login" do
      post :set, params: { password: SECRET }
      set_client_ip('1.2.3.4')
      post :verify, params: { password: SECRET }
      expect(response).to have_http_status(:ok)

      record = login_records('success').last
      expect(record).to include(level: :info, token_type: 'password', client_id: '1.2.3.4', endpoint: 'auth#verify')
      # The session issued for the login is audited too, without the token
      created = @records.select { |r| r[:event] == 'session_created' }.last
      expect(created).to include(token_type: 'session')
      expect(@records.to_s).not_to include(response.body)
    end

    it "records a failed password login as a warning" do
      post :set, params: { password: SECRET }
      set_client_ip('1.2.3.4')
      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)

      record = login_records('failure').last
      expect(record).to include(level: :warn, token_type: 'password', client_id: '1.2.3.4', endpoint: 'auth#verify')
      expect(login_records('success')).to be_empty
    end

    it "records the lockout once when the limit trips and every rejected request after it" do
      post :set, params: { password: SECRET }
      set_client_ip('1.2.3.4')
      9.times { post :verify, params: { password: 'BAD' } }
      expect(login_records('locked_out')).to be_empty

      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)
      locked = login_records('locked_out')
      expect(locked.length).to eql 1
      expect(locked[0]).to include(level: :warn, token_type: 'password', client_id: '1.2.3.4', attempts: 10, window_seconds: 120)

      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:too_many_requests)
      post :verify, params: { password: SECRET }
      expect(response).to have_http_status(:too_many_requests)
      limited = login_records('rate_limited')
      expect(limited.length).to eql 2
      expect(limited[0]).to include(level: :warn, client_id: '1.2.3.4', endpoint: 'auth#verify')
      expect(login_records('locked_out').length).to eql 1
      expect(login_records('failure').length).to eql 10
    end

    it "records service password logins" do
      set_client_ip('1.2.3.4')
      post :verify_service, params: { password: 'BAD' }
      expect(login_records('failure').last).to include(level: :warn, token_type: 'service', endpoint: 'auth#verify_service')

      post :verify_service, params: { password: 'openc3service' }
      expect(login_records('success').last).to include(level: :info, token_type: 'service', client_id: '1.2.3.4')
      expect(@records.to_s).not_to include('openc3service')
    end

    it "records the service lockout" do
      set_client_ip('1.2.3.4')
      10.times { post :verify_service, params: { password: 'BAD' } }
      expect(login_records('locked_out').last).to include(token_type: 'service', endpoint: 'auth#verify_service')
      post :verify_service, params: { password: 'BAD' }
      expect(login_records('rate_limited').last).to include(token_type: 'service')
    end

    it "records session token checks without the token" do
      post :set, params: { password: SECRET }
      token = response.body
      set_client_ip('1.2.3.4')

      post :verify_token, params: { token: token }
      expect(login_records('success').last).to include(token_type: 'session', endpoint: 'auth#verify_token')

      post :verify_token, params: { token: "ses_#{'A' * 22}" }
      expect(login_records('failure').last).to include(token_type: 'session', endpoint: 'auth#verify_token')

      post :verify_token, params: { token: 'garbage' }
      expect(login_records('failure').last).to include(token_type: 'session', reason: 'malformed_token')
      expect(@records.to_s).not_to include(token)
      expect(@records.to_s).not_to include('garbage')
    end

    it "records password changes and bad old passwords" do
      set_client_ip('1.2.3.4')
      post :set, params: { password: SECRET }
      changed = @records.select { |r| r[:event] == 'password_changed' }
      expect(changed.length).to eql 1
      expect(changed[0]).to include(user: 'anonymous', outcome: 'success', client_id: '1.2.3.4', endpoint: 'auth#set')
      # Changing the password revokes every session, which is audited
      expect(@records.select { |r| r[:event] == 'logout_all' }.length).to eql 1

      post :set, params: { password: 'Another1!', old_password: 'BAD' }
      expect(response).to have_http_status(:error)
      expect(login_records('failure').last).to include(level: :warn, endpoint: 'auth#set', reason: 'old_password incorrect')
      expect(@records.to_s).not_to include('Another1!')
    end
  end
end
