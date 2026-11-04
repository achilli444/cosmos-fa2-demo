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

require 'digest'
require 'spec_helper'
require 'openc3/models/auth_model'

module OpenC3
  PW_HASH_PRIMARY_KEY = 'OPENC3__TOKEN'
  AUTH_INITIAL_PASSWORD = 'password'

  describe AuthModel, type: :model do
    before(:each) do
      @redis = mock_redis()

      # Disable the auth model mock for this spec
      allow(OpenC3::AuthModel).to receive(:verify).and_call_original
      allow(OpenC3::AuthModel).to receive(:verify_no_service).and_call_original
    end

    describe "authentication" do
      it "creates new" do
        model = AuthModel.new()
        expect(model).to be_a(AuthModel)
      end

      it "self.set" do
        expect{ AuthModel.set('token1token1', nil) }.to \
          raise_error(/old_password must not be nil or empty/)

        expect{ AuthModel.set('token1token1', 'token2token2', PW_HASH_PRIMARY_KEY) }.to \
          raise_error(/old_password incorrect/)

        AuthModel.set('newpassword', AUTH_INITIAL_PASSWORD)
        expect(AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any)).to eq(false)
        expect(AuthModel.verify_no_service('newpassword', mode: :any)).to eq(true)
      end

      it "self.verify" do
        expect(AuthModel.verify('badpassword')).to eq(false)
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD, no_password: false)).to eq(true)
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD, no_password: true)).to eq(false)
      end

      it "verifies and terminates a session token" do
        token1 = AuthModel.generate_session
        token2 = AuthModel.generate_session
        expect(AuthModel.verify(token1)).to eq(true)
        expect(AuthModel.verify(token2)).to eq(true)

        # Make sure terminating one doesn't affect the other
        AuthModel.terminate(token1)
        expect(AuthModel.verify(token1)).to eq(false)
        expect(AuthModel.verify(token2)).to eq(true)
      end

      it "verifies a session token and logs out" do
        token1 = AuthModel.generate_session
        token2 = AuthModel.generate_session
        expect(AuthModel.verify(token1)).to eq(true)
        expect(AuthModel.verify(token2)).to eq(true)

        # Make sure all sessions are terminated
        AuthModel.logout
        expect(AuthModel.verify(token1)).to eq(false)
        expect(AuthModel.verify(token2)).to eq(false)
      end

      it "creates a one-time use token" do
        token = AuthModel.generate_session(otp: true)
        expect(AuthModel.verify(token)).to eq(true)

        # Already verified, second attempt shouldn't work
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "revokes all sessions on password change" do
        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)

        AuthModel.set('newpassword', AUTH_INITIAL_PASSWORD)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "raises when stored password hash is SHA256" do
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end

    describe "session expiry" do
      SESSIONS_KEY = 'OPENC3__SESSIONS'

      before(:each) do
        @start = Time.now
        allow(Time).to receive(:now).and_return(@start)
      end

      def advance(seconds)
        allow(Time).to receive(:now).and_return(@start + seconds)
      end

      it "enforces limits by default" do
        expect(AuthModel::SESSION_IDLE_TIMEOUT).to eq(900)
        expect(AuthModel::SESSION_MAX_LIFETIME).to eq(43200)
      end

      it "stores creation and last used timestamps" do
        token = AuthModel.generate_session
        data = JSON.parse(@redis.hget(SESSIONS_KEY, token))
        expect(Time.iso8601(data['created_at'])).to be_within(1).of(@start)
        expect(Time.iso8601(data['last_used_at'])).to be_within(1).of(@start)
      end

      it "rejects and deletes a token idle longer than SESSION_IDLE_TIMEOUT" do
        token = AuthModel.generate_session
        advance(AuthModel::SESSION_IDLE_TIMEOUT - 1)
        expect(AuthModel.verify(token)).to eq(true)
        advance(AuthModel::SESSION_IDLE_TIMEOUT - 1 + AuthModel::SESSION_IDLE_TIMEOUT + 1)
        expect(AuthModel.verify(token)).to eq(false)
        expect(@redis.hexists(SESSIONS_KEY, token)).to eq(false)
        # Stays rejected even though the session cache is warm
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "refreshes the idle timeout on use" do
        token = AuthModel.generate_session
        step = AuthModel::SESSION_IDLE_TIMEOUT - 1
        elapsed = 0
        5.times do
          elapsed += step
          advance(elapsed)
          expect(AuthModel.verify(token)).to eq(true)
        end
        expect(elapsed).to be > AuthModel::SESSION_IDLE_TIMEOUT
        data = JSON.parse(@redis.hget(SESSIONS_KEY, token))
        expect(Time.iso8601(data['last_used_at'])).to be_within(1).of(@start + elapsed)
        expect(Time.iso8601(data['created_at'])).to be_within(1).of(@start)
      end

      it "rate limits last_used_at writes" do
        token = AuthModel.generate_session
        AuthModel.verify(token)
        expect(@redis).not_to receive(:hset)
        advance(AuthModel::SESSION_TOUCH_INTERVAL - 1)
        expect(AuthModel.verify(token)).to eq(true)
      end

      it "rejects a token older than SESSION_MAX_LIFETIME regardless of activity" do
        token = AuthModel.generate_session
        step = AuthModel::SESSION_IDLE_TIMEOUT - 1
        elapsed = 0
        while elapsed + step <= AuthModel::SESSION_MAX_LIFETIME
          elapsed += step
          advance(elapsed)
          expect(AuthModel.verify(token)).to eq(true)
        end
        advance(AuthModel::SESSION_MAX_LIFETIME + 1)
        expect(AuthModel.verify(token)).to eq(false)
        expect(@redis.hexists(SESSIONS_KEY, token)).to eq(false)
      end

      it "honors a shorter configured idle timeout" do
        stub_const("OpenC3::AuthModel::SESSION_IDLE_TIMEOUT", 60)
        token = AuthModel.generate_session
        advance(61)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "honors a shorter configured max lifetime" do
        stub_const("OpenC3::AuthModel::SESSION_MAX_LIFETIME", 120)
        stub_const("OpenC3::AuthModel::SESSION_TOUCH_INTERVAL", 0)
        token = AuthModel.generate_session
        advance(100)
        expect(AuthModel.verify(token)).to eq(true)
        advance(121)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "disables a limit set to 0" do
        stub_const("OpenC3::AuthModel::SESSION_IDLE_TIMEOUT", 0)
        stub_const("OpenC3::AuthModel::SESSION_MAX_LIFETIME", 0)
        token = AuthModel.generate_session
        advance(365 * 86400)
        expect(AuthModel.verify(token)).to eq(true)
      end

      it "treats a legacy bare timestamp as both created and last used" do
        @redis.hset(SESSIONS_KEY, 'ses_legacy', (@start - 60).iso8601)
        expect(AuthModel.verify('ses_legacy')).to eq(true)
        @redis.hset(SESSIONS_KEY, 'ses_stale', (@start - AuthModel::SESSION_IDLE_TIMEOUT - 1).iso8601)
        expect(AuthModel.verify('ses_stale')).to eq(false)
        expect(@redis.hexists(SESSIONS_KEY, 'ses_stale')).to eq(false)
      end

      it "treats an unparseable session value as expired" do
        @redis.hset(SESSIONS_KEY, 'ses_bad', 'garbage')
        @redis.hset(SESSIONS_KEY, 'ses_json', '{"created_at":"nope"}')
        expect(AuthModel.verify('ses_bad')).to eq(false)
        expect(AuthModel.verify('ses_json')).to eq(false)
        expect(@redis.hexists(SESSIONS_KEY, 'ses_bad')).to eq(false)
      end

      it "re-reads Redis when a cached session looks expired" do
        # Another API process may have refreshed last_used_at since this process cached it
        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)
        advance(AuthModel::SESSION_IDLE_TIMEOUT - 10)
        value = { 'created_at' => @start.iso8601, 'last_used_at' => Time.now.iso8601 }.to_json
        @redis.hset(SESSIONS_KEY, token, value)
        advance(AuthModel::SESSION_IDLE_TIMEOUT + 10)
        expect(AuthModel.verify(token)).to eq(true)
      end

      it "expires one-time tokens too" do
        token = AuthModel.generate_session(otp: true)
        advance(AuthModel::SESSION_IDLE_TIMEOUT + 1)
        expect(AuthModel.verify(token)).to eq(false)
      end
    end
  end
end
