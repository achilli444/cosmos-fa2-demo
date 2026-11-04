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

      it "verifies a brand new session token immediately after a failed check" do
        # This is the login page sequence: the stale token in localStorage is
        # checked (fails), the user types the password, and the token that comes
        # back is checked on the next page load. A cached negative result would
        # 401 that check and bounce the user straight back to the login form.
        stale = "#{AuthModel::SESSION_PREFIX}#{'A' * 22}"
        expect(AuthModel.verify(stale)).to eq(false)

        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)
        expect(AuthModel.verify(stale)).to eq(false)
      end

      it "never enumerates the stored sessions" do
        # verify_token is unauthenticated, so a caller must not be able to make
        # us walk every session on every request.
        expect(Store).not_to receive(:hgetall)
        expect(Store).not_to receive(:scan_each)
        expect(Store).not_to receive(:keys)

        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true) # reads just this token
        expect(AuthModel.verify(token)).to eq(true) # served from the cache
        10.times do
          bogus = "#{AuthModel::SESSION_PREFIX}#{SecureRandom.urlsafe_base64(nil, false)}"
          expect(AuthModel.verify(bogus)).to eq(false)
        end
      end

      it "stops using a cached session token once the cache expires" do
        token = AuthModel.generate_session
        expect(AuthModel.verify(token)).to eq(true)

        # Delete it behind the cache's back, the way another process would
        @redis.del("#{AuthModel::SESSION_KEY_PREFIX}#{token}")
        expect(AuthModel.verify(token)).to eq(true)

        # Past SESSION_CACHE_TIMEOUT the cache is dropped and the token is gone.
        # Compute the future time before stubbing so Time.now isn't stubbed yet.
        future = Time.now + AuthModel::SESSION_CACHE_TIMEOUT + 1
        allow(Time).to receive(:now).and_return(future)
        expect(AuthModel.verify(token)).to eq(false)
      end

      describe "session lifetime" do
        def session_key(token)
          "#{AuthModel::SESSION_KEY_PREFIX}#{token}"
        end

        after(:each) do
          ENV.delete('OPENC3_SESSION_IDLE_TIMEOUT')
          ENV.delete('OPENC3_SESSION_MAX_AGE')
        end

        it "defaults to a 15 minute idle timeout and 12 hour max age" do
          expect(AuthModel.session_idle_timeout).to eq(900)
          expect(AuthModel.session_max_age).to eq(43_200)
        end

        it "reads the limits from the environment" do
          ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = '300'
          ENV['OPENC3_SESSION_MAX_AGE'] = '3600'
          expect(AuthModel.session_idle_timeout).to eq(300)
          expect(AuthModel.session_max_age).to eq(3600)
        end

        it "refuses limits that would disable expiry" do
          ['0', '-5', 'never', '1.5'].each do |bad|
            ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = bad
            expect { AuthModel.session_idle_timeout }.to raise_error(ArgumentError, /OPENC3_SESSION_IDLE_TIMEOUT/)
            ENV.delete('OPENC3_SESSION_IDLE_TIMEOUT')
            ENV['OPENC3_SESSION_MAX_AGE'] = bad
            expect { AuthModel.session_max_age }.to raise_error(ArgumentError, /OPENC3_SESSION_MAX_AGE/)
            ENV.delete('OPENC3_SESSION_MAX_AGE')
          end
        end

        it "stores every new session with the idle timeout as its TTL" do
          token = AuthModel.generate_session
          otp = AuthModel.generate_session(otp: true)
          expect(@redis.ttl(session_key(token))).to be_between(899, 900)
          expect(@redis.ttl(session_key(otp))).to be_between(899, 900)
        end

        it "resets the idle timer each time the session is used" do
          ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = '600'
          token = AuthModel.generate_session
          # Simulate 9 minutes of inactivity by shortening the TTL directly
          @redis.expire(session_key(token), 60)
          expect(AuthModel.verify(token)).to eq(true)
          expect(@redis.ttl(session_key(token))).to be_between(599, 600)
        end

        it "rejects a session once it idles out" do
          token = AuthModel.generate_session
          expect(AuthModel.verify(token)).to eq(true)
          # Redis expires the key; another process sees no session at all
          @redis.del(session_key(token))
          future = Time.now + AuthModel::SESSION_CACHE_TIMEOUT + 1
          allow(Time).to receive(:now).and_return(future)
          expect(AuthModel.verify(token)).to eq(false)
        end

        it "never lets a refresh push the TTL past the absolute lifetime" do
          ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = '900'
          ENV['OPENC3_SESSION_MAX_AGE'] = '1000'
          token = AuthModel.generate_session
          expect(@redis.ttl(session_key(token))).to be_between(899, 900)

          # 700s in, only 300s of lifetime remain so the TTL is capped there
          later = Time.now + 700
          allow(Time).to receive(:now).and_return(later)
          expect(AuthModel.verify(token)).to eq(true)
          expect(@redis.ttl(session_key(token))).to be_between(299, 300)
        end

        it "rejects and removes a session older than the max age even if recently used" do
          ENV['OPENC3_SESSION_MAX_AGE'] = '3600'
          token = AuthModel.generate_session
          expect(AuthModel.verify(token)).to eq(true)

          # Still in the in-process cache, but past the absolute limit
          expired = Time.now + 3600
          allow(Time).to receive(:now).and_return(expired)
          expect(AuthModel.verify(token)).to eq(false)
          expect(@redis.exists(session_key(token))).to eq(0)

          # And when it comes from Redis rather than the cache
          token2 = AuthModel.generate_session
          @redis.set(session_key(token2), (expired - 3600).iso8601)
          allow(Time).to receive(:now).and_return(expired + AuthModel::SESSION_CACHE_TIMEOUT + 1)
          expect(AuthModel.verify(token2)).to eq(false)
          expect(@redis.exists(session_key(token2))).to eq(0)
        end

        it "treats an unparseable stored session as no session" do
          token = AuthModel.generate_session
          @redis.set(session_key(token), 'garbage')
          expect(AuthModel.verify(token)).to eq(false)
        end

        it "logout removes every session key and the legacy sessions hash" do
          tokens = 3.times.map { AuthModel.generate_session }
          @redis.hset(AuthModel::LEGACY_SESSIONS_KEY, 'ses_old', Time.now.iso8601)
          AuthModel.logout
          tokens.each { |t| expect(@redis.exists(session_key(t))).to eq(0) }
          expect(@redis.exists(AuthModel::LEGACY_SESSIONS_KEY)).to eq(0)
        end
      end

      it "raises when stored password hash is SHA256" do
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end
  end
end
