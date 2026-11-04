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

      it "never reads the entire session hash" do
        # verify_token is unauthenticated, so a caller must not be able to make
        # us pull every session on every request. Only generate_session, which
        # runs after the caller has authenticated, may scan the hash (to prune).
        token = AuthModel.generate_session
        expect(Store).not_to receive(:hgetall)

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
        @redis.hdel(AuthModel::SESSIONS_KEY, AuthModel.session_digest(token))
        expect(AuthModel.verify(token)).to eq(true)

        # Past SESSION_CACHE_TIMEOUT the cache is dropped and the token is gone.
        # Compute the future time before stubbing so Time.now isn't stubbed yet.
        future = Time.now + AuthModel::SESSION_CACHE_TIMEOUT + 1
        allow(Time).to receive(:now).and_return(future)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "stores only a digest of the session token" do
        token = AuthModel.generate_session
        fields = @redis.hkeys(AuthModel::SESSIONS_KEY)
        expect(fields).not_to include(token)
        expect(fields).to include(Digest::SHA256.hexdigest(token))
        fields.each { |field| expect(field).not_to include(token[AuthModel::SESSION_PREFIX.length..]) }
        expect(AuthModel.verify(token)).to eq(true)
      end

      it "rejects and removes a pre-digest plaintext session entry" do
        legacy = "#{AuthModel::SESSION_PREFIX}#{SecureRandom.urlsafe_base64(nil, false)}"
        @redis.hset(AuthModel::SESSIONS_KEY, legacy, Time.now.iso8601)
        expect(AuthModel.verify(legacy)).to eq(false)

        # Pruned on the next login
        AuthModel.generate_session
        expect(@redis.hexists(AuthModel::SESSIONS_KEY, legacy)).to eq(false)
      end

      describe "session lifetime" do
        before(:each) do
          @now = Time.now
          allow(Time).to receive(:now).and_return(@now)
        end

        def advance(seconds)
          @now += seconds
          allow(Time).to receive(:now).and_return(@now)
        end

        it "defaults to a 15 minute idle timeout and 12 hour maximum age" do
          expect(AuthModel.session_idle_timeout).to eq(900)
          expect(AuthModel.session_max_age).to eq(43200)
          expect(AuthModel.session_max_concurrent).to eq(10)
        end

        it "reads the limits from the environment and rejects bad values" do
          ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = '60'
          ENV['OPENC3_SESSION_MAX_AGE'] = '120'
          ENV['OPENC3_SESSION_MAX_CONCURRENT'] = '2'
          expect(AuthModel.session_idle_timeout).to eq(60)
          expect(AuthModel.session_max_age).to eq(120)
          expect(AuthModel.session_max_concurrent).to eq(2)

          ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = '0'
          expect { AuthModel.session_idle_timeout }.to raise_error(ArgumentError, /positive integer/)
          ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = 'forever'
          expect { AuthModel.session_idle_timeout }.to raise_error(ArgumentError, /positive integer/)
          ENV['OPENC3_SESSION_IDLE_TIMEOUT'] = ''
          expect(AuthModel.session_idle_timeout).to eq(AuthModel::DEFAULT_SESSION_IDLE_TIMEOUT)
        ensure
          ENV.delete('OPENC3_SESSION_IDLE_TIMEOUT')
          ENV.delete('OPENC3_SESSION_MAX_AGE')
          ENV.delete('OPENC3_SESSION_MAX_CONCURRENT')
        end

        it "terminates a session left idle past the idle timeout" do
          token = AuthModel.generate_session
          expect(AuthModel.verify(token)).to eq(true)

          advance(AuthModel.session_idle_timeout + 1)
          expect(AuthModel.verify(token)).to eq(false)
          # Removed from Redis, not just rejected
          expect(@redis.hexists(AuthModel::SESSIONS_KEY, AuthModel.session_digest(token))).to eq(false)
        end

        it "keeps a session alive while it is being used" do
          token = AuthModel.generate_session
          step = AuthModel.session_idle_timeout - 60
          5.times do
            advance(step)
            expect(AuthModel.verify(token)).to eq(true)
          end
          # Now go quiet
          advance(AuthModel.session_idle_timeout + 1)
          expect(AuthModel.verify(token)).to eq(false)
        end

        it "terminates a continuously used session once it reaches the maximum age" do
          start = @now
          token = AuthModel.generate_session
          step = AuthModel.session_idle_timeout - 60
          # Keep using it right up to (but not past) the maximum age
          while (@now + step - start) < AuthModel.session_max_age
            advance(step)
            expect(AuthModel.verify(token)).to eq(true)
          end
          advance(step)
          expect(AuthModel.verify(token)).to eq(false)
        end

        it "evicts the least recently used session past the concurrent session cap" do
          max = AuthModel.session_max_concurrent
          tokens = Array.new(max) { AuthModel.generate_session }
          tokens.each { |t| expect(AuthModel.verify(t)).to eq(true) }

          # Use the oldest token so it is no longer the least recently used
          advance(AuthModel::SESSION_CACHE_TIMEOUT + 1)
          expect(AuthModel.verify(tokens[0])).to eq(true)

          advance(AuthModel::SESSION_CACHE_TIMEOUT + 1)
          extra = AuthModel.generate_session
          expect(AuthModel.verify(extra)).to eq(true)
          expect(AuthModel.verify(tokens[0])).to eq(true)
          expect(AuthModel.verify(tokens[1])).to eq(false) # evicted
          tokens[2..].each { |t| expect(AuthModel.verify(t)).to eq(true) }
          expect(@redis.hlen(AuthModel::SESSIONS_KEY)).to eq(max)
        end

        it "does not count one-time tokens against the session cap" do
          max = AuthModel.session_max_concurrent
          tokens = Array.new(max) { AuthModel.generate_session }
          otp = AuthModel.generate_session(otp: true)
          tokens.each { |t| expect(AuthModel.verify(t)).to eq(true) }
          expect(AuthModel.verify(otp)).to eq(true)
        end

        it "expires an unused one-time token" do
          otp = AuthModel.generate_session(otp: true)
          advance(AuthModel.session_idle_timeout + 1)
          expect(AuthModel.verify(otp)).to eq(false)
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
