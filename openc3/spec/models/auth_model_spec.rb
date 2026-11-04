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
        # us pull every session ever created on every request. Nothing prunes
        # the sessions hash short of a logout, so it only grows.
        expect(Store).not_to receive(:hgetall)

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
        @redis.hdel(AuthModel::SESSIONS_KEY, token)
        expect(AuthModel.verify(token)).to eq(true)

        # Past SESSION_CACHE_TIMEOUT the cache is dropped and the token is gone.
        # Compute the future time before stubbing so Time.now isn't stubbed yet.
        future = Time.now + AuthModel::SESSION_CACHE_TIMEOUT + 1
        allow(Time).to receive(:now).and_return(future)
        expect(AuthModel.verify(token)).to eq(false)
      end

      it "raises when stored password hash is SHA256" do
        @redis.hset(AuthModel::USERS_KEY, AuthModel::LEGACY_USERNAME, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end
    describe "individual accounts" do
      it "treats the legacy password as the legacy account" do
        expect(AuthModel.users).to eq([AuthModel::LEGACY_USERNAME])
        expect(AuthModel.user?(AuthModel::LEGACY_USERNAME)).to be true
        expect(AuthModel.verify_user(AuthModel::LEGACY_USERNAME, AUTH_INITIAL_PASSWORD)).to be true
      end

      it "creates accounts with their own passwords" do
        AuthModel.set_user('alice', 'alicepass1')
        AuthModel.set_user('bob', 'bobpassword')
        expect(AuthModel.users).to eq([AuthModel::LEGACY_USERNAME, 'alice', 'bob'])
        expect(AuthModel.verify_user('alice', 'alicepass1')).to be true
        expect(AuthModel.verify_user('alice', 'bobpassword')).to be false
        expect(AuthModel.verify_user('bob', 'alicepass1')).to be false
        expect(AuthModel.verify_user('nobody', 'alicepass1')).to be false
        # The shared password is not accepted for an individual account
        expect(AuthModel.verify_user('alice', AUTH_INITIAL_PASSWORD)).to be false
      end

      it "rejects bad usernames and short passwords" do
        expect { AuthModel.set_user('a b', 'longenough') }.to raise_error(/username must be/)
        expect { AuthModel.set_user('', 'longenough') }.to raise_error(/username must not/)
        expect { AuthModel.set_user('alice', 'short') }.to raise_error(/at least/)
      end

      it "requires the old password to change an account and revokes only its sessions" do
        AuthModel.set_user('alice', 'alicepass1')
        alice = AuthModel.generate_session(username: 'alice')
        admin = AuthModel.generate_session(username: AuthModel::LEGACY_USERNAME)
        expect { AuthModel.set_user('alice', 'newalicepass') }.to raise_error(/old_password must not/)
        expect { AuthModel.set_user('alice', 'newalicepass', 'wrong') }.to raise_error(/old_password incorrect/)
        AuthModel.set_user('alice', 'newalicepass', 'alicepass1')
        expect(AuthModel.verify_user('alice', 'newalicepass')).to be true
        expect(AuthModel.verify(alice)).to be false
        expect(AuthModel.verify(admin)).to be true
      end

      it "deletes an account and its sessions but never the last one" do
        AuthModel.set_user('alice', 'alicepass1')
        alice = AuthModel.generate_session(username: 'alice')
        AuthModel.delete_user('alice')
        expect(AuthModel.user?('alice')).to be false
        expect(AuthModel.verify(alice)).to be false
        expect { AuthModel.delete_user(AuthModel::LEGACY_USERNAME) }.to raise_error(/last account/)
        expect { AuthModel.delete_user('ghost') }.to raise_error(/unknown user/)
      end

      it "binds sessions to the user that logged in" do
        token = AuthModel.generate_session(username: 'alice')
        expect(AuthModel.identity(token)).to eq({ 'username' => 'alice', 'service' => false })
        # Sessions created before accounts existed only stored a timestamp
        @redis.hset(AuthModel::SESSIONS_KEY, 'ses_old', Time.now.iso8601)
        expect(AuthModel.identity('ses_old')['username']).to eq('anonymous')
        expect(AuthModel.identity(nil)['username']).to eq('anonymous')
      end
    end

    describe "service tokens" do
      it "are accepted like sessions, carry the user and can be revoked" do
        token = AuthModel.generate_service_token(username: 'alice', purpose: 'script')
        expect(AuthModel.service_token?(token)).to be true
        expect(AuthModel.verify(token)).to be true
        expect(AuthModel.identity(token)).to eq({ 'username' => 'alice', 'service' => false })
        expect(@redis.ttl(AuthModel::SERVICE_TOKEN_KEY_PREFIX + token)).to be > 0
        AuthModel.terminate(token)
        expect(@redis.exists(AuthModel::SERVICE_TOKEN_KEY_PREFIX + token)).to eq(0)
        AuthModel.logout # drop caches
        expect(AuthModel.verify(token)).to be false
      end

      it "require a user" do
        expect { AuthModel.generate_service_token(username: nil, purpose: 'script') }.to raise_error(/username required/)
      end

      it "reject tokens that were never issued" do
        expect(AuthModel.verify('svc_' + 'A' * 43)).to be false
      end
    end

    describe "service password" do
      after(:each) { ENV.delete('OPENC3_SERVICE_PASSWORD') }

      it "is compared in constant time" do
        ENV['OPENC3_SERVICE_PASSWORD'] = 'a-unique-service-secret'
        expect(OpenSSL).to receive(:fixed_length_secure_compare).at_least(:once).and_call_original
        expect(AuthModel.verify('a-unique-service-secret', service_only: true)).to be true
        expect(AuthModel.verify('a-unique-service-secreX', service_only: true)).to be false
        expect(AuthModel.verify('short', service_only: true)).to be false
        expect(AuthModel.identity('a-unique-service-secret')).to eq({ 'username' => 'service', 'service' => true })
      end

      it "never accepts the insecure default shipped in .env" do
        ENV['OPENC3_SERVICE_PASSWORD'] = 'openc3service'
        expect(AuthModel.verify('openc3service', service_only: true)).to be false
        expect(AuthModel.verify('openc3service')).to be false
      end

      it "is not accepted when unset" do
        expect(AuthModel.verify(nil, service_only: true)).to be false
        expect(AuthModel.verify('', service_only: true)).to be false
      end
    end
  end
end
