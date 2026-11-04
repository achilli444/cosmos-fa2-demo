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

      it "resolves a session token to its principal" do
        expect(AuthModel.principal(nil)).to be_nil
        expect(AuthModel.principal('')).to be_nil
        expect(AuthModel.principal("#{AuthModel::SESSION_PREFIX}#{'A' * 22}")).to be_nil

        admin = AuthModel.principal(AuthModel.generate_session)
        expect(admin).to eq({ 'username' => AuthModel::BUILTIN_ADMIN_USERNAME, 'roles' => AuthModel::BUILTIN_ADMIN_ROLES })

        token = AuthModel.generate_session(username: 'alice', roles: ['viewer'])
        expect(AuthModel.principal(token)).to eq({ 'username' => 'alice', 'roles' => ['viewer'] })
        AuthModel.terminate(token)
        expect(AuthModel.principal(token)).to be_nil
      end

      it "consumes an OTP when resolving its principal" do
        otp = AuthModel.generate_session(otp: true, username: 'alice', roles: ['viewer'])
        expect(AuthModel.principal(otp)['username']).to eq('alice')
        expect(AuthModel.principal(otp)).to be_nil
      end

      it "resolves the service password to the service principal" do
        ENV['OPENC3_SERVICE_PASSWORD'] = 'servicepw_spec'
        expect(AuthModel.principal('servicepw_spec')).to eq({ 'username' => AuthModel::SERVICE_USERNAME, 'roles' => AuthModel::SERVICE_ROLES })
      ensure
        ENV.delete('OPENC3_SERVICE_PASSWORD')
      end

      it "treats a legacy timestamp session as the built-in admin" do
        token = "#{AuthModel::SESSION_PREFIX}#{'B' * 22}"
        @redis.hset(AuthModel::SESSIONS_KEY, token, Time.now.iso8601)
        expect(AuthModel.verify(token)).to eq(true)
        expect(AuthModel.principal(token)['username']).to eq(AuthModel::BUILTIN_ADMIN_USERNAME)
      end

      it "raises when stored password hash is SHA256" do
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end

    describe "named accounts" do
      it "creates, lists and authenticates a user without exposing the hash" do
        record = AuthModel.create_user(username: 'alice', password: 'alicepassword', roles: ['viewer'], name: 'Alice')
        expect(record['username']).to eq('alice')
        expect(record['roles']).to eq(['viewer'])
        expect(record['enabled']).to be true
        expect(record).not_to have_key('password_hash')
        expect(AuthModel.users['alice']).not_to have_key('password_hash')
        expect(AuthModel.user('alice')['password_hash']).to start_with('$argon2')

        expect(AuthModel.authenticate_user('alice', 'wrong')).to be_nil
        expect(AuthModel.authenticate_user('alice', '')).to be_nil
        expect(AuthModel.authenticate_user('nobody', 'alicepassword')).to be_nil
        principal = AuthModel.authenticate_user('alice', 'alicepassword')
        expect(principal).to eq({ 'username' => 'alice', 'roles' => ['viewer'] })
        expect(AuthModel.user('alice')['last_login']).not_to be_nil
      end

      it "rejects reserved and malformed usernames, duplicates and short passwords" do
        expect { AuthModel.create_user(username: 'admin', password: 'password1', roles: ['viewer']) }.to raise_error(/invalid username/)
        expect { AuthModel.create_user(username: 'service', password: 'password1', roles: ['viewer']) }.to raise_error(/invalid username/)
        expect { AuthModel.create_user(username: 'bad user', password: 'password1', roles: ['viewer']) }.to raise_error(/invalid username/)
        expect { AuthModel.create_user(username: 'alice', password: 'short', roles: ['viewer']) }.to raise_error(/at least 8/)
        AuthModel.create_user(username: 'alice', password: 'alicepassword', roles: ['viewer'])
        expect { AuthModel.create_user(username: 'alice', password: 'alicepassword', roles: ['viewer']) }.to raise_error(/already exists/)
      end

      it "terminates sessions when roles change, the account is disabled or deleted" do
        AuthModel.create_user(username: 'alice', password: 'alicepassword', roles: ['operator'])
        admin_token = AuthModel.generate_session
        token = AuthModel.generate_session(username: 'alice', roles: ['operator'])

        AuthModel.update_user('alice', roles: ['viewer'])
        expect(AuthModel.principal(token)).to be_nil
        expect(AuthModel.principal(admin_token)).not_to be_nil
        expect(AuthModel.authenticate_user('alice', 'alicepassword')['roles']).to eq(['viewer'])

        token = AuthModel.generate_session(username: 'alice', roles: ['viewer'])
        AuthModel.update_user('alice', enabled: false)
        expect(AuthModel.principal(token)).to be_nil
        expect(AuthModel.authenticate_user('alice', 'alicepassword')).to be_nil

        AuthModel.update_user('alice', enabled: true, password: 'newalicepassword')
        expect(AuthModel.authenticate_user('alice', 'alicepassword')).to be_nil
        expect(AuthModel.authenticate_user('alice', 'newalicepassword')).not_to be_nil

        token = AuthModel.generate_session(username: 'alice', roles: ['viewer'])
        AuthModel.delete_user('alice')
        expect(AuthModel.principal(token)).to be_nil
        expect(AuthModel.user('alice')).to be_nil
        expect { AuthModel.delete_user('alice') }.to raise_error(/user not found/)
        expect { AuthModel.update_user('alice', roles: ['viewer']) }.to raise_error(/user not found/)
      end

      it "disables an account that has been inactive past the limit" do
        AuthModel.create_user(username: 'alice', password: 'alicepassword', roles: ['viewer'])
        record = AuthModel.user('alice')
        stale = (Time.now - (AuthModel::USER_INACTIVITY_DAYS + 1) * 86400).iso8601
        record['created_at'] = record['updated_at'] = record['last_login'] = stale
        @redis.hset(AuthModel::USERS_KEY, 'alice', JSON.generate(record))

        expect(AuthModel.authenticate_user('alice', 'alicepassword')).to be_nil
        expect(AuthModel.user('alice')['enabled']).to be false

        # Re-enabling by an administrator restores access
        AuthModel.update_user('alice', enabled: true)
        expect(AuthModel.authenticate_user('alice', 'alicepassword')).not_to be_nil
      end
    end

  end
end
