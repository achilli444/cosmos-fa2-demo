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

    describe "identities" do
      it "verify_user binds the built-in password to admin" do
        identity = AuthModel.verify_user(nil, AUTH_INITIAL_PASSWORD)
        expect(identity['username']).to eq('admin')
        expect(identity['roles']).to eq(['admin'])
        expect(AuthModel.verify_user('', AUTH_INITIAL_PASSWORD)['username']).to eq('admin')
        expect(AuthModel.verify_user('admin', AUTH_INITIAL_PASSWORD)['username']).to eq('admin')
        expect(AuthModel.verify_user('admin', 'bad')).to be_nil
        expect(AuthModel.verify_user('nobody', AUTH_INITIAL_PASSWORD)).to be_nil
        expect(AuthModel.verify_user('admin', nil)).to be_nil
      end

      it "manages named users with roles" do
        expect { AuthModel.set_user(username: 'ops', roles: ['operator']) }.to raise_error(/password is required/)
        expect { AuthModel.set_user(username: 'ops', password: 'short', roles: ['operator']) }.to raise_error(/at least 8/)
        expect { AuthModel.set_user(username: 'ops', password: 'operatorpass', roles: ['service']) }.to raise_error(/invalid roles/)
        expect { AuthModel.set_user(username: 'ops', password: 'operatorpass', roles: []) }.to raise_error(/at least one role/)
        expect { AuthModel.set_user(username: 'bad user', password: 'operatorpass', roles: ['viewer']) }.to raise_error(/username must match/)
        expect { AuthModel.set_user(username: 'admin', password: 'operatorpass', roles: ['viewer']) }.to raise_error(/built-in/)

        AuthModel.set_user(username: 'ops', password: 'operatorpass', roles: ['operator'], name: 'Ops Person')
        identity = AuthModel.verify_user('ops', 'operatorpass')
        expect(identity).to eq({ 'username' => 'ops', 'name' => 'Ops Person', 'roles' => ['operator'] })
        expect(AuthModel.verify_user('ops', 'bad')).to be_nil
        # Named user passwords are never valid as the admin password
        expect(AuthModel.verify_user(nil, 'operatorpass')).to be_nil
        expect(AuthModel.user_roles('ops')).to eq(['operator'])
        expect(AuthModel.user_roles('admin')).to eq(['admin'])
        expect(AuthModel.user_roles('nobody')).to be_nil

        users = AuthModel.users
        expect(users.map { |u| u['username'] }).to contain_exactly('admin', 'ops')
        expect(users.none? { |u| u.key?('password_hash') }).to be true

        # Update roles without changing the password
        AuthModel.set_user(username: 'ops', roles: ['viewer'])
        expect(AuthModel.verify_user('ops', 'operatorpass')['roles']).to eq(['viewer'])

        expect { AuthModel.delete_user('admin') }.to raise_error(/built-in/)
        AuthModel.delete_user('ops')
        expect(AuthModel.verify_user('ops', 'operatorpass')).to be_nil
      end

      it "binds sessions to an identity" do
        AuthModel.set_user(username: 'ops', password: 'operatorpass', roles: ['operator'])
        token = AuthModel.generate_session(username: 'ops', roles: ['operator'], name: 'Ops')
        expect(AuthModel.verify(token)).to eq(true)
        expect(AuthModel.identity(token)).to eq({ 'username' => 'ops', 'name' => 'Ops', 'roles' => ['operator'] })
        expect(AuthModel.identity('ses_bogus')).to be_nil
        expect(AuthModel.identity(nil)).to be_nil
        # Passwords never resolve to an identity, only sessions do
        expect(AuthModel.identity(AUTH_INITIAL_PASSWORD)).to be_nil
        # Default session is the built-in admin
        expect(AuthModel.identity(AuthModel.generate_session)['username']).to eq('admin')
        # Sessions created before identities were bound map to admin
        Store.hset(AuthModel::SESSIONS_KEY, 'ses_legacy', Time.now.iso8601)
        expect(AuthModel.identity('ses_legacy')).to eq({ 'username' => 'admin', 'name' => 'admin', 'roles' => ['admin'] })
      end

      it "terminates a user's sessions when the user changes" do
        AuthModel.set_user(username: 'ops', password: 'operatorpass', roles: ['operator'])
        ops_token = AuthModel.generate_session(username: 'ops', roles: ['operator'])
        admin_token = AuthModel.generate_session
        expect(AuthModel.verify(ops_token)).to eq(true)
        AuthModel.set_user(username: 'ops', roles: ['viewer'])
        expect(AuthModel.verify(ops_token)).to eq(false)
        expect(AuthModel.verify(admin_token)).to eq(true)

        ops_token = AuthModel.generate_session(username: 'ops', roles: ['viewer'])
        AuthModel.delete_user('ops')
        expect(AuthModel.verify(ops_token)).to eq(false)
        expect(AuthModel.verify(admin_token)).to eq(true)
      end

      it "binds the service password to a service identity" do
        ENV['OPENC3_SERVICE_PASSWORD'] = 'servicepass'
        identity = AuthModel.identity('servicepass')
        expect(identity['roles']).to eq(['service'])
        expect(identity['service']).to be true
      ensure
        ENV.delete('OPENC3_SERVICE_PASSWORD')
      end
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
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end
  end
end
