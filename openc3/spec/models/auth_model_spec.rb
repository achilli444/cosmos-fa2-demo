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

      it "only accepts the service password when service_only is requested" do
        service_password = ENV['OPENC3_SERVICE_PASSWORD']
        expect(service_password).not_to be_nil

        # /auth/verify_service exchanges it for a session
        expect(AuthModel.verify(service_password, service_only: true)).to eq(true)
        expect(AuthModel.verify('badpassword', service_only: true)).to eq(false)
        expect(AuthModel.verify(nil, service_only: true)).to eq(false)
        expect(AuthModel.verify('', service_only: true)).to eq(false)

        # but it is never a bearer token on the generic authorize path,
        # with or without the password mode, and never a user password
        expect(AuthModel.verify(service_password)).to eq(false)
        expect(AuthModel.verify(service_password, no_password: true)).to eq(false)
        expect(AuthModel.verify(service_password, no_password: false)).to eq(false)
        expect(AuthModel.verify_no_service(service_password, mode: :any)).to eq(false)

        # and service_only never falls through to a user password or session
        token = AuthModel.generate_session
        expect(AuthModel.verify(token, service_only: true)).to eq(false)
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD, service_only: true)).to eq(false)
      end

      it "rejects the service password when none is configured" do
        allow(ENV).to receive(:fetch).and_call_original
        allow(ENV).to receive(:fetch).with('OPENC3_SERVICE_PASSWORD', nil).and_return(nil)
        expect(AuthModel.verify('openc3service', service_only: true)).to eq(false)
        allow(ENV).to receive(:fetch).with('OPENC3_SERVICE_PASSWORD', nil).and_return('')
        expect(AuthModel.verify('', service_only: true)).to eq(false)
      end

      it "compares the service password in constant time" do
        service_password = ENV['OPENC3_SERVICE_PASSWORD']
        allow(OpenSSL).to receive(:secure_compare).and_call_original
        expect(AuthModel.verify_service_password('guess')).to eq(false)
        expect(OpenSSL).to have_received(:secure_compare).with(service_password, 'guess')
        # A prefix of the real password must not short circuit to true
        expect(AuthModel.verify_service_password(service_password[0..-2])).to eq(false)
        expect(AuthModel.verify_service_password(service_password + 'x')).to eq(false)
      end

      it "raises when stored password hash is SHA256" do
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end
  end
end
