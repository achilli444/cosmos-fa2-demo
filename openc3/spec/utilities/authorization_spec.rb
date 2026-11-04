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

require 'spec_helper'
require 'openc3/utilities/authorization'

module OpenC3
  describe Authorization do
    class AuthorizationTest
      include Authorization

      public :authorize, :user_info
    end

    before(:each) do
      mock_redis()
      @auth = AuthorizationTest.new
      @token = AuthModel.generate_session()
    end

    describe "AuthModel.session_id" do
      it "is stable for a token and never reveals it" do
        id = AuthModel.session_id(@token)
        expect(id).to match(/\A\h{12}\z/)
        expect(AuthModel.session_id(@token)).to eql id
        expect(@token).not_to include(id)
        expect(id).not_to include(@token[4, 8])
      end

      it "is different for different tokens" do
        expect(AuthModel.session_id(@token)).not_to eql AuthModel.session_id(AuthModel.generate_session())
      end

      it "is nil without a token" do
        expect(AuthModel.session_id(nil)).to be_nil
        expect(AuthModel.session_id('')).to be_nil
      end
    end

    describe "user_info" do
      it "tags the anonymous user with the session id" do
        info = @auth.user_info(@token)
        expect(info['session']).to eql AuthModel.session_id(@token)
        expect(info['username']).to eql "anonymous@#{info['session']}"
        expect(info['username']).not_to include(@token)
      end

      it "returns the same identity for every call with the same token" do
        expect(@auth.user_info(@token)).to eql @auth.user_info(@token)
      end

      it "is explicitly anonymous with no token" do
        expect(@auth.user_info(nil)).to eql({ 'username' => 'anonymous', 'session' => nil })
      end

      it "names the service user without hashing the service password" do
        info = @auth.user_info(ENV['OPENC3_SERVICE_PASSWORD'])
        expect(info).to eql({ 'username' => 'service', 'session' => nil })
      end

      it "does not treat a prefix of the service password as the service" do
        info = @auth.user_info(ENV['OPENC3_SERVICE_PASSWORD'][0..-2])
        expect(info['username']).to start_with('anonymous@')
      end
    end

    describe "authorize" do
      it "returns the caller identity" do
        user = @auth.authorize(permission: 'cmd', scope: 'DEFAULT', token: @token)
        expect(user).to eql @auth.user_info(@token)
        expect(user['username']).to match(/\Aanonymous@\h{12}\z/)
      end

      it "requires a scope" do
        expect { @auth.authorize(permission: 'cmd', token: @token) }.to raise_error(AuthError, "Scope is required")
      end

      context "with authorization enabled" do
        before(:each) { $openc3_authorize = true }
        after(:each) { $openc3_authorize = false }

        it "requires a token" do
          expect { @auth.authorize(permission: 'cmd', scope: 'DEFAULT') }.to raise_error(AuthError, "Token is required")
        end

        it "returns the identity for a valid token" do
          user = @auth.authorize(permission: 'cmd', scope: 'DEFAULT', token: @token)
          expect(user['session']).to eql AuthModel.session_id(@token)
        end
      end
    end

    describe "generate_otp" do
      it "accepts the user hash returned by authorize" do
        user = @auth.authorize(permission: 'system', scope: 'DEFAULT', token: @token)
        otp = Authorization.generate_otp(user)
        expect(otp).to start_with(AuthModel::OTP_PREFIX)
      end

      it "accepts the bare anonymous username" do
        expect(Authorization.generate_otp('anonymous')).to start_with(AuthModel::OTP_PREFIX)
      end

      it "rejects other users" do
        expect { Authorization.generate_otp({ 'username' => 'mallory' }) }.to raise_error(AuthError, "Invalid OTP user")
        expect { Authorization.generate_otp(nil) }.to raise_error(AuthError, "Invalid OTP user")
      end
    end
  end
end
