# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software; you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/utilities/authorization'
require 'openc3/models/auth_model'

module OpenC3
  describe Authorization do
    class AuthorizationTest
      include Authorization

      def call_authorize(**kwargs)
        authorize(**kwargs)
      end

      def call_user_info(token)
        user_info(token)
      end
    end

    before(:each) do
      mock_redis()
      @auth = AuthorizationTest.new
      @saved_microservice_name = ENV['OPENC3_MICROSERVICE_NAME']
    end

    after(:each) do
      if @saved_microservice_name
        ENV['OPENC3_MICROSERVICE_NAME'] = @saved_microservice_name
      else
        ENV.delete('OPENC3_MICROSERVICE_NAME')
      end
    end

    describe "user_from_token" do
      it "returns an empty hash without a token" do
        expect(Authorization.user_from_token(nil)).to eql({})
        expect(Authorization.user_from_token('')).to eql({})
      end

      it "identifies a login session without exposing the session token" do
        token = AuthModel.generate_session()
        user = Authorization.user_from_token(token)
        expect(user['username']).to match(/\Aanonymous:[0-9a-f]{12}\z/)
        expect(user['session']).to eql user['username'].split(':')[1]
        expect(user['session']).to eql AuthModel.session_id(token)
        expect(user.to_s).not_to include(token.delete_prefix(AuthModel::SESSION_PREFIX))
        # Stable for the life of the session
        expect(Authorization.user_from_token(token)).to eql user
      end

      it "distinguishes two login sessions" do
        user1 = Authorization.user_from_token(AuthModel.generate_session())
        user2 = Authorization.user_from_token(AuthModel.generate_session())
        expect(user1['username']).not_to eql user2['username']
      end

      it "identifies one time password tokens as a session" do
        user = Authorization.user_from_token(AuthModel.generate_session(otp: true))
        expect(user['username']).to match(/\Aanonymous:[0-9a-f]{12}\z/)
      end

      it "identifies the service password as the calling microservice" do
        ENV['OPENC3_MICROSERVICE_NAME'] = 'DEFAULT__INTERFACE__INST_INT'
        user = Authorization.user_from_token(ENV['OPENC3_SERVICE_PASSWORD'])
        expect(user['username']).to eql 'DEFAULT__INTERFACE__INST_INT'
        expect(user['service']).to be true

        ENV.delete('OPENC3_MICROSERVICE_NAME')
        user = Authorization.user_from_token(ENV['OPENC3_SERVICE_PASSWORD'])
        expect(user['username']).to eql 'service'
      end

      it "falls back to anonymous for tokens that are not sessions" do
        user = Authorization.user_from_token('not_a_session')
        expect(user).to eql({ 'username' => 'anonymous' })
      end
    end

    describe "authorize" do
      it "requires a scope" do
        expect { @auth.call_authorize(permission: 'cmd', token: $openc3_token) }.to raise_error(AuthError, "Scope is required")
      end

      it "returns the user behind the token" do
        user = @auth.call_authorize(permission: 'cmd', scope: 'DEFAULT', token: $openc3_token)
        expect(user).to eql Authorization.user_from_token($openc3_token)
        expect(user['username']).to match(/\Aanonymous:[0-9a-f]{12}\z/)
        expect(@auth.call_user_info($openc3_token)).to eql user
      end

      it "returns nil for internal calls without a token" do
        expect(@auth.call_authorize(permission: 'cmd', scope: 'DEFAULT', token: nil)).to be_nil
      end

      context "with $openc3_authorize" do
        before(:each) { $openc3_authorize = true }
        after(:each) { $openc3_authorize = false }

        it "requires a token" do
          expect { @auth.call_authorize(permission: 'cmd', scope: 'DEFAULT') }.to raise_error(AuthError, "Token is required")
        end

        it "rejects an invalid token before identifying the user" do
          allow(AuthModel).to receive(:verify).and_return(false)
          expect { @auth.call_authorize(permission: 'cmd', scope: 'DEFAULT', token: 'ses_bogus') }.to raise_error(AuthError, "Token is invalid")
        end

        it "returns the user for a verified token" do
          expect(AuthModel).to receive(:verify).with($openc3_token).and_return(true)
          user = @auth.call_authorize(permission: 'cmd', scope: 'DEFAULT', token: $openc3_token)
          expect(user['username']).to match(/\Aanonymous:[0-9a-f]{12}\z/)
        end
      end
    end

    describe "audit_username" do
      it "uses the username from the user hash" do
        expect(Authorization.audit_username({ 'username' => 'operator1' })).to eql 'operator1'
      end

      it "falls back to the microservice name and then anonymous" do
        ENV['OPENC3_MICROSERVICE_NAME'] = 'DEFAULT__DECOM__INST_INT'
        expect(Authorization.audit_username(nil)).to eql 'DEFAULT__DECOM__INST_INT'
        expect(Authorization.audit_username({})).to eql 'DEFAULT__DECOM__INST_INT'
        ENV.delete('OPENC3_MICROSERVICE_NAME')
        expect(Authorization.audit_username(nil)).to eql 'anonymous'
        expect(Authorization.audit_username({ 'username' => '' })).to eql 'anonymous'
      end
    end

    describe "generate_otp" do
      it "accepts the user hash returned by authorize" do
        user = @auth.call_authorize(permission: 'system', scope: 'DEFAULT', token: $openc3_token)
        expect(Authorization.generate_otp(user)).to start_with(AuthModel::OTP_PREFIX)
      end

      it "accepts the legacy anonymous string" do
        expect(Authorization.generate_otp('anonymous')).to start_with(AuthModel::OTP_PREFIX)
      end

      it "rejects other users" do
        expect { Authorization.generate_otp({ 'username' => 'service' }) }.to raise_error(AuthError, "Invalid OTP user")
        expect { Authorization.generate_otp(nil) }.to raise_error(AuthError, "Invalid OTP user")
      end
    end
  end
end
