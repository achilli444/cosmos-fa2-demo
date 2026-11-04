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

require "spec_helper"
require "openc3/utilities/authorization"

module OpenC3
  describe Authorization do
    class AuthorizationHarness
      include Authorization

      public :authorize, :user_info
    end

    before(:each) do
      @redis = mock_redis()
      # Use the real AuthModel so identities come from stored sessions
      allow(OpenC3::AuthModel).to receive(:verify).and_call_original
      allow(OpenC3::AuthModel).to receive(:verify_no_service).and_call_original
      @saved_authorize = $openc3_authorize
      $openc3_authorize = true
      @saved_env = ENV.to_h.slice('OPENC3_SESSION_ROLE', 'OPENC3_SERVICE_ROLE', 'OPENC3_MICROSERVICE_NAME')
      ENV.delete('OPENC3_SESSION_ROLE')
      ENV.delete('OPENC3_SERVICE_ROLE')
      ENV.delete('OPENC3_MICROSERVICE_NAME')
      @api = AuthorizationHarness.new
      @session = AuthModel.generate_session(user: Authorization.session_user)
      @service_session = AuthModel.generate_session(user: Authorization.session_user(service: true))
    end

    after(:each) do
      $openc3_authorize = @saved_authorize
      %w(OPENC3_SESSION_ROLE OPENC3_SERVICE_ROLE OPENC3_MICROSERVICE_NAME).each do |name|
        if @saved_env.key?(name)
          ENV[name] = @saved_env[name]
        else
          ENV.delete(name)
        end
      end
    end

    describe "authorize" do
      it "requires a scope" do
        expect { @api.authorize(permission: 'tlm', token: @session) }.to raise_error(AuthError, /Scope is required/)
      end

      it "requires a token" do
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: nil) }.to raise_error(AuthError, /Token is required/)
      end

      it "rejects an invalid token" do
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: 'ses_bogus') }.to raise_error(AuthError, /Token is invalid/)
      end

      it "fails closed on a missing or unknown permission" do
        expect { @api.authorize(scope: 'DEFAULT', token: @session) }.to raise_error(ForbiddenError, /Permission is required/)
        expect { @api.authorize(permission: 'launch', scope: 'DEFAULT', token: @session) }.to raise_error(ForbiddenError, /Unknown permission 'launch'/)
      end

      it "returns the user hash for a login session with every permission by default" do
        user = @api.authorize(permission: 'cmd', target_name: 'INST', packet_name: 'ABORT', scope: 'DEFAULT', token: @session)
        expect(user).to be_a(Hash)
        expect(user['username']).to match(/\Aoperator-[0-9a-f]{8}\z/)
        expect(user['roles']).to eq(['admin'])
        expect(user['permissions']).to include('cmd', 'cmd_raw', 'tlm_set', 'admin')
      end

      it "keeps the same identity across requests in one session" do
        first = @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: @session)
        second = @api.authorize(permission: 'cmd', scope: 'DEFAULT', token: @session)
        expect(second['username']).to eq(first['username'])
        other = AuthModel.generate_session(user: Authorization.session_user)
        expect(@api.authorize(permission: 'tlm', scope: 'DEFAULT', token: other)['username']).to_not eq(first['username'])
      end

      it "enforces OPENC3_SESSION_ROLE on login sessions" do
        ENV['OPENC3_SESSION_ROLE'] = 'viewer'
        expect(@api.authorize(permission: 'tlm', scope: 'DEFAULT', token: @session)['roles']).to eq(['viewer'])
        %w(cmd cmd_raw tlm_set script_run admin).each do |permission|
          expect { @api.authorize(permission: permission, target_name: 'INST', scope: 'DEFAULT', token: @session) }.to raise_error(ForbiddenError, /does not have permission '#{permission}' for INST/)
        end
      end

      it "enforces OPENC3_SERVICE_ROLE on the service password and service sessions" do
        ENV['OPENC3_SERVICE_ROLE'] = 'runner'
        ENV['OPENC3_SESSION_ROLE'] = 'viewer'
        user = @api.authorize(permission: 'cmd', scope: 'DEFAULT', token: ENV['OPENC3_SERVICE_PASSWORD'])
        expect(user['username']).to eq('service')
        expect(user['roles']).to eq(['runner'])
        expect { @api.authorize(permission: 'admin', scope: 'DEFAULT', token: ENV['OPENC3_SERVICE_PASSWORD']) }.to raise_error(ForbiddenError)

        user = @api.authorize(permission: 'cmd', scope: 'DEFAULT', token: @service_session)
        expect(user['username']).to match(/\Aservice-[0-9a-f]{8}\z/)
        expect(user['roles']).to eq(['runner'])
        expect { @api.authorize(permission: 'script_edit', scope: 'DEFAULT', token: @service_session) }.to raise_error(ForbiddenError)
      end

      it "rejects an unknown role rather than granting access" do
        ENV['OPENC3_SESSION_ROLE'] = 'superuser'
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: @session) }.to raise_error(AuthError, /OPENC3_SESSION_ROLE 'superuser'/)
      end

      it "attributes a one-time token to the session that created it and consumes it" do
        user = @api.authorize(permission: 'system', scope: 'DEFAULT', token: @session)
        otp = Authorization.generate_otp(user)
        otp_user = @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: otp)
        expect(otp_user['username']).to eq(user['username'])
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: otp) }.to raise_error(AuthError, /Token is invalid/)
      end

      it "rejects an OTP request without an identity" do
        expect { Authorization.generate_otp('anonymous') }.to raise_error(AuthError, /Invalid OTP user/)
      end

      it "attributes trusted in-process callers to the microservice" do
        $openc3_authorize = false
        ENV['OPENC3_MICROSERVICE_NAME'] = 'DEFAULT__DECOM__INST'
        user = @api.authorize(permission: 'cmd', scope: 'DEFAULT', token: nil)
        expect(user['username']).to eq('DEFAULT__DECOM__INST')
        expect(user['roles']).to eq(['admin'])
        expect { @api.authorize(permission: 'bogus', scope: 'DEFAULT') }.to raise_error(ForbiddenError)
      end
    end

    describe "user_info" do
      it "returns the session identity without consuming a one-time token" do
        expect(@api.user_info(@session)['username']).to match(/\Aoperator-[0-9a-f]{8}\z/)
        otp = Authorization.generate_otp(@api.user_info(@session))
        expect(@api.user_info(otp)['username']).to eq(@api.user_info(@session)['username'])
        expect(AuthModel.verify(otp)).to eq(true)
      end

      it "returns an empty hash for a missing token and anonymous for an unknown one" do
        expect(@api.user_info(nil)).to eq({})
        expect(@api.user_info('ses_bogus')['username']).to eq('anonymous')
        expect(@api.user_info('ses_bogus')['permissions']).to eq([])
      end
    end
  end
end
