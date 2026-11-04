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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

require 'spec_helper'
require 'openc3/utilities/authorization'

module OpenC3
  describe Authorization do
    class AuthorizationTester
      include Authorization

      public :authorize, :user_info
    end

    before(:each) do
      mock_redis()
      allow(OpenC3::AuthModel).to receive(:verify).and_call_original
      allow(OpenC3::AuthModel).to receive(:verify_no_service).and_call_original
      allow(OpenC3::AuthModel).to receive(:session_user).and_call_original
      @saved_authorize = $openc3_authorize
      $openc3_authorize = true
      @api = AuthorizationTester.new
      @admin_token = AuthModel.generate_session
      @viewer_token = AuthModel.generate_session(user: AuthModel.add_user('viewer1', 'password1', roles: ['viewer']))
      @op_token = AuthModel.generate_session(user: AuthModel.add_user('op1', 'password1', roles: ['operator'], targets: ['INST']))
    end

    after(:each) do
      $openc3_authorize = @saved_authorize
    end

    describe "authorize" do
      it "requires a scope and a valid token" do
        expect { @api.authorize(permission: 'tlm', token: @admin_token) }.to raise_error(AuthError, /Scope is required/)
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT') }.to raise_error(AuthError, /Token is required/)
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: 'ses_bogus') }.to raise_error(AuthError, /Token is invalid/)
      end

      it "returns the operator the token was issued to as a Hash" do
        user = @api.authorize(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT', token: @admin_token)
        expect(user).to be_a(Hash)
        expect(user['username']).to eq('admin')
        expect(user['roles']).to include('operator')
        user = @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: @viewer_token)
        expect(user['username']).to eq('viewer1')
      end

      it "enforces the requested permission" do
        expect { @api.authorize(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT', token: @viewer_token) }.to \
          raise_error(ForbiddenError, /viewer1.*cmd.*INST/)
        expect { @api.authorize(permission: 'cmd_raw', interface_name: 'INST_INT', target_name: 'INST', scope: 'DEFAULT', token: @viewer_token) }.to \
          raise_error(ForbiddenError, /cmd_raw.*via INST_INT/)
        expect { @api.authorize(permission: 'script_run', scope: 'DEFAULT', token: @viewer_token) }.to raise_error(ForbiddenError)
        expect { @api.authorize(permission: 'admin', scope: 'DEFAULT', token: @op_token) }.to raise_error(ForbiddenError)
      end

      it "enforces per-operator target allow lists for commanding" do
        expect(@api.authorize(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT', token: @op_token)['username']).to eq('op1')
        expect { @api.authorize(permission: 'cmd', target_name: 'INST2', scope: 'DEFAULT', token: @op_token) }.to raise_error(ForbiddenError, /INST2/)
        # Telemetry is not restricted by the command allow list
        expect(@api.authorize(permission: 'tlm', target_name: 'INST2', scope: 'DEFAULT', token: @op_token)['username']).to eq('op1')
      end

      it "fails closed for identity-less (legacy) sessions" do
        Store.hset(AuthModel::SESSIONS_KEY, 'ses_legacy', Time.now.iso8601)
        expect(AuthModel.verify('ses_legacy')).to eq(true)
        expect { @api.authorize(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT', token: 'ses_legacy') }.to raise_error(AuthError, /Token is invalid/)
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: 'ses_legacy') }.to raise_error(AuthError)
      end

      it "fails closed for sessions whose roles were revoked" do
        token = AuthModel.generate_session(user: { 'username' => 'ghost', 'roles' => [] })
        expect { @api.authorize(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT', token: token) }.to raise_error(AuthError, /no operator role/)
        expect { @api.authorize(permission: 'tlm', scope: 'DEFAULT', token: token) }.to raise_error(ForbiddenError)
      end

      it "accepts the service password as the service identity" do
        ENV['OPENC3_SERVICE_PASSWORD'] = 'servicepass'
        ENV['OPENC3_MICROSERVICE_NAME'] = 'DEFAULT__DECOM__INST'
        user = @api.authorize(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT', token: 'servicepass')
        expect(user['username']).to eq('DEFAULT__DECOM__INST')
        expect(user['roles']).to eq(['service'])
      ensure
        ENV.delete('OPENC3_SERVICE_PASSWORD')
        ENV.delete('OPENC3_MICROSERVICE_NAME')
      end

      it "attributes to the microservice when authorization is disabled" do
        $openc3_authorize = false
        ENV['OPENC3_MICROSERVICE_NAME'] = 'DEFAULT__INTERFACE__INST_INT'
        user = @api.authorize(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT')
        expect(user).to be_a(Hash)
        expect(user['username']).to eq('DEFAULT__INTERFACE__INST_INT')
      ensure
        ENV.delete('OPENC3_MICROSERVICE_NAME')
      end
    end

    describe "user_info" do
      it "returns the operator for a token and {} otherwise" do
        expect(@api.user_info(@viewer_token)['username']).to eq('viewer1')
        expect(@api.user_info('ses_bogus')).to eq({})
        expect(@api.user_info(nil)).to eq({})
      end
    end

    describe "generate_otp" do
      it "issues a one-time token bound to the user" do
        user = @api.authorize(permission: 'system', scope: 'DEFAULT', token: @viewer_token)
        otp = Authorization.generate_otp(user)
        expect(AuthModel.session_user(otp)['username']).to eq('viewer1')
        expect { Authorization.generate_otp('anonymous') }.to raise_error(AuthError, /Invalid OTP user/)
      end
    end
  end
end
