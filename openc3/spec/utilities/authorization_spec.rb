# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software: you can modify and/or redistribute it
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
  # Only exercises the Core fallback module (Enterprise replaces it)
  describe Authorization do
    class AuthorizationTester
      include Authorization

      public :authorize, :user_info
    end

    before(:each) do
      mock_redis()
      allow(OpenC3::AuthModel).to receive(:verify).and_call_original
      allow(OpenC3::AuthModel).to receive(:verify_no_service).and_call_original
      @authorize = $openc3_authorize
      $openc3_authorize = true
      AuthModel.set_user(username: 'viewer1', password: 'viewerpass', roles: ['viewer'])
      AuthModel.set_user(username: 'operator1', password: 'operatorpass', roles: ['operator'])
      @admin_token = AuthModel.generate_session(**AuthModel.verify_user(nil, $openc3_password).slice('username', 'roles', 'name').transform_keys(&:to_sym))
      @viewer_token = AuthModel.generate_session(**AuthModel.verify_user('viewer1', 'viewerpass').slice('username', 'roles', 'name').transform_keys(&:to_sym))
      @operator_token = AuthModel.generate_session(**AuthModel.verify_user('operator1', 'operatorpass').slice('username', 'roles', 'name').transform_keys(&:to_sym))
      @tester = AuthorizationTester.new
    end

    after(:each) do
      $openc3_authorize = @authorize
    end

    describe "authorize" do
      it "requires a scope" do
        expect { @tester.authorize(permission: 'tlm', token: @admin_token) }.to raise_error(AuthError, /Scope is required/)
      end

      it "requires a token" do
        expect { @tester.authorize(permission: 'tlm', scope: 'DEFAULT') }.to raise_error(AuthError, /Token is required/)
      end

      it "rejects an invalid token" do
        expect { @tester.authorize(permission: 'tlm', scope: 'DEFAULT', token: 'ses_bogus') }.to raise_error(AuthError, /Token is invalid/)
      end

      it "rejects a raw password as a token" do
        expect { @tester.authorize(permission: 'tlm', scope: 'DEFAULT', token: $openc3_password) }.to raise_error(AuthError, /Token is invalid/)
      end

      it "returns the bound identity for a permitted request" do
        user = @tester.authorize(permission: 'cmd', target_name: 'INST', packet_name: 'ABORT', scope: 'DEFAULT', token: @operator_token)
        expect(user['username']).to eq('operator1')
        expect(user['roles']).to eq(['operator'])
      end

      it "forbids a permission the role does not grant" do
        expect(@tester.authorize(permission: 'tlm', scope: 'DEFAULT', token: @viewer_token)['username']).to eq('viewer1')
        expect { @tester.authorize(permission: 'cmd', target_name: 'INST', packet_name: 'ABORT', scope: 'DEFAULT', token: @viewer_token) }.to raise_error(ForbiddenError, /viewer1.*not permitted 'cmd' on INST ABORT/)
        expect { @tester.authorize(permission: 'script_run', scope: 'DEFAULT', token: @viewer_token) }.to raise_error(ForbiddenError)
        expect { @tester.authorize(permission: 'admin', scope: 'DEFAULT', token: @viewer_token) }.to raise_error(ForbiddenError)
        expect { @tester.authorize(permission: 'admin', scope: 'DEFAULT', token: @operator_token) }.to raise_error(ForbiddenError)
        expect { @tester.authorize(permission: 'script_approver', scope: 'DEFAULT', token: @operator_token) }.to raise_error(ForbiddenError)
      end

      it "denies unknown permissions to everyone but admin" do
        expect { @tester.authorize(permission: 'something_new', scope: 'DEFAULT', token: @operator_token) }.to raise_error(ForbiddenError)
        expect(@tester.authorize(permission: 'something_new', scope: 'DEFAULT', token: @admin_token)['username']).to eq('admin')
      end

      it "grants admin everything" do
        %w[system tlm cmd cmd_raw tlm_set script_view script_run script_edit script_approver admin system_set superadmin].each do |permission|
          expect(@tester.authorize(permission: permission, scope: 'DEFAULT', token: @admin_token)['username']).to eq('admin')
        end
      end

      it "binds the service password to a service identity" do
        ENV['OPENC3_SERVICE_PASSWORD'] = 'servicepass'
        ENV['OPENC3_MICROSERVICE_NAME'] = 'DEFAULT__QUEUE__TEST'
        user = @tester.authorize(permission: 'cmd', scope: 'DEFAULT', token: 'servicepass')
        expect(user['username']).to eq('DEFAULT__QUEUE__TEST')
        expect(user['roles']).to eq(['service'])
      ensure
        ENV.delete('OPENC3_SERVICE_PASSWORD')
        ENV.delete('OPENC3_MICROSERVICE_NAME')
      end

      it "maps legacy sessions without an identity to admin" do
        Store.hset(AuthModel::SESSIONS_KEY, 'ses_legacy', Time.now.iso8601)
        user = @tester.authorize(permission: 'admin', scope: 'DEFAULT', token: 'ses_legacy')
        expect(user['username']).to eq('admin')
      end

      it "stops honoring a session once the user's roles change" do
        expect(@tester.authorize(permission: 'cmd', scope: 'DEFAULT', token: @operator_token)['username']).to eq('operator1')
        AuthModel.set_user(username: 'operator1', roles: ['viewer'])
        expect { @tester.authorize(permission: 'cmd', scope: 'DEFAULT', token: @operator_token) }.to raise_error(AuthError, /Token is invalid/)
      end

      it "returns anonymous when authorization is disabled" do
        $openc3_authorize = false
        expect(@tester.authorize(permission: 'cmd', scope: 'DEFAULT')).to eq(Authorization::ANONYMOUS_USER)
      end
    end

    describe "user_info" do
      it "returns the identity bound to the token" do
        expect(@tester.user_info(@viewer_token)['username']).to eq('viewer1')
        expect(@tester.user_info(@admin_token)['username']).to eq('admin')
        expect(@tester.user_info('ses_bogus')).to eq({})
        expect(@tester.user_info(nil)).to eq({})
      end
    end

    describe "generate_otp" do
      it "binds the OTP to the requesting identity" do
        user = @tester.authorize(permission: 'system', scope: 'DEFAULT', token: @viewer_token)
        otp = Authorization.generate_otp(user)
        expect(otp).to start_with(AuthModel::OTP_PREFIX)
        expect(@tester.user_info(otp)['username']).to eq('viewer1')
        expect(@tester.user_info(otp)).to eq({}) # one time use
      end

      it "rejects garbage" do
        expect { Authorization.generate_otp(nil) }.to raise_error(AuthError)
        expect { Authorization.generate_otp('someone') }.to raise_error(AuthError)
      end
    end

    describe "user_permitted?" do
      it "re-checks a stored username against configured users" do
        expect(Authorization.user_permitted?('operator1', permission: 'cmd')).to be true
        expect(Authorization.user_permitted?('viewer1', permission: 'cmd')).to be false
        expect(Authorization.user_permitted?('admin', permission: 'cmd')).to be true
        expect(Authorization.user_permitted?('anonymous', permission: 'cmd')).to be false
        expect(Authorization.user_permitted?(nil, permission: 'cmd')).to be false
        AuthModel.delete_user('operator1')
        expect(Authorization.user_permitted?('operator1', permission: 'cmd')).to be false
      end
    end
  end
end
