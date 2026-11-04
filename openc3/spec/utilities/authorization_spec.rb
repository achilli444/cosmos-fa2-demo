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
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/utilities/authorization'

module OpenC3
  describe Authorization do
    # The Core role matrix is only used when Enterprise is not installed
    next if defined?(OPENC3_ENTERPRISE_VERSION)

    class AuthorizationHarness
      include Authorization
      def check(**kwargs)
        authorize(**kwargs)
      end
      def info(token)
        user_info(token)
      end
    end

    before(:each) do
      mock_redis()
      allow(AuthModel).to receive(:verify).and_call_original
      allow(AuthModel).to receive(:verify_no_service).and_call_original
      @harness = AuthorizationHarness.new
      @authorize = $openc3_authorize
      $openc3_authorize = true
    end

    after(:each) do
      $openc3_authorize = @authorize
    end

    def session(roles)
      AuthModel.generate_session(username: "user_#{roles.join('_')}", roles: roles)
    end

    describe "role matrix" do
      it "grants admin the admin permissions but not cmd" do
        expect(Authorization.permitted?(['admin'], 'admin')).to be true
        expect(Authorization.permitted?(['admin'], 'system_set')).to be true
        expect(Authorization.permitted?(['admin'], 'cmd')).to be false
      end

      it "grants operator cmd and script_edit but not admin or script_approver" do
        expect(Authorization.permitted?(['operator'], 'cmd')).to be true
        expect(Authorization.permitted?(['operator'], 'script_edit')).to be true
        expect(Authorization.permitted?(['operator'], 'admin')).to be false
        expect(Authorization.permitted?(['operator'], 'script_approver')).to be false
      end

      it "grants viewer read only permissions" do
        expect(Authorization.permissions_for(['viewer'])).to contain_exactly('system', 'tlm', 'cmd_info', 'script_view')
      end

      it "grants approver script_approver" do
        expect(Authorization.permitted?(['approver'], 'script_approver')).to be true
        expect(Authorization.permitted?(['approver'], 'system')).to be false
      end

      it "ignores unknown roles" do
        expect(Authorization.permissions_for(['bogus'])).to eq([])
      end
    end

    describe "authorize" do
      it "requires a scope" do
        expect { @harness.check(permission: 'system', token: $openc3_token) }.to raise_error(AuthError, /Scope is required/)
      end

      it "requires a token" do
        expect { @harness.check(permission: 'system', scope: 'DEFAULT') }.to raise_error(AuthError, /Token is required/)
      end

      it "rejects an invalid token" do
        expect { @harness.check(permission: 'system', scope: 'DEFAULT', token: 'ses_bogus') }.to raise_error(AuthError, /Token is invalid/)
      end

      it "returns the built-in admin principal for the shared password session" do
        user = @harness.check(permission: 'admin', scope: 'DEFAULT', token: $openc3_token)
        expect(user['username']).to eq(AuthModel::BUILTIN_ADMIN_USERNAME)
        expect(user['roles']).to eq(AuthModel::BUILTIN_ADMIN_ROLES)
        # The shared password retains every permission it had before roles existed
        %w(system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_edit script_run script_approver admin superadmin).each do |permission|
          expect { @harness.check(permission: permission, scope: 'DEFAULT', token: $openc3_token) }.not_to raise_error
        end
      end

      it "treats a legacy timestamp session as the built-in admin" do
        token = "#{AuthModel::SESSION_PREFIX}#{'A' * 22}"
        Store.hset(AuthModel::SESSIONS_KEY, token, Time.now.iso8601)
        user = @harness.check(permission: 'admin', scope: 'DEFAULT', token: token)
        expect(user['username']).to eq(AuthModel::BUILTIN_ADMIN_USERNAME)
      end

      it "returns the service principal for the service password" do
        ENV['OPENC3_SERVICE_PASSWORD'] = 'openc3service_spec'
        user = @harness.check(permission: 'cmd', target_name: 'INST', scope: 'DEFAULT', token: 'openc3service_spec')
        expect(user['username']).to eq(AuthModel::SERVICE_USERNAME)
      ensure
        ENV.delete('OPENC3_SERVICE_PASSWORD')
      end

      it "raises ForbiddenError when the principal lacks the permission" do
        token = session(['viewer'])
        expect(@harness.check(permission: 'tlm', scope: 'DEFAULT', token: token)['username']).to eq('user_viewer')
        expect { @harness.check(permission: 'cmd', target_name: 'INST', packet_name: 'ABORT', scope: 'DEFAULT', token: token) }.to \
          raise_error(ForbiddenError, /'user_viewer'.*not permitted 'cmd' on INST ABORT/)
        expect { @harness.check(permission: 'admin', scope: 'DEFAULT', token: token) }.to raise_error(ForbiddenError)
        expect { @harness.check(permission: 'system_set', interface_name: 'INST_INT', scope: 'DEFAULT', token: token) }.to \
          raise_error(ForbiddenError, /INST_INT/)
      end

      it "denies operator the admin and approver permissions" do
        token = session(['operator'])
        expect { @harness.check(permission: 'cmd', scope: 'DEFAULT', token: token) }.not_to raise_error
        expect { @harness.check(permission: 'admin', scope: 'DEFAULT', token: token) }.to raise_error(ForbiddenError)
        expect { @harness.check(permission: 'script_approver', scope: 'DEFAULT', token: token) }.to raise_error(ForbiddenError)
      end

      it "denies admin the cmd permission" do
        token = session(['admin'])
        expect { @harness.check(permission: 'admin', scope: 'DEFAULT', token: token) }.not_to raise_error
        expect { @harness.check(permission: 'cmd', scope: 'DEFAULT', token: token) }.to raise_error(ForbiddenError)
      end

      it "combines permissions across roles" do
        token = session(['viewer', 'approver'])
        expect { @harness.check(permission: 'script_approver', scope: 'DEFAULT', token: token) }.not_to raise_error
        expect { @harness.check(permission: 'tlm', scope: 'DEFAULT', token: token) }.not_to raise_error
        expect { @harness.check(permission: 'cmd', scope: 'DEFAULT', token: token) }.to raise_error(ForbiddenError)
      end

      it "only authenticates when no permission is requested" do
        token = session(['viewer'])
        expect(@harness.check(scope: 'DEFAULT', token: token)['username']).to eq('user_viewer')
      end

      it "skips enforcement for in-process callers when $openc3_authorize is not set" do
        $openc3_authorize = nil
        expect(@harness.check(permission: 'admin', scope: 'DEFAULT')).to eq(Authorization::ANONYMOUS_USER)
      end
    end

    describe "user_info" do
      it "returns the principal for a token" do
        token = session(['viewer'])
        expect(@harness.info(token)).to eq({ 'username' => 'user_viewer', 'roles' => ['viewer'] })
        expect(@harness.info('ses_bogus')).to eq({})
        expect(@harness.info(nil)).to eq({})
      end
    end

    describe "generate_otp" do
      it "issues a one time token carrying the user's roles" do
        otp = Authorization.generate_otp({ 'username' => 'user_viewer', 'roles' => ['viewer'] })
        expect(otp).to start_with(AuthModel::OTP_PREFIX)
        user = @harness.check(permission: 'tlm', scope: 'DEFAULT', token: otp)
        expect(user['roles']).to eq(['viewer'])
        expect { @harness.check(permission: 'tlm', scope: 'DEFAULT', token: otp) }.to raise_error(AuthError)
      end

      it "rejects an unknown user" do
        expect { Authorization.generate_otp(nil) }.to raise_error(AuthError, /Invalid OTP user/)
      end
    end
  end
end
