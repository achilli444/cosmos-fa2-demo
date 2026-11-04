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
require 'openc3/models/auth_model'
require 'openc3/utilities/authorization'

module OpenC3
  describe Authorization do
    let(:api) { Class.new { include Authorization }.new }

    def authorize(**kwargs)
      api.send(:authorize, **{ scope: 'DEFAULT' }.merge(kwargs))
    end

    before(:each) do
      mock_redis()
      allow(OpenC3::AuthModel).to receive(:verify).and_call_original
      allow(OpenC3::AuthModel).to receive(:verify_no_service).and_call_original
      allow(OpenC3::AuthModel).to receive(:role).and_call_original
      @saved_authorize = $openc3_authorize
      @saved_env = ENV.to_h.slice('OPENC3_SERVICE_PASSWORD', 'OPENC3_OPERATOR_TARGETS', 'OPENC3_VIEWER_TARGETS', 'OPENC3_ADMIN_TARGETS')
      ENV['OPENC3_SERVICE_PASSWORD'] = 'svcpassword'
      ENV.delete('OPENC3_OPERATOR_TARGETS')
      ENV.delete('OPENC3_VIEWER_TARGETS')
      ENV.delete('OPENC3_ADMIN_TARGETS')
      $openc3_authorize = true
      @admin = AuthModel.generate_session(role: 'admin')
      @operator = AuthModel.generate_session(role: 'operator')
      @viewer = AuthModel.generate_session(role: 'viewer')
    end

    after(:each) do
      $openc3_authorize = @saved_authorize
      %w(OPENC3_SERVICE_PASSWORD OPENC3_OPERATOR_TARGETS OPENC3_VIEWER_TARGETS OPENC3_ADMIN_TARGETS).each do |key|
        @saved_env.key?(key) ? ENV[key] = @saved_env[key] : ENV.delete(key)
      end
    end

    describe "authorize" do
      it "requires a scope" do
        expect { api.send(:authorize, permission: 'tlm', token: @admin) }.to raise_error(AuthError, /Scope is required/)
      end

      it "returns the anonymous user when authorization is disabled" do
        $openc3_authorize = false
        expect(authorize(permission: 'admin')).to eql OpenC3::Authorization::ANONYMOUS_USER
      end

      it "requires a valid session or service token" do
        expect { authorize(permission: 'tlm') }.to raise_error(AuthError, /Token is required/)
        expect { authorize(permission: 'tlm', token: 'ses_bogus') }.to raise_error(AuthError, /Token is invalid/)
      end

      it "requires a permission" do
        expect { authorize(permission: nil, token: @admin) }.to raise_error(ForbiddenError, /Permission is required/)
      end

      it "returns the user with its role" do
        expect(authorize(permission: 'admin', token: @admin)).to eql({ 'username' => 'admin', 'roles' => ['admin'] })
        expect(authorize(permission: 'cmd', token: @operator)).to eql({ 'username' => 'operator', 'roles' => ['operator'] })
      end

      it "grants the admin role every permission" do
        Authorization::ADMIN_PERMISSIONS.each do |permission|
          expect { authorize(permission: permission, token: @admin, target_name: 'INST', packet_name: 'COLLECT') }.not_to raise_error
        end
      end

      it "denies the operator role admin permissions" do
        %w(cmd cmd_raw tlm tlm_set script_run script_edit system_set).each do |permission|
          expect { authorize(permission: permission, token: @operator, target_name: 'INST') }.not_to raise_error
        end
        %w(admin superadmin).each do |permission|
          expect { authorize(permission: permission, token: @operator, target_name: 'INST') }.to \
            raise_error(ForbiddenError, /Role 'operator' does not have permission '#{permission}'/)
        end
      end

      it "limits the viewer role to read-only permissions" do
        %w(system tlm cmd_info script_view).each do |permission|
          expect { authorize(permission: permission, token: @viewer, target_name: 'INST') }.not_to raise_error
        end
        %w(cmd cmd_raw tlm_set script_run script_edit system_set admin superadmin).each do |permission|
          expect { authorize(permission: permission, token: @viewer, target_name: 'INST') }.to \
            raise_error(ForbiddenError, /Role 'viewer' does not have permission '#{permission}'/)
        end
      end

      it "treats the service password as the service role" do
        expect(authorize(permission: 'cmd', token: 'svcpassword', target_name: 'INST', packet_name: 'COLLECT')['roles']).to eql ['service']
        expect { authorize(permission: 'admin', token: 'svcpassword') }.to \
          raise_error(ForbiddenError, /Role 'service' does not have permission 'admin'/)
      end

      it "scopes a role to OPENC3_<ROLE>_TARGETS" do
        ENV['OPENC3_OPERATOR_TARGETS'] = 'inst, EXAMPLE'
        expect { authorize(permission: 'cmd', token: @operator, target_name: 'INST', packet_name: 'COLLECT') }.not_to raise_error
        expect { authorize(permission: 'cmd', token: @operator, target_name: 'EXAMPLE') }.not_to raise_error
        expect { authorize(permission: 'tlm', token: @operator, target_name: 'INST2') }.to \
          raise_error(ForbiddenError, /Role 'operator' is not authorized for target 'INST2'/)
        # Other roles are unaffected
        expect { authorize(permission: 'cmd', token: @admin, target_name: 'INST2') }.not_to raise_error
        expect { authorize(permission: 'tlm', token: @viewer, target_name: 'INST2') }.not_to raise_error
        # Calls without a target are not target scoped
        expect { authorize(permission: 'system', token: @operator) }.not_to raise_error
      end

      it "consumes one-time tokens" do
        otp = Authorization.generate_otp({ 'username' => 'operator', 'roles' => ['operator'] })
        expect(otp).to start_with('otp_')
        expect(authorize(permission: 'tlm', token: otp)['roles']).to eql ['operator']
        expect { authorize(permission: 'tlm', token: otp) }.to raise_error(AuthError, /Token is invalid/)
      end
    end

    describe "generate_otp" do
      it "binds the OTP to the requesting user's role" do
        otp = Authorization.generate_otp({ 'username' => 'viewer', 'roles' => ['viewer'] })
        expect(AuthModel.role(otp)).to eql 'viewer'
        expect { Authorization.generate_otp(Authorization::ANONYMOUS_USER) }.to raise_error(AuthError, /Invalid OTP user/)
        expect { Authorization.generate_otp({ 'username' => 'x', 'roles' => ['root'] }) }.to raise_error(AuthError, /Invalid OTP user/)
      end
    end

    describe "user_info" do
      it "returns the role without consuming an OTP" do
        otp = AuthModel.generate_session(otp: true, role: 'operator')
        expect(api.send(:user_info, otp)).to eql({ 'username' => 'operator', 'roles' => ['operator'] })
        expect(api.send(:user_info, otp)).to eql({ 'username' => 'operator', 'roles' => ['operator'] })
        expect(api.send(:user_info, 'ses_bogus')).to eql({})
        expect(api.send(:user_info, nil)).to eql({})
      end
    end
  end
end
