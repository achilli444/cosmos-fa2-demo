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
      allow(OpenC3::AuthModel).to receive(:role).and_call_original
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

      it "binds sessions to a role" do
        admin = AuthModel.generate_session
        operator = AuthModel.generate_session(role: 'operator')
        otp = AuthModel.generate_session(otp: true, role: 'viewer')
        expect(AuthModel.role(admin)).to eql 'admin'
        expect(AuthModel.role(operator)).to eql 'operator'
        expect(AuthModel.role(otp, consume_otp: false)).to eql 'viewer'
        expect(AuthModel.role(otp)).to eql 'viewer'
        expect(AuthModel.role(otp)).to be_nil # consumed
        expect(AuthModel.role('ses_bogus')).to be_nil
        expect(AuthModel.role(nil)).to be_nil
        expect { AuthModel.generate_session(role: 'root') }.to raise_error(/invalid role 'root'/)
      end

      it "does not accept a plaintext password as a token" do
        expect(AuthModel.verify(AUTH_INITIAL_PASSWORD)).to eq(false)
        expect(AuthModel.role(AUTH_INITIAL_PASSWORD)).to be_nil
      end

      it "returns the service role for the service password" do
        saved = ENV['OPENC3_SERVICE_PASSWORD']
        begin
          ENV['OPENC3_SERVICE_PASSWORD'] = 'svcpassword'
          expect(AuthModel.role('svcpassword')).to eql 'service'
          ENV.delete('OPENC3_SERVICE_PASSWORD')
          expect(AuthModel.role('svcpassword')).to be_nil
        ensure
          ENV['OPENC3_SERVICE_PASSWORD'] = saved
        end
      end

      it "treats legacy sessions (bare timestamp) as admin" do
        @redis.hset(AuthModel::SESSIONS_KEY, 'ses_legacy', Time.now.iso8601)
        expect(AuthModel.verify('ses_legacy')).to eq(true)
        expect(AuthModel.role('ses_legacy')).to eql 'admin'
      end

      it "sets role passwords" do
        expect { AuthModel.set_role_password('admin', 'operator1') }.to raise_error(/invalid role 'admin'/)
        expect { AuthModel.set_role_password('root', 'operator1') }.to raise_error(/invalid role 'root'/)
        expect { AuthModel.set_role_password('operator', 'short') }.to raise_error(/at least 8 characters/)
        expect { AuthModel.set_role_password('operator', AUTH_INITIAL_PASSWORD) }.to raise_error(/already in use/)

        AuthModel.set_role_password('operator', 'operator1')
        AuthModel.set_role_password('viewer', 'viewer123')
        expect(AuthModel.password_role(AUTH_INITIAL_PASSWORD)).to eql 'admin'
        expect(AuthModel.password_role('operator1')).to eql 'operator'
        expect(AuthModel.password_role('viewer123')).to eql 'viewer'
        expect(AuthModel.password_role('nope')).to be_nil
        expect(AuthModel.verify_no_service('operator1', mode: :password)).to eq(true)
        expect(AuthModel.verify_no_service('operator1', mode: :token)).to eq(false)
      end

      it "terminates only that role's sessions when its password changes" do
        admin = AuthModel.generate_session
        operator = AuthModel.generate_session(role: 'operator')
        AuthModel.set_role_password('operator', 'operator1')
        expect(AuthModel.role(admin)).to eql 'admin'
        expect(AuthModel.role(operator)).to be_nil

        operator = AuthModel.generate_session(role: 'operator')
        AuthModel.set('newpassword', AUTH_INITIAL_PASSWORD) # admin change revokes everything
        expect(AuthModel.role(admin)).to be_nil
        expect(AuthModel.role(operator)).to be_nil
      end

      it "raises when stored password hash is SHA256" do
        @redis.set(PW_HASH_PRIMARY_KEY, Digest::SHA256.hexdigest(AUTH_INITIAL_PASSWORD))
        expect{ AuthModel.verify_no_service(AUTH_INITIAL_PASSWORD, mode: :any) }.to \
          raise_error(/invalid password hash/)
      end
    end
  end
end
