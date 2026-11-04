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
    class AuthorizationSpecHost
      include Authorization

      public :authorize
    end

    let(:host) { AuthorizationSpecHost.new }

    before(:each) do
      mock_redis()
      @saved_authorize = $openc3_authorize
    end

    after(:each) do
      $openc3_authorize = @saved_authorize
    end

    describe "authorize" do
      it "audits and raises when the scope is missing" do
        expect(SecurityAudit).to receive(:authorization_failure).with("Scope is required", hash_including(permission: 'cmd', target_name: 'INST'))
        expect { host.authorize(permission: 'cmd', target_name: 'INST') }.to raise_error(AuthError, "Scope is required")
      end

      it "audits and raises when the token is missing" do
        $openc3_authorize = true
        expect(SecurityAudit).to receive(:authorization_failure).with("Token is required", hash_including(scope: 'DEFAULT', permission: 'tlm'))
        expect { host.authorize(permission: 'tlm', scope: 'DEFAULT') }.to raise_error(AuthError, "Token is required")
      end

      it "audits and raises when the token is invalid, without logging the token" do
        $openc3_authorize = true
        allow(AuthModel).to receive(:verify).with('BAD_TOKEN').and_return(false)
        capture_io do |stdout|
          expect { host.authorize(permission: 'tlm', scope: 'DEFAULT', token: 'BAD_TOKEN') }.to raise_error(AuthError, "Token is invalid")
          record = JSON.parse(stdout.string.lines.last)
          expect(record['type']).to eql 'security'
          expect(record['security']).to include('event' => 'authorize', 'outcome' => 'failure',
                                                'reason' => 'Token is invalid', 'scope' => 'DEFAULT', 'permission' => 'tlm')
          expect(stdout.string).not_to include('BAD_TOKEN')
        end
      end

      it "names the requesting source and user from the audit context" do
        $openc3_authorize = true
        allow(AuthModel).to receive(:verify).and_return(false)
        capture_io do |stdout|
          SecurityAudit.with_context(source: '10.0.0.7', user: 'mallory', method: 'cmd') do
            expect { host.authorize(permission: 'cmd', scope: 'DEFAULT', token: 'X') }.to raise_error(AuthError)
          end
          record = JSON.parse(stdout.string.lines.last)
          expect(record['user']).to eql 'mallory'
          expect(record['security']).to include('source' => '10.0.0.7', 'user' => 'mallory', 'method' => 'cmd')
        end
      end

      it "does not audit a successful authorization" do
        $openc3_authorize = true
        allow(AuthModel).to receive(:verify).with('GOOD').and_return(true)
        expect(SecurityAudit).not_to receive(:log)
        expect(host.authorize(permission: 'tlm', scope: 'DEFAULT', token: 'GOOD')).to eql Authorization::ANONYMOUS_USER
      end
    end

    describe "generate_otp" do
      it "audits and raises for a non-anonymous user" do
        expect(SecurityAudit).to receive(:authorization_failure).with("Invalid OTP user", user: 'eve')
        expect { Authorization.generate_otp('eve') }.to raise_error(AuthError, "Invalid OTP user")
      end
    end
  end
end
