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
require 'openc3/utilities/operator_token'

module OpenC3
  describe OperatorToken do
    let(:operator_token) { AuthModel::SESSION_PREFIX + ('a' * 22) }

    before(:each) do
      mock_redis()
      @saved_env = ENV.to_hash
      ENV['OPENC3_SERVICE_PASSWORD'] = 'service_password_must_not_be_used'
      ENV.delete('OPENC3_API_CLIENT')
    end

    after(:each) do
      ENV.clear
      @saved_env.each { |k, v| ENV[k] = v }
    end

    describe "for_request" do
      it "returns the caller's own token" do
        expect(OperatorToken.for_request(operator_token)).to eq(operator_token)
      end

      it "never substitutes the service password when the request has no token" do
        expect { OperatorToken.for_request(nil) }.to raise_error(NoOperatorTokenError, /No operator token/)
        expect { OperatorToken.for_request('') }.to raise_error(NoOperatorTokenError)
        expect { OperatorToken.for_request('  ') }.to raise_error(NoOperatorTokenError)
      end
    end

    describe "script_environment" do
      context "in Core" do
        it "hands the operator's own token to the script and nothing else" do
          env = OperatorToken.script_environment(operator_token, username: 'anonymous', scope: 'DEFAULT')
          expect(env).to eq({ 'OPENC3_API_PASSWORD' => operator_token })
          expect(env.values).not_to include(ENV['OPENC3_SERVICE_PASSWORD'])
        end

        it "does not look up offline access for the anonymous user" do
          expect(OfflineAccessModel).not_to receive(:get_model)
          OperatorToken.script_environment(operator_token, username: 'Anonymous', scope: 'DEFAULT')
        end

        it "raises instead of falling back to the service password" do
          expect {
            OperatorToken.script_environment(nil, username: 'anonymous', scope: 'DEFAULT')
          }.to raise_error(NoOperatorTokenError, "No operator token available for script")
        end
      end

      context "with an offline access token" do
        let(:model) { OfflineAccessModel.new(name: 'operator', offline_access_token: 'refresh_token', scope: 'DEFAULT') }
        let(:auth) { double('auth') }

        before(:each) do
          model.create
          allow(OpenC3KeycloakAuthentication).to receive(:new).and_return(auth)
        end

        it "uses the operator's validated offline access token" do
          expect(auth).to receive(:get_token_from_refresh_token).with('refresh_token').and_return('access')
          env = OperatorToken.script_environment(nil, username: 'operator', scope: 'DEFAULT')
          expect(env).to eq({ 'OPENC3_API_TOKEN' => 'refresh_token' })
        end

        it "clears an invalid offline access token and raises" do
          expect(auth).to receive(:get_token_from_refresh_token).and_return(nil)
          expect {
            OperatorToken.script_environment(nil, username: 'operator', scope: 'DEFAULT')
          }.to raise_error(OpenC3AuthenticationError, "offline_access token invalid for script")
          expect(OfflineAccessModel.get_model(name: 'operator', scope: 'DEFAULT').offline_access_token).to be_nil
        end
      end

      context "in Enterprise without an offline access token" do
        it "raises rather than using the service account" do
          ENV['OPENC3_API_CLIENT'] = 'api'
          expect {
            OperatorToken.script_environment(operator_token, username: 'operator', scope: 'DEFAULT')
          }.to raise_error(NoOperatorTokenError, /initialize offline access/)
        end
      end
    end
  end
end
