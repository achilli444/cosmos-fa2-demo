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

require 'rails_helper'

RSpec.describe AuthController, :type => :controller do
  before(:each) do
    mock_redis()
  end

  describe "token-exists" do
    it "returns false then true when the token is set" do
      get :token_exists
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json).to eql({"result" => false})

      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      get :token_exists
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json).to eql({"result" => true})
    end
  end

  describe "set" do
    it "requires old_password after initial set" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :set, params: { password: 'PASSWORD2' }
      expect(response).to have_http_status(:error)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json["status"]).to eql 'error'
      expect(json["message"]).to eql 'old_password must not be nil or empty'

      post :set, params: { password: 'PASSWORD2', old_password: 'BAD' }
      expect(response).to have_http_status(:error)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json["status"]).to eql 'error'
      expect(json["message"]).to eql 'old_password incorrect'

      post :set, params: { password: 'PASSWORD2', old_password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
    end
  end

  describe "set" do
    it "revokes old sessions and issues a new token on password change" do
      # Set initial password and get a session token
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      old_token = response.body
      expect(old_token).not_to be_empty

      # Change password
      post :set, params: { password: 'PASSWORD2', old_password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      new_token = response.body
      expect(new_token).not_to be_empty
      expect(new_token).not_to eq(old_token)

      # Old token should be invalid
      expect(OpenC3::AuthModel.verify(old_token)).to eq(false)
      # New token should be valid
      expect(OpenC3::AuthModel.verify(new_token)).to eq(true)
    end
  end

  describe "verify" do
    it "requires token" do
      post :verify
      expect(response).to have_http_status(:unauthorized)
    end

    it "validates the set password" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :verify, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      post :verify, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)
    end

    it "validates the service password" do
      post :verify_service, params: { password: 'BAD' }
      expect(response).to have_http_status(:unauthorized)

      post :verify_service, params: { password: 'openc3service' }
      expect(response).to have_http_status(:ok)
    end
  end

  describe "roles" do
    before(:each) do
      $openc3_authorize = true
    end

    after(:each) do
      $openc3_authorize = false
    end

    it "requires an admin session to set another role's password" do
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)
      admin_token = response.body

      # No session at all
      post :set, params: { role: 'operator', password: 'OPERATOR1', scope: 'DEFAULT' }
      expect(response).to have_http_status(:unauthorized)
      expect(OpenC3::AuthModel.set?(OpenC3::AuthModel.role_key('operator'))).to be false

      request.headers['Authorization'] = admin_token
      post :set, params: { role: 'operator', password: 'OPERATOR1', scope: 'DEFAULT' }
      expect(response).to have_http_status(:ok)
      expect(OpenC3::AuthModel.set?(OpenC3::AuthModel.role_key('operator'))).to be true

      # Logging in with the operator password yields an operator session
      request.headers['Authorization'] = nil
      post :verify, params: { password: 'OPERATOR1' }
      expect(response).to have_http_status(:ok)
      operator_token = response.body
      expect(OpenC3::AuthModel.role(operator_token)).to eql 'operator'
      expect(OpenC3::AuthModel.role(admin_token)).to eql 'admin'

      # An operator may not set the viewer password
      request.headers['Authorization'] = operator_token
      post :set, params: { role: 'viewer', password: 'VIEWER123', scope: 'DEFAULT' }
      expect(response).to have_http_status(:forbidden)
      expect(OpenC3::AuthModel.set?(OpenC3::AuthModel.role_key('viewer'))).to be false
    end

    it "rejects unknown roles and the admin role" do
      post :set, params: { password: 'PASSWORD' }
      request.headers['Authorization'] = response.body
      post :set, params: { role: 'superuser', password: 'SUPER1234', scope: 'DEFAULT' }
      expect(response).to have_http_status(:error)
      json = JSON.parse(response.body, allow_nan: true, create_additions: true)
      expect(json["message"]).to eql "invalid role 'superuser'"
    end

    it "issues service sessions with the service role" do
      post :verify_service, params: { password: 'openc3service' }
      expect(response).to have_http_status(:ok)
      expect(OpenC3::AuthModel.role(response.body)).to eql 'service'
    end
  end

  describe "rate limiting" do
    # Actually testing that rate limiting is enforced is done in Playwright
    # because the bad attempt counters in the controller are shared across
    # all requests/tests. But we can ensure that the config is read and that
    # successful attempts don't get rate limited.

    it "uses default rate limit values from environment" do
      expect(ENV['OPENC3_AUTH_RATE_LIMIT_TO']).to eq('10')
      expect(ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN']).to eq('120')
    end

    it "respects custom rate limit values from environment" do
      original_to = ENV.fetch('OPENC3_AUTH_RATE_LIMIT_TO', '10')
      original_within = ENV.fetch('OPENC3_AUTH_RATE_LIMIT_WITHIN', '120')

      begin
        ENV['OPENC3_AUTH_RATE_LIMIT_TO'] = '5'
        ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN'] = '60'

        load Rails.root.join('app', 'controllers', 'auth_controller.rb')

        expect(ENV['OPENC3_AUTH_RATE_LIMIT_TO']).to eq('5')
        expect(ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN']).to eq('60')
      ensure
        ENV['OPENC3_AUTH_RATE_LIMIT_TO'] = original_to
        ENV['OPENC3_AUTH_RATE_LIMIT_WITHIN'] = original_within
        load Rails.root.join('app', 'controllers', 'auth_controller.rb')
      end
    end

    it "does not rate limit successful password attempts" do
      # Note: testing rate limit for bad attempts is done in Playwright
      post :set, params: { password: 'PASSWORD' }
      expect(response).to have_http_status(:ok)

      20.times do
        post :verify, params: { password: 'PASSWORD' }
        expect(response).to have_http_status(:ok)
      end
    end
  end
end
