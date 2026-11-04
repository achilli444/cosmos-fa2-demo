# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

require "rails_helper"

RSpec.describe UsersController, type: :controller do
  describe "UsersController" do
    it "GET active" do
      get :active
      expect(response).to have_http_status(:ok)
    end

    it "manages operator accounts as admin only" do
      mock_redis()
      allow(OpenC3::AuthModel).to receive(:session_user).and_call_original
      $openc3_authorize = true # the spec helper disables it; these endpoints rely on it
      admin_token = OpenC3::AuthModel.generate_session

      request.headers['HTTP_AUTHORIZATION'] = admin_token
      post :create, params: { username: 'alice', password: 'alicepass1', roles: ['operator'], targets: ['INST'], scope: 'DEFAULT' }
      expect(response).to have_http_status(:created)
      json = JSON.parse(response.body)
      expect(json).to eql({ 'username' => 'alice', 'name' => 'alice', 'roles' => ['operator'], 'targets' => ['INST'] })

      post :create, params: { username: 'bob', password: 'short', roles: ['operator'], scope: 'DEFAULT' }
      expect(response).to have_http_status(:bad_request)

      get :index, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body).map { |u| u['username'] }).to eql ['admin', 'alice']

      # A non-admin operator can not read or change accounts
      alice_token = OpenC3::AuthModel.generate_session(user: OpenC3::AuthModel.user('alice'))
      request.headers['HTTP_AUTHORIZATION'] = alice_token
      get :index, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:forbidden)
      post :create, params: { username: 'eve', password: 'evepass123', roles: ['admin'], scope: 'DEFAULT' }
      expect(response).to have_http_status(:forbidden)
      delete :destroy, params: { username: 'alice', scope: 'DEFAULT' }
      expect(response).to have_http_status(:forbidden)

      request.headers['HTTP_AUTHORIZATION'] = admin_token
      delete :destroy, params: { username: 'alice', scope: 'DEFAULT' }
      expect(response).to have_http_status(:ok)
      expect(OpenC3::AuthModel.verify(alice_token)).to be false
      delete :destroy, params: { username: 'alice', scope: 'DEFAULT' }
      expect(response).to have_http_status(:not_found)
    ensure
      $openc3_authorize = false
    end

    it "Logout terminates only the caller's own session token" do
      request.headers['HTTP_AUTHORIZATION'] = 'ses_mytoken'
      expect(OpenC3::AuthModel).to receive(:terminate).with('ses_mytoken')
      put :logout, params: {user: "user", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
    end
  end
end
