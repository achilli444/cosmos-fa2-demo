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

    it "Logout terminates only the caller's own session token" do
      request.headers['HTTP_AUTHORIZATION'] = 'ses_mytoken'
      expect(OpenC3::AuthModel).to receive(:terminate).with('ses_mytoken')
      put :logout, params: {user: "user", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
    end
  end

  describe "named account management" do
    before(:each) do
      mock_redis
      @authorize = $openc3_authorize
      $openc3_authorize = true
      allow(OpenC3::Logger).to receive(:info)
      @admin = OpenC3::AuthModel.generate_session(username: 'root', roles: ['admin'])
      @operator = OpenC3::AuthModel.generate_session(username: 'op', roles: ['operator'])
    end

    after(:each) do
      $openc3_authorize = @authorize
    end

    it "requires authentication" do
      get :index, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:unauthorized)
    end

    it "forbids anyone without the admin permission" do
      request.headers['HTTP_AUTHORIZATION'] = @operator
      get :index, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:forbidden)
      post :create, params: { scope: 'DEFAULT', username: 'alice', password: 'alicepassword', roles: ['viewer'] }
      expect(response).to have_http_status(:forbidden)
      put :update, params: { scope: 'DEFAULT', id: 'alice', roles: ['admin'] }
      expect(response).to have_http_status(:forbidden)
      delete :destroy, params: { scope: 'DEFAULT', id: 'alice' }
      expect(response).to have_http_status(:forbidden)
      expect(OpenC3::AuthModel.users).to eq({})
    end

    it "lets an admin create, update and delete accounts with an audit record" do
      request.headers['HTTP_AUTHORIZATION'] = @admin
      expect(OpenC3::Logger).to receive(:info).with(/User created: alice roles: \["viewer"\]/, hash_including(user: 'root'))
      post :create, params: { scope: 'DEFAULT', username: 'alice', password: 'alicepassword', roles: ['viewer'], name: 'Alice' }
      expect(response).to have_http_status(:created)
      json = JSON.parse(response.body)
      expect(json['username']).to eq('alice')
      expect(json).not_to have_key('password_hash')

      get :index, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json.keys).to eq(['alice'])
      expect(json['alice']).not_to have_key('password_hash')

      get :show, params: { scope: 'DEFAULT', id: 'alice' }
      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body)['roles']).to eq(['viewer'])
      get :show, params: { scope: 'DEFAULT', id: 'nobody' }
      expect(response).to have_http_status(:not_found)

      expect(OpenC3::Logger).to receive(:info).with(/User updated: alice roles: \["operator"\], enabled: false/, hash_including(user: 'root'))
      put :update, params: { scope: 'DEFAULT', id: 'alice', roles: ['operator'], enabled: false }
      expect(response).to have_http_status(:ok)
      expect(OpenC3::AuthModel.user('alice')['enabled']).to be false
      expect(OpenC3::AuthModel.user('alice')['roles']).to eq(['operator'])

      expect(OpenC3::Logger).to receive(:info).with(/User deleted: alice/, hash_including(user: 'root'))
      delete :destroy, params: { scope: 'DEFAULT', id: 'alice' }
      expect(response).to have_http_status(:ok)
      expect(OpenC3::AuthModel.users).to eq({})
      delete :destroy, params: { scope: 'DEFAULT', id: 'alice' }
      expect(response).to have_http_status(:not_found)
    end

    it "rejects unknown roles and reserved usernames" do
      request.headers['HTTP_AUTHORIZATION'] = @admin
      post :create, params: { scope: 'DEFAULT', username: 'alice', password: 'alicepassword', roles: ['superuser'] }
      expect(response).to have_http_status(:bad_request)
      post :create, params: { scope: 'DEFAULT', username: 'alice', password: 'alicepassword' }
      expect(response).to have_http_status(:bad_request)
      post :create, params: { scope: 'DEFAULT', username: 'admin', password: 'alicepassword', roles: ['viewer'] }
      expect(response).to have_http_status(:bad_request)
      expect(JSON.parse(response.body)['message']).to match(/invalid username/)
      expect(OpenC3::AuthModel.users).to eq({})
    end
  end

end
