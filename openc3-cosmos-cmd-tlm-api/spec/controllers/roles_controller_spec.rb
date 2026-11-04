# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

require "rails_helper"

RSpec.describe RolesController, :type => :controller do
  before(:each) do
    mock_redis
    @authorize = $openc3_authorize
    $openc3_authorize = true
    request.headers['HTTP_AUTHORIZATION'] = OpenC3::AuthModel.generate_session(username: 'v', roles: ['viewer'])
  end

  after(:each) do
    $openc3_authorize = @authorize
  end

  it "lists the fixed Core roles" do
    get :index, params: { scope: 'DEFAULT' }
    expect(response).to have_http_status(:ok)
    json = JSON.parse(response.body)
    expect(json.map { |role| role['name'] }).to eq(OpenC3::Authorization::ROLES)
  end

  it "shows a role's permissions" do
    get :show, params: { scope: 'DEFAULT', id: 'approver' }
    expect(response).to have_http_status(:ok)
    json = JSON.parse(response.body)
    expect(json['permissions']).to include({ 'permission' => 'script_approver' })
    get :show, params: { scope: 'DEFAULT', id: 'bogus' }
    expect(response).to have_http_status(:not_found)
  end

  it "does not allow roles to be created in Core" do
    post :create, params: { scope: 'DEFAULT', json: '{}' }
    expect(response).to have_http_status(:forbidden)
    request.headers['HTTP_AUTHORIZATION'] = OpenC3::AuthModel.generate_session(username: 'root', roles: ['admin'])
    post :create, params: { scope: 'DEFAULT', json: '{}' }
    expect(response).to have_http_status(:not_implemented)
  end
end
