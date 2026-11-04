# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

require "rails_helper"

RSpec.describe PermissionsController, :type => :controller do
  before(:each) do
    mock_redis
    @authorize = $openc3_authorize
    $openc3_authorize = true
  end

  after(:each) do
    $openc3_authorize = @authorize
  end

  describe "index" do
    it "requires authentication" do
      get :index, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:unauthorized)
    end

    it "returns the Core role to permission matrix" do
      request.headers['HTTP_AUTHORIZATION'] = OpenC3::AuthModel.generate_session(username: 'v', roles: ['viewer'])
      get :index, params: { scope: 'DEFAULT' }
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json['viewer']).to eq(%w(system tlm cmd_info script_view))
      expect(json['admin']).to include('admin')
      expect(json['approver']).to include('script_approver')
    end
  end
end
