# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'rails_helper'

RSpec.describe InternalStatusController, :type => :controller do
  before(:each) do
    mock_redis()
  end

  describe "GET status" do
    it "returns a Hash<string, string> and status code 200" do
      get :status
      expect(JSON.parse(response.body, symbolize_names: true, allow_nan: true)).to include(status: 'UP')
      expect(response).to have_http_status(:ok)
    end

    it "does not expose backend errors to unauthenticated callers" do
      allow(Rails.logger).to receive(:error)
      allow(OpenC3::PingModel).to receive(:get).and_raise(Redis::CannotConnectError.new("Error connecting to Redis on openc3-redis:6379 (ECONNREFUSED)"))
      get :status
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eql('error')
      expect(json["message"]).to eql(ApplicationController::GENERIC_ERROR_MESSAGE)
      expect(json["request_id"]).to be_a(String)
      expect(json).not_to have_key("type")
      expect(response.body).not_to include("openc3-redis")
      expect(response.body).not_to include("6379")
    end
  end
end
