# encoding: ascii-8bit

# Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This program is free software: you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'rails_helper'

RSpec.describe ApplicationController, :type => :controller do
  controller do
    def boom
      raise StandardError, "redis://internal-host:6379 connection refused"
    end

    def missing
      params.require(:needed)
      head :ok
    end
  end

  before(:each) do
    routes.draw do
      get 'boom' => 'anonymous#boom'
      get 'missing' => 'anonymous#missing'
    end
  end

  describe "unexpected exceptions" do
    it "returns a generic error with a correlation id and no internal details" do
      get :boom
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eql("error")
      expect(json["message"]).to eql(ApplicationController::GENERIC_ERROR_MESSAGE)
      expect(json["request_id"]).to be_a(String)
      expect(json["request_id"]).not_to be_empty
      expect(json).not_to have_key("type")
      expect(json).not_to have_key("backtrace")
      expect(response.body).not_to include("internal-host")
      expect(response.body).not_to include("StandardError")
    end

    it "logs the exception class, message and backtrace server-side under the same correlation id" do
      logged = nil
      logger = double("logger")
      allow(logger).to receive(:error) { |msg| logged = msg }
      allow(controller).to receive(:logger).and_return(logger)
      get :boom
      json = JSON.parse(response.body)
      expect(logged).to include("[request_id=#{json["request_id"]}]")
      expect(logged).to include("StandardError: redis://internal-host:6379 connection refused")
      expect(logged).to include("application_controller_spec.rb")
    end
  end

  describe "missing parameters" do
    it "returns 400 naming only the missing parameter" do
      get :missing
      expect(response).to have_http_status(:bad_request)
      json = JSON.parse(response.body)
      expect(json["status"]).to eql("error")
      expect(json["message"]).to include("needed")
      expect(json["request_id"]).to be_a(String)
      expect(json).not_to have_key("backtrace")
    end
  end
end
