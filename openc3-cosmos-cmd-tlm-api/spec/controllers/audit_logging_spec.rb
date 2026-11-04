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
# See GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'rails_helper'

RSpec.describe ApplicationController, type: :controller do
  controller do
    def index
      head :ok
    end

    def create
      head :created
    end

    def update
      audit("Widget updated: #{params[:id]}")
      head :ok
    end

    def destroy
      render json: { status: 'error', message: 'nope' }, status: :forbidden
    end
  end

  before(:each) do
    mock_redis()
  end

  describe "AuditLogging" do
    it "records a user-attributed audit record for mutating requests that did not call audit" do
      expect(OpenC3::Logger).to receive(:info).with("anonymous#create POST /anonymous -> 201", scope: "DEFAULT", user: "anonymous")
      post :create, params: { scope: "DEFAULT" }
    end

    it "records rejected mutating requests at warn level" do
      expect(OpenC3::Logger).to receive(:warn).with("anonymous#destroy DELETE /anonymous/1 -> 403", scope: "DEFAULT", user: "anonymous")
      delete :destroy, params: { id: 1, scope: "DEFAULT" }
    end

    it "does not record read-only requests" do
      expect(OpenC3::Logger).not_to receive(:info)
      expect(OpenC3::Logger).not_to receive(:warn)
      get :index, params: { scope: "DEFAULT" }
    end

    it "does not double-log when the action called audit" do
      expect(OpenC3::Logger).to receive(:info).once.with("Widget updated: 1", scope: "DEFAULT", user: "anonymous")
      put :update, params: { id: 1, scope: "DEFAULT" }
    end
  end
end
