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

require "rails_helper"

RSpec.describe ApplicationController, type: :controller do
  controller do
    def index
      head :ok
    end

    def create
      head :created
    end

    def update
      render json: { status: 'error', message: 'forbidden' }, status: :forbidden
    end

    def destroy
      render json: { status: 'error', message: 'boom' }, status: :internal_server_error
    end
  end

  before(:each) do
    allow(OpenC3::Logger).to receive(:info)
  end

  describe "audit_log" do
    it "does not audit GET requests" do
      expect(OpenC3::Logger).not_to receive(:info).with(/\AAudit:/, anything)
      get :index, params: { scope: "DEFAULT" }
      expect(response).to have_http_status(:ok)
    end

    it "audits a successful state-changing request with user, action, scope and outcome" do
      expect(OpenC3::Logger).to receive(:info).with(
        "Audit: anonymous POST /anonymous anonymous#create scope=DEFAULT => success (201)",
        scope: "DEFAULT",
        user: "anonymous",
        type: OpenC3::Logger::LOG,
        other: {
          audit_controller: "anonymous",
          audit_action: "create",
          audit_method: "POST",
          audit_path: "/anonymous",
          audit_resource: "",
          audit_status: 201,
          audit_outcome: "success",
        }
      )
      post :create, params: { scope: "DEFAULT" }
      expect(response).to have_http_status(:created)
    end

    it "records resource identifiers and the request scope" do
      expect(OpenC3::Logger).to receive(:info).with(
        "Audit: anonymous DELETE /anonymous/INST anonymous#destroy id=INST scope=TEST => failure (500)",
        hash_including(scope: "TEST", user: "anonymous", other: hash_including(audit_resource: "id=INST", audit_outcome: "failure"))
      )
      delete :destroy, params: { id: "INST", scope: "TEST" }
      expect(response).to have_http_status(:internal_server_error)
    end

    it "records denied outcomes" do
      expect(OpenC3::Logger).to receive(:info).with(
        /\AAudit: anonymous PUT \/anonymous\/INST anonymous#update id=INST scope=DEFAULT => denied \(403\)\z/,
        hash_including(scope: "DEFAULT", user: "anonymous")
      )
      put :update, params: { id: "INST", scope: "DEFAULT" }
      expect(response).to have_http_status(:forbidden)
    end

    it "does not record request bodies or secret-bearing parameters" do
      expect(OpenC3::Logger).to receive(:info) do |message, **kwargs|
        expect(message).not_to include("hunter2")
        expect(kwargs[:other].values.join).not_to include("hunter2")
      end
      post :create, params: { scope: "DEFAULT", password: "hunter2", json: '{"value":"hunter2"}' }
      expect(response).to have_http_status(:created)
    end

    it "falls back to the DEFAULT log topic when the scope is not a plain name" do
      expect(OpenC3::Logger).to receive(:info).with(
        /scope=DEFAULT => success/,
        hash_including(scope: "DEFAULT")
      )
      post :create, params: { scope: "../DEFAULT" }
      expect(response).to have_http_status(:created)
    end

    it "truncates long resource identifiers" do
      long_id = "A" * 300
      expect(OpenC3::Logger).to receive(:info).with(
        /id=#{"A" * 200}\.\.\. scope=DEFAULT/,
        anything
      )
      delete :destroy, params: { id: long_id, scope: "DEFAULT" }
    end

    it "never breaks the response when logging fails" do
      allow(OpenC3::Logger).to receive(:info).and_raise(StandardError.new("redis down"))
      expect(controller).to receive(:log_error).with(an_instance_of(StandardError))
      post :create, params: { scope: "DEFAULT" }
      expect(response).to have_http_status(:created)
    end

    it "falls back to an unknown user when user lookup fails" do
      allow(controller).to receive(:username).and_raise(StandardError.new("bad token"))
      expect(OpenC3::Logger).to receive(:info).with(
        /\AAudit: unknown POST/,
        hash_including(user: "unknown")
      )
      post :create, params: { scope: "DEFAULT" }
      expect(response).to have_http_status(:created)
    end
  end

  describe "ApiController" do
    it "opts out of the audit hook because it logs every JSON-RPC call itself" do
      expect(ApiController._process_action_callbacks.map(&:filter)).not_to include(:audit_log)
      expect(ApplicationController._process_action_callbacks.map(&:filter)).to include(:audit_log)
    end
  end
end
