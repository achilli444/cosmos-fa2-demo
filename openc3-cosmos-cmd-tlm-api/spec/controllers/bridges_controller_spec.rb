# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.

require "rails_helper"
require "openc3/models/bridge_model"
require "openc3/models/microservice_model"

RSpec.describe BridgesController, type: :controller do
  before(:each) do
    mock_redis
    allow(OpenC3::Logger).to receive(:info)
    allow(OpenC3::Logger).to receive(:error)
    allow(OpenC3::Bucket).to receive(:getClient).and_return(double("bucket", list_objects: []))

    OpenC3::BridgeModel.build_microservice(bridge_name: "READY", scope: "DEFAULT").create
    OpenC3::BridgeModel.build_microservice(bridge_name: "PENDING", scope: "DEFAULT").create
    OpenC3::MicroserviceModel.new(name: "DEFAULT__USER__OTHER", scope: "DEFAULT").create
    OpenC3::BridgeModel.new(
      name: "READY",
      scope: "DEFAULT",
      public_key: "hub-public-key",
      ticket: "secret-ticket",
      app_public_key: "app-public-key",
      enroll_code: "secret-code",
      enroll_code_generated_at: Time.now.to_i,
    ).create
    OpenC3::BridgeModel.new(name: "ORPHAN", scope: "DEFAULT", ticket: "orphan-ticket").create
  end

  describe "GET show" do
    it "requires system authorization and returns only safe bridge summaries" do
      expect(controller).to receive(:authorization).with("system").and_return(true)

      get :show, params: { id: "all", scope: "DEFAULT" }

      expect(response).to have_http_status(:ok)
      result = JSON.parse(response.body)
      expect(result).to eq(
        "READY" => {
          "name" => "READY",
          "app_public_key" => "app-public-key",
          "reachable" => true,
        },
        "PENDING" => {
          "name" => "PENDING",
          "app_public_key" => nil,
          "reachable" => false,
        },
      )
      expect(response.body).not_to include("secret-ticket", "secret-code", "hub-public-key")
    end

    it "returns a safe summary for one bridge" do
      get :show, params: { id: "ready", scope: "DEFAULT" }

      expect(JSON.parse(response.body)).to eq(
        "name" => "READY",
        "app_public_key" => "app-public-key",
        "reachable" => true,
      )
    end
  end

  describe "GET index" do
    it "requires system authorization and includes bridges whose hubs have not started" do
      expect(controller).to receive(:authorization).with("system").and_return(true)

      get :index, params: { scope: "DEFAULT" }

      expect(JSON.parse(response.body)).to contain_exactly("READY", "PENDING")
    end
  end

  describe "DELETE destroy" do
    it "records the session-tagged user and request source" do
      request.headers['HTTP_AUTHORIZATION'] = OpenC3::AuthModel.generate_session()
      secret_client = double("secrets")
      allow(secret_client).to receive(:delete).and_raise("missing")
      allow(OpenC3::Secrets).to receive(:getClient).and_return(secret_client)

      expect(OpenC3::Logger).to receive(:warn).with(
        "Bridge secret: BRIDGE_PENDING_PRIVATE_KEY not found for delete with error missing",
        scope: "DEFAULT",
        user: /\Aanonymous@\h{12}\z/,
        other: hash_including('remote_ip' => "0.0.0.0"),
      )
      expect(OpenC3::Logger).to receive(:info).with(
        "Bridge destroyed: PENDING",
        scope: "DEFAULT",
        user: /\Aanonymous@\h{12}\z/,
        other: hash_including('remote_ip' => "0.0.0.0"),
      )

      delete :destroy, params: { id: "PENDING", scope: "DEFAULT" }

      expect(response).to have_http_status(:ok)
    end

    it "deletes a pending bridge that has no BridgeModel record" do
      secret_client = double("secrets", delete: nil)
      allow(OpenC3::Secrets).to receive(:getClient).and_return(secret_client)

      delete :destroy, params: { id: "PENDING", scope: "DEFAULT" }

      expect(response).to have_http_status(:ok)
      expect(
        OpenC3::MicroserviceModel.get_model(name: "DEFAULT__BRIDGE__PENDING", scope: "DEFAULT")
      ).to be_nil
    end
  end
end
