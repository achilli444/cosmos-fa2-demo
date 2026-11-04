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

require "rails_helper"

RSpec.describe PluginStoreController, type: :controller do
  describe "GET index" do
    it "returns the cached plugin store data" do
      plugins = [{ "id" => 1, "name" => "openc3-cosmos-test" }]
      allow(OpenC3::PluginStoreModel).to receive(:ensure_exists)
      allow(OpenC3::PluginStoreModel).to receive(:all).and_return(plugins.to_json)

      get :index, params: { scope: "DEFAULT" }
      expect(response).to have_http_status(:ok)
      expect(OpenC3::PluginStoreModel).to have_received(:ensure_exists)
      json = JSON.parse(response.body)
      expect(json).to eq(plugins)
    end

    it "returns nothing without authorization" do
      allow(OpenC3::PluginStoreModel).to receive(:ensure_exists)
      allow(OpenC3::PluginStoreModel).to receive(:all)

      get :index
      expect(response).to have_http_status(:unauthorized)
      expect(OpenC3::PluginStoreModel).not_to have_received(:all)
    end

    it "does not contact the plugin store without authorization" do
      allow(OpenC3::PluginStoreModel).to receive(:update)
      allow(OpenC3::PluginStoreModel).to receive(:all).and_return(nil)

      get :index
      expect(response).to have_http_status(:unauthorized)
      expect(OpenC3::PluginStoreModel).not_to have_received(:update)
    end
  end
end
