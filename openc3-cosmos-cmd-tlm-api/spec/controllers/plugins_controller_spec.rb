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
require "tempfile"

RSpec.describe PluginsController, type: :controller do
  before(:each) do
    allow(OpenC3::Logger).to receive(:info)
    allow(OpenC3::Logger).to receive(:error)
  end

  describe "GET index" do
    it "returns list of installed plugins" do
      allow(OpenC3::PluginModel).to receive(:names).and_return(["PLUGIN1", "PLUGIN2"])

      get :index, params: {scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json).to eq(["PLUGIN1", "PLUGIN2"])
    end

    it "returns nothing without authorization" do
      get :index
      expect(response).to have_http_status(:unauthorized)
    end

    it "handles errors during index" do
      allow(OpenC3::PluginModel).to receive(:names).and_raise(StandardError.new("Database error"))

      get :index, params: {scope: "DEFAULT"}
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("Database error")
    end
  end

  describe "GET show" do
    it "returns a specific plugin" do
      plugin_data = {"name" => "TEST_PLUGIN", "version" => "1.0.0"}
      allow(OpenC3::PluginModel).to receive(:get).and_return(plugin_data)

      get :show, params: {id: "TEST_PLUGIN", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json).to eq(plugin_data)
    end

    it "returns all plugins when id is 'all'" do
      plugins_data = {
        "PLUGIN1" => {"name" => "PLUGIN1"},
        "PLUGIN2" => {"name" => "PLUGIN2"}
      }
      allow(OpenC3::PluginModel).to receive(:all).and_return(plugins_data)
      allow(OpenC3::PluginStoreModel).to receive(:all).and_return([].to_json)

      get :show, params: {id: "all", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json).to eq(plugins_data)
    end

    it "returns nothing without authorization" do
      get :show, params: {id: "TEST_PLUGIN"}
      expect(response).to have_http_status(:unauthorized)
    end

    it "handles errors during show" do
      allow(OpenC3::PluginModel).to receive(:get).and_raise(StandardError.new("Plugin not found"))

      get :show, params: {id: "TEST_PLUGIN", scope: "DEFAULT"}
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("Plugin not found")
    end
  end

  describe "POST modified_diff" do
    it "returns the list of modified files that differ from the plugin" do
      allow(OpenC3::PluginModel).to receive(:modified_diff)
        .with({"name" => "x"}, scope: "DEFAULT").and_return(["INST/screen.txt"])

      post :modified_diff, params: {scope: "DEFAULT", plugin_hash: '{"name":"x"}'}
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["files"]).to eq(["INST/screen.txt"])
    end

    it "returns bad_request on invalid plugin_hash JSON" do
      post :modified_diff, params: {scope: "DEFAULT", plugin_hash: "not json"}
      expect(response).to have_http_status(:bad_request)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
    end

    it "returns nothing without authorization" do
      post :modified_diff, params: {plugin_hash: "{}"}
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "POST create" do
    before(:each) do
      @file = Tempfile.new(["test-plugin", ".gem"])
      @file.write("gem content")
      @file.rewind

      @upload_file = fixture_file_upload(@file.path, "application/octet-stream")
      allow(@upload_file).to receive(:original_filename).and_return("test-plugin.gem")

      allow(Dir).to receive(:mktmpdir).and_return("/tmp/test")
      allow(FileUtils).to receive(:cp)
      allow(FileUtils).to receive(:remove_entry_secure)
    end

    it "creates a new plugin successfully" do
      install_result = {
        "name" => "TEST_PLUGIN",
        "variables" => {},
        "plugin_txt_lines" => []
      }
      allow(OpenC3::PluginModel).to receive(:install_phase1).and_return(install_result)

      post :create, params: {plugin: @upload_file, scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json).to eq(install_result)
    end

    it "handles plugin creation with existing variables" do
      existing_model = {
        "variables" => {"VAR1" => "value1"},
        "plugin_txt_lines" => ["line1", "line2"]
      }
      allow(OpenC3::PluginModel).to receive(:get).and_return(existing_model)

      install_result = {
        "name" => "TEST_PLUGIN",
        "variables" => {"VAR1" => "value1"},
        "plugin_txt_lines" => ["line1", "line2"]
      }

      expect(OpenC3::PluginModel).to receive(:install_phase1).with(
        "/tmp/test/test-plugin.gem",
        existing_variables: {"VAR1" => "value1"},
        existing_plugin_txt_lines: ["line1", "line2"],
        store_plugin_id: nil,
        store_version_id: nil,
        scope: "DEFAULT"
      ).and_return(install_result)

      put :update, params: {id: "TEST_PLUGIN", plugin: @upload_file, scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json).to eq(install_result)
    end

    it "returns error when no file is provided" do
      post :create, params: {scope: "DEFAULT"}
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("No file received")
    end

    it "handles errors during plugin installation" do
      allow(OpenC3::PluginModel).to receive(:install_phase1).and_raise(StandardError.new("Installation failed"))

      post :create, params: {plugin: @upload_file, scope: "DEFAULT"}
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("Installation failed")
    end

    it "returns bad request when gem file is empty" do
      allow(OpenC3::PluginModel).to receive(:install_phase1).and_raise(OpenC3::EmptyGemFileError.new("Gem file is empty: test-plugin.gem"))

      post :create, params: { plugin: @upload_file, scope: "DEFAULT" }
      expect(response).to have_http_status(:bad_request)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("Gem file is empty: test-plugin.gem")
    end

    it "raises EmptyGemFileError when gem file is empty" do
      Tempfile.create(["empty-plugin", ".gem"]) do |tf|
        expect {
          OpenC3::PluginModel.install_phase1(tf.path, scope: "DEFAULT")
        }.to raise_error(OpenC3::EmptyGemFileError, /Gem file is empty/)
      end
    end

    it "cleans up temporary directory on success" do
      allow(OpenC3::PluginModel).to receive(:install_phase1).and_return({})
      expect(FileUtils).to receive(:remove_entry_secure).with("/tmp/test", true)

      post :create, params: {plugin: @upload_file, scope: "DEFAULT"}
    end

    it "cleans up temporary directory on error" do
      allow(OpenC3::PluginModel).to receive(:install_phase1).and_raise(StandardError.new("Installation failed"))
      expect(FileUtils).to receive(:remove_entry_secure).with("/tmp/test", true)

      post :create, params: {plugin: @upload_file, scope: "DEFAULT"}
    end

    it "returns nothing without authorization" do
      post :create, params: {plugin: @upload_file}
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "PUT update" do
    before(:each) do
      @file = Tempfile.new(["test-plugin", ".gem"])
      @file.write("gem content")
      @file.rewind

      @upload_file = fixture_file_upload(@file.path, "application/octet-stream")
      allow(@upload_file).to receive(:original_filename).and_return("test-plugin.gem")

      allow(Dir).to receive(:mktmpdir).and_return("/tmp/test")
      allow(FileUtils).to receive(:cp)
      allow(FileUtils).to receive(:remove_entry_secure)
    end

    it "updates an existing plugin" do
      existing_plugin = {
        "name" => "TEST_PLUGIN",
        "variables" => {"VAR1" => "existing_value"},
        "plugin_txt_lines" => ["existing_line"]
      }
      allow(OpenC3::PluginModel).to receive(:get).and_return(existing_plugin)

      install_result = {
        "name" => "TEST_PLUGIN",
        "variables" => {"VAR1" => "existing_value"},
        "plugin_txt_lines" => ["existing_line"]
      }

      expect(OpenC3::PluginModel).to receive(:install_phase1).with(
        "/tmp/test/test-plugin.gem",
        existing_variables: {"VAR1" => "existing_value"},
        existing_plugin_txt_lines: ["existing_line"],
        store_plugin_id: nil,
        store_version_id: nil,
        scope: "DEFAULT"
      ).and_return(install_result)

      put :update, params: {id: "TEST_PLUGIN", plugin: @upload_file, scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json).to eq(install_result)
    end

    it "returns nothing without authorization" do
      put :update, params: {id: "TEST_PLUGIN", plugin: @upload_file}
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "POST install" do
    before(:each) do
      allow(Dir).to receive(:mktmpdir).and_return("/tmp/test")
      allow(Dir::Tmpname).to receive(:create).and_return("plugin-instance-123.json")
      allow(File).to receive(:open).and_yield(double("file", write: true))
    end

    it "installs a plugin with hash parameters" do
      plugin_hash = '{"variables": {"VAR1": "value1"}}'
      process_result = double("ProcessInfo", name: "process_123")

      allow(OpenC3::ProcessManager.instance).to receive(:spawn).and_return(process_result)

      post :install, params: {
        id: "TEST_PLUGIN__1.0.0__plugin",
        plugin_hash: plugin_hash,
        scope: "DEFAULT"
      }

      expect(response).to have_http_status(:ok)
      expect(response.body).to eq("process_123")
    end

    it "extracts gem name from plugin id correctly" do
      plugin_hash = '{"variables": {}}'
      process_result = double("ProcessInfo", name: "process_123")

      expect(OpenC3::ProcessManager.instance).to receive(:spawn).with(
        ["ruby", "/openc3/bin/openc3cli", "load", "TEST_PLUGIN", "DEFAULT", anything, "force"],
        "plugin_install",
        "TEST_PLUGIN__1.0.0__plugin",
        anything,
        hash_including(temp_dir: "/tmp/test", scope: "DEFAULT")
      ).and_return(process_result)

      post :install, params: {
        id: "TEST_PLUGIN__1.0.0__plugin",
        plugin_hash: plugin_hash,
        scope: "DEFAULT"
      }
    end

    it "handles errors during installation" do
      plugin_hash = '{"variables": {}}'
      allow(OpenC3::ProcessManager.instance).to receive(:spawn).and_raise(StandardError.new("Spawn failed"))

      post :install, params: {
        id: "TEST_PLUGIN__1.0.0__plugin",
        plugin_hash: plugin_hash,
        scope: "DEFAULT"
      }

      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("Spawn failed")
    end

    it "returns nothing without authorization" do
      post :install, params: {id: "TEST_PLUGIN", plugin_hash: "{}"}
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "DELETE destroy" do
    it "uninstalls a plugin successfully" do
      process_result = double("ProcessInfo", name: "process_123")

      expect(OpenC3::ProcessManager.instance).to receive(:spawn).with(
        ["ruby", "/openc3/bin/openc3cli", "unload", "TEST_PLUGIN", "DEFAULT"],
        "plugin_uninstall",
        "TEST_PLUGIN",
        anything,
        hash_including(scope: "DEFAULT")
      ).and_return(process_result)

      delete :destroy, params: {id: "TEST_PLUGIN", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      expect(response.body).to eq("process_123")
    end

    it "handles errors during uninstallation" do
      allow(OpenC3::ProcessManager.instance).to receive(:spawn).and_raise(StandardError.new("Uninstall failed"))

      delete :destroy, params: {id: "TEST_PLUGIN", scope: "DEFAULT"}
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("Uninstall failed")
    end

    it "returns nothing without authorization" do
      delete :destroy, params: {id: "TEST_PLUGIN"}
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "POST migrate_to_uv" do
    it "spawns a migratetouv process and returns its name" do
      process = double("process", name: "process_1")
      expect(OpenC3::ProcessManager.instance).to receive(:spawn).with(
        ["ruby", "/openc3/bin/openc3cli", "migratetouv", "TEST_PLUGIN", "DEFAULT"],
        "plugin_migrate_to_uv", "TEST_PLUGIN", anything, scope: "DEFAULT"
      ).and_return(process)

      post :migrate_to_uv, params: {id: "TEST_PLUGIN", scope: "DEFAULT"}
      expect(response).to have_http_status(:ok)
      expect(response.body).to include("process_1")
    end

    it "returns error when spawn raises" do
      expect(OpenC3::ProcessManager.instance).to receive(:spawn).and_raise(RuntimeError.new("Spawn failed"))

      post :migrate_to_uv, params: {id: "TEST_PLUGIN", scope: "DEFAULT"}
      expect(response).to have_http_status(:internal_server_error)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
    end

    it "returns nothing without authorization" do
      post :migrate_to_uv, params: {id: "TEST_PLUGIN"}
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "check_localhost_reachability" do
    before(:each) do
      setting = {"name" => "store_api_key", "data" => "super-secret-store-key"}
      allow(OpenC3::SettingModel).to receive(:get).with(name: "store_api_key", scope: "DEFAULT").and_return(setting)
    end

    def with_local_http_server(status_line)
      server = TCPServer.new("127.0.0.1", 0)
      port = server.addr[1]
      requests = []
      thread = Thread.new do
        client = server.accept
        request = +""
        while (line = client.gets) && line != "\r\n"
          request << line
        end
        requests << request
        client.write("HTTP/1.1 #{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        client.close
      end
      yield port, requests
      thread.join(2)
    ensure
      server.close
    end

    it "returns non-localhost urls untouched without probing" do
      expect(Net::HTTP).not_to receive(:start)
      url = "https://store.openc3.com/gems/test-1.0.0.gem"
      expect(controller.check_localhost_reachability(url, 7)).to eq(url)
    end

    it "probes localhost without sending the store API key" do
      with_local_http_server("200 OK") do |port, requests|
        url = "http://127.0.0.1:#{port}/gems/test-1.0.0.gem"
        expect(controller.check_localhost_reachability(url, 7)).to eq(url)
        expect(requests.length).to eq(1)
        expect(requests.first).to match(%r{\AGET /api/v1.2/cosmos_plugins/7 HTTP/1.1})
        expect(requests.first).not_to match(/authorization/i)
        expect(requests.first).not_to include("super-secret-store-key")
      end
    end

    it "treats an unauthenticated 401 as reachable" do
      with_local_http_server("401 Unauthorized") do |port, requests|
        url = "http://localhost:#{port}/gems/test-1.0.0.gem"
        expect(controller.check_localhost_reachability(url, 7)).to eq(url)
        expect(requests.first).not_to match(/authorization/i)
      end
    end

    it "uses TLS when the gem url is https" do
      response = double("response", code: "200")
      expect(Net::HTTP).to receive(:start).with("localhost", 8443, use_ssl: true) do |&block|
        http = double("http")
        expect(http).to receive(:request) do |req|
          expect(req["Authorization"]).to be_nil
          expect(req.path).to eq("/api/v1.2/cosmos_plugins/7")
          response
        end
        block.call(http)
      end
      url = "https://localhost:8443/gems/test-1.0.0.gem"
      expect(controller.check_localhost_reachability(url, 7)).to eq(url)
    end

    it "falls back to host.docker.internal when localhost is unreachable" do
      response = double("response", code: "200")
      expect(Net::HTTP).to receive(:start).with("localhost", 3000, use_ssl: false).and_raise(Errno::ECONNREFUSED)
      expect(Net::HTTP).to receive(:start).with("host.docker.internal", 3000, use_ssl: false) do |&block|
        http = double("http")
        expect(http).to receive(:request) do |req|
          expect(req["Authorization"]).to be_nil
          response
        end
        block.call(http)
      end
      url = "http://localhost:3000/gems/test-1.0.0.gem"
      expect(controller.check_localhost_reachability(url, 7)).to eq("http://host.docker.internal:3000/gems/test-1.0.0.gem")
    end

    it "returns nil when neither host is reachable" do
      allow(Net::HTTP).to receive(:start).and_raise(Errno::ECONNREFUSED)
      expect(controller.check_localhost_reachability("http://localhost:3000/gems/test-1.0.0.gem", 7)).to be_nil
    end

    it "does not treat a 404 as reachable" do
      with_local_http_server("404 Not Found") do |port, _requests|
        allow(Net::HTTP).to receive(:start).and_call_original
        allow(Net::HTTP).to receive(:start).with("host.docker.internal", port, use_ssl: false).and_raise(Errno::ECONNREFUSED)
        expect(controller.check_localhost_reachability("http://127.0.0.1:#{port}/gems/test-1.0.0.gem", 7)).to be_nil
      end
    end
  end
end
