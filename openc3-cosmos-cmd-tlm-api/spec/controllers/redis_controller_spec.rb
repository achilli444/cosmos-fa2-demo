# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

require "rails_helper"

RSpec.describe RedisController, type: :controller do
  before(:each) do
    mock_redis
    allow(OpenC3::Logger).to receive(:info)
  end

  describe "#execute_raw" do
    it "rejects disallowed commands" do
      request.content_type = "text/plain"
      post :execute_raw, body: "AUTH password", params: {scope: "DEFAULT"}
      expect(response).to have_http_status(:unprocessable_content)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("The AUTH command is not allowed.")
    end

    it "executes command on main store" do
      expect_any_instance_of(OpenC3::Store).to receive(:method_missing).with(:GET, ["key"]).and_return("value")
      request.content_type = "text/plain"
      post :execute_raw, body: "GET key", params: {scope: "DEFAULT"}
      expect(response).to have_http_status(:created)
      json = JSON.parse(response.body)
      expect(json["result"]).to eq("value")
    end

    it "executes command on ephemeral store" do
      expect_any_instance_of(OpenC3::EphemeralStore).to receive(:method_missing).with(:SET, ["key", "value"]).and_return("OK")
      request.content_type = "text/plain"
      post :execute_raw, body: "SET key value", params: {ephemeral: true, scope: "DEFAULT"}
      expect(response).to have_http_status(:created)
      json = JSON.parse(response.body)
      expect(json["result"]).to eq("OK")
    end

    it "logs the key name but never the stored value or result" do
      expect_any_instance_of(OpenC3::Store).to receive(:method_missing).with(:HGET, ["DEFAULT__openc3__secrets", "API_KEY"]).and_return("s3cr3t-value")
      expect(OpenC3::Logger).to receive(:info) do |message, **kwargs|
        expect(message).to include("HGET DEFAULT__openc3__secrets")
        expect(message).to include("Redis command executed")
        expect(message).to include("result String (12)")
        expect(message).not_to include("s3cr3t-value")
        expect(message).not_to include("API_KEY")
        expect(kwargs[:user]).to eq("anonymous")
      end
      request.content_type = "text/plain"
      post :execute_raw, body: "HGET DEFAULT__openc3__secrets API_KEY", params: {scope: "DEFAULT"}
      expect(response).to have_http_status(:created)
      expect(JSON.parse(response.body)["result"]).to eq("s3cr3t-value")
    end

    it "never logs written values" do
      expect_any_instance_of(OpenC3::Store).to receive(:method_missing).with(:HSET, ["DEFAULT__openc3__secrets", "API_KEY", "hunter2"]).and_return(1)
      expect(OpenC3::Logger).to receive(:info) do |message, **_kwargs|
        expect(message).to include("HSET DEFAULT__openc3__secrets (3 args)")
        expect(message).to include("result 1")
        expect(message).not_to include("hunter2")
      end
      request.content_type = "text/plain"
      post :execute_raw, body: "HSET DEFAULT__openc3__secrets API_KEY hunter2", params: {scope: "DEFAULT"}
      expect(response).to have_http_status(:created)
    end

    it "logs only the command name for commands whose arguments are not key names" do
      expect_any_instance_of(OpenC3::EphemeralStore).to receive(:method_missing).with(:EVAL, ["return", "redis.call('GET','DEFAULT__openc3__secrets')", "0"]).and_return(["a", "b"])
      expect(OpenC3::Logger).to receive(:info) do |message, **_kwargs|
        expect(message).to include("OpenC3::EphemeralStore db_shard 2: EVAL (3 args)")
        expect(message).to include("result Array (2)")
        expect(message).not_to include("redis.call")
        expect(message).not_to include("openc3__secrets")
      end
      request.content_type = "text/plain"
      post :execute_raw, body: "EVAL return redis.call('GET','DEFAULT__openc3__secrets') 0", params: {ephemeral: true, db_shard: 2, scope: "DEFAULT"}
      expect(response).to have_http_status(:created)
    end

    it "logs a failure without the arguments when the command raises" do
      expect_any_instance_of(OpenC3::Store).to receive(:method_missing).with(:HSET, ["DEFAULT__openc3__secrets", "API_KEY", "hunter2"]).and_raise(Redis::CommandError, "WRONGTYPE hunter2")
      expect(OpenC3::Logger).to receive(:info) do |message, **_kwargs|
        expect(message).to include("Redis command failed (OpenC3::Store db_shard 0: HSET DEFAULT__openc3__secrets (3 args)): Redis::CommandError")
        expect(message).not_to include("hunter2")
      end
      request.content_type = "text/plain"
      expect {
        post :execute_raw, body: "HSET DEFAULT__openc3__secrets API_KEY hunter2", params: {scope: "DEFAULT"}
      }.to raise_error(Redis::CommandError)
    end

    it "requires admin access" do
      request.content_type = "text/plain"
      post :execute_raw, body: "GET key"
      expect(response).to have_http_status(:unauthorized)
    end
  end
end
