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
require "openc3/utilities/aws_bucket"
require 'openc3/utilities/script'

RSpec.describe ScriptsController, type: :controller do
  before(:each) do
    ENV.delete("OPENC3_LOCAL_MODE")
    mock_redis
  end

  describe "ping" do
    it "returns OK" do
      get :ping
      expect(response.body).to eq("OK")
      expect(response).to have_http_status(:ok)
    end
  end

  describe "index" do
    it "returns all scripts" do
      scripts = [
        {"name" => "script1.rb", "modified_time" => Time.now.to_s},
        {"name" => "script2.rb", "modified_time" => Time.now.to_s}
      ]
      expect(Script).to receive(:all).with("DEFAULT", nil).and_return(scripts)

      get :index, params: {scope: "DEFAULT"}

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json.length).to eq(2)
      expect(json[0]["name"]).to eq("script1.rb")
    end

    it "returns scripts filtered by target" do
      scripts = [
        {"name" => "INST/script1.rb", "modified_time" => Time.now.to_s}
      ]
      expect(Script).to receive(:all).with("DEFAULT", "INST").and_return(scripts)

      get :index, params: {scope: "DEFAULT", target: "INST"}

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json.length).to eq(1)
      expect(json[0]["name"]).to eq("INST/script1.rb")
    end

    it "handles authorization failure" do
      get :index

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "delete_temp" do
    it "deletes temporary scripts" do
      deleted_files = ["temp/script1.rb", "temp/script2.rb"]
      expect(Script).to receive(:delete_temp).with("DEFAULT").and_return(deleted_files)

      post :delete_temp, params: {scope: "DEFAULT"}

      expect(response).to have_http_status(:ok)
      expect(JSON.parse(response.body).length).to eq(2)
    end

    it "handles authorization failure" do
      post :delete_temp

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "create" do
    it "creates a script when none exist" do
      s3 = instance_double("Aws::S3::Client")
      # nil means no script exists
      allow(s3).to receive(:get_object).and_return(nil)
      # Expect to call put_object to store the new script
      expect(s3).to receive(:put_object)
      expect(s3).to receive(:wait_until)
      allow(Aws::S3::Client).to receive(:new).and_return(s3)

      post :create, params: {scope: "DEFAULT", name: "script.rb", text: "text"}
      expect(response).to have_http_status(:ok)
    end

    it "saves when text changes" do
      s3 = instance_double("Aws::S3::Client")
      # Simulate returning a file with 'new text'
      file = double("file")
      allow(file).to receive_message_chain(:body, read: "new text")
      expect(s3).to receive(:get_object).and_return(file)
      # Expect to call put_object to store the changed script
      expect(s3).to receive(:put_object)
      expect(s3).to receive(:wait_until)
      allow(Aws::S3::Client).to receive(:new).and_return(s3)

      post :create, params: {scope: "DEFAULT", name: "script.rb", text: "text"}
      expect(response).to have_http_status(:ok)
    end

    it "does not save when text is the same" do
      s3 = instance_double("Aws::S3::Client")
      # Simulate returning a file with identical 'text'
      file = double("file")
      allow(file).to receive_message_chain(:body, read: "text")
      expect(s3).to receive(:get_object).and_return(file)
      expect(s3).to_not receive(:put_object)
      allow(Aws::S3::Client).to receive(:new).and_return(s3)

      post :create, params: {scope: "DEFAULT", name: "script.rb", text: "text"}
      expect(response).to have_http_status(:ok)
    end

    it "does not pass params which aren't permitted" do
      expect(Script).to receive(:create) do |params|
        # Check that we don't pass extra params
        expect(params.keys).to eql(%w[text breakpoints scope name])
      end
      post :create, params: {scope: "DEFAULT", name: "script.rb", text: "text", breakpoints: [1], other: "nope"}
      expect(response).to have_http_status(:ok)
    end
  end

  describe "run" do
    it "returns an ok response" do
      expect(Script).to receive(:run).with("DEFAULT", "INST/procedures/test.rb", nil, false, nil, "Anonymous", "anonymous", 1, nil).and_return(1)
      post :run, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}
      expect(response).to have_http_status(:ok)
    end

    it "returns an error response" do
      expect(Script).to receive(:run).with("DEFAULT", "INST/procedures/test.rb", nil, false, nil, "Anonymous", "anonymous", 1, nil)
      post :run, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}
      expect(response).to have_http_status(:not_found)
    end
  end

  describe "body" do
    it "returns script content when the script exists" do
      script_content = "puts 'Hello World'"
      breakpoints = [1, 5]

      expect(Script).to receive(:body).with("DEFAULT", "INST/procedures/test.rb").and_return(script_content)
      expect(Script).to receive(:locked?).with("DEFAULT", "INST/procedures/test.rb").and_return(false)
      expect(Script).to receive(:lock).with("DEFAULT", "INST/procedures/test.rb", "anonymous")
      expect(Script).to receive(:get_breakpoints).with("DEFAULT", "INST/procedures/test.rb").and_return(breakpoints)

      get :body, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["contents"]).to eq(script_content)
      expect(json["breakpoints"]).to eq(breakpoints)
      expect(json["locked"]).to eq(false)
    end

    it "does not lock script if already locked" do
      script_content = "puts 'Hello World'"
      breakpoints = [1, 5]

      expect(Script).to receive(:body).with("DEFAULT", "INST/procedures/test.rb").and_return(script_content)
      expect(Script).to receive(:locked?).with("DEFAULT", "INST/procedures/test.rb").and_return(true)
      expect(Script).not_to receive(:lock)
      expect(Script).to receive(:get_breakpoints).with("DEFAULT", "INST/procedures/test.rb").and_return(breakpoints)

      get :body, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["contents"]).to eq(script_content)
      expect(json["locked"]).to eq(true)
    end

    it "processes suite files correctly" do
      script_content = "class TestSuite < OpenC3::Suite\n  def test_method\n    puts 'test'\n  end\nend"
      breakpoints = []
      suites_data = "{\"suites\":[]}"

      expect(Script).to receive(:body).with("DEFAULT", "INST/procedures/test.rb").and_return(script_content)
      expect(Script).to receive(:locked?).with("DEFAULT", "INST/procedures/test.rb").and_return(false)
      expect(Script).to receive(:lock).with("DEFAULT", "INST/procedures/test.rb", "anonymous")
      expect(Script).to receive(:get_breakpoints).with("DEFAULT", "INST/procedures/test.rb").and_return(breakpoints)
      expect(Script).to receive(:process_suite).with("INST/procedures/test.rb", script_content, username: "anonymous", scope: "DEFAULT").and_return([suites_data, nil, true])

      get :body, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["contents"]).to eq(script_content)
      expect(json["suites"]).to eq(suites_data)
      expect(json["success"]).to eq(true)
    end

    it "processes Python suite files correctly" do
      script_content = "class TestSuite(Suite):\n  def test_method(self):\n    print('test')\n"
      breakpoints = []
      suites_data = "{\"suites\":[]}"

      expect(Script).to receive(:body).with("DEFAULT", "INST/procedures/test.py").and_return(script_content)
      expect(Script).to receive(:locked?).with("DEFAULT", "INST/procedures/test.py").and_return(false)
      expect(Script).to receive(:lock).with("DEFAULT", "INST/procedures/test.py", "anonymous")
      expect(Script).to receive(:get_breakpoints).with("DEFAULT", "INST/procedures/test.py").and_return(breakpoints)
      expect(Script).to receive(:process_suite).with("INST/procedures/test.py", script_content, username: "anonymous", scope: "DEFAULT").and_return([suites_data, nil, true])

      get :body, params: {scope: "DEFAULT", name: "INST/procedures/test.py"}

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["contents"]).to eq(script_content)
      expect(json["suites"]).to eq(suites_data)
      expect(json["success"]).to eq(true)
    end

    it "returns not found when script does not exist" do
      expect(Script).to receive(:body).with("DEFAULT", "INST/procedures/nonexistent.rb").and_return(nil)
      get :body, params: {scope: "DEFAULT", name: "INST/procedures/nonexistent.rb"}

      expect(response).to have_http_status(:not_found)
    end

    it "handles authorization failure" do
      get :body, params: {name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "lock" do
    it "locks a script" do
      expect(Script).to receive(:lock).with("DEFAULT", "INST/procedures/test.rb", "anonymous")

      post :lock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
    end

    it "handles authorization failure" do
      post :lock, params: {name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "unlock" do
    it "unlocks a script that is locked by the user" do
      expect(Script).to receive(:locked?).with("DEFAULT", "INST/procedures/test.rb").and_return("anonymous")
      expect(Script).to receive(:unlock).with("DEFAULT", "INST/procedures/test.rb")

      post :unlock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
    end

    it "does not unlock a script locked by another user" do
      expect(Script).to receive(:locked?).with("DEFAULT", "INST/procedures/test.rb").and_return("another_user")
      expect(Script).not_to receive(:unlock)

      post :unlock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
    end

    it "handles authorization failure" do
      post :unlock, params: {name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "destroy" do
    it "destroys a script" do
      expect(Script).to receive(:destroy).with("DEFAULT", "INST/procedures/test.rb")
      allow(OpenC3::Logger).to receive(:info)

      delete :destroy, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
    end

    it "handles exceptions" do
      expect(Script).to receive(:destroy).with("DEFAULT", "INST/procedures/test.rb").and_raise("Destruction failed")
      allow_any_instance_of(ScriptsController).to receive(:log_error)

      delete :destroy, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(500)
      json = JSON.parse(response.body)
      expect(json["status"]).to eq("error")
      expect(json["message"]).to eq("Destruction failed")
    end

    it "handles authorization failure" do
      delete :destroy, params: {name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "delete_all_breakpoints" do
    it "deletes all breakpoints" do
      # Need to mock OpenC3::Store directly
      mock_redis
      expect_any_instance_of(OpenC3::Store).to receive(:method_missing).with(:del, "DEFAULT__script-breakpoints")

      post :delete_all_breakpoints, params: {scope: "DEFAULT"}

      expect(response).to have_http_status(:ok)
    end

    it "handles authorization failure" do
      post :delete_all_breakpoints

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "syntax" do
    it "checks Ruby syntax successfully" do
      valid_script = "puts 'Hello World'"

      expect(Script).to receive(:syntax).with("script.rb", valid_script).and_return({
        "title" => "Syntax Check Successful",
        "description" => ["Syntax OK"]
      })

      post :syntax, params: {name: "script.rb", scope: "DEFAULT"}, body: valid_script

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["title"]).to eq("Syntax Check Successful")
    end

    it "reports Ruby syntax errors" do
      invalid_script = "puts 'Hello World"

      expect(Script).to receive(:syntax).with("script.rb", invalid_script).and_return({
        "title" => "Syntax Check Failed",
        "description" => ["2: syntax error, unexpected end-of-input"]
      })

      post :syntax, params: {name: "script.rb", scope: "DEFAULT"}, body: invalid_script

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["title"]).to eq("Syntax Check Failed")
    end

    it "handles authorization failure" do
      post :syntax, params: {name: "INST/procedures/script.rb"}

      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe "instrumented" do
    it "returns instrumented script" do
      script = "puts 'Hello World'"
      instrumented_result = {
        "title" => "Instrumented Script",
        "description" => "[\"instrumented code here\"]"
      }

      expect(Script).to receive(:instrumented).with("script.rb", script).and_return(instrumented_result)

      post :instrumented, params: {name: "script.rb", scope: "DEFAULT"}, body: script

      expect(response).to have_http_status(:ok)
      json = JSON.parse(response.body)
      expect(json["title"]).to eq("Instrumented Script")
    end

    it "handles authorization failure" do
      post :instrumented, params: {name: "script.rb"}

      expect(response).to have_http_status(:unauthorized)
    end
  end
  describe "audit records" do
    # CNSSP 12 para 9 / 16.e: state changes and denied requests must leave a
    # user-attributed record. See ApplicationController#audit_request.
    def capture_audit(level)
      records = []
      allow(OpenC3::Logger).to receive(level) do |message, **options|
        records << [message, options]
      end
      records
    end

    it "logs an ordinary (non-suite) script save" do
      allow(Script).to receive(:create)
      records = capture_audit(:info)

      post :create, params: {scope: "DEFAULT", name: "INST/procedures/test.rb", text: "puts 1"}

      expect(response).to have_http_status(:ok)
      expect(records.length).to eq(1)
      message, options = records[0]
      expect(message).to eq("Script saved: INST/procedures/test.rb")
      expect(options[:scope]).to eq("DEFAULT")
      expect(options[:user]).to eq("anonymous")
      expect(options[:other]).to include(
        audit: 'script-api', action: 'create', script: 'INST/procedures/test.rb',
        status: 200, outcome: 'success', permission: 'script_edit'
      )
    end

    it "logs a suite save even when suite analysis fails" do
      suite = "class TestSuite < OpenC3::Suite\nend"
      allow(Script).to receive(:create)
      expect(Script).to receive(:process_suite).and_return([nil, "analysis failed", false])
      records = capture_audit(:info)

      post :create, params: {scope: "DEFAULT", name: "INST/procedures/suite.rb", text: suite}

      expect(response).to have_http_status(:ok)
      expect(records.length).to eq(1)
      expect(records[0][0]).to eq("Script saved: INST/procedures/suite.rb")
      expect(records[0][1][:other]).to include(suite: true, suite_success: false)
    end

    it "logs the script save as a failure when Script.create raises" do
      allow(Script).to receive(:create).and_raise("bucket unavailable")
      allow_any_instance_of(ScriptsController).to receive(:log_error)
      records = capture_audit(:warn)

      post :create, params: {scope: "DEFAULT", name: "INST/procedures/test.rb", text: "puts 1"}

      expect(response).to have_http_status(500)
      expect(records.length).to eq(1)
      expect(records[0][0]).to eq("scripts#create error: INST/procedures/test.rb")
      expect(records[0][1][:other]).to include(status: 500, outcome: 'error')
    end

    it "logs temp script deletion with the number of files removed" do
      expect(Script).to receive(:delete_temp).with("DEFAULT").and_return(["temp/a.rb", "temp/b.rb"])
      records = capture_audit(:info)

      delete :delete_temp, params: {scope: "DEFAULT"}

      expect(response).to have_http_status(:ok)
      expect(records.length).to eq(1)
      expect(records[0][0]).to eq("Temp scripts deleted")
      expect(records[0][1][:user]).to eq("anonymous")
      expect(records[0][1][:other]).to include(action: 'delete_temp', outcome: 'success', deleted: 2)
    end

    it "logs the scope-wide breakpoint wipe" do
      mock_redis
      allow_any_instance_of(OpenC3::Store).to receive(:method_missing).with(:del, "DEFAULT__script-breakpoints")
      records = capture_audit(:info)

      delete :delete_all_breakpoints, params: {scope: "DEFAULT"}

      expect(response).to have_http_status(:ok)
      expect(records.length).to eq(1)
      expect(records[0][0]).to eq("All breakpoints deleted")
      expect(records[0][1]).to include(scope: "DEFAULT", user: "anonymous")
      expect(records[0][1][:other]).to include(action: 'delete_all_breakpoints', outcome: 'success')
    end

    it "logs lock, unlock, run and destroy" do
      allow(Script).to receive(:lock)
      allow(Script).to receive(:locked?).and_return("anonymous")
      allow(Script).to receive(:unlock)
      allow(Script).to receive(:run).and_return(7)
      allow(Script).to receive(:destroy)
      records = capture_audit(:info)

      post :lock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}
      post :unlock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}
      post :run, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}
      delete :destroy, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      messages = [
        "Script locked: INST/procedures/test.rb",
        "Script unlocked: INST/procedures/test.rb",
        "Script started: INST/procedures/test.rb",
        "Script destroyed: INST/procedures/test.rb",
      ]
      expect(records.map(&:first)).to eq(messages)
      expect(records[2][1][:other]).to include(running_script_id: 7, permission: 'script_run', target: 'INST')
    end

    it "records an unlock attempt on a script locked by another user as skipped" do
      allow(Script).to receive(:locked?).and_return("someone_else")
      expect(Script).not_to receive(:unlock)
      records = capture_audit(:warn)

      post :unlock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
      expect(records.length).to eq(1)
      expect(records[0][0]).to eq("scripts#unlock skipped: INST/procedures/test.rb")
      expect(records[0][1][:other]).to include(outcome: 'skipped', locked_by: 'someone_else')
    end

    it "does not log successful read-only requests" do
      allow(Script).to receive(:all).and_return([])
      expect(OpenC3::Logger).not_to receive(:info)
      expect(OpenC3::Logger).not_to receive(:warn)

      get :index, params: {scope: "DEFAULT"}

      expect(response).to have_http_status(:ok)
    end

    it "logs a WARN for unauthorized requests on any endpoint without the token" do
      request.headers['Authorization'] = 'super-secret-token'
      records = capture_audit(:warn)

      get :index, params: {name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:unauthorized)
      expect(records.length).to eq(1)
      message, options = records[0]
      expect(message).to eq("scripts#index unauthorized: INST/procedures/test.rb")
      expect(options[:other]).to include(
        action: 'index', status: 401, outcome: 'unauthorized',
        permission: 'script_view', reason: 'Scope is required', path: '/script-api/scripts'
      )
      expect(options.to_s).not_to include('super-secret-token')
    end

    it "logs a WARN for forbidden requests" do
      allow_any_instance_of(ScriptsController).to receive(:authorize).and_raise(OpenC3::ForbiddenError.new("Insufficient permission"))
      records = capture_audit(:warn)

      delete :destroy, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:forbidden)
      expect(records.length).to eq(1)
      expect(records[0][0]).to eq("scripts#destroy forbidden: INST/procedures/test.rb")
      expect(records[0][1]).to include(scope: "DEFAULT")
      expect(records[0][1][:other]).to include(
        status: 403, outcome: 'forbidden', permission: 'script_edit', reason: 'Insufficient permission'
      )
    end

    it "still writes a record when an audited action raises" do
      allow(Script).to receive(:lock).and_raise("redis down")
      records = capture_audit(:warn)

      expect { post :lock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"} }.to raise_error("redis down")

      expect(records.length).to eq(1)
      expect(records[0][0]).to eq("scripts#lock error: INST/procedures/test.rb")
      expect(records[0][1][:other]).to include(status: 500, outcome: 'error', error: 'RuntimeError')
    end

    it "never lets an audit failure break the request" do
      allow(Script).to receive(:lock)
      allow(OpenC3::Logger).to receive(:info).and_raise("logger down")
      expect_any_instance_of(ScriptsController).to receive(:log_error)

      post :lock, params: {scope: "DEFAULT", name: "INST/procedures/test.rb"}

      expect(response).to have_http_status(:ok)
    end
  end
end
