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

require 'spec_helper'
require 'openc3/topics/interface_topic'

module OpenC3
  describe InterfaceTopic do
    before(:each) do
      mock_redis()
      allow(InterfaceTopic).to receive(:_db_shard_for_interface).and_return(0)
      allow(Topic).to receive(:update_topic_offsets)
      allow(Topic).to receive(:write_topic).and_return("1234-0")
    end

    # Yield a single ack message carrying the given result for the cmd_id
    # returned by the stubbed write_topic
    def stub_ack(result)
      allow(Topic).to receive(:read_topics) do |_topics, **_kwargs, &block|
        block.call("ACKTOPIC", "1234-1", { "id" => "1234-0", "result" => result }, nil)
      end
    end

    describe "directives" do
      it "carry the acting username so the microservice can attribute the action" do
        expect(Topic).to receive(:write_topic).with("{DEFAULT__CMD}INTERFACE__INST_INT", { 'connect' => 'true', 'username' => 'alice' }, '*', 100, db_shard: 0)
        InterfaceTopic.connect_interface("INST_INT", username: 'alice', scope: "DEFAULT")

        expect(Topic).to receive(:write_topic).with("{DEFAULT__CMD}INTERFACE__INST_INT", { 'disconnect' => 'true', 'username' => 'alice' }, '*', 100, db_shard: 0)
        InterfaceTopic.disconnect_interface("INST_INT", username: 'alice', scope: "DEFAULT")

        expect(Topic).to receive(:write_topic).with("{DEFAULT__CMD}INTERFACE__INST_INT", hash_including('target_control', 'username' => 'alice'), '*', 100, db_shard: 0)
        InterfaceTopic.interface_target_disable("INST_INT", "INST", username: 'alice', scope: "DEFAULT")
      end

      it "omit the username when none is given" do
        expect(Topic).to receive(:write_topic).with("{DEFAULT__CMD}INTERFACE__INST_INT", { 'log_stream' => 'true' }, '*', 100, db_shard: 0)
        InterfaceTopic.start_raw_logging("INST_INT", scope: "DEFAULT")
      end
    end

    describe "interface_details" do
      it "parses the JSON result from the microservice" do
        stub_ack({ 'name' => 'INST_INT', 'state' => 'CONNECTED' }.to_json)
        details = InterfaceTopic.interface_details("INST_INT", scope: "DEFAULT")
        expect(details['name']).to eql "INST_INT"
        expect(details['state']).to eql "CONNECTED"
      end

      it "raises with the error text if the microservice returns a plain error message" do
        # The microservice returns the exception message rather than JSON if
        # details raises, so surface that text instead of a JSON parse error
        stub_ack("undefined method 'foo' for nil")
        expect { InterfaceTopic.interface_details("INST_INT", scope: "DEFAULT") }.to \
          raise_error(/interface_details failed: undefined method 'foo' for nil/)
      end
    end
  end
end
