# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software; you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/topics/router_topic'

module OpenC3
  describe RouterTopic do
    before(:each) do
      mock_redis()
      setup_system()
    end

    describe "self.route_command" do
      it "records the router identity, cmd_string and log_message on identified commands" do
        packet = System.commands.packet('INST', 'ABORT')
        packet.restore_defaults
        expect(Topic).to receive(:write_topic) do |topic, msg_hash|
          expect(topic).to eql "{DEFAULT__CMD}TARGET__INST"
          expect(msg_hash['target_name']).to eql 'INST'
          expect(msg_hash['cmd_name']).to eql 'ABORT'
          expect(msg_hash['cmd_buffer']).to eql packet.buffer(false)
          expect(msg_hash['username']).to eql 'MY_ROUTER'
          expect(msg_hash['cmd_string']).to eql 'cmd("INST ABORT")'
          expect(msg_hash['log_message']).to eql 'false'
        end
        RouterTopic.route_command(packet, ['INST'], scope: 'DEFAULT', username: 'MY_ROUTER', cmd_string: 'cmd("INST ABORT")', log_message: false)
      end

      it "records the router identity on unidentified commands" do
        packet = Packet.new(nil, nil)
        packet.buffer = "\x00\x01"
        expect(Topic).to receive(:write_topic) do |topic, msg_hash|
          expect(topic).to eql "{DEFAULT__CMD}TARGET__INST"
          expect(msg_hash['target_name']).to eql 'UNKNOWN'
          expect(msg_hash['cmd_name']).to eql 'UNKNOWN'
          expect(msg_hash['username']).to eql 'MY_ROUTER'
          expect(msg_hash['log_message']).to eql 'true'
        end
        RouterTopic.route_command(packet, ['INST'], scope: 'DEFAULT', username: 'MY_ROUTER')
      end

      it "defaults to log_message true without a username when not given" do
        packet = System.commands.packet('INST', 'ABORT')
        packet.restore_defaults
        expect(Topic).to receive(:write_topic) do |_topic, msg_hash|
          expect(msg_hash).not_to have_key('username')
          expect(msg_hash).not_to have_key('cmd_string')
          expect(msg_hash['log_message']).to eql 'true'
        end
        RouterTopic.route_command(packet, ['INST'], scope: 'DEFAULT')
      end
    end
  end
end
