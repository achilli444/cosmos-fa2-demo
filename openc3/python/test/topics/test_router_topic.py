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

import unittest
from unittest.mock import patch

from openc3.packets.packet import Packet
from openc3.system.system import System
from openc3.topics.router_topic import RouterTopic
from test.test_helper import mock_redis, setup_system


class TestRouterTopic(unittest.TestCase):
    def setUp(self):
        mock_redis(self)
        setup_system()

    @patch("openc3.topics.router_topic.Topic.write_topic")
    def test_route_command_records_router_identity(self, write_topic):
        packet = System.commands.packet("INST", "ABORT")
        packet.restore_defaults()
        RouterTopic.route_command(
            packet, ["INST"], scope="DEFAULT", username="MY_ROUTER", cmd_string='cmd("INST ABORT")', log_message=False
        )
        topic, msg_hash = write_topic.call_args.args[0:2]
        self.assertEqual(topic, "{DEFAULT__CMD}TARGET__INST")
        self.assertEqual(msg_hash["target_name"], "INST")
        self.assertEqual(msg_hash["cmd_name"], "ABORT")
        self.assertEqual(msg_hash["cmd_buffer"], bytes(packet.buffer_no_copy()))
        self.assertEqual(msg_hash["username"], "MY_ROUTER")
        self.assertEqual(msg_hash["cmd_string"], 'cmd("INST ABORT")')
        self.assertEqual(msg_hash["log_message"], "False")

    @patch("openc3.topics.router_topic.Topic.write_topic")
    def test_route_command_records_router_identity_on_unidentified_commands(self, write_topic):
        packet = Packet(None, None)
        packet.buffer = b"\x00\x01"
        RouterTopic.route_command(packet, ["INST"], scope="DEFAULT", username="MY_ROUTER")
        topic, msg_hash = write_topic.call_args.args[0:2]
        self.assertEqual(topic, "{DEFAULT__CMD}TARGET__INST")
        self.assertEqual(msg_hash["target_name"], "UNKNOWN")
        self.assertEqual(msg_hash["cmd_name"], "UNKNOWN")
        self.assertEqual(msg_hash["username"], "MY_ROUTER")
        self.assertEqual(msg_hash["log_message"], "True")

    @patch("openc3.topics.router_topic.Topic.write_topic")
    def test_route_command_defaults(self, write_topic):
        packet = System.commands.packet("INST", "ABORT")
        packet.restore_defaults()
        RouterTopic.route_command(packet, ["INST"], scope="DEFAULT")
        msg_hash = write_topic.call_args.args[1]
        self.assertNotIn("username", msg_hash)
        self.assertNotIn("cmd_string", msg_hash)
        self.assertEqual(msg_hash["log_message"], "True")
