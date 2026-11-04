# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

import os
import unittest
from unittest.mock import patch

from openc3.script.server_proxy import ApiServerProxy, ScriptServerProxy
from openc3.utilities.authentication import OpenC3AuthenticationError, reset_cleartext_auth_warning
from openc3.utilities.logger import Logger
from test.test_helper import *


class TestApiServerProxyGenerateUrl(unittest.TestCase):
    def setUp(self):
        reset_cleartext_auth_warning()
        self.proxy = ApiServerProxy.__new__(ApiServerProxy)

    @patch("openc3.script.server_proxy.OPENC3_API_SCHEMA", "https")
    @patch("openc3.script.server_proxy.OPENC3_API_PORT", 2901)
    def test_defaults_to_https_in_cluster(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.proxy.generate_url(), "https://openc3-cosmos-cmd-tlm-api:2901")

    @patch("openc3.script.server_proxy.OPENC3_API_SCHEMA", "http")
    @patch("openc3.script.server_proxy.OPENC3_API_PORT", 2901)
    def test_refuses_http_without_opt_in(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(OpenC3AuthenticationError, "cleartext http.*OPENC3_API_SCHEMA"),
        ):
            self.proxy.generate_url()

    @patch("openc3.script.server_proxy.OPENC3_API_SCHEMA", "http")
    @patch("openc3.script.server_proxy.OPENC3_API_PORT", 2901)
    def test_allows_http_with_opt_in_and_warns(self):
        with (
            patch.dict(os.environ, {"OPENC3_ALLOW_INSECURE_AUTH": "true"}, clear=True),
            patch.object(Logger.instance(), "warn") as warn,
        ):
            self.assertEqual(self.proxy.generate_url(), "http://openc3-cosmos-cmd-tlm-api:2901")
        warn.assert_called_once()


class TestScriptServerProxyGenerateUrl(unittest.TestCase):
    def setUp(self):
        reset_cleartext_auth_warning()
        self.proxy = ScriptServerProxy.__new__(ScriptServerProxy)

    @patch("openc3.script.server_proxy.OPENC3_SCRIPT_API_SCHEMA", "https")
    @patch("openc3.script.server_proxy.OPENC3_SCRIPT_API_PORT", 2902)
    def test_defaults_to_https_in_cluster(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.proxy.generate_url(), "https://openc3-cosmos-script-runner-api:2902")

    @patch("openc3.script.server_proxy.OPENC3_SCRIPT_API_SCHEMA", "http")
    @patch("openc3.script.server_proxy.OPENC3_SCRIPT_API_PORT", 2902)
    def test_refuses_http_without_opt_in(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(OpenC3AuthenticationError, "cleartext http.*OPENC3_SCRIPT_API_SCHEMA"),
        ):
            self.proxy.generate_url()

    @patch("openc3.script.server_proxy.OPENC3_SCRIPT_API_SCHEMA", "http")
    @patch("openc3.script.server_proxy.OPENC3_SCRIPT_API_PORT", 2902)
    def test_uses_localhost_over_http_with_openc3_devel(self):
        with (
            patch.dict(os.environ, {"OPENC3_DEVEL": "../openc3"}, clear=True),
            patch.object(Logger.instance(), "warn"),
        ):
            self.assertEqual(self.proxy.generate_url(), "http://127.0.0.1:2902")


if __name__ == "__main__":
    unittest.main()
