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

"""Deployment-wide policy for command and telemetry links.

Every network interface shipped with COSMOS calls ``check`` from its connect
method with a description of the transport and whether that transport is
encrypted (TLS) or carries an authenticated-encryption protocol. The outcome
depends on ``OPENC3_REQUIRE_ENCRYPTED_LINKS``:

* unset / false (default, backwards compatible): plaintext links connect but a
  warning is logged every time so the unencrypted path is visible in the audit log.
* true / 1 / yes: plaintext links are refused with ``PlaintextLinkError`` unless
  the interface carries ``OPTION ALLOW_PLAINTEXT true``, which records an
  explicitly approved bypass. The bypass is still logged as a warning.
"""

import os

from openc3.config.config_parser import ConfigParser
from openc3.utilities.logger import Logger


ENV_VAR = "OPENC3_REQUIRE_ENCRYPTED_LINKS"
BYPASS_OPTION = "ALLOW_PLAINTEXT"
TRUE_VALUES = ("true", "1", "yes", "on")


class PlaintextLinkError(RuntimeError):
    """Raised when an interface would carry commands or telemetry over a plaintext
    link while the deployment policy requires encrypted links."""


def require_encrypted_links():
    return os.environ.get(ENV_VAR, "").strip().lower() in TRUE_VALUES


def plaintext_allowed(options):
    values = options.get(BYPASS_OPTION)
    if values is None:
        return False
    value = values[0] if isinstance(values, list | tuple) else values
    if value is None or value == []:
        return True  # bare OPTION ALLOW_PLAINTEXT
    return ConfigParser.handle_true_false(value) is True


def aead_protocol(protocols):
    return any(getattr(protocol, "authenticated_encryption", lambda: False)() for protocol in protocols)


def check(interface, transport, encrypted=False):
    """Evaluate the policy for an interface about to connect.

    Returns True when the link is protected, False when plaintext was permitted
    (and logged) and raises PlaintextLinkError when policy refuses the link.
    """
    if encrypted:
        return True

    read_protected = (not interface.read_allowed) or aead_protocol(interface.read_protocols)
    write_protected = (not interface.write_allowed) or aead_protocol(interface.write_protocols)
    if read_protected and write_protected:
        return True

    name = interface.name
    if plaintext_allowed(interface.options):
        Logger.warn(
            f"{name}: plaintext link {transport} permitted by {BYPASS_OPTION} (approved cryptographic bypass); "
            "commands and telemetry are not encrypted on this link"
        )
        return False

    if require_encrypted_links():
        raise PlaintextLinkError(
            f"{name}: refusing plaintext link {transport}: {ENV_VAR} is set. Enable TLS, add an authenticated "
            f"encryption PROTOCOL, or record an approved bypass with OPTION {BYPASS_OPTION} true"
        )

    Logger.warn(
        f"{name}: plaintext link {transport}: commands and telemetry are not encrypted on this link "
        f"(set {ENV_VAR}=true to refuse plaintext links)"
    )
    return False
