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

import hashlib
import hmac

from openc3.models.model import Model


class BridgeModel(Model):
    """Stores the identity of a named Iroh bridge.

    A bridge is the openc3-app/host connection endpoint managed by a
    ``BridgeMicroservice``. This model stores the bridge's public key (its Iroh
    EndpointId) and most recent connection ticket, so a ``BridgeInterface`` can
    look the bridge up by name and dial it. The corresponding **private key is
    kept in the secrets store**, not here. A pending one-time enrollment code is
    stored only as a SHA-256 digest (``enroll_code_hash``), never in plaintext.

    Multiple named bridges are supported (one model per bridge name per scope).
    """

    PRIMARY_KEY = "openc3_bridges"
    ENROLLMENT_CODE_TTL_SECONDS = 10 * 60

    # NOTE: The following class methods are reimplemented so the base Model
    # class methods work with this scoped primary key.
    @classmethod
    def get(cls, name: str, scope: str):
        return super().get(f"{scope}__{cls.PRIMARY_KEY}", name)

    @classmethod
    def names(cls, scope: str):
        return super().names(f"{scope}__{cls.PRIMARY_KEY}")

    @classmethod
    def all(cls, scope: str):
        return super().all(f"{scope}__{cls.PRIMARY_KEY}")

    # END NOTE

    def __init__(
        self,
        name: str,
        scope: str,
        public_key: str = None,
        ticket: str = None,
        app_public_key: str = None,
        enroll_code_hash: str = None,
        enroll_code_generated_at: int = None,
        port: int = None,
        updated_at: int = None,
        plugin: str = None,
        enroll_code: str = None,  # legacy plaintext field: accepted so old records load, never kept
    ):
        super().__init__(
            f"{scope}__{self.PRIMARY_KEY}",
            name=name,
            scope=scope,
            updated_at=updated_at,
            plugin=plugin,
        )
        # The bridge's Iroh public key (EndpointId) as a hex string. The matching
        # private key lives in the secrets store, not in this model.
        self.public_key = public_key
        # Most recent EndpointTicket (endpoint id + addressing), refreshed by
        # the BridgeMicroservice each startup.
        self.ticket = ticket
        # The authorized openc3-app control identity (its Iroh EndpointId, hex).
        # Set during enrollment; the hub only accepts api/* connections from it.
        self.app_public_key = app_public_key
        # SHA-256 hex digest of the pending one-time manual-enrollment code (set
        # when a manual enrollment token is generated; cleared once redeemed over
        # the api/enroll ALPN or once expired). The plaintext code is never stored;
        # legacy plaintext ``enroll_code`` records intentionally fail closed.
        self.enroll_code_hash = enroll_code_hash
        # Unix timestamp set when the one-time code is generated. Codes from
        # records predating this field intentionally fail closed.
        self.enroll_code_generated_at = enroll_code_generated_at
        # Fixed UDP port this bridge's hub binds inside the container. Assigned
        # once from the published range (see compose.yaml) and reused across
        # restarts so the host can always reach the hub at 127.0.0.1:<port>.
        self.port = port

    def as_json(self):
        return {
            "name": self.name,
            "scope": self.scope,
            "updated_at": self.updated_at,
            "plugin": self.plugin,
            "public_key": self.public_key,
            "ticket": self.ticket,
            "app_public_key": self.app_public_key,
            "enroll_code_hash": self.enroll_code_hash,
            "enroll_code_generated_at": self.enroll_code_generated_at,
            "port": self.port,
        }

    @staticmethod
    def hash_enrollment_code(code: str) -> str:
        """SHA-256 hex digest of an enrollment code; this is what is persisted and
        compared (mirrors BridgeModel.hash_enrollment_code in Ruby)."""
        return hashlib.sha256(str(code).encode()).hexdigest()

    def enrollment_code_valid(self, code: str, now: float) -> bool:
        if not self.enroll_code_hash or not code or not isinstance(code, str):
            return False
        if self.enrollment_code_expired(now):
            return False
        return hmac.compare_digest(self.hash_enrollment_code(code), str(self.enroll_code_hash))

    def enrollment_code_expired(self, now: float) -> bool:
        """True if a pending code exists but is outside its validity window
        (including codes with no generation timestamp, which fail closed)."""
        if not self.enroll_code_hash:
            return False
        if self.enroll_code_generated_at is None:
            return True
        age = now - self.enroll_code_generated_at
        return not (0 <= age <= self.ENROLLMENT_CODE_TTL_SECONDS)

    def clear_enrollment_code(self):
        """Drop the pending enrollment code (after redemption or expiry)."""
        self.enroll_code_hash = None
        self.enroll_code_generated_at = None
