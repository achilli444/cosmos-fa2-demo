# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

from openc3.models.model import Model
from openc3.utilities import secret_encryption


# Note: This model is locked to the DEFAULT scope
class OfflineAccessModel(Model):
    PRIMARY_KEY = "DEFAULT__openc3__offline_access"

    # NOTE: The following three class methods are used by the ModelController
    # and are reimplemented to enable various Model class methods to work
    @classmethod
    def get(cls, name: str, scope: str):
        return super().get(OfflineAccessModel.PRIMARY_KEY, name=name)

    @classmethod
    def names(cls, scope: str):
        return super().names(OfflineAccessModel.PRIMARY_KEY)

    @classmethod
    def all(cls, scope: str):
        return super().all(OfflineAccessModel.PRIMARY_KEY)

    def __init__(
        self,
        name: str,
        offline_access_token: str = None,
        updated_at: float = None,
        scope: str = "DEFAULT",
    ):
        super().__init__(
            OfflineAccessModel.PRIMARY_KEY,
            name=name,
            updated_at=updated_at,
            scope="DEFAULT",
        )
        # Long lived Keycloak refresh token: plaintext in memory, encrypted in Redis
        self.offline_access_token = secret_encryption.decrypt(
            offline_access_token, OfflineAccessModel.encryption_context(name)
        )

    # @return [Hash] JSON encoding of this model with the token encrypted
    def as_json(self):
        token = self.offline_access_token
        if token is not None and not secret_encryption.is_encrypted(token):
            token = secret_encryption.encrypt(str(token), OfflineAccessModel.encryption_context(self.name))
        return {
            "name": self.name,
            "updated_at": self.updated_at,
            "offline_access_token": token,
            "scope": self.scope,
        }
