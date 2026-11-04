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
from openc3.utilities.logger import Logger
from openc3.utilities.secret_cipher import SecretCipher, SecretCipherDecryptError


# Note: This model is locked to the DEFAULT scope
#
# The offline_access_token is a long-lived Keycloak refresh token (a bearer
# authenticator) so it is encrypted with SecretCipher before it is written to
# Redis and decrypted when the model is read back. The plaintext only exists
# in memory on this object.
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
        self.offline_access_token = self._decrypt_token(offline_access_token)

    @classmethod
    def aad(cls, name: str) -> str:
        """Additional authenticated data binding a token to its user"""
        return f"{cls.PRIMARY_KEY}:{name}"

    # @return [Hash] JSON encoding of this model with the token encrypted at rest
    def as_json(self):
        token = self.offline_access_token
        if token is not None:
            token = SecretCipher.encrypt(token, aad=OfflineAccessModel.aad(name=self.name))
        return {
            "name": self.name,
            "updated_at": self.updated_at,
            "offline_access_token": token,
            "scope": self.scope,
        }

    # Tokens that can't be authenticated (tampered with or encrypted under a
    # rotated key) are treated as absent so the user is prompted to
    # re-authorize offline access rather than the ciphertext being used.
    def _decrypt_token(self, value):
        if not SecretCipher.is_encrypted(value):
            return value
        try:
            return SecretCipher.decrypt(value, aad=OfflineAccessModel.aad(name=self.name))
        except SecretCipherDecryptError as error:
            Logger.error(f"Unable to decrypt offline access token for {self.name}: {error}")
            return None
