# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

from openc3.environment import OPENC3_SCOPE
from openc3.models.model import Model
from openc3.utilities import secret_encryption


class SecretModel(Model):
    """Secret values are encrypted with secret_encryption before they reach Redis.
    The class level get / all methods return the stored (encrypted) JSON;
    use RedisSecrets.get or SecretModel.value for the plaintext."""

    PRIMARY_KEY = "openc3__secrets"

    # NOTE: The following three class methods are used by the ModelController
    # and are reimplemented to enable various Model class methods to work
    @classmethod
    def get(cls, name: str, scope: str):
        return super().get(f"{scope}__{SecretModel.PRIMARY_KEY}", name)

    @classmethod
    def names(cls, scope: str):
        return super().names(f"{scope}__{SecretModel.PRIMARY_KEY}")

    @classmethod
    def all(cls, scope: str):
        return super().all(f"{scope}__{SecretModel.PRIMARY_KEY}")

    @classmethod
    def encryption_context(cls, name: str, scope: str) -> str:
        """Additional authenticated data binding a ciphertext to the Redis key and field"""
        return f"{scope}__{SecretModel.PRIMARY_KEY}:{name}"

    # END NOTE

    def __init__(self, name: str, value: str, scope: str = OPENC3_SCOPE):
        super().__init__(f"{scope}__{SecretModel.PRIMARY_KEY}", name=name, scope=scope)
        self._value: str = value

    @property
    def value(self) -> str:
        """Decrypted secret value"""
        return secret_encryption.decrypt(self._value, SecretModel.encryption_context(self.name, self.scope))

    @value.setter
    def value(self, value: str):
        self._value = value

    def legacy_plaintext(self) -> bool:
        return not secret_encryption.is_encrypted(self._value)

    # @return [Hash] JSON encoding of this model with the value encrypted
    def as_json(self):
        value = self._value
        if not secret_encryption.is_encrypted(value):
            value = secret_encryption.encrypt(str(value), SecretModel.encryption_context(self.name, self.scope))
        return {
            "name": self.name,
            "value": value,
        }
