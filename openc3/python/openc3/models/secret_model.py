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
from openc3.utilities.logger import Logger
from openc3.utilities.secret_cipher import SecretCipher


class SecretModel(Model):
    """Secret values are encrypted with SecretCipher before they reach Redis and
    decrypted on read, so the hash under <scope>__openc3__secrets only ever
    holds ciphertext. Values written before encryption existed are plain
    strings; they are still readable and are encrypted the next time they are
    set."""

    PRIMARY_KEY = "openc3__secrets"

    # NOTE: The following three class methods are used by the ModelController
    # and are reimplemented to enable various Model class methods to work
    @classmethod
    def get(cls, name: str, scope: str):
        return cls._decrypt_json(super().get(f"{scope}__{SecretModel.PRIMARY_KEY}", name), name=name, scope=scope)

    @classmethod
    def names(cls, scope: str):
        return super().names(f"{scope}__{SecretModel.PRIMARY_KEY}")

    @classmethod
    def all(cls, scope: str):
        all_secrets = super().all(f"{scope}__{SecretModel.PRIMARY_KEY}")
        for name, json_data in all_secrets.items():
            all_secrets[name] = cls._decrypt_json(json_data, name=name, scope=scope)
        return all_secrets

    # END NOTE

    @classmethod
    def aad(cls, name: str, scope: str) -> str:
        """Additional authenticated data binds a ciphertext to its scope and name"""
        return f"{scope}__{SecretModel.PRIMARY_KEY}:{name}"

    @classmethod
    def _decrypt_json(cls, json_data, name: str, scope: str):
        if json_data is None:
            return None
        value = json_data.get("value")
        if SecretCipher.is_encrypted(value):
            json_data["value"] = SecretCipher.decrypt(value, aad=cls.aad(name=name, scope=scope))
        else:
            Logger.warn(f"Secret '{name}' is stored unencrypted, set it again to encrypt it at rest", scope=scope)
        return json_data

    def __init__(self, name: str, value, scope: str = OPENC3_SCOPE):
        super().__init__(f"{scope}__{SecretModel.PRIMARY_KEY}", name=name, scope=scope)
        # from_json / get_model hand us the stored envelope
        if SecretCipher.is_encrypted(value):
            value = SecretCipher.decrypt(value, aad=SecretModel.aad(name=name, scope=scope))
        self.value: str = value

    # @return [Hash] JSON encoding of this model with the value encrypted
    def as_json(self):
        return {
            "name": self.name,
            "value": SecretCipher.encrypt(str(self.value), aad=SecretModel.aad(name=self.name, scope=self.scope)),
        }
