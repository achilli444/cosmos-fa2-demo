# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/models/model'
require 'openc3/utilities/secret_cipher'
require 'openc3/utilities/logger'

module OpenC3
  # Note: This model is locked to the DEFAULT scope
  #
  # The offline_access_token is a long-lived Keycloak refresh token (a bearer
  # authenticator) so it is encrypted with SecretCipher before it is written to
  # Redis and decrypted when the model is read back. The plaintext only exists
  # in memory on this object.
  class OfflineAccessModel < Model
    PRIMARY_KEY = 'DEFAULT__openc3__offline_access'

    attr_accessor :offline_access_token

    # NOTE: The following three class methods are used by the ModelController
    # and are reimplemented to enable various Model class methods to work
    def self.get(name:, scope:)
      super(PRIMARY_KEY, name: name)
    end

    def self.names(scope:)
      super(PRIMARY_KEY)
    end

    def self.all(scope:)
      super(PRIMARY_KEY)
    end
    # END NOTE

    def initialize(name:, offline_access_token: nil, updated_at: nil, scope: 'DEFAULT')
      super(PRIMARY_KEY, name: name, updated_at: updated_at, scope: 'DEFAULT')
      @offline_access_token = decrypt_token(offline_access_token)
    end

    # @return [String] Additional authenticated data binding a token to its user
    def self.aad(name:)
      "#{PRIMARY_KEY}:#{name}"
    end

    # @return [Hash] JSON encoding of this model with the token encrypted at rest
    def as_json(*a)
      token = @offline_access_token
      token = SecretCipher.encrypt(token, aad: self.class.aad(name: @name)) unless token.nil?
      { 'name' => @name,
        'updated_at' => @updated_at,
        'offline_access_token' => token,
        'scope' => @scope }
    end

    private

    # Tokens that can't be authenticated (tampered with or encrypted under a
    # rotated key) are treated as absent so the user is prompted to
    # re-authorize offline access rather than the ciphertext being used.
    def decrypt_token(value)
      return value unless SecretCipher.encrypted?(value)

      SecretCipher.decrypt(value, aad: self.class.aad(name: @name))
    rescue SecretCipher::DecryptError => e
      Logger.error("Unable to decrypt offline access token for #{@name}: #{e.message}")
      nil
    end
  end
end
