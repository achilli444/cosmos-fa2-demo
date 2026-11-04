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
require 'openc3/utilities/secret_encryption'

module OpenC3
  # Note: This model is locked to the DEFAULT scope
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

    # @return [String] additional authenticated data binding a ciphertext to
    #   the Redis key and field it is stored under
    def self.encryption_context(name:)
      "#{PRIMARY_KEY}:#{name}"
    end

    # The offline access token is a long lived Keycloak refresh token so it
    # is held in memory as plaintext but encrypted with SecretEncryption
    # whenever it is written to Redis.
    def initialize(name:, offline_access_token: nil, updated_at: nil, scope: 'DEFAULT')
      super(PRIMARY_KEY, name: name, updated_at: updated_at, scope: 'DEFAULT')
      @offline_access_token = SecretEncryption.decrypt(offline_access_token, context: self.class.encryption_context(name: name))
    end

    # @return [Hash] JSON encoding of this model with the token encrypted
    def as_json(*a)
      token = @offline_access_token
      if token and !SecretEncryption.encrypted?(token)
        token = SecretEncryption.encrypt(token.to_s, context: self.class.encryption_context(name: @name))
      end
      { 'name' => @name,
        'updated_at' => @updated_at,
        'offline_access_token' => token,
        'scope' => @scope }
    end
  end
end
