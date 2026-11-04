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
  # Secret values are encrypted with SecretEncryption before they reach Redis.
  # The class level get / all methods return the stored (encrypted) JSON;
  # use RedisSecrets#get or SecretModel#value for the plaintext.
  class SecretModel < Model
    PRIMARY_KEY = 'openc3__secrets'

    # NOTE: The following three class methods are used by the ModelController
    # and are reimplemented to enable various Model class methods to work
    def self.get(name:, scope:)
      super("#{scope}__#{PRIMARY_KEY}", name: name)
    end

    def self.names(scope:)
      super("#{scope}__#{PRIMARY_KEY}")
    end

    def self.all(scope:)
      super("#{scope}__#{PRIMARY_KEY}")
    end
    # END NOTE

    # @return [String] additional authenticated data binding a ciphertext to
    #   the Redis key and field it is stored under
    def self.encryption_context(name:, scope:)
      "#{scope}__#{PRIMARY_KEY}:#{name}"
    end

    def initialize(name:, value:, scope:)
      super("#{scope}__#{PRIMARY_KEY}", name: name, scope: scope)
      @value = value
    end

    # @return [String] decrypted secret value
    def value
      SecretEncryption.decrypt(@value, context: self.class.encryption_context(name: @name, scope: @scope))
    end

    # @return [Boolean] true if the stored value still needs to be encrypted
    def legacy_plaintext?
      !SecretEncryption.encrypted?(@value)
    end

    # @return [Hash] JSON encoding of this model with the value encrypted
    def as_json(*a)
      value = @value.as_json(*a)
      unless SecretEncryption.encrypted?(value)
        value = SecretEncryption.encrypt(value.to_s, context: self.class.encryption_context(name: @name, scope: @scope))
      end
      {
        'name' => @name,
        'value' => value,
      }
    end
  end
end
