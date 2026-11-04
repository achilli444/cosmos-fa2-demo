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
require 'openc3/utilities/logger'
require 'openc3/utilities/secret_cipher'

module OpenC3
  # Secret values are encrypted with SecretCipher before they reach Redis and
  # decrypted on read, so the hash under <scope>__openc3__secrets only ever
  # holds ciphertext. Values written before encryption existed are plain
  # Strings; they are still readable and are encrypted the next time they are
  # set.
  class SecretModel < Model
    PRIMARY_KEY = 'openc3__secrets'

    # NOTE: The following three class methods are used by the ModelController
    # and are reimplemented to enable various Model class methods to work
    def self.get(name:, scope:)
      decrypt_json(super("#{scope}__#{PRIMARY_KEY}", name: name), name: name, scope: scope)
    end

    def self.names(scope:)
      super("#{scope}__#{PRIMARY_KEY}")
    end

    def self.all(scope:)
      all = super("#{scope}__#{PRIMARY_KEY}")
      all.each { |name, json| all[name] = decrypt_json(json, name: name, scope: scope) }
      all
    end
    # END NOTE

    # Additional authenticated data binds a ciphertext to its scope and name
    def self.aad(name:, scope:)
      "#{scope}__#{PRIMARY_KEY}:#{name}"
    end

    def self.decrypt_json(json, name:, scope:)
      return nil unless json

      value = json['value']
      if SecretCipher.encrypted?(value)
        json['value'] = SecretCipher.decrypt(value, aad: aad(name: name, scope: scope))
      else
        Logger.warn("Secret '#{name}' is stored unencrypted, set it again to encrypt it at rest", scope: scope)
      end
      json
    end

    def initialize(name:, value:, scope:)
      super("#{scope}__#{PRIMARY_KEY}", name: name, scope: scope)
      # from_json / get_model hand us the stored envelope
      if SecretCipher.encrypted?(value)
        value = SecretCipher.decrypt(value, aad: self.class.aad(name: name, scope: scope))
      end
      @value = value
    end

    # @return [Hash] JSON encoding of this model with the value encrypted
    def as_json(*a)
      {
        'name' => @name,
        'value' => SecretCipher.encrypt(@value.to_s, aad: self.class.aad(name: @name, scope: @scope)),
      }
    end
  end
end
