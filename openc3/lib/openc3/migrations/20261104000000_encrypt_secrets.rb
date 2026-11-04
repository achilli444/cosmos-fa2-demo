# encoding: ascii-8bit

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

require 'openc3/utilities/migration'
require 'openc3/utilities/secret_encryption'
require 'openc3/models/scope_model'
require 'openc3/models/secret_model'
require 'openc3/models/offline_access_model'

module OpenC3
  # Re-writes secrets and Keycloak offline access tokens that were stored as
  # plaintext JSON before SecretEncryption existed so they are encrypted at
  # rest. Requires OPENC3_SECRET_ENCRYPTION_KEY.
  class EncryptSecrets < Migration
    def self.run
      unless SecretEncryption.configured?
        raise SecretEncryption::KeyMissingError, "#{SecretEncryption::KEY_ENV} must be set before existing secrets can be encrypted"
      end

      ScopeModel.names.each do |scope|
        SecretModel.get_all_models(scope: scope).each do |name, model|
          next unless model.legacy_plaintext?

          model.update
          puts "Encrypted secret #{name} in scope #{scope}"
        end
      end

      OfflineAccessModel.all(scope: 'DEFAULT').each do |name, json|
        token = json['offline_access_token']
        next if token.nil? or SecretEncryption.encrypted?(token)

        OfflineAccessModel.from_json(json, scope: 'DEFAULT').update
        puts "Encrypted offline access token for #{name}"
      end
    end
  end
end

unless ENV['OPENC3_NO_MIGRATE']
  OpenC3::EncryptSecrets.run
end
