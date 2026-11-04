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

require 'openssl'

module OpenC3
  # Single source of truth for the transport the internal service clients use:
  # service authentication, the script API proxies, Redis / Valkey, the QuestDB
  # PG wire connection and the local bucket endpoint. TLS is the default.
  #
  # OPENC3_PLAINTEXT_TRANSPORT=1 opts a deployment back into plaintext for
  # development stacks whose backing services do not terminate TLS (the shipped
  # .env sets it for compose.yaml). OPENC3_TLS_CA_FILE points the clients at a
  # private CA bundle when the services use certificates not in the system store.
  module TransportSecurity
    PLAINTEXT_ENV = 'OPENC3_PLAINTEXT_TRANSPORT'
    CA_FILE_ENV = 'OPENC3_TLS_CA_FILE'
    TRUE_VALUES = %w(1 true yes on).freeze

    def self.plaintext?
      TRUE_VALUES.include?(ENV[PLAINTEXT_ENV].to_s.strip.downcase)
    end

    def self.http_scheme
      plaintext? ? 'http' : 'https'
    end

    def self.redis_scheme
      plaintext? ? 'redis' : 'rediss'
    end

    # libpq's own default is 'prefer', which silently falls back to plaintext
    def self.pg_sslmode
      plaintext? ? 'prefer' : 'verify-full'
    end

    def self.ca_file
      value = ENV[CA_FILE_ENV].to_s.strip
      value.empty? ? nil : value
    end

    # Extra options for Redis.new; nil when running plaintext
    def self.redis_ssl_params
      return nil if plaintext?

      params = { verify_mode: OpenSSL::SSL::VERIFY_PEER }
      params[:ca_file] = ca_file if ca_file
      params
    end
  end
end
