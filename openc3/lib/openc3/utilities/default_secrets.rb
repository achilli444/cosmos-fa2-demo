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

require 'openc3/utilities/env_helper'

module OpenC3
  # Detects the public placeholder credentials shipped in the COSMOS .env file.
  # The file is published with COSMOS, so a deployment that keeps any of these
  # values is trivially compromised. Rails services call check! at boot and
  # refuse to start unless OPENC3_ALLOW_DEFAULT_PASSWORDS opts in (local demos).
  class DefaultSecrets
    class Error < StandardError; end

    ALLOW_ENV = 'OPENC3_ALLOW_DEFAULT_PASSWORDS'

    DEFAULT_PASSWORDS = {
      'OPENC3_REDIS_PASSWORD' => 'openc3password',
      'OPENC3_SR_REDIS_PASSWORD' => 'scriptrunnerpassword',
      'OPENC3_BUCKET_PASSWORD' => 'openc3bucketpassword',
      'OPENC3_SR_BUCKET_PASSWORD' => 'scriptrunnerbucketpassword',
      'OPENC3_TSDB_PASSWORD' => 'openc3questpassword',
      'OPENC3_SERVICE_PASSWORD' => 'openc3service',
    }.freeze

    # SECRET_KEY_BASE values that were ever committed to the public repository
    SHIPPED_SECRET_KEY_BASES = [
      'bdb4300d46c9d4f116ce3dbbd54cac6b20802d8be1c2333cf5f6f90b1627799ac5d043e8460744077bc0bd6aacdd5c4bf53f499a68303c6752e7f327b874b96a',
    ].freeze

    # Rails needs a real key to sign cookies; anything shorter is a mistake
    MIN_SECRET_KEY_BASE_LENGTH = 64

    # @return [Array<String>] names of the password variables still set to a shipped placeholder
    def self.default_passwords_in_use(env = ENV)
      DEFAULT_PASSWORDS.select { |key, value| env[key] == value }.keys
    end

    # @return [String, nil] reason SECRET_KEY_BASE is unusable, or nil when it is acceptable
    def self.secret_key_base_problem(env = ENV)
      value = env['SECRET_KEY_BASE'].to_s.strip
      return 'is not set' if value.empty?
      return 'is the key that ships in the public COSMOS repository' if SHIPPED_SECRET_KEY_BASES.include?(value)
      return "is too short (#{value.length} chars, need at least #{MIN_SECRET_KEY_BASE_LENGTH})" if value.length < MIN_SECRET_KEY_BASE_LENGTH

      nil
    end

    def self.allowed?(env = ENV)
      ['true', '1', 'yes', 'on'].include?(env[ALLOW_ENV].to_s.downcase)
    end

    # @return [Array<String>] human readable problems, empty when the environment is safe
    def self.problems(env = ENV)
      problems = []
      problem = secret_key_base_problem(env)
      problems << "SECRET_KEY_BASE #{problem}. Generate one with: openssl rand -hex 64" if problem
      in_use = default_passwords_in_use(env)
      unless in_use.empty?
        problems << "public placeholder passwords from .env still in use: #{in_use.join(', ')}"
      end
      problems
    end

    # Raise unless the environment is free of shipped secrets. With
    # OPENC3_ALLOW_DEFAULT_PASSWORDS set the problems are only logged so a
    # local demo can still start.
    # @param service [String] name used in the messages
    # @param logger [#warn, #error] where to report
    def self.check!(service:, env: ENV, logger: nil)
      problems = problems(env)
      return true if problems.empty?

      if allowed?(env)
        message = "#{service} is running with insecure shipped secrets because #{ALLOW_ENV} is set. " \
                  'Only do this for a local demo nothing else can reach. ' + problems.join('; ')
        logger ? logger.warn(message) : warn("WARNING: #{message}")
        return false
      end

      message = "#{service} refusing to start with shipped secrets: #{problems.join('; ')}. " \
                'Set real values in .env.local (see docs.openc3.com/docs/getting-started/security) ' \
                "or set #{ALLOW_ENV}=1 for a local demo only."
      logger ? logger.error(message) : warn("ERROR: #{message}")
      raise Error, message
    end
  end
end
