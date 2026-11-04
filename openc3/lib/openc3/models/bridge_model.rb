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

require 'openc3/models/model'
require 'openc3/models/microservice_model'
require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'securerandom'

module OpenC3
  # Stores the identity of a named Iroh bridge (the bridge_microservice hub).
  #
  # A bridge is the COSMOS-side Iroh server that openc3-app and host interfaces
  # connect to. This model stores the bridge's Iroh public key (its EndpointId)
  # and most recent connection ticket, plus the authorized openc3-app control
  # identity (app_public_key) recorded during enrollment. The bridge's own
  # private key lives in the secrets store, never here. Only a SHA-256 digest of
  # a pending one-time enrollment code is stored (enroll_code_hash); the code
  # itself is returned exactly once inside the enrollment token.
  #
  # This Ruby model mirrors the Python BridgeModel (same scoped primary key and
  # JSON shape) so the openc3cli `bridgeenroll` command can read and update the
  # same records the Python BridgeMicroservice maintains.
  class BridgeModel < Model
    PRIMARY_KEY = 'openc3_bridges'
    ENROLLMENT_CODE_TTL_SECONDS = 10 * 60

    attr_accessor :public_key
    attr_accessor :ticket
    attr_accessor :app_public_key
    attr_accessor :enroll_code_hash
    attr_accessor :enroll_code_generated_at
    attr_accessor :port

    # The bridge stack (bridge_microservice.py) is Python and runs from the core
    # library regardless of the interfaces bridged through it.
    def self.bridge_python_bin
      ENV['OPENC3_PYTHON_BIN'] || '/openc3/python/.venv/bin/python'
    end

    BRIDGE_WORK_DIR = '/openc3/python/openc3/microservices'

    # Build (but do not create) the MicroserviceModel for a bridge_microservice
    # hub named `bridge_name` in `scope`. Centralizes the cmd/work_dir/options so
    # ScopeModel, the DEFAULT-bridge migration, and InterfaceModel stay in sync.
    def self.build_microservice(bridge_name:, scope:, parent: nil, shard: 0, plugin: nil)
      microservice_name = "#{scope}__BRIDGE__#{bridge_name.to_s.upcase}"
      MicroserviceModel.new(
        name: microservice_name,
        cmd: [bridge_python_bin, 'bridge_microservice.py', microservice_name],
        work_dir: BRIDGE_WORK_DIR,
        options: [['BRIDGE_NAME', bridge_name.to_s.upcase]],
        parent: parent,
        shard: shard.to_i,
        plugin: plugin,
        scope: scope
      )
    end

    # NOTE: The following three class methods are reimplemented (like other
    # scoped models) so the ModelController and Model class methods work.
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

    def initialize(
      name:,
      scope:,
      public_key: nil,
      ticket: nil,
      app_public_key: nil,
      enroll_code_hash: nil,
      enroll_code_generated_at: nil,
      port: nil,
      updated_at: nil,
      plugin: nil,
      enroll_code: nil # legacy plaintext field: accepted so old records load, never kept
    )
      super("#{scope}__#{PRIMARY_KEY}", name: name, updated_at: updated_at, plugin: plugin, scope: scope)
      @public_key = public_key
      @ticket = ticket
      @app_public_key = app_public_key
      @enroll_code_hash = enroll_code_hash
      @enroll_code_generated_at = enroll_code_generated_at
      @port = port
    end

    def as_json(*_a)
      {
        'name' => @name,
        'scope' => @scope,
        'updated_at' => @updated_at,
        'plugin' => @plugin,
        'public_key' => @public_key,
        'ticket' => @ticket,
        'app_public_key' => @app_public_key,
        'enroll_code_hash' => @enroll_code_hash,
        'enroll_code_generated_at' => @enroll_code_generated_at,
        'port' => @port
      }
    end

    # SHA-256 hex digest of an enrollment code; this is what is persisted and
    # compared (mirrors BridgeModel.hash_enrollment_code in Python).
    def self.hash_enrollment_code(code)
      Digest::SHA256.hexdigest(code.to_s)
    end

    # Generate a one-time manual-enrollment code, store only its hash on this
    # bridge, and return a token (base64 JSON of bridge name + hub ticket + code)
    # that a remote openc3-app pastes to enroll. Requires the bridge to be up
    # (ticket present). The code is redeemed once over the api/enroll ALPN.
    def generate_enrollment_token
      raise "Bridge '#{@name}' has no ticket yet; is its bridge_microservice running?" if @ticket.nil? || @ticket.empty?

      code = SecureRandom.hex(16)
      @enroll_code_hash = self.class.hash_enrollment_code(code)
      @enroll_code_generated_at = Time.now.to_i
      update()
      payload = { 'v' => 1, 'bridge' => @name, 'ticket' => @ticket, 'code' => code }
      Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
    end

    # True if `code` matches the pending enrollment code hash and the code is
    # still within ENROLLMENT_CODE_TTL_SECONDS of generation.
    def enrollment_code_valid?(code, now = Time.now.to_i)
      return false if @enroll_code_hash.nil? || @enroll_code_hash.empty? || code.nil? || code.to_s.empty?
      return false if @enroll_code_generated_at.nil?

      age = now.to_i - @enroll_code_generated_at.to_i
      return false unless age >= 0 && age <= ENROLLMENT_CODE_TTL_SECONDS

      OpenSSL.fixed_length_secure_compare(self.class.hash_enrollment_code(code), @enroll_code_hash.to_s)
    rescue ArgumentError
      false
    end

    # Drop the pending enrollment code (after redemption or expiry).
    def clear_enrollment_code
      @enroll_code_hash = nil
      @enroll_code_generated_at = nil
    end
  end
end
