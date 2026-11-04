# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'argon2'
require 'json'
require 'securerandom'
require 'time'
require 'openc3/utilities/store'

module OpenC3
  class AuthModel
    ARGON2_PROFILE = ENV["OPENC3_ARGON2_PROFILE"]&.to_sym || :rfc_9106_low_memory

    # Redis keys
    PRIMARY_KEY = 'OPENC3__TOKEN' # for argon2 password hash of the built-in admin account
    SESSIONS_KEY = 'OPENC3__SESSIONS' # for hash containing session tokens
    USERS_KEY = 'OPENC3__USERS' # for hash of per-operator accounts (username => JSON)

    # The built-in account whose password is the original COSMOS Core password
    # (PRIMARY_KEY). It exists so a fresh install can bootstrap itself and create
    # named operator accounts. Its roles can be narrowed with OPENC3_ADMIN_ROLES
    # (e.g. 'admin') so the shared password can no longer command.
    ADMIN_USERNAME = 'admin'
    DEFAULT_ADMIN_ROLES = ['admin', 'operator']

    # Identity given to callers that present the service password
    SERVICE_ROLE = 'service'

    USERNAME_REGEX = /\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\z/

    # Core role definitions. These mirror the built-in COSMOS Enterprise roles
    # (see docs/guides/roles-permissions.md) so a user provisioned in Core has
    # the same meaning when the deployment moves to Enterprise.
    ROLE_PERMISSIONS = {
      'admin' => %w[system system_set tlm cmd_info script_view admin superadmin],
      'operator' => %w[system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_edit script_run],
      'runner' => %w[system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_run],
      'viewer' => %w[system tlm cmd_info script_view],
      'approver' => %w[system tlm cmd_info script_view script_approver approve_hazardous approve_restricted approve_normal],
      # Internal microservices and Script Runner inside the trust zone
      SERVICE_ROLE => %w[system system_set tlm tlm_set cmd_info cmd_raw cmd script_view script_edit script_run script_approver admin superadmin],
    }.freeze
    ROLES = (ROLE_PERMISSIONS.keys - [SERVICE_ROLE]).freeze

    # Permissions that transmit to or reconfigure a target. Only these honor a
    # per-user target allow list.
    TARGET_PERMISSIONS = %w[cmd cmd_raw].freeze

    # The length of time in seconds to keep redis values in memory
    PW_HASH_CACHE_TIMEOUT = 5
    SESSION_CACHE_TIMEOUT = 5

    # Cached argon2 password hash
    @@pw_hash_cache = nil
    @@pw_hash_cache_time = nil

    # Cached session tokens
    @@session_cache = nil
    @@session_cache_time = nil

    MIN_PASSWORD_LENGTH = 8

    SESSION_PREFIX = "ses_"
    OTP_PREFIX = "otp_"

    # A session token is SESSION_PREFIX followed by the unpadded urlsafe base64
    # encoding of 16 random bytes, i.e. exactly 22 characters of [A-Za-z0-9_-].
    # Keep this in sync with generate_session.
    SESSION_TOKEN_REGEX = /\A#{SESSION_PREFIX}[A-Za-z0-9_-]{22}\z/

    # Whether the given value could have been produced by generate_session.
    # Callers handling a token from an unauthenticated request use this to
    # reject garbage before doing any Redis work. Checking only the prefix is
    # not enough: something like "ses_AAA" would pass and still cost us a read.
    # @param token [String] the value to check
    # @return [Boolean] whether the value is shaped like a session token
    def self.session_token?(token)
      SESSION_TOKEN_REGEX.match?(token.to_s)
    end

    def self.set?(key = PRIMARY_KEY)
      Store.exists(key) == 1
    end

    # Checks whether the provided token is a valid user password, service password, or session token.
    # @param token [String] the plaintext password or session token to check (required)
    # @param no_password [Boolean] enforces use of a session token or service password (default: true)
    # @param service_only [Boolean] enforces use of a service password (default: false)
    # @return [Boolean] whether the provided password/token is valid
    def self.verify(token, no_password: true, service_only: false)
      # Handle a service password - Generally only used by ScriptRunner
      # TODO: Replace this with temporary service tokens
      service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD', nil)
      return true if service_password and service_password == token

      return false if service_only

      mode = no_password ? :token : :any
      return verify_no_service(token, mode: mode)
    end

    # Checks whether the provided token is a valid user password or session token.
    # @param token [String] the plaintext password or session token to check (required)
    # @param mode [String] optionally restrict verification to just the password or token. Valid values: :password, :token, or :any (default :token)
    # @return [Boolean] whether the provided password/token is valid
    def self.verify_no_service(token, mode: :token)
      modes = [:password, :token, :any]
      raise ArgumentError, "Invalid mode '#{mode}': must be one of #{modes}" unless modes.include?(mode)

      return false if token.nil? or token.empty?

      # Check cached session tokens and password hash
      time = Time.now
      unless mode == :password
        # Drop the whole cache once it ages out rather than tracking per token
        # times. This bounds how long a terminated token keeps working to
        # SESSION_CACHE_TIMEOUT, same as before.
        if @@session_cache.nil? or (time - @@session_cache_time) >= SESSION_CACHE_TIMEOUT
          @@session_cache = {}
          @@session_cache_time = time
        end

        if @@session_cache[token]
          terminate_otp(token)
          return true
        end

        # Check the stored session tokens for just this token. Deliberately not
        # HGETALL: verify_token is unauthenticated, so reading the entire
        # session hash here lets any caller make us pull every session ever
        # created on every request, and that hash only grows. HGET is O(1) and
        # can't be amplified. The cache then fills with the tokens actually in
        # use instead of all of them.
        stored = Store.hget(SESSIONS_KEY, token)
        if stored
          @@session_cache[token] = stored
          terminate_otp(token)
          return true
        end
      end

      unless mode == :token
        return true if @@pw_hash_cache and (time - @@pw_hash_cache_time) < PW_HASH_CACHE_TIMEOUT and Argon2::Password.verify_password(token, @@pw_hash_cache)

        # Check stored password hash
        pw_hash = Store.get(PRIMARY_KEY)
        raise "invalid password hash" if pw_hash.nil? || !pw_hash.start_with?("$argon2") # Catch users who didn't run the migration utility when upgrading to COSMOS 7

        @@pw_hash_cache = pw_hash
        @@pw_hash_cache_time = time
        return true if Argon2::Password.verify_password(token, @@pw_hash_cache)
      end

      return false
    end

    # Roles of the built-in admin account. OPENC3_ADMIN_ROLES lets a deployment
    # strip 'operator' so the shared password can no longer send commands.
    def self.admin_roles
      roles = ENV.fetch('OPENC3_ADMIN_ROLES', '').split(',').map(&:strip).reject(&:empty?)
      roles = DEFAULT_ADMIN_ROLES if roles.empty?
      roles.select { |role| ROLES.include?(role) }
    end

    # The identity used by holders of the service password. The username is the
    # calling microservice (or the operator a Script Runner script runs as) so
    # the command record still names who caused the transmission.
    # @param username [String] optional username to attribute service calls to
    # @return [Hash] user hash
    def self.service_user(username = nil)
      username = username.to_s.strip
      username = ENV.fetch('OPENC3_MICROSERVICE_NAME', 'service') if username.empty?
      { 'username' => username, 'name' => username, 'roles' => [SERVICE_ROLE], 'targets' => nil }
    end

    # Resolves a token (session token or service password) to the user it was
    # issued to. Returns nil for unknown, expired or legacy identity-less tokens.
    # @param token [String] session token or service password
    # @return [Hash, nil] user hash with 'username', 'name', 'roles', 'targets'
    def self.session_user(token)
      return nil if token.nil? or token.empty?

      service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD', nil)
      return service_user if service_password and service_password == token

      time = Time.now
      if @@session_cache.nil? or (time - @@session_cache_time) >= SESSION_CACHE_TIMEOUT
        @@session_cache = {}
        @@session_cache_time = time
      end
      stored = @@session_cache[token]
      unless stored
        stored = Store.hget(SESSIONS_KEY, token)
        return nil unless stored

        @@session_cache[token] = stored
      end
      user = parse_session(stored)
      terminate_otp(token)
      return user
    end

    # @return [Boolean] whether the user's roles grant the permission on the target
    def self.permitted?(user, permission, target_name: nil)
      return false unless user.is_a?(Hash)
      return true if permission.nil?

      permissions = Array(user['roles']).flat_map { |role| ROLE_PERMISSIONS[role.to_s] || [] }
      return false unless permissions.include?(permission.to_s)

      if TARGET_PERMISSIONS.include?(permission.to_s) and target_name
        targets = user['targets']
        return targets.map(&:to_s).map(&:upcase).include?(target_name.to_s.upcase) if targets.is_a?(Array) and !targets.empty?
      end
      return true
    end

    # Authenticates an operator. A nil username is the built-in admin account so
    # existing single-password clients keep working.
    # @return [Hash, nil] the user hash or nil if the credentials are wrong
    def self.authenticate(username, password)
      return nil if password.nil? or password.empty?

      username = username.to_s.strip
      if username.empty? or username == ADMIN_USERNAME
        return nil unless verify_no_service(password, mode: :password)

        return admin_user
      end
      record = user_record(username)
      return nil unless record
      return nil unless Argon2::Password.verify_password(password, record['password_hash'])

      return public_user(username, record)
    end

    def self.admin_user
      { 'username' => ADMIN_USERNAME, 'name' => ADMIN_USERNAME, 'roles' => admin_roles, 'targets' => nil }
    end

    # @return [Array<Hash>] every account (built-in admin first) without password hashes
    def self.users
      list = [admin_user]
      (Store.hgetall(USERS_KEY) || {}).sort.each do |username, json|
        list << public_user(username, JSON.parse(json))
      end
      list
    end

    def self.user(username)
      username = username.to_s
      return admin_user if username == ADMIN_USERNAME

      record = user_record(username)
      record ? public_user(username, record) : nil
    end

    # Creates or replaces a named operator account.
    # @param username [String] account name
    # @param password [String] plaintext password (hashed with argon2)
    # @param roles [Array<String>] subset of ROLES
    # @param targets [Array<String>, nil] target allow list for cmd/cmd_raw, nil for all
    def self.add_user(username, password, roles:, targets: nil)
      username = username.to_s.strip
      raise "username must match #{USERNAME_REGEX.inspect}" unless USERNAME_REGEX.match?(username)
      raise "username '#{ADMIN_USERNAME}' is reserved" if username == ADMIN_USERNAME
      raise "password must not be nil or empty" if password.nil? or password.empty?
      raise "password must be at least #{MIN_PASSWORD_LENGTH} characters" if password.length < MIN_PASSWORD_LENGTH

      roles = Array(roles).map(&:to_s).uniq
      raise "roles must not be empty" if roles.empty?

      bad = roles - ROLES
      raise "unknown roles: #{bad.join(', ')} (valid: #{ROLES.join(', ')})" unless bad.empty?

      if targets
        targets = Array(targets).map { |t| t.to_s.strip.upcase }.reject(&:empty?).uniq
        targets = nil if targets.empty?
      end
      record = { 'password_hash' => Argon2::Password.create(password, profile: ARGON2_PROFILE), 'roles' => roles, 'targets' => targets }
      Store.hset(USERS_KEY, username, JSON.generate(record))
      terminate_user_sessions(username)
      public_user(username, record)
    end

    def self.remove_user(username)
      username = username.to_s
      raise "username '#{ADMIN_USERNAME}' is reserved" if username == ADMIN_USERNAME

      removed = Store.hdel(USERS_KEY, username)
      terminate_user_sessions(username)
      removed.to_i > 0
    end

    # Terminates every session issued to the given username
    def self.terminate_user_sessions(username)
      (Store.hgetall(SESSIONS_KEY) || {}).each do |token, stored|
        user = parse_session(stored)
        terminate(token) if user and user['username'] == username
      end
    end

    def self.user_record(username)
      json = Store.hget(USERS_KEY, username.to_s)
      json ? JSON.parse(json) : nil
    rescue JSON::ParserError
      nil
    end
    private_class_method :user_record

    def self.public_user(username, record)
      { 'username' => username, 'name' => username, 'roles' => Array(record['roles']), 'targets' => record['targets'] }
    end
    private_class_method :public_user

    # Sessions created before accounts existed stored only a timestamp. Those
    # carry no identity and therefore no permissions (fail closed); the user
    # simply logs in again.
    def self.parse_session(stored)
      return nil if stored.nil?

      data = JSON.parse(stored)
      return nil unless data.is_a?(Hash) and data['username']

      { 'username' => data['username'], 'name' => data['name'] || data['username'], 'roles' => Array(data['roles']), 'targets' => data['targets'] }
    rescue JSON::ParserError
      nil
    end
    private_class_method :parse_session

    def self.set(password, old_password, key = PRIMARY_KEY)
      raise "password must not be nil or empty" if password.nil? or password.empty?
      raise "password must be at least 8 characters" if password.length < MIN_PASSWORD_LENGTH

      if set?(key)
        raise "old_password must not be nil or empty" if old_password.nil? or old_password.empty?
        raise "old_password incorrect" unless verify_no_service(old_password, mode: :password)
      end
      pw_hash = Argon2::Password.create(password, profile: ARGON2_PROFILE)
      Store.set(key, pw_hash)
      @@pw_hash_cache = nil
      @@pw_hash_cache_time = nil
      logout
    end

    # Creates a new session token bound to a user. DO NOT CALL BEFORE VERIFYING.
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @param user [Hash] the authenticated user (see authenticate). Defaults to
    #   the built-in admin account for the legacy single-password flow.
    # @return [String] the new session token
    def self.generate_session(otp: false, user: admin_user)
      raise ArgumentError, "user must be a Hash with a username" unless user.is_a?(Hash) and user['username']

      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      session = {
        'username' => user['username'],
        'name' => user['name'] || user['username'],
        'roles' => Array(user['roles']),
        'targets' => user['targets'],
        'created_at' => Time.now.iso8601
      }
      Store.hset(SESSIONS_KEY, token, JSON.generate(session))
      return token
    end

    # Terminates every session.
    def self.logout
      Store.del(SESSIONS_KEY)
      @@session_cache = nil
      @@session_cache_time = nil
    end

    # Terminates the given session token.
    def self.terminate(token)
      Store.hdel(SESSIONS_KEY, token)
      @@session_cache.delete(token) if @@session_cache
    end

    # Terminates the session if the token is an OTP.
    def self.terminate_otp(token)
      terminate(token) if token.start_with?(OTP_PREFIX)
    end
  end
end
