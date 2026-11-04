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
    PRIMARY_KEY = 'OPENC3__TOKEN' # for argon2 password hash
    SESSIONS_KEY = 'OPENC3__SESSIONS' # for hash containing session tokens
    USERS_KEY = 'OPENC3__USERS' # for hash of username => JSON user record

    # Core principals. The built-in administrator is whoever holds the shared
    # password stored at PRIMARY_KEY; it keeps every role so existing
    # deployments behave as before. Named accounts live under USERS_KEY and
    # only get the roles an administrator grants them.
    BUILTIN_ADMIN_USERNAME = 'admin'
    BUILTIN_ADMIN_ROLES = %w(admin operator approver).freeze
    # OPENC3_SERVICE_PASSWORD is presented by microservices and spawned scripts
    SERVICE_USERNAME = 'service'
    SERVICE_ROLES = BUILTIN_ADMIN_ROLES
    USERNAME_REGEX = /\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\z/
    # Named accounts unused for this many days are disabled at their next
    # login attempt (AC-2(3)). 0 disables the check. The built-in
    # administrator is exempt so an operator can always recover access.
    USER_INACTIVITY_DAYS = ENV.fetch('OPENC3_USER_INACTIVITY_DAYS', '35').to_i

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
        if lookup_session(token, time)
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

    # Resolves a token to the principal it was issued to.
    # @param token [String] service password or session token
    # @return [Hash, nil] {'username' => String, 'roles' => Array<String>} or nil if the token is not valid
    def self.principal(token)
      return nil if token.nil? or token.empty?

      service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD', nil)
      if service_password and !service_password.empty? and service_password == token
        return { 'username' => SERVICE_USERNAME, 'roles' => SERVICE_ROLES.dup }
      end

      stored = lookup_session(token)
      return nil unless stored
      terminate_otp(token)
      return parse_session(stored)
    end

    # Looks up a session token, first in the cache and then in Redis.
    # @return [String, nil] the stored session record
    def self.lookup_session(token, time = Time.now)
      # Drop the whole cache once it ages out rather than tracking per token
      # times. This bounds how long a terminated token keeps working to
      # SESSION_CACHE_TIMEOUT, same as before.
      if @@session_cache.nil? or (time - @@session_cache_time) >= SESSION_CACHE_TIMEOUT
        @@session_cache = {}
        @@session_cache_time = time
      end
      return @@session_cache[token] if @@session_cache[token]

      # Check the stored session tokens for just this token. Deliberately not
      # HGETALL: verify_token is unauthenticated, so reading the entire
      # session hash here lets any caller make us pull every session ever
      # created on every request, and that hash only grows. HGET is O(1) and
      # can't be amplified. The cache then fills with the tokens actually in
      # use instead of all of them.
      stored = Store.hget(SESSIONS_KEY, token)
      @@session_cache[token] = stored if stored
      return stored
    end

    def self.parse_session(stored)
      data = JSON.parse(stored) rescue nil
      if data.is_a?(Hash) and data['username']
        return { 'username' => data['username'].to_s, 'roles' => Array(data['roles']).map(&:to_s) }
      end
      # Sessions created before roles were recorded hold only a timestamp. They
      # were issued to the holder of the shared password, the built-in admin.
      return { 'username' => BUILTIN_ADMIN_USERNAME, 'roles' => BUILTIN_ADMIN_ROLES.dup }
    end

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

    # Creates a new session token. DO NOT CALL BEFORE VERIFYING.
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @param username [String] principal the session belongs to (default: built-in admin)
    # @param roles [Array<String>] roles granted to the session (default: built-in admin roles)
    # @return [String] the new session token
    def self.generate_session(otp: false, username: BUILTIN_ADMIN_USERNAME, roles: BUILTIN_ADMIN_ROLES)
      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      record = { 'username' => username.to_s, 'roles' => Array(roles).map(&:to_s), 'created_at' => Time.now.iso8601 }
      Store.hset(SESSIONS_KEY, token, JSON.generate(record))
      return token
    end

    # Terminates every session belonging to the given named account.
    def self.terminate_user_sessions(username)
      sessions = Store.hgetall(SESSIONS_KEY)
      return unless sessions
      sessions.each do |token, stored|
        terminate(token) if parse_session(stored)['username'] == username
      end
    end

    # Named account management. Records are stored as JSON in the USERS_KEY
    # hash. The password hash is never returned by users / user.

    def self.valid_username?(username)
      USERNAME_REGEX.match?(username.to_s) and
        ![BUILTIN_ADMIN_USERNAME, SERVICE_USERNAME].include?(username.to_s.downcase)
    end

    # @return [Hash] username => user record without password_hash
    def self.users
      records = Store.hgetall(USERS_KEY) || {}
      result = {}
      records.each do |username, json|
        record = JSON.parse(json)
        record.delete('password_hash')
        result[username] = record
      end
      return result
    end

    # @return [Hash, nil] full user record including password_hash
    def self.user(username)
      json = Store.hget(USERS_KEY, username.to_s)
      return nil unless json
      return JSON.parse(json)
    end

    def self.create_user(username:, password:, roles:, name: nil, enabled: true)
      raise "invalid username" unless valid_username?(username)
      raise "user already exists" if Store.hexists(USERS_KEY, username)
      validate_password(password)
      now = Time.now.iso8601
      record = {
        'username' => username,
        'name' => name.to_s,
        'roles' => Array(roles).map(&:to_s).uniq,
        'enabled' => enabled ? true : false,
        'password_hash' => Argon2::Password.create(password, profile: ARGON2_PROFILE),
        'created_at' => now,
        'updated_at' => now,
        'last_login' => nil,
      }
      Store.hset(USERS_KEY, username, JSON.generate(record))
      record.delete('password_hash')
      return record
    end

    # Updates a named account. Disabling an account or changing its password
    # or roles terminates its sessions so the change takes effect immediately.
    def self.update_user(username, roles: nil, enabled: nil, password: nil, name: nil)
      record = user(username)
      raise "user not found" unless record
      revoke = false
      unless roles.nil?
        record['roles'] = Array(roles).map(&:to_s).uniq
        revoke = true
      end
      unless enabled.nil?
        record['enabled'] = enabled ? true : false
        revoke = true unless record['enabled']
      end
      unless password.nil?
        validate_password(password)
        record['password_hash'] = Argon2::Password.create(password, profile: ARGON2_PROFILE)
        revoke = true
      end
      record['name'] = name.to_s unless name.nil?
      record['updated_at'] = Time.now.iso8601
      Store.hset(USERS_KEY, username, JSON.generate(record))
      terminate_user_sessions(username) if revoke
      record.delete('password_hash')
      return record
    end

    def self.delete_user(username)
      raise "user not found" unless Store.hexists(USERS_KEY, username.to_s)
      Store.hdel(USERS_KEY, username.to_s)
      terminate_user_sessions(username.to_s)
    end

    # Authenticates a named account.
    # @return [Hash, nil] principal {'username', 'roles'} or nil if the login is rejected
    def self.authenticate_user(username, password)
      return nil if password.nil? or password.empty?
      record = user(username)
      return nil unless record
      return nil unless record['enabled']
      return nil unless Argon2::Password.verify_password(password, record['password_hash'])

      if USER_INACTIVITY_DAYS > 0
        # Any administrator change (updated_at) restarts the inactivity clock
        last_used = [record['last_login'], record['updated_at'], record['created_at']].compact.map { |time| Time.parse(time) }.max
        if (Time.now - last_used) > (USER_INACTIVITY_DAYS * 86400)
          record['enabled'] = false
          record['updated_at'] = Time.now.iso8601
          Store.hset(USERS_KEY, username, JSON.generate(record))
          return nil
        end
      end

      record['last_login'] = Time.now.iso8601
      Store.hset(USERS_KEY, username, JSON.generate(record))
      return { 'username' => record['username'], 'roles' => Array(record['roles']) }
    end

    def self.validate_password(password)
      raise "password must not be nil or empty" if password.nil? or password.empty?
      raise "password must be at least 8 characters" if password.length < MIN_PASSWORD_LENGTH
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
