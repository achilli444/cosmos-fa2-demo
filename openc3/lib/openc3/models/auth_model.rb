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
require 'securerandom'
require 'json'
require 'time'
require 'openc3/utilities/store'

module OpenC3
  class AuthModel
    ARGON2_PROFILE = ENV["OPENC3_ARGON2_PROFILE"]&.to_sym || :rfc_9106_low_memory

    # Redis keys
    PRIMARY_KEY = 'OPENC3__TOKEN' # for the built-in admin argon2 password hash
    SESSIONS_KEY = 'OPENC3__SESSIONS' # for hash containing session tokens => JSON identity
    USERS_KEY = 'OPENC3__USERS' # for hash containing username => JSON {password_hash, roles, name}

    # Core identities. The password stored under PRIMARY_KEY is the built-in
    # admin account so existing deployments keep working. Additional users are
    # stored under USERS_KEY with their own argon2 hash and roles.
    ADMIN_USERNAME = 'admin'
    SERVICE_USERNAME = 'service'
    ADMIN_ROLES = ['admin'].freeze
    SERVICE_ROLES = ['service'].freeze
    # Roles that can be assigned to a user. 'service' is reserved for the
    # service password and can not be assigned.
    ROLES = %w[viewer operator approver admin].freeze
    USERNAME_REGEX = /\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\z/

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

    # Resolves the identity bound to a session token or the service password.
    # Passwords are deliberately not accepted here: an identity is only ever
    # bound at login (verify_user) and carried by the session token.
    # @param token [String] the session token or service password
    # @return [Hash, nil] {'username', 'roles', 'name'} or nil if the token is invalid
    def self.identity(token)
      return nil if token.nil? or token.empty?

      service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD', nil)
      if service_password and service_password == token
        return {
          'username' => ENV['OPENC3_MICROSERVICE_NAME'] || SERVICE_USERNAME,
          'name' => ENV['OPENC3_MICROSERVICE_NAME'] || SERVICE_USERNAME,
          'roles' => SERVICE_ROLES.dup,
          'service' => true
        }
      end

      stored = session_lookup(token)
      return nil unless stored

      terminate_otp(token)
      return parse_session(stored)
    end

    # Verifies a username and password and returns the bound identity.
    # A nil or empty username means the built-in admin account whose password
    # is stored under PRIMARY_KEY. Named users are stored under USERS_KEY.
    # @return [Hash, nil] identity hash or nil if the credentials are invalid
    def self.verify_user(username, password)
      return nil if password.nil? or password.empty?

      username = ADMIN_USERNAME if username.nil? or username.to_s.empty?
      username = username.to_s

      user = get_user(username)
      if user
        return nil unless Argon2::Password.verify_password(password, user['password_hash'])

        return { 'username' => username, 'name' => user['name'] || username, 'roles' => user['roles'] }
      elsif username == ADMIN_USERNAME
        return nil unless verify_no_service(password, mode: :password)

        return { 'username' => ADMIN_USERNAME, 'name' => ADMIN_USERNAME, 'roles' => ADMIN_ROLES.dup }
      end
      return nil
    end

    # Returns the roles configured for a username, used when re-checking a
    # stored operator identity (e.g. a queued command released later).
    # @return [Array<String>, nil] roles or nil if the user does not exist
    def self.user_roles(username)
      return nil if username.nil? or username.to_s.empty?

      user = get_user(username.to_s)
      return user['roles'] if user
      return ADMIN_ROLES.dup if username.to_s == ADMIN_USERNAME and set?

      return nil
    end

    # @return [Array<Hash>] configured users without their password hashes
    def self.users
      list = []
      list << { 'username' => ADMIN_USERNAME, 'name' => ADMIN_USERNAME, 'roles' => ADMIN_ROLES.dup, 'builtin' => true } if set?
      Store.hgetall(USERS_KEY).each do |username, json|
        next if username == ADMIN_USERNAME # admin is always the built-in account

        user = JSON.parse(json)
        list << { 'username' => username, 'name' => user['name'] || username, 'roles' => user['roles'] }
      end
      return list
    end

    # Creates or updates a named user. Admin only (enforced by the caller).
    # @param username [String] the username
    # @param password [String, nil] new password (required when creating)
    # @param roles [Array<String>] subset of ROLES
    # @param name [String, nil] display name
    def self.set_user(username:, password: nil, roles:, name: nil)
      raise "username must match #{USERNAME_REGEX.inspect}" unless USERNAME_REGEX.match?(username.to_s)
      raise "username '#{ADMIN_USERNAME}' is the built-in account, use set" if username == ADMIN_USERNAME

      roles = Array(roles).map(&:to_s).uniq
      raise "at least one role is required" if roles.empty?

      invalid = roles - ROLES
      raise "invalid roles #{invalid}: must be one of #{ROLES}" unless invalid.empty?

      existing = get_user(username)
      if password.nil? or password.empty?
        raise "password is required for a new user" unless existing

        pw_hash = existing['password_hash']
      else
        raise "password must be at least #{MIN_PASSWORD_LENGTH} characters" if password.length < MIN_PASSWORD_LENGTH

        pw_hash = Argon2::Password.create(password, profile: ARGON2_PROFILE)
      end
      Store.hset(USERS_KEY, username, JSON.generate({ 'password_hash' => pw_hash, 'roles' => roles, 'name' => name || username }))
      # Any change to credentials or roles invalidates that user's sessions
      terminate_user_sessions(username)
    end

    # Deletes a named user and terminates their sessions.
    def self.delete_user(username)
      raise "username '#{ADMIN_USERNAME}' is the built-in account and can not be deleted" if username == ADMIN_USERNAME

      Store.hdel(USERS_KEY, username)
      terminate_user_sessions(username)
    end

    def self.get_user(username)
      json = Store.hget(USERS_KEY, username)
      return nil unless json

      return JSON.parse(json)
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
        if session_lookup(token)
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

    # Looks up the stored session value for a token, using the session cache.
    # @return [String, nil] the stored session value or nil
    def self.session_lookup(token)
      time = Time.now
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

    # Parses a stored session value into an identity. Sessions created before
    # identities were bound store a bare timestamp; those were only ever
    # issued for the single (admin) password so they map to the admin account.
    def self.parse_session(stored)
      if stored.start_with?('{')
        session = JSON.parse(stored)
        return {
          'username' => session['username'] || ADMIN_USERNAME,
          'name' => session['name'] || session['username'] || ADMIN_USERNAME,
          'roles' => session['roles'] || ADMIN_ROLES.dup
        }
      else
        return { 'username' => ADMIN_USERNAME, 'name' => ADMIN_USERNAME, 'roles' => ADMIN_ROLES.dup }
      end
    end

    # Creates a new session token bound to an identity. DO NOT CALL BEFORE VERIFYING.
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @param username [String] the authenticated username bound to the session
    # @param roles [Array<String>] the roles bound to the session
    # @param name [String, nil] the display name bound to the session
    # @return [String] the new session token
    def self.generate_session(otp: false, username: ADMIN_USERNAME, roles: ADMIN_ROLES, name: nil)
      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      session = {
        'time' => Time.now.iso8601,
        'username' => username,
        'name' => name || username,
        'roles' => Array(roles).map(&:to_s)
      }
      Store.hset(SESSIONS_KEY, token, JSON.generate(session))
      return token
    end

    # Terminates every session belonging to the given username.
    def self.terminate_user_sessions(username)
      Store.hgetall(SESSIONS_KEY).each do |token, stored|
        terminate(token) if parse_session(stored)['username'] == username
      end
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
