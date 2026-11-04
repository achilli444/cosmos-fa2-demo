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
require 'openssl'
require 'securerandom'
require 'time'
require 'openc3/utilities/store'
require 'openc3/utilities/logger'

module OpenC3
  class AuthModel
    ARGON2_PROFILE = ENV["OPENC3_ARGON2_PROFILE"]&.to_sym || :rfc_9106_low_memory

    # Redis keys
    PRIMARY_KEY = 'OPENC3__TOKEN' # legacy single argon2 password hash (pre individual accounts)
    USERS_KEY = 'OPENC3__USERS' # hash of username => argon2 password hash
    SESSIONS_KEY = 'OPENC3__SESSIONS' # for hash containing session tokens
    SERVICE_TOKEN_KEY_PREFIX = 'OPENC3__SERVICE_TOKEN__' # one expiring key per service token

    # The username the legacy single password (PRIMARY_KEY) belongs to. Existing
    # deployments keep working: the password everyone used to share becomes the
    # password of this one account until individual accounts are created.
    LEGACY_USERNAME = ENV['OPENC3_LEGACY_USERNAME'] || 'admin'
    ANONYMOUS_USERNAME = 'anonymous'

    # The length of time in seconds to keep redis values in memory
    PW_HASH_CACHE_TIMEOUT = 5
    SESSION_CACHE_TIMEOUT = 5

    # Cached argon2 password hashes by username
    @@pw_hash_cache = {}
    @@pw_hash_cache_time = nil

    # Cached session / service tokens => identity
    @@session_cache = nil
    @@session_cache_time = nil

    MIN_PASSWORD_LENGTH = 8
    USERNAME_REGEX = /\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\z/

    SESSION_PREFIX = "ses_"
    OTP_PREFIX = "otp_"
    SERVICE_TOKEN_PREFIX = "svc_"

    # Service tokens are minted for a single run (script, suite analysis) on
    # behalf of an authenticated user and expire on their own. Every successful
    # verification slides the expiry so a long running script keeps working while
    # it is actually talking to the API; an abandoned token dies after this long.
    SERVICE_TOKEN_TTL = (ENV['OPENC3_SERVICE_TOKEN_TTL'] || 86400).to_i

    # The value shipped in the repo .env. A deployment that keeps it has a
    # credential anyone can read from GitHub, so it is never accepted.
    INSECURE_SERVICE_PASSWORDS = ['openc3service'].freeze
    @@service_password_warned = false

    # A session token is SESSION_PREFIX followed by the unpadded urlsafe base64
    # encoding of 16 random bytes, i.e. exactly 22 characters of [A-Za-z0-9_-].
    # Keep this in sync with generate_session.
    SESSION_TOKEN_REGEX = /\A#{SESSION_PREFIX}[A-Za-z0-9_-]{22}\z/
    SERVICE_TOKEN_REGEX = /\A#{SERVICE_TOKEN_PREFIX}[A-Za-z0-9_-]{43}\z/

    # Whether the given value could have been produced by generate_session.
    # Callers handling a token from an unauthenticated request use this to
    # reject garbage before doing any Redis work. Checking only the prefix is
    # not enough: something like "ses_AAA" would pass and still cost us a read.
    # @param token [String] the value to check
    # @return [Boolean] whether the value is shaped like a session token
    def self.session_token?(token)
      SESSION_TOKEN_REGEX.match?(token.to_s)
    end

    # @return [Boolean] whether the value is shaped like a service token
    def self.service_token?(token)
      SERVICE_TOKEN_REGEX.match?(token.to_s)
    end

    # @return [Boolean] whether any account (individual or legacy) exists
    def self.set?(key = PRIMARY_KEY)
      return true if Store.exists(key) == 1

      return Store.hlen(USERS_KEY) > 0
    end

    # @return [Boolean] whether the username has an account
    def self.user?(username)
      return false if username.nil? or username.empty?
      return true if Store.hexists(USERS_KEY, username)

      return username == LEGACY_USERNAME && Store.exists(PRIMARY_KEY) == 1
    end

    # @return [Array<String>] every username with an account
    def self.users
      names = Store.hkeys(USERS_KEY)
      names << LEGACY_USERNAME if Store.exists(PRIMARY_KEY) == 1 and !names.include?(LEGACY_USERNAME)
      return names.sort
    end

    # The configured service password, or nil when it is unset or is a known
    # insecure default. Logged once so operators notice the credential is dead.
    def self.service_password
      service_password = ENV.fetch('OPENC3_SERVICE_PASSWORD', nil)
      return nil if service_password.nil? or service_password.empty?

      if INSECURE_SERVICE_PASSWORDS.include?(service_password)
        unless @@service_password_warned
          @@service_password_warned = true
          Logger.error("OPENC3_SERVICE_PASSWORD is set to the insecure default shipped in .env and will not be accepted. Set a unique value in .env.local.")
        end
        return nil
      end
      return service_password
    end

    # Constant time string comparison for static secrets (CWE-208)
    def self.secure_compare(expected, actual)
      return false if expected.nil? or actual.nil?

      expected = expected.to_s
      actual = actual.to_s
      return false unless expected.bytesize == actual.bytesize

      OpenSSL.fixed_length_secure_compare(expected, actual)
    end

    # Checks whether the provided token is a valid user password, service password, service token, or session token.
    # @param token [String] the plaintext password or session token to check (required)
    # @param no_password [Boolean] enforces use of a session token or service password (default: true)
    # @param service_only [Boolean] enforces use of a service password (default: false)
    # @return [Boolean] whether the provided password/token is valid
    def self.verify(token, no_password: true, service_only: false)
      # Handle a service password - only for non-interactive system services
      return true if secure_compare(service_password, token)

      return false if service_only

      mode = no_password ? :token : :any
      return verify_no_service(token, mode: mode)
    end

    # Who the token belongs to. DO NOT CALL BEFORE VERIFYING.
    # @return [Hash] 'username' and whether this is the 'service' identity
    def self.identity(token)
      return { 'username' => ANONYMOUS_USERNAME, 'service' => false } if token.nil? or token.empty?
      return { 'username' => 'service', 'service' => true } if secure_compare(service_password, token)

      stored = cached_token(token)
      stored = Store.hget(SESSIONS_KEY, token) if stored.nil? and !service_token?(token)
      stored = Store.get(SERVICE_TOKEN_KEY_PREFIX + token) if stored.nil? and service_token?(token)
      username = username_from_stored(stored)
      return { 'username' => username, 'service' => false }
    end

    # Checks whether the provided token is a valid user password, session token or service token.
    # @param token [String] the plaintext password or session token to check (required)
    # @param mode [String] optionally restrict verification to just the password or token. Valid values: :password, :token, or :any (default :token)
    # @param username [String] the account a plaintext password belongs to. Defaults to the legacy account.
    # @return [Boolean] whether the provided password/token is valid
    def self.verify_no_service(token, mode: :token, username: nil)
      modes = [:password, :token, :any]
      raise ArgumentError, "Invalid mode '#{mode}': must be one of #{modes}" unless modes.include?(mode)

      return false if token.nil? or token.empty?

      # Check cached session tokens and password hash
      time = Time.now
      unless mode == :password
        return true if cached_token(token, time)

        if service_token?(token)
          key = SERVICE_TOKEN_KEY_PREFIX + token
          stored = Store.get(key)
          if stored
            # Slide the expiry: the run is still alive and using the API
            Store.expire(key, SERVICE_TOKEN_TTL)
            @@session_cache[token] = stored
            return true
          end
        else
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
      end

      unless mode == :token
        return verify_user(username || LEGACY_USERNAME, token, time: time)
      end

      return false
    end

    # Checks a plaintext password against one account's argon2 hash
    # @return [Boolean] whether the password belongs to the user
    def self.verify_user(username, password, time: Time.now)
      return false if username.nil? or username.empty? or password.nil? or password.empty?

      if @@pw_hash_cache_time.nil? or (time - @@pw_hash_cache_time) >= PW_HASH_CACHE_TIMEOUT
        @@pw_hash_cache = {}
        @@pw_hash_cache_time = time
      end
      cached = @@pw_hash_cache[username]
      return true if cached and Argon2::Password.verify_password(password, cached)

      # Cache miss or mismatch: re-read in case the hash changed under us
      pw_hash = user_hash(username)
      return false if pw_hash.nil?
      raise "invalid password hash" unless pw_hash.start_with?("$argon2") # Catch users who didn't run the migration utility when upgrading to COSMOS 7

      @@pw_hash_cache[username] = pw_hash
      return Argon2::Password.verify_password(password, pw_hash)
    end

    # Sets the password of the legacy account. Kept for callers that predate
    # individual accounts; see set_user.
    def self.set(password, old_password, key = PRIMARY_KEY)
      if key == PRIMARY_KEY
        set_user(LEGACY_USERNAME, password, old_password)
      else
        validate_password(password)
        if set?(key)
          raise "old_password must not be nil or empty" if old_password.nil? or old_password.empty?
          raise "old_password incorrect" unless Argon2::Password.verify_password(old_password, Store.get(key))
        end
        Store.set(key, Argon2::Password.create(password, profile: ARGON2_PROFILE))
      end
    end

    # Creates an account or changes its password.
    # Changing an existing account's password requires the old password and
    # revokes that account's sessions. Creating an account requires no old
    # password; the controller decides who may create accounts.
    def self.set_user(username, password, old_password = nil)
      validate_username(username)
      validate_password(password)

      if user?(username)
        raise "old_password must not be nil or empty" if old_password.nil? or old_password.empty?
        raise "old_password incorrect" unless verify_user(username, old_password)
      end
      pw_hash = Argon2::Password.create(password, profile: ARGON2_PROFILE)
      Store.hset(USERS_KEY, username, pw_hash)
      # The legacy hash is superseded once its account lives in USERS_KEY
      Store.del(PRIMARY_KEY) if username == LEGACY_USERNAME
      @@pw_hash_cache = {}
      @@pw_hash_cache_time = nil
      logout(username: username)
    end

    # Removes an account and every session it holds (AC-2: revoke one person
    # without rotating anyone else's credential).
    def self.delete_user(username)
      raise "unknown user '#{username}'" unless user?(username)
      raise "cannot delete the last account" if users.length <= 1

      Store.hdel(USERS_KEY, username)
      Store.del(PRIMARY_KEY) if username == LEGACY_USERNAME
      @@pw_hash_cache = {}
      @@pw_hash_cache_time = nil
      logout(username: username)
    end

    # Creates a new session token. DO NOT CALL BEFORE VERIFYING.
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @param username [String] the authenticated account the session belongs to
    # @return [String] the new session token
    def self.generate_session(otp: false, username: LEGACY_USERNAME)
      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      Store.hset(SESSIONS_KEY, token, { 'username' => username, 'created_at' => Time.now.iso8601 }.to_json)
      return token
    end

    # Mints a short-lived token for one run (script, suite analysis) acting on
    # behalf of username. DO NOT CALL BEFORE VERIFYING THE USER. The token is
    # accepted by verify like a session token, carries the user's identity, and
    # expires after ttl seconds of not being used or when revoked.
    # @return [String] the new service token
    def self.generate_service_token(username:, purpose:, ttl: SERVICE_TOKEN_TTL)
      raise "username required for service token" if username.nil? or username.empty?

      token = SERVICE_TOKEN_PREFIX + SecureRandom.urlsafe_base64(32, false)
      value = { 'username' => username, 'purpose' => purpose, 'created_at' => Time.now.iso8601 }.to_json
      Store.setex(SERVICE_TOKEN_KEY_PREFIX + token, ttl.to_i, value)
      return token
    end

    # Terminates every session, or only the sessions of one account.
    def self.logout(username: nil)
      if username
        Store.hscan_each(SESSIONS_KEY) do |token, stored|
          Store.hdel(SESSIONS_KEY, token) if username_from_stored(stored) == username
        end
      else
        Store.del(SESSIONS_KEY)
      end
      @@session_cache = nil
      @@session_cache_time = nil
    end

    # Terminates the given session or service token.
    def self.terminate(token)
      return if token.nil?

      if service_token?(token)
        Store.del(SERVICE_TOKEN_KEY_PREFIX + token)
      else
        Store.hdel(SESSIONS_KEY, token)
      end
      @@session_cache.delete(token) if @@session_cache
    end

    # Terminates the session if the token is an OTP.
    def self.terminate_otp(token)
      terminate(token) if token.start_with?(OTP_PREFIX)
    end

    # The argon2 hash for an account, falling back to the legacy single hash
    def self.user_hash(username)
      pw_hash = Store.hget(USERS_KEY, username)
      pw_hash = Store.get(PRIMARY_KEY) if pw_hash.nil? and username == LEGACY_USERNAME
      return pw_hash
    end

    def self.validate_username(username)
      raise "username must not be nil or empty" if username.nil? or username.empty?
      raise "username must be 1-64 letters, digits, '_', '.', '@' or '-'" unless USERNAME_REGEX.match?(username)
    end

    def self.validate_password(password)
      raise "password must not be nil or empty" if password.nil? or password.empty?
      raise "password must be at least #{MIN_PASSWORD_LENGTH} characters" if password.length < MIN_PASSWORD_LENGTH
    end

    # Returns the stored value for a cached token, dropping the whole cache once
    # it ages out rather than tracking per token times. This bounds how long a
    # terminated token keeps working to SESSION_CACHE_TIMEOUT.
    def self.cached_token(token, time = Time.now)
      if @@session_cache.nil? or (time - @@session_cache_time) >= SESSION_CACHE_TIMEOUT
        @@session_cache = {}
        @@session_cache_time = time
      end
      stored = @@session_cache[token]
      terminate_otp(token) if stored
      return stored
    end

    # Sessions created before individual accounts stored only a timestamp
    def self.username_from_stored(stored)
      return ANONYMOUS_USERNAME if stored.nil?

      parsed = JSON.parse(stored) rescue nil
      return ANONYMOUS_USERNAME unless parsed.is_a?(Hash)

      return parsed['username'] || ANONYMOUS_USERNAME
    end
    private_class_method :user_hash, :validate_username, :validate_password, :cached_token, :username_from_stored
  end
end
