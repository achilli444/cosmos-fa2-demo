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
require 'time'
require 'openc3/utilities/store'

module OpenC3
  class AuthModel
    ARGON2_PROFILE = ENV["OPENC3_ARGON2_PROFILE"]&.to_sym || :rfc_9106_low_memory

    # Redis keys
    PRIMARY_KEY = 'OPENC3__TOKEN' # for argon2 password hash
    # Each session is its own key (SESSION_KEY_PREFIX + token) holding the
    # creation time, with a Redis TTL that enforces the idle timeout. A
    # per-key TTL is what lets Redis expire abandoned sessions on its own and
    # keeps a concurrent terminate from being undone by a refresh: EXPIRE on a
    # deleted key is a no-op, whereas re-writing a hash field would
    # resurrect it.
    SESSION_KEY_PREFIX = 'OPENC3__SESSION__'
    LEGACY_SESSIONS_KEY = 'OPENC3__SESSIONS' # pre-TTL hash, only ever deleted now

    # Session lifetime limits in seconds. A session ends when it has gone
    # unused for the idle timeout OR when it is older than the max age,
    # whichever comes first. Both are read from the environment on each use so
    # a container restart with new values applies to existing sessions too.
    # Defaults: 15 minute idle timeout (the common organizational value for
    # AC-11/AC-12 style requirements), 12 hour absolute lifetime (one shift).
    DEFAULT_SESSION_IDLE_TIMEOUT = 900
    DEFAULT_SESSION_MAX_AGE = 43_200

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

    # Seconds a session may go unused before it is terminated.
    # @return [Integer] OPENC3_SESSION_IDLE_TIMEOUT or the default
    def self.session_idle_timeout
      positive_env_seconds('OPENC3_SESSION_IDLE_TIMEOUT', DEFAULT_SESSION_IDLE_TIMEOUT)
    end

    # Seconds a session may live regardless of use before it is terminated.
    # @return [Integer] OPENC3_SESSION_MAX_AGE or the default
    def self.session_max_age
      positive_env_seconds('OPENC3_SESSION_MAX_AGE', DEFAULT_SESSION_MAX_AGE)
    end

    # Refuses to silently run without a limit: a value that doesn't parse or
    # that is zero / negative would otherwise disable session expiry.
    def self.positive_env_seconds(name, default)
      value = ENV.fetch(name, nil)
      return default if value.nil? or value.strip.empty?

      seconds = Integer(value, 10, exception: false)
      raise ArgumentError, "#{name} must be a positive integer number of seconds, got '#{value}'" if seconds.nil? or seconds <= 0

      seconds
    end
    private_class_method :positive_env_seconds

    def self.session_key(token)
      SESSION_KEY_PREFIX + token
    end
    private_class_method :session_key

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

        created_at = @@session_cache[token]
        if created_at
          # The idle timeout can't elapse inside the cache window because the
          # Redis TTL was refreshed when this entry was cached, but the
          # absolute limit can.
          if session_expired?(created_at, time)
            terminate(token)
            return false
          end
          terminate_otp(token)
          return true
        end

        # Look up just this token. verify_token is unauthenticated, so the
        # lookup must stay O(1): a caller can't make us scan every session on
        # every request. The cache then fills with the tokens actually in use.
        created_at = read_session(token)
        if created_at
          if session_expired?(created_at, time)
            terminate(token)
            return false
          end
          # Using the session resets its idle timer. The TTL is capped so the
          # key can never outlive the absolute limit, and EXPIRE on a key that
          # terminate or logout just deleted does nothing, so a refresh can't
          # bring a terminated session back.
          Store.expire(session_key(token), remaining_ttl(created_at, time))
          @@session_cache[token] = created_at
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

    # Creates a new session token. DO NOT CALL BEFORE VERIFYING.
    # The session expires after session_idle_timeout seconds without use or
    # session_max_age seconds after creation, whichever comes first.
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @return [String] the new session token
    def self.generate_session(otp: false)
      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      now = Time.now
      Store.set(session_key(token), now.iso8601, ex: remaining_ttl(now, now))
      return token
    end

    # Terminates every session.
    def self.logout
      Store.scan_each(match: "#{SESSION_KEY_PREFIX}*", count: 1000) do |key|
        Store.del(key)
      end
      Store.del(LEGACY_SESSIONS_KEY)
      @@session_cache = nil
      @@session_cache_time = nil
    end

    # Terminates the given session token.
    def self.terminate(token)
      Store.del(session_key(token))
      @@session_cache.delete(token) if @@session_cache
    end

    # Whether the session's absolute lifetime has elapsed. Idle expiry is
    # enforced by the Redis TTL, so a key that still exists hasn't idled out.
    def self.session_expired?(created_at, now = Time.now)
      (now - created_at) >= session_max_age
    end
    private_class_method :session_expired?

    # TTL to apply on use: the idle timeout, cut short by whatever is left of
    # the absolute lifetime. Never less than 1 so Redis can't reject it.
    def self.remaining_ttl(created_at, now = Time.now)
      remaining = (created_at + session_max_age - now).ceil
      [[session_idle_timeout, remaining].min, 1].max
    end
    private_class_method :remaining_ttl

    # Creation time of the stored session, or nil if there is no such session.
    # A value that doesn't parse is treated as no session rather than as a
    # session with no age.
    def self.read_session(token)
      stored = Store.get(session_key(token))
      return nil if stored.nil?

      Time.iso8601(stored)
    rescue ArgumentError
      nil
    end
    private_class_method :read_session

    # Terminates the session if the token is an OTP.
    def self.terminate_otp(token)
      terminate(token) if token.start_with?(OTP_PREFIX)
    end
  end
end
