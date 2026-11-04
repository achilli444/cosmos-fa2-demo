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

module OpenC3
  class AuthModel
    ARGON2_PROFILE = ENV["OPENC3_ARGON2_PROFILE"]&.to_sym || :rfc_9106_low_memory

    # Redis keys
    PRIMARY_KEY = 'OPENC3__TOKEN' # for argon2 password hash
    # Hash of active sessions. Fields are the SHA-256 digest of the session
    # token (never the token itself, so a Redis dump does not hand out live
    # sessions) and values are JSON session records (see session_record).
    SESSIONS_KEY = 'OPENC3__SESSIONS'

    # Session lifetime defaults in seconds, overridable via the environment.
    # A session ends when it has not been used for the idle timeout or when it
    # reaches the absolute maximum age, whichever comes first. Every service
    # that verifies tokens must see the same values (see compose.yaml).
    DEFAULT_SESSION_IDLE_TIMEOUT = 900 # 15 minutes
    DEFAULT_SESSION_MAX_AGE = 43200 # 12 hours
    # Core has a single shared account, so this caps the sessions for the
    # whole system. Creating one past the cap evicts the least recently used.
    DEFAULT_SESSION_MAX_CONCURRENT = 10

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

    # Seconds a session may go unused before it is terminated.
    def self.session_idle_timeout
      positive_integer_env('OPENC3_SESSION_IDLE_TIMEOUT', DEFAULT_SESSION_IDLE_TIMEOUT)
    end

    # Seconds after creation at which a session is terminated regardless of use.
    def self.session_max_age
      positive_integer_env('OPENC3_SESSION_MAX_AGE', DEFAULT_SESSION_MAX_AGE)
    end

    # Maximum number of concurrent (non one-time) sessions.
    def self.session_max_concurrent
      positive_integer_env('OPENC3_SESSION_MAX_CONCURRENT', DEFAULT_SESSION_MAX_CONCURRENT)
    end

    def self.positive_integer_env(name, default)
      raw = ENV.fetch(name, nil)
      return default if raw.nil? or raw.strip.empty?

      value = Integer(raw, exception: false)
      raise ArgumentError, "#{name} must be a positive integer, got #{raw.inspect}" unless value and value > 0

      value
    end

    # The Redis field under which a token is stored. SHA-256 is one-way, so
    # reading the sessions hash yields nothing a client could present.
    def self.session_digest(token)
      OpenSSL::Digest::SHA256.hexdigest(token)
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

        digest = session_digest(token)
        if @@session_cache[digest]
          terminate_otp(token)
          return true
        end

        # Check the stored session tokens for just this token. Deliberately not
        # HGETALL: verify_token is unauthenticated, so reading the entire
        # session hash here lets any caller make us pull every session on every
        # request. HGET is O(1) and can't be amplified. The cache then fills
        # with the tokens actually in use instead of all of them.
        stored = Store.hget(SESSIONS_KEY, digest)
        if stored
          session = parse_session(stored)
          if session and session_active?(session, time)
            # Refresh the idle clock. The cache means this write happens at
            # most once per SESSION_CACHE_TIMEOUT per process, not per request.
            unless session['otp']
              session['last_used'] = time.iso8601
              Store.hset(SESSIONS_KEY, digest, JSON.generate(session))
            end
            @@session_cache[digest] = true
            terminate_otp(token)
            return true
          end
          # Expired, or a pre-digest plaintext entry left over from an upgrade
          Store.hdel(SESSIONS_KEY, digest)
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
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @return [String] the new session token
    def self.generate_session(otp: false)
      time = Time.now
      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      # OTPs are consumed on first use and don't hold a seat; a regular
      # session must fit under the cap, evicting the least recently used.
      prune_sessions(time, reserve: otp ? 0 : 1)
      Store.hset(SESSIONS_KEY, session_digest(token), JSON.generate(session_record(time, otp)))
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
      digest = session_digest(token)
      Store.hdel(SESSIONS_KEY, digest)
      @@session_cache.delete(digest) if @@session_cache
    end

    # Drops expired and unreadable sessions and, when the regular sessions plus
    # the reserved seats exceed the cap, the least recently used ones. Only
    # called from generate_session, after the caller has authenticated, so the
    # HGETALL here is bounded by the cap and can't be driven by a stranger.
    def self.prune_sessions(time = Time.now, reserve: 0)
      active = []
      (Store.hgetall(SESSIONS_KEY) || {}).each do |digest, raw|
        session = parse_session(raw)
        if session.nil? or !session_active?(session, time)
          remove_session(digest)
        elsif !session['otp']
          active << [digest, Time.iso8601(session['last_used'])]
        end
      end
      excess = active.size + reserve - session_max_concurrent
      if excess > 0
        active.sort_by { |_, last_used| last_used }.first(excess).each do |digest, _|
          remove_session(digest)
        end
      end
    end

    def self.remove_session(digest)
      Store.hdel(SESSIONS_KEY, digest)
      @@session_cache.delete(digest) if @@session_cache
    end

    def self.session_record(time, otp)
      { 'created' => time.iso8601, 'last_used' => time.iso8601, 'otp' => otp }
    end

    # @return [Hash, nil] the stored session record, or nil if it isn't one
    def self.parse_session(raw)
      session = JSON.parse(raw)
      return nil unless session.is_a?(Hash) and session['created'] and session['last_used']

      session
    rescue JSON::ParserError
      nil
    end

    # Whether the session is within both its idle timeout and maximum age.
    def self.session_active?(session, time = Time.now)
      created = Time.iso8601(session['created'])
      last_used = Time.iso8601(session['last_used'])
      (time - created) < session_max_age and (time - last_used) < session_idle_timeout
    rescue ArgumentError, TypeError
      false
    end

    # Terminates the session if the token is an OTP.
    def self.terminate_otp(token)
      terminate(token) if token.start_with?(OTP_PREFIX)
    end
  end
end
