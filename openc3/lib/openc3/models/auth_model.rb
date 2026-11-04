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

    # The length of time in minutes to keep redis values in memory
    PW_HASH_CACHE_TIMEOUT = 5
    SESSION_CACHE_TIMEOUT = 5

    # Session lifetime limits in seconds. A session token is rejected (and deleted)
    # once it has been unused for SESSION_IDLE_TIMEOUT or has existed for
    # SESSION_MAX_LIFETIME, whichever comes first. A value of 0 disables that limit.
    SESSION_IDLE_TIMEOUT = (ENV['OPENC3_SESSION_IDLE_TIMEOUT'] || '900').to_i # 15 minutes
    SESSION_MAX_LIFETIME = (ENV['OPENC3_SESSION_MAX_LIFETIME'] || '43200').to_i # 12 hours
    # Minimum seconds between writes of a session's last_used_at timestamp
    SESSION_TOUCH_INTERVAL = 60

    # Cached argon2 password hash
    @@pw_hash_cache = nil
    @@pw_hash_cache_time = nil

    # Cached session tokens
    @@session_cache = nil
    @@session_cache_time = nil

    MIN_PASSWORD_LENGTH = 8

    SESSION_PREFIX = "ses_"
    OTP_PREFIX = "otp_"

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
      service_password = ENV['OPENC3_SERVICE_PASSWORD']
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
        if @@session_cache and (time - @@session_cache_time) < SESSION_CACHE_TIMEOUT
          session = @@session_cache[token]
          # An expired cache entry may have been refreshed by another process so fall through to Redis
          if session and !session_expired?(session, time)
            accept_session(token, session, time)
            return true
          end
        end

        # Check stored session tokens
        @@session_cache = Store.hgetall(SESSIONS_KEY)
        @@session_cache_time = time
        session = @@session_cache[token]
        if session
          if session_expired?(session, time)
            terminate(token)
          else
            accept_session(token, session, time)
            return true
          end
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
      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      Store.hset(SESSIONS_KEY, token, session_value(Time.now, Time.now))
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

    # Returns whether the stored session has exceeded its idle timeout or maximum lifetime.
    # Unparsable values are treated as expired.
    def self.session_expired?(session, time = Time.now)
      created_at, last_used_at = session_times(session)
      return true unless created_at and last_used_at
      return true if SESSION_MAX_LIFETIME > 0 and (time - created_at) > SESSION_MAX_LIFETIME
      return true if SESSION_IDLE_TIMEOUT > 0 and (time - last_used_at) > SESSION_IDLE_TIMEOUT

      return false
    end

    # Accepts a live session: consumes OTPs and records activity for idle tracking.
    def self.accept_session(token, session, time)
      if token.start_with?(OTP_PREFIX)
        terminate(token)
      else
        touch_session(token, session, time)
      end
    end

    # Records the session as used so the idle timeout restarts. Writes are rate
    # limited by SESSION_TOUCH_INTERVAL to avoid a Redis write on every request.
    def self.touch_session(token, session, time)
      created_at, last_used_at = session_times(session)
      return if (time - last_used_at) < SESSION_TOUCH_INTERVAL

      value = session_value(created_at, time)
      Store.hset(SESSIONS_KEY, token, value)
      @@session_cache[token] = value if @@session_cache
    end

    def self.session_value(created_at, last_used_at)
      JSON.generate({ 'created_at' => created_at.iso8601, 'last_used_at' => last_used_at.iso8601 })
    end

    # Parses the stored session value into [created_at, last_used_at].
    # Sessions created before lifetimes were tracked hold a bare creation timestamp.
    def self.session_times(session)
      if session.start_with?('{')
        data = JSON.parse(session)
        created_at = Time.iso8601(data['created_at'])
        last_used_at = Time.iso8601(data['last_used_at'] || data['created_at'])
      else
        created_at = last_used_at = Time.iso8601(session)
      end
      return [created_at, last_used_at]
    rescue StandardError
      return [nil, nil]
    end
    private_class_method :accept_session, :touch_session, :session_value, :session_times
  end
end
