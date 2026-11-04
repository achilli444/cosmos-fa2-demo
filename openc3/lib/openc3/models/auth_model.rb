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

require 'base64'
require 'openssl'
require 'openc3/utilities/store'

module OpenC3
  class AuthModel
    # Passwords are stored as PBKDF2-HMAC-SHA-256 (NIST SP 800-132) computed by
    # OpenSSL, so a FIPS 140 validated OpenSSL provider covers the password
    # store (SC-13, IA-5(1)). Argon2 is not a FIPS approved algorithm; hashes
    # written by earlier versions are still verified (via the argon2 gem, loaded
    # only when such a hash is encountered) and rewritten as PBKDF2 on the next
    # successful password check.
    #
    # Stored format: $pbkdf2-sha256$<iterations>$<base64 salt>$<base64 key>
    PBKDF2_PREFIX = '$pbkdf2-sha256$'
    PBKDF2_DIGEST = 'sha256'
    PBKDF2_SALT_LENGTH = 16 # bytes; SP 800-132 requires at least 128 bits
    PBKDF2_KEY_LENGTH = 32 # bytes
    # OWASP recommendation for PBKDF2-HMAC-SHA-256
    PBKDF2_DEFAULT_ITERATIONS = 600_000
    # SP 800-63B-4 floor; OPENC3_PBKDF2_ITERATIONS can raise the default but not go below this
    PBKDF2_MIN_ITERATIONS = 10_000
    LEGACY_ARGON2_PREFIX = '$argon2'

    # Redis keys
    PRIMARY_KEY = 'OPENC3__TOKEN' # for the password hash
    SESSIONS_KEY = 'OPENC3__SESSIONS' # for hash containing session tokens

    # The length of time in seconds to keep redis values in memory
    PW_HASH_CACHE_TIMEOUT = 5
    SESSION_CACHE_TIMEOUT = 5

    # Cached password hash
    @@pw_hash_cache = nil
    @@pw_hash_cache_time = nil

    # Cached session tokens
    @@session_cache = nil
    @@session_cache_time = nil

    MIN_PASSWORD_LENGTH = 8

    SESSION_PREFIX = "ses_"
    OTP_PREFIX = "otp_"

    # A session token is SESSION_PREFIX followed by the unpadded urlsafe base64
    # encoding of SESSION_TOKEN_BYTES random bytes, i.e. exactly 22 characters
    # of [A-Za-z0-9_-]. Keep this in sync with generate_session.
    SESSION_TOKEN_BYTES = 16
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
        return true if @@pw_hash_cache and (time - @@pw_hash_cache_time) < PW_HASH_CACHE_TIMEOUT and check_password?(token, @@pw_hash_cache)

        # Check stored password hash
        pw_hash = Store.get(PRIMARY_KEY)
        raise "invalid password hash" unless supported_hash?(pw_hash) # Catch users who didn't run the migration utility when upgrading to COSMOS 7

        @@pw_hash_cache = pw_hash
        @@pw_hash_cache_time = time
        return true if check_password?(token, @@pw_hash_cache)
      end

      return false
    end

    # Derives the stored representation of a password with PBKDF2-HMAC-SHA-256
    # and a fresh random salt. This is the only hash format new passwords are
    # written in.
    # @param password [String] the plaintext password
    # @return [String] the PBKDF2 hash string
    def self.hash_password(password)
      iterations = pbkdf2_iterations()
      salt = OpenSSL::Random.random_bytes(PBKDF2_SALT_LENGTH)
      key = OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: iterations, length: PBKDF2_KEY_LENGTH, hash: PBKDF2_DIGEST)
      "#{PBKDF2_PREFIX}#{iterations}$#{Base64.strict_encode64(salt)}$#{Base64.strict_encode64(key)}"
    end

    # The PBKDF2 iteration count used for new hashes. OPENC3_PBKDF2_ITERATIONS
    # overrides the default but is clamped to PBKDF2_MIN_ITERATIONS.
    # @return [Integer]
    def self.pbkdf2_iterations
      configured = ENV.fetch('OPENC3_PBKDF2_ITERATIONS', nil)
      iterations = (configured.nil? or configured.empty?) ? PBKDF2_DEFAULT_ITERATIONS : configured.to_i
      [iterations, PBKDF2_MIN_ITERATIONS].max
    end

    # Whether the stored hash is in a format this version can verify.
    # @param pw_hash [String, nil] the stored hash
    # @return [Boolean]
    def self.supported_hash?(pw_hash)
      return false if pw_hash.nil?

      pw_hash.start_with?(PBKDF2_PREFIX) or legacy_hash?(pw_hash)
    end

    # Whether the stored hash was written by a pre-PBKDF2 version (Argon2).
    # @param pw_hash [String] the stored hash
    # @return [Boolean]
    def self.legacy_hash?(pw_hash)
      pw_hash.start_with?(LEGACY_ARGON2_PREFIX)
    end

    # Compares a plaintext password against a stored hash of any supported format.
    # Does not touch the store.
    # @param password [String] the plaintext password
    # @param pw_hash [String] the stored hash
    # @return [Boolean] whether the password produced the hash
    def self.password_matches?(password, pw_hash)
      if pw_hash.start_with?(PBKDF2_PREFIX)
        pbkdf2_matches?(password, pw_hash)
      elsif legacy_hash?(pw_hash)
        legacy_argon2_matches?(password, pw_hash)
      else
        false
      end
    end

    # Verifies the password and, if the stored hash is a legacy format,
    # rewrites it as PBKDF2 so the legacy verifier is never needed again.
    def self.check_password?(password, pw_hash)
      return false unless password_matches?(password, pw_hash)

      if legacy_hash?(pw_hash)
        new_hash = hash_password(password)
        Store.set(PRIMARY_KEY, new_hash)
        @@pw_hash_cache = new_hash
        @@pw_hash_cache_time = Time.now
      end
      true
    end

    def self.pbkdf2_matches?(password, pw_hash)
      fields = pw_hash.split('$')
      # ["", "pbkdf2-sha256", iterations, salt, key]
      return false unless fields.length == 5

      iterations = fields[2].to_i
      return false if iterations <= 0

      salt = Base64.strict_decode64(fields[3])
      expected = Base64.strict_decode64(fields[4])
      return false if expected.empty?

      actual = OpenSSL::KDF.pbkdf2_hmac(password, salt: salt, iterations: iterations, length: expected.bytesize, hash: PBKDF2_DIGEST)
      OpenSSL.fixed_length_secure_compare(actual, expected)
    rescue ArgumentError
      false
    end

    # Argon2 is only loaded here, on demand, so deployments whose hash has
    # already been migrated never load the non-FIPS library.
    def self.legacy_argon2_matches?(password, pw_hash)
      require 'argon2'
      Argon2::Password.verify_password(password, pw_hash)
    end
    private_class_method :pbkdf2_matches?, :legacy_argon2_matches?

    def self.set(password, old_password, key = PRIMARY_KEY)
      raise "password must not be nil or empty" if password.nil? or password.empty?
      raise "password must be at least 8 characters" if password.length < MIN_PASSWORD_LENGTH

      if set?(key)
        raise "old_password must not be nil or empty" if old_password.nil? or old_password.empty?
        raise "old_password incorrect" unless verify_no_service(old_password, mode: :password)
      end
      pw_hash = hash_password(password)
      Store.set(key, pw_hash)
      @@pw_hash_cache = nil
      @@pw_hash_cache_time = nil
      logout
    end

    # Creates a new session token. DO NOT CALL BEFORE VERIFYING.
    # Random bytes come from OpenSSL's DRBG (RAND_bytes) rather than Ruby's
    # SecureRandom so the token source is the same (optionally FIPS validated)
    # module as the password KDF.
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @return [String] the new session token
    def self.generate_session(otp: false)
      token = Base64.urlsafe_encode64(OpenSSL::Random.random_bytes(SESSION_TOKEN_BYTES), padding: false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      Store.hset(SESSIONS_KEY, token, Time.now.iso8601)
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
