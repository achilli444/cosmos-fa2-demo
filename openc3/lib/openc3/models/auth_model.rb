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
require 'openc3/utilities/store'

module OpenC3
  class AuthModel
    ARGON2_PROFILE = ENV["OPENC3_ARGON2_PROFILE"]&.to_sym || :rfc_9106_low_memory

    # Redis keys
    PRIMARY_KEY = 'OPENC3__TOKEN' # argon2 hash of the admin password
    SESSIONS_KEY = 'OPENC3__SESSIONS' # hash of session token => JSON {"role", "created"}

    # Core roles. The admin password is the one created at first login (PRIMARY_KEY).
    # The other role passwords are optional and set by an admin (see set_role_password).
    # The service role is bound to OPENC3_SERVICE_PASSWORD and is never stored in Redis.
    ADMIN_ROLE = 'admin'
    SERVICE_ROLE = 'service'
    PASSWORD_ROLES = [ADMIN_ROLE, 'operator', 'viewer'].freeze
    ROLES = (PASSWORD_ROLES + [SERVICE_ROLE]).freeze

    # The length of time in minutes to keep redis values in memory
    PW_HASH_CACHE_TIMEOUT = 5
    SESSION_CACHE_TIMEOUT = 5

    # Cached argon2 password hashes by role (nil value = role password not set)
    @@pw_hash_cache = {}
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

    # Redis key holding the argon2 password hash for the given role
    def self.role_key(role)
      role == ADMIN_ROLE ? PRIMARY_KEY : "#{PRIMARY_KEY}__#{role.upcase}"
    end

    # Checks whether the provided token is a valid user password, service password, or session token.
    # @param token [String] the plaintext password or session token to check (required)
    # @param no_password [Boolean] enforces use of a session token or service password (default: true)
    # @param service_only [Boolean] enforces use of a service password (default: false)
    # @return [Boolean] whether the provided password/token is valid
    def self.verify(token, no_password: true, service_only: false)
      return true if service_password?(token)
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

      unless mode == :password
        return true if session_role(token, consume_otp: true)
      end

      unless mode == :token
        return true if password_role(token)
      end

      return false
    end

    # Returns the role bound to a valid service password or session token.
    # Plaintext user passwords are deliberately NOT accepted: API callers must
    # exchange their password for a session first (AuthController#verify).
    # @param token [String] service password or session token
    # @param consume_otp [Boolean] terminate the session if it is a one-time token (default: true)
    # @return [String, nil] the role name or nil if the token is not valid
    def self.role(token, consume_otp: true)
      return nil if token.nil? or token.empty?
      return SERVICE_ROLE if service_password?(token)
      return session_role(token, consume_otp: consume_otp)
    end

    # Returns the role whose password matches the given plaintext password.
    # @return [String, nil] the role name or nil if no role password matches
    def self.password_role(password)
      return nil if password.nil? or password.empty?

      time = Time.now
      if @@pw_hash_cache_time.nil? or (time - @@pw_hash_cache_time) >= PW_HASH_CACHE_TIMEOUT
        @@pw_hash_cache = {}
        @@pw_hash_cache_time = time
      end

      PASSWORD_ROLES.each do |role|
        unless @@pw_hash_cache.key?(role)
          pw_hash = Store.get(role_key(role))
          if role == ADMIN_ROLE
            # Catch users who didn't run the migration utility when upgrading to COSMOS 7
            raise "invalid password hash" if pw_hash.nil? || !pw_hash.start_with?("$argon2")
          end
          @@pw_hash_cache[role] = pw_hash
        end
        pw_hash = @@pw_hash_cache[role]
        next unless pw_hash
        return role if Argon2::Password.verify_password(password, pw_hash)
      end
      return nil
    end

    # Sets the admin password (the password created at first login)
    def self.set(password, old_password, key = PRIMARY_KEY)
      raise "password must not be nil or empty" if password.nil? or password.empty?
      raise "password must be at least 8 characters" if password.length < MIN_PASSWORD_LENGTH

      if set?(key)
        raise "old_password must not be nil or empty" if old_password.nil? or old_password.empty?
        raise "old_password incorrect" unless verify_no_service(old_password, mode: :password)
      end
      pw_hash = Argon2::Password.create(password, profile: ARGON2_PROFILE)
      Store.set(key, pw_hash)
      clear_pw_hash_cache
      logout
    end

    # Sets the password for a non-admin role. Callers MUST authorize 'admin' first.
    # Terminates existing sessions of that role so the new credential takes effect.
    def self.set_role_password(role, password)
      raise "invalid role '#{role}'" unless PASSWORD_ROLES.include?(role) and role != ADMIN_ROLE
      raise "password must not be nil or empty" if password.nil? or password.empty?
      raise "password must be at least 8 characters" if password.length < MIN_PASSWORD_LENGTH
      raise "password already in use by another role" if password_role(password)

      pw_hash = Argon2::Password.create(password, profile: ARGON2_PROFILE)
      Store.set(role_key(role), pw_hash)
      clear_pw_hash_cache
      logout(role: role)
    end

    # Creates a new session token bound to a role. DO NOT CALL BEFORE VERIFYING.
    # @param otp [Boolean] whether to create a one-time use token (default: false)
    # @param role [String] the role the session grants (default: admin)
    # @return [String] the new session token
    def self.generate_session(otp: false, role: ADMIN_ROLE)
      raise "invalid role '#{role}'" unless ROLES.include?(role)

      token = SecureRandom.urlsafe_base64(nil, false)
      if otp
        token = OTP_PREFIX + token
      else
        token = SESSION_PREFIX + token
      end
      Store.hset(SESSIONS_KEY, token, JSON.generate({ 'role' => role, 'created' => Time.now.iso8601 }))
      return token
    end

    # Terminates every session, or only the sessions of the given role.
    def self.logout(role: nil)
      if role
        Store.hgetall(SESSIONS_KEY).each do |token, data|
          Store.hdel(SESSIONS_KEY, token) if parse_session_role(data) == role
        end
      else
        Store.del(SESSIONS_KEY)
      end
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

    def self.clear_pw_hash_cache
      @@pw_hash_cache = {}
      @@pw_hash_cache_time = nil
    end

    def self.service_password?(token)
      # TODO: Replace this with temporary service tokens
      service_password = ENV['OPENC3_SERVICE_PASSWORD']
      return (service_password and service_password == token) ? true : false
    end

    # Looks up a session token (using the cache) and returns its role or nil
    def self.session_role(token, consume_otp:)
      time = Time.now
      unless @@session_cache and (time - @@session_cache_time) < SESSION_CACHE_TIMEOUT and @@session_cache[token]
        @@session_cache = Store.hgetall(SESSIONS_KEY)
        @@session_cache_time = time
      end
      data = @@session_cache[token]
      return nil unless data

      terminate_otp(token) if consume_otp
      return parse_session_role(data)
    end

    # Sessions created before roles existed stored a bare timestamp; they were
    # issued against the single (admin) password so they keep the admin role.
    def self.parse_session_role(data)
      parsed = JSON.parse(data) rescue nil
      role = parsed.is_a?(Hash) ? parsed['role'] : nil
      return ROLES.include?(role) ? role : ADMIN_ROLE
    end

    private_class_method :service_password?, :session_role, :parse_session_role
  end
end
