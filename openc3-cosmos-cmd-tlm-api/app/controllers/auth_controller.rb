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

require 'openc3'
require 'openc3/models/auth_model'

class AuthController < ApplicationController
  MAX_BAD_ATTEMPTS = ENV.fetch('OPENC3_AUTH_RATE_LIMIT_TO', '10').to_i
  BAD_ATTEMPTS_WINDOW = ENV.fetch('OPENC3_AUTH_RATE_LIMIT_WITHIN', '120').to_i

  # Bad attempt counters are scoped per requesting client (see client_id) so a
  # malicious client can only lock itself out rather than every operator.
  USER_BAD_ATTEMPTS_KEY_PREFIX = 'openc3__auth_bad_attempts__user'
  SERVICE_BAD_ATTEMPTS_KEY_PREFIX = 'openc3__auth_bad_attempts__service'

  def token_exists
    result = OpenC3::AuthModel.set?
    render json: {
      result: result
    }
  end

  def verify
    if user_rate_limited?
      audit_login('rate_limited', 'password')
      head :too_many_requests
      return
    end

    begin
      if OpenC3::AuthModel.verify_no_service(params[:password], mode: :password)
        clear_user_bad_attempts
        audit_login('success', 'password')
        render :plain => OpenC3::AuthModel.generate_session()
      else
        record_user_bad_attempt
        audit_login('failure', 'password')
        head :unauthorized
      end
    rescue StandardError => e
      log_error(e)
      render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
    end
  end

  # Checks an existing session token. The login page calls this to skip the
  # login form when the browser already holds a valid session. Deliberately
  # separate from verify: a session token is never a valid password, so passing
  # one to verify always failed and counted as a bad password attempt, letting a
  # stale token in localStorage eat into the rate limit. Session tokens are
  # 128 bits of randomness, so there is nothing here to brute force.
  def verify_token
    # Reject anything that isn't shaped like a session token before touching
    # Redis. Verification is an HGET, so it's O(1), but this endpoint is
    # unauthenticated: the invariant is that garbage does no Redis work at all.
    # session_token? checks the full shape, not just the prefix, so a caller
    # that knows the prefix still can't
    # fall through with a token generate_session could never have produced. The
    # login page only ever holds a real token, so this costs us nothing. Note
    # this also keeps an OTP token out of verify_no_service, which would consume
    # it.
    unless OpenC3::AuthModel.session_token?(params[:token])
      audit_login('failure', 'session', reason: 'malformed_token')
      head :unauthorized
      return
    end

    begin
      if OpenC3::AuthModel.verify_no_service(params[:token], mode: :token)
        audit_login('success', 'session')
        head :ok
      else
        audit_login('failure', 'session')
        head :unauthorized
      end
    rescue StandardError => e
      log_error(e)
      render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
    end
  end

  def verify_service
    if service_rate_limited?
      audit_login('rate_limited', 'service')
      head :too_many_requests
      return
    end

    begin
      if OpenC3::AuthModel.verify(params[:password], service_only: true)
        clear_service_bad_attempts
        audit_login('success', 'service')
        render :plain => OpenC3::AuthModel.generate_session()
      else
        record_service_bad_attempt
        audit_login('failure', 'service')
        head :unauthorized
      end
    rescue StandardError => e
      log_error(e)
      render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
    end
  end

  def get_otp
    user = authorization('system')
    return unless user
    render :plain => OpenC3::Authorization.generate_otp(user)
  end

  def set
    if user_rate_limited?
      audit_login('rate_limited', 'password')
      head :too_many_requests
      return
    end

    begin
      # Set throws an exception if it fails for any reason
      OpenC3::AuthModel.set(params[:password], params[:old_password])
      clear_user_bad_attempts
      audit("Password changed", user: username(), event: 'password_changed', outcome: 'success')
      render :plain => OpenC3::AuthModel.generate_session()
    rescue StandardError => e
      if e.message == "old_password incorrect"
        record_user_bad_attempt
        audit_login('failure', 'password', reason: 'old_password incorrect')
      end
      log_error(e)
      render json: { status: 'error', message: e.message, type: e.class }, status: :internal_server_error
    end
  end

  private

  # Audit record for a logon attempt (see ApplicationController#audit). Bad
  # attempt counters are keyed by client_id (defined there) so a malicious
  # client can only lock itself out rather than every operator.
  # @param outcome [String] 'success', 'failure', 'rate_limited' or 'locked_out'
  # @param token_type [String] what was presented: 'password', 'service' or 'session'
  def audit_login(outcome, token_type, **fields)
    level = outcome == 'success' ? :info : :warn
    audit("Login #{outcome.tr('_', ' ')}", level: level, event: 'login', outcome: outcome, token_type: token_type, **fields)
  end

  def user_bad_attempts_key
    "#{USER_BAD_ATTEMPTS_KEY_PREFIX}__#{client_id}"
  end

  def service_bad_attempts_key
    "#{SERVICE_BAD_ATTEMPTS_KEY_PREFIX}__#{client_id}"
  end

  # Checks to see if this client has been rate limited due to bad user password attempts
  def user_rate_limited?
    rate_limited?(user_bad_attempts_key, 'user')
  end

  # Initializes or increments this client's bad attempt counter for the user password
  def record_user_bad_attempt
    record_bad_attempt(user_bad_attempts_key, 'user')
  end

  # Clears this client's bad attempt counter after a successful user authentication
  def clear_user_bad_attempts
    clear_bad_attempts(user_bad_attempts_key, 'user')
  end

  # Checks to see if this client has been rate limited due to bad service password attempts
  def service_rate_limited?
    rate_limited?(service_bad_attempts_key, 'service')
  end

  # Initializes or increments this client's bad attempt counter for the service password
  def record_service_bad_attempt
    record_bad_attempt(service_bad_attempts_key, 'service')
  end

  # Clears this client's bad attempt counter after a successful service authentication
  def clear_service_bad_attempts
    clear_bad_attempts(service_bad_attempts_key, 'service')
  end

  def rate_limited?(key, type)
    begin
      count = OpenC3::EphemeralStore.get(key)
      limited = count.to_i >= MAX_BAD_ATTEMPTS
      # A limited client returns before recording another bad attempt, so if the
      # counter somehow has no TTL (incr succeeded but expire didn't) nothing
      # would ever set one and the client would be locked out forever
      if limited and OpenC3::EphemeralStore.ttl(key) < 0
        OpenC3::EphemeralStore.expire(key, BAD_ATTEMPTS_WINDOW)
      end
      return limited
    rescue StandardError => error
      OpenC3::Logger.error("Redis error checking #{type} rate limit: #{error.message}")
      return false
    end
  end

  def record_bad_attempt(key, type)
    begin
      count = OpenC3::EphemeralStore.incr(key)
      # Refresh the TTL on every bad attempt so the window is measured from the
      # last bad attempt rather than the first. Note a client that is already
      # limited returns before getting here, so it can't extend its own lockout:
      # the lockout always ends BAD_ATTEMPTS_WINDOW after the attempt that
      # tripped it.
      OpenC3::EphemeralStore.expire(key, BAD_ATTEMPTS_WINDOW)
      # Distinct record the moment the limit trips so external alerting can
      # key on it without counting failures itself
      if count.to_i == MAX_BAD_ATTEMPTS
        audit_login('locked_out', type == 'service' ? 'service' : 'password', attempts: count.to_i, window_seconds: BAD_ATTEMPTS_WINDOW)
      end
    rescue StandardError => error
      OpenC3::Logger.error("Redis error recording #{type} bad attempt: #{error.message}")
    end
  end

  def clear_bad_attempts(key, type)
    begin
      OpenC3::EphemeralStore.del(key)
    rescue StandardError => error
      OpenC3::Logger.error("Redis error clearing #{type} bad attempts: #{error.message}")
    end
  end
end
