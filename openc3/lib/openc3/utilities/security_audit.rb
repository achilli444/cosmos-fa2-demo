# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'openc3/utilities/logger'

module OpenC3
  # Emits structured security audit events (authentication and authorization
  # outcomes) through OpenC3::Logger so they can be forwarded to a SIEM.
  # Every event carries who (user), where from (source address), what
  # (event / method) and the outcome. Credentials (passwords, tokens) are
  # never included.
  module SecurityAudit
    # Logger type used for every security event so they can be filtered out
    # of the general log stream
    TYPE = 'security'

    SUCCESS = 'success'
    FAILURE = 'failure'
    RATE_LIMITED = 'rate_limited'

    CONTEXT_KEY = :openc3_security_audit_context

    # Request headers consulted (in order) to find the client address. The
    # first is set by the traefik reverse proxy for every proxied request.
    SOURCE_HEADERS = %w(HTTP_X_FORWARDED_FOR HTTP_X_REAL_IP REMOTE_ADDR)

    # @return [Hash] the per-thread request context (source, user, method)
    #   that enriches events logged deeper in the call stack
    def self.context
      Thread.current[CONTEXT_KEY] || {}
    end

    # Runs the block with the given request details merged into the audit
    # context so that events raised inside authorize() or the JSON-RPC
    # dispatcher can name the caller. Values already present in the context
    # (e.g. the Rails remote_ip) are kept unless the new value is non-nil.
    def self.with_context(source: nil, user: nil, method: nil)
      previous = Thread.current[CONTEXT_KEY]
      merged = (previous || {}).dup
      merged[:source] = source if source
      merged[:user] = user if user
      merged[:method] = method if method
      Thread.current[CONTEXT_KEY] = merged
      yield
    ensure
      Thread.current[CONTEXT_KEY] = previous
    end

    # @param headers [Hash] Rack style request headers (HTTP_* keys)
    # @return [String, nil] the client address or nil if not present
    def self.source_from_headers(headers)
      return nil unless headers

      SOURCE_HEADERS.each do |name|
        value = headers[name]
        next if value.nil? || value.to_s.strip.empty?

        # X-Forwarded-For is a comma separated list, the first is the client
        return value.to_s.split(',').first.strip
      end
      nil
    end

    # Logs a structured security event.
    #
    # @param event [String] event name, e.g. 'login', 'authorize'
    # @param outcome [String] SUCCESS, FAILURE or RATE_LIMITED
    # @param reason [String] why the outcome happened (never a credential)
    # @param user [String] user name, defaults to the context user
    # @param source [String] client address, defaults to the context source
    # @param scope [String] scope the request targeted. The event is written
    #   to that scope's log stream (so it shows in its Log Messages tool) or to
    #   the NOSCOPE stream when the scope is unknown, e.g. at login.
    # @param details [Hash] additional structured fields
    def self.log(event:, outcome:, reason: nil, user: nil, source: nil, scope: nil, **details)
      ctx = context
      data = {
        event: event,
        outcome: outcome,
        reason: reason,
        user: user || ctx[:user] || 'anonymous',
        source: source || ctx[:source],
        method: details.delete(:method) || ctx[:method],
        scope: scope,
      }.merge(details).compact
      message = "Security event #{event} #{outcome}"
      message << ": #{reason}" if reason
      message << " (user: #{data[:user]}, source: #{data[:source] || 'unknown'})"
      # Fields are written flat (scalar values only): the log record is also
      # XADDed to the Redis log stream, which cannot hold nested hashes
      fields = data.reject { |key, _| key == :user }.transform_values(&:to_s)
      if outcome == SUCCESS
        Logger.info(message, scope: scope, user: data[:user], type: TYPE, other: fields)
      else
        Logger.warn(message, scope: scope, user: data[:user], type: TYPE, other: fields)
      end
      data
    end

    # Convenience wrapper used at the authorize() raise sites
    def self.authorization_failure(reason, forbidden: false, **details)
      log(event: forbidden ? 'authorize_forbidden' : 'authorize', outcome: FAILURE, reason: reason, **details)
    end
  end
end
