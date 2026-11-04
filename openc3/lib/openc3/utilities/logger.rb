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

require 'openc3/core_ext/class'
require 'openc3/core_ext/time'
require 'openc3/utilities/store_queued'
require 'socket'
require 'logger'
require 'time'
require 'json'
require 'openc3/utilities/env_helper'

module OpenC3
  # Supports different levels of logging and only writes if the level
  # is exceeded.
  class Logger
    # @return [Boolean] Whether to output the message to stdout
    instance_attr_accessor :stdout

    # @return [Integer] The logging level
    instance_attr_accessor :level

    # @return [String] Additional detail to add to messages
    instance_attr_accessor :detail_string

    # @return [String] Microservice name
    attr_reader :microservice_name

    @@mutex = Mutex.new
    @@instance = nil
    @@scope = ENV.fetch('OPENC3_SCOPE', 'DEFAULT')

    # Levels in increasing severity. Logging at a level prints that level
    # and everything above it, e.g. WARN prints WARN, ERROR and FATAL.
    DEBUG = ::Logger::DEBUG
    INFO  = ::Logger::INFO
    WARN  = ::Logger::WARN
    ERROR = ::Logger::ERROR
    FATAL = ::Logger::FATAL

    # Level names as they appear in log messages and OPENC3_LOG_LEVEL
    DEBUG_LEVEL = 'DEBUG'
    INFO_LEVEL = 'INFO'
    WARN_LEVEL = 'WARN'
    ERROR_LEVEL = 'ERROR'
    FATAL_LEVEL = 'FATAL'

    LEVELS = {
      DEBUG_LEVEL => DEBUG,
      INFO_LEVEL => INFO,
      WARN_LEVEL => WARN,
      ERROR_LEVEL => ERROR,
      FATAL_LEVEL => FATAL
    }.freeze

    # Types
    LOG = 'log'
    NOTIFICATION = 'notification'
    ALERT = 'alert'
    EPHEMERAL = 'ephemeral'

    # Replacement written in place of a credential or secret value
    REDACTED = '[REDACTED]'

    # Key names (matched case-insensitively as substrings, like Rails
    # filter_parameters) whose values are never allowed into a log message.
    # Covers session tokens, Keycloak bearer / refresh / id tokens, the service
    # password, Redis secret values and API keys.
    SENSITIVE_KEYS = %w(
      authorization
      password
      passwd
      passw
      secret
      token
      api_key
      apikey
      cookie
      otp
      credential
      private_key
    ).freeze

    SENSITIVE_KEY_REGEX = /(?:#{SENSITIVE_KEYS.join('|')})/i

    # Matches a sensitive key followed by its value in the serializations that
    # reach the logger: Ruby Hash#inspect ("key"=>"value", key: "value",
    # "key" => "value"), JSON ("key":"value"), form / query (key=value) and
    # HTTP header (Key: value) syntax. Values may be quoted or bare.
    # The key is captured so the log still shows WHICH field was redacted.
    # Quoted values may also be backslash-escaped (a JSON body inspected inside
    # a Hash) and bare values may be an HTTP auth scheme followed by its token.
    SENSITIVE_PATTERN = /
      (?<key>(?:\\?["'])?[A-Za-z0-9_\-]*#{SENSITIVE_KEY_REGEX}[A-Za-z0-9_\-]*(?:\\?["'])?)
      (?<sep>\s*(?:=>|:|=)\s*)
      (?<value>
        \\"(?:(?!\\").)*\\"
        | "(?:[^"\\]|\\.)*"
        | '(?:[^'\\]|\\.)*'
        | (?:Bearer|Basic|Token)\s+[^\s,}\]&;]+
        | [^\s,}\]&;]+
      )
    /xi

    # @return [Integer] Level named by the OPENC3_LOG_LEVEL env var.
    #   INFO if the var is unset or isn't a level name.
    def self.default_level
      level = ENV.fetch('OPENC3_LOG_LEVEL', '')
      name = level.to_s.strip.upcase
      return INFO if name.empty?

      LEVELS.fetch(name) do
        unless @warned_bad_level
          @warned_bad_level = true
          $stderr.puts "OPENC3_LOG_LEVEL '#{level}' is not one of #{LEVELS.keys.join(', ')}, using INFO"
        end
        INFO
      end
    end

    # @param level [Integer] The initial logging level
    def initialize(level = Logger.default_level)
      @stdout = true
      @level = level
      @detail_string = nil
      @container_name = Socket.gethostname
      @microservice_name = nil
      @no_store = ENV.fetch('OPENC3_NO_STORE', nil)
    end

    # Only set the microservice name once (to help with multi microservices)
    def microservice_name=(name)
      @microservice_name = name unless @microservice_name
    end

    def self.microservice_name
      self.instance.microservice_name
    end

    def self.microservice_name=(name)
      self.instance.microservice_name = name
    end

    # @param message [String] The message to print if the log level is at or
    #   below the method name log level.
    # @param block [Proc] Block to call which should return a string to append
    #   to the log message
    def debug(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      log_message(DEBUG_LEVEL, message, scope: scope, user: user, type: type, url: url, other: other, &block) if @level <= DEBUG
    end

    # (see #debug)
    def info(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      log_message(INFO_LEVEL, message, scope: scope, user: user, type: type, url: url, other: other, &block) if @level <= INFO
    end

    # (see #debug)
    def warn(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      log_message(WARN_LEVEL, message, scope: scope, user: user, type: type, url: url, other: other, &block) if @level <= WARN
    end

    # (see #debug)
    def error(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      log_message(ERROR_LEVEL, message, scope: scope, user: user, type: type, url: url, other: other, &block) if @level <= ERROR
    end

    # (see #debug)
    def fatal(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      log_message(FATAL_LEVEL, message, scope: scope, user: user, type: type, url: url, other: other, &block) if @level <= FATAL
    end

    # (see #debug)
    def self.debug(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      self.instance.debug(message, scope: scope, user: user, type: type, url: url, other: other, &block)
    end

    # (see #debug)
    def self.info(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      self.instance.info(message, scope: scope, user: user, type: type, url: url, other: other, &block)
    end

    # (see #debug)
    def self.warn(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      self.instance.warn(message, scope: scope, user: user, type: type, url: url, other: other, &block)
    end

    # (see #debug)
    def self.error(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      self.instance.error(message, scope: scope, user: user, type: type, url: url, other: other, &block)
    end

    # (see #debug)
    def self.fatal(message = nil, scope: @@scope, user: nil, type: LOG, url: nil, other: nil, &block)
      self.instance.fatal(message, scope: scope, user: user, type: type, url: url, other: other, &block)
    end

    # @return [Logger] The logger instance
    def self.instance
      return @@instance if @@instance

      @@mutex.synchronize do
        @@instance ||= self.new
      end
      @@instance
    end

    def self.scope
      return @@scope
    end

    def self.scope=(scope)
      @@scope = scope
    end

    def scope
      return @@scope
    end

    def scope=(scope)
      @@scope = scope
    end

    # Redact credential values from a log message.
    #
    # This is the central scrubber every message passes through before it is
    # written to stdout or the openc3_log_messages stream, so a credential that
    # is interpolated into a message (an Authorization header in a request dump,
    # a password in a form body, a token in a JSON response) is replaced by
    # REDACTED instead of reaching the central log.
    #
    # @param message [String, Hash, Array, Object] The message to scrub.
    #   Strings are scrubbed in place of key/value pairs, Hashes and Arrays are
    #   scrubbed by key, anything else is returned unchanged.
    # @return [Object] The scrubbed message
    def self.scrub(message)
      case message
      when String
        return message unless message.match?(SENSITIVE_KEY_REGEX)

        message.gsub(SENSITIVE_PATTERN) do
          m = Regexp.last_match
          # Prose such as "Unable to refresh token: connection refused" is a bare
          # key, a colon and a bare word. Serialized credentials always have a
          # quoted key, a quoted value, a => or = separator, or an auth scheme.
          if m[:key].match?(/["']/) || m[:sep].match?(/=/) || m[:value].match?(/\A(?:\\?["']|(?:Bearer|Basic|Token)\s)/i)
            "#{m[:key]}#{m[:sep]}#{REDACTED}"
          else
            m[0]
          end
        end
      when Hash, Array
        scrub_hash(message)
      else
        message
      end
    end

    # Deep copy a Hash (or Array of Hashes) replacing every value whose key
    # matches SENSITIVE_KEYS with REDACTED. Non-sensitive String values are
    # scrubbed with {scrub} so a serialized credential inside them is caught too.
    #
    # @param object [Hash, Array, Object] The object to scrub
    # @return [Hash, Array, Object] A scrubbed copy
    def self.scrub_hash(object)
      case object
      when Hash
        object.each_with_object({}) do |(key, value), result|
          result[key] = sensitive_key?(key) ? REDACTED : scrub_hash(value)
        end
      when Array
        object.map { |value| scrub_hash(value) }
      when String
        scrub(object)
      else
        object
      end
    end

    # @param key [String, Symbol] A hash key or header name
    # @return [Boolean] Whether values under this key must be redacted
    def self.sensitive_key?(key)
      key.to_s.match?(SENSITIVE_KEY_REGEX)
    end

    def build_log_data(log_level, message, user: nil, type: nil, url: nil, other: nil, &block)
      time = Time.now.utc
      # timestamp iso8601 with 6 decimal places to match the python output format
      data = { time: time.to_nsec_from_epoch, '@timestamp' => time.iso8601(6), level: log_level }
      data[:microservice_name] = @microservice_name if @microservice_name
      data[:detail] = @detail_string if @detail_string
      data[:user] = user if user # Enterprise: If a user is passed, put its name. Don't include user data if no user was passed.
      if block_given?
        message = yield
      end
      data[:container_name] = @container_name
      data[:message] = Logger.scrub(message) if message
      data[:type] = type if type
      data[:url] = url if url
      data = data.merge(Logger.scrub_hash(other)) if other
      return data
    end

    def self.build_log_data(log_level, message, user: nil, type: nil, url: nil, other: nil)
      self.instance.build_log_data(log_level, message, user: user, type: type, url: url, other: other)
    end

    protected

    def log_message(log_level, message, scope:, user:, type:, url:, other: nil, &block)
      @@mutex.synchronize do
        data = build_log_data(log_level, message, user: user, type: type, url: url, other: other, &block)
        if @stdout
          # send warning, error, and fatal to stderr if OPENC3_LOG_STDERR env var is set to 1 or true
          if [WARN_LEVEL, ERROR_LEVEL, FATAL_LEVEL].include?(log_level) && EnvHelper.enabled?('OPENC3_LOG_STDERR')
            io = $stderr
          else
            io = $stdout
          end
          io.puts data.as_json().to_json(allow_nan: true)
          io.flush
        end
        unless @no_store
          if scope
            EphemeralStoreQueued.write_topic("#{scope}__openc3_log_messages", data)
          else
            EphemeralStoreQueued.write_topic("NOSCOPE__openc3_log_messages", data)
          end
        end
      end
    end
  end
end
