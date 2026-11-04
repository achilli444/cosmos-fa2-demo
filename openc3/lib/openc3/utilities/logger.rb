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
    @@scope = ENV['OPENC3_SCOPE']

    # DEBUG only prints DEBUG messages
    DEBUG = ::Logger::DEBUG
    # INFO prints INFO, DEBUG messages
    INFO  = ::Logger::INFO
    # WARN prints WARN, INFO, DEBUG messages
    WARN  = ::Logger::WARN
    # ERROR prints ERROR, WARN, INFO, DEBUG messages
    ERROR = ::Logger::ERROR
    # FATAL prints FATAL, ERROR, WARN, INFO, DEBUG messages
    FATAL = ::Logger::FATAL

    DEBUG_LEVEL = 'DEBUG'
    INFO_LEVEL = 'INFO'
    WARN_LEVEL = 'WARN'
    ERROR_LEVEL = 'ERROR'
    FATAL_LEVEL = 'FATAL'

    # Types
    LOG = 'log'
    NOTIFICATION = 'notification'
    ALERT = 'alert'
    EPHEMERAL = 'ephemeral'

    # Placeholder substituted for secret values by redact
    REDACTED = '[REDACTED]'
    # Hash keys / setting names / form fields whose values must never be logged
    SENSITIVE_KEY_PATTERN = /pass(word|wd|phrase)|secret|token|api_?key|credential|private_key|authorization|cookie|_key\z/i
    # Inline "key: value", "key => value", "key=value" (JSON, Ruby inspect, form-encoded)
    SENSITIVE_PAIR_PATTERN = /(["']?)(\w*(?:pass(?:word|wd|phrase)|secret|token|api_?key|credential|private_key|authorization|cookie)\w*)\1(\s*(?:=>|=|:)\s*)(["']?)((?:bearer\s+)?[^"'&\s,}\]]*)\4/i
    BEARER_PATTERN = /(bearer\s+)[A-Za-z0-9\-._~+\/]+=*/i

    # @param level [Integer] The initial logging level
    def initialize(level = Logger::INFO)
      @stdout = true
      @level = level
      @detail_string = nil
      @container_name = Socket.gethostname
      @microservice_name = nil
      @no_store = ENV['OPENC3_NO_STORE']
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
      data[:message] = message if message
      data[:type] = type if type
      data[:url] = url if url
      data = data.merge(other) if other
      return data
    end

    def self.build_log_data(log_level, message, user: nil, type: nil, url: nil, other: nil)
      self.instance.build_log_data(log_level, message, user: user, type: type, url: url, other: other)
    end

    # @param key [String, Symbol] Hash key, setting name or form field name
    # @return [Boolean] Whether values stored under this key are secrets
    def self.sensitive_key?(key)
      !!(key.to_s =~ SENSITIVE_KEY_PATTERN)
    end

    # Returns a copy of value safe to write to a log message. Hash values stored
    # under a sensitive key are replaced with REDACTED (recursively). Strings
    # are parsed as JSON when possible and otherwise scrubbed of inline
    # key/value pairs and bearer tokens. All other objects are returned as is.
    def self.redact(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, val), result|
          result[key] = sensitive_key?(key) ? REDACTED : redact(val)
        end
      when Array
        value.map { |val| redact(val) }
      when String
        redact_string(value)
      else
        value
      end
    end

    def self.redact_string(string)
      stripped = string.strip
      if stripped.start_with?('{', '[')
        begin
          parsed = JSON.parse(stripped, allow_nan: true)
          return JSON.generate(redact(parsed), allow_nan: true) if parsed.is_a?(Hash) or parsed.is_a?(Array)
        rescue StandardError
          # Not JSON (or not encodable), fall through to pattern based redaction
        end
      end
      redacted = string.gsub(SENSITIVE_PAIR_PATTERN) { "#{$1}#{$2}#{$1}#{$3}#{$4}#{REDACTED}#{$4}" }
      redacted.gsub(BEARER_PATTERN) { "#{$1}#{REDACTED}" }
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
