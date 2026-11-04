# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software: you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'uri'

module ScriptRunnerApi
  # Single source of truth for which browser origins and Host headers the
  # script-runner-api trusts. Drives Rack::Cors (config/initializers/cors.rb),
  # ActionDispatch::HostAuthorization (config.hosts) and the Action Cable
  # origin check (config.action_cable.allowed_request_origins).
  #
  # OPENC3_ALLOWED_ORIGINS is a comma or whitespace separated list of origins
  # (scheme://host[:port]). When unset, OPENC3_EXTERNAL_URL (the URL users
  # reach COSMOS at) is used. When neither is set nothing is allowed.
  module AllowedOrigins
    ENV_VAR = 'OPENC3_ALLOWED_ORIGINS'
    FALLBACK_ENV_VAR = 'OPENC3_EXTERNAL_URL'
    SERVICE_HOSTNAME_ENV_VAR = 'OPENC3_SCRIPT_API_HOSTNAME'
    DEFAULT_SERVICE_HOSTNAME = 'openc3-cosmos-script-runner-api'
    LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'].freeze
    SEPARATOR = /[\s,]+/

    module_function

    # Origins allowed to make cross-origin requests and open WebSockets,
    # normalized to scheme://host[:port] with default ports omitted so they
    # compare equal to the Origin header browsers send.
    def origins(env = ENV)
      raw = env[ENV_VAR].to_s.strip
      raw = env[FALLBACK_ENV_VAR].to_s.strip if raw.empty?
      raw.split(SEPARATOR).reject(&:empty?).map { |value| normalize_origin(value) }.uniq
    end

    # Host header values accepted by ActionDispatch::HostAuthorization: the
    # hostnames of the allowed origins, this service's own hostname (Traefik
    # forwards with passHostHeader: false) and loopback for local access.
    def hosts(env = ENV)
      names = origins(env).map { |origin| URI.parse(origin).host }
      names << (env[SERVICE_HOSTNAME_ENV_VAR] || DEFAULT_SERVICE_HOSTNAME)
      names.concat(LOOPBACK_HOSTS)
      names.uniq
    end

    def configured?(env = ENV)
      !origins(env).empty?
    end

    def normalize_origin(value)
      uri = URI.parse(value)
      unless uri.is_a?(URI::HTTP) && uri.host
        raise ArgumentError, "#{ENV_VAR}/#{FALLBACK_ENV_VAR} entries must be http(s) URLs, got #{value.inspect}"
      end

      origin = "#{uri.scheme}://#{uri.host}"
      origin += ":#{uri.port}" unless uri.port == uri.default_port
      origin
    rescue URI::InvalidURIError
      raise ArgumentError, "#{ENV_VAR}/#{FALLBACK_ENV_VAR} entries must be http(s) URLs, got #{value.inspect}"
    end
  end
end
