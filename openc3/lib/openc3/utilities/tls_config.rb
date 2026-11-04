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

require 'openssl'
require 'uri'
require 'openc3/utilities/env_helper'

module OpenC3
  # Shared TLS settings for the internal service clients (Redis/Valkey, QuestDB,
  # S3-compatible buckets). The same environment variables drive the Python
  # clients in openc3/python/openc3/utilities/tls_config.py.
  #
  #   OPENC3_REDIS_TLS=1             connect with rediss:// (TLS) and verify the server certificate
  #   OPENC3_REDIS_TLS_CA_FILE       PEM CA bundle used to verify the Redis server (default: system store)
  #   OPENC3_REDIS_TLS_CERT_FILE     PEM client certificate for mutual TLS (optional)
  #   OPENC3_REDIS_TLS_KEY_FILE      PEM client key for mutual TLS (optional)
  #   OPENC3_TSDB_TLS=1              use sslmode=verify-full for QuestDB PG connections and HTTPS for ILP ingest
  #   OPENC3_TSDB_TLS_CA_FILE        PEM CA bundle used to verify QuestDB (default: system store)
  #   OPENC3_BUCKET_TLS=1            require an https:// bucket endpoint (plaintext http:// endpoints are rejected)
  #   OPENC3_BUCKET_TLS_CA_FILE      PEM CA bundle used to verify the bucket endpoint (default: system store)
  #
  # Certificate verification is always on when TLS is enabled; there is deliberately no
  # knob to turn it off. Supply the issuing CA via the *_CA_FILE variables instead.
  module TlsConfig
    class Error < RuntimeError; end

    DEFAULT_BUCKET_HOST = 'openc3-buckets:9000'
    DEFAULT_DEVEL_BUCKET_HOST = '127.0.0.1:9000'

    def self.redis_tls?
      EnvHelper.enabled?('OPENC3_REDIS_TLS')
    end

    # Build the Redis URL for the given host and port, selecting rediss:// when TLS is enabled.
    def self.redis_url(hostname, port)
      "#{redis_tls? ? 'rediss' : 'redis'}://#{hostname}:#{port}"
    end

    # OpenSSL parameters passed to Redis.new(ssl_params:). Returns nil when TLS is disabled.
    def self.redis_ssl_params
      return nil unless redis_tls?

      params = { verify_mode: OpenSSL::SSL::VERIFY_PEER }
      ca_file = env_file('OPENC3_REDIS_TLS_CA_FILE')
      params[:ca_file] = ca_file if ca_file
      cert_file = env_file('OPENC3_REDIS_TLS_CERT_FILE')
      key_file = env_file('OPENC3_REDIS_TLS_KEY_FILE')
      if cert_file.nil? ^ key_file.nil?
        raise Error, 'OPENC3_REDIS_TLS_CERT_FILE and OPENC3_REDIS_TLS_KEY_FILE must be set together'
      end

      if cert_file
        params[:cert] = cert_file
        params[:key] = key_file
      end
      params
    end

    # Keyword arguments merged into Redis.new for TLS. Empty hash when TLS is disabled.
    def self.redis_options
      params = redis_ssl_params
      params ? { ssl: true, ssl_params: params } : {}
    end

    def self.tsdb_tls?
      EnvHelper.enabled?('OPENC3_TSDB_TLS')
    end

    # Connection parameters merged into PG::Connection.new. Empty hash when TLS is disabled.
    # sslmode=verify-full checks both the certificate chain and the hostname. Without an
    # explicit CA file, libpq 16+ accepts sslrootcert=system to use the OS trust store.
    def self.tsdb_pg_params
      return {} unless tsdb_tls?

      { sslmode: 'verify-full', sslrootcert: env_file('OPENC3_TSDB_TLS_CA_FILE') || 'system' }
    end

    def self.bucket_tls?
      EnvHelper.enabled?('OPENC3_BUCKET_TLS')
    end

    # PEM CA bundle for the bucket endpoint, or nil to use the system trust store.
    def self.bucket_ca_file
      env_file('OPENC3_BUCKET_TLS_CA_FILE')
    end

    # Resolve the S3-compatible bucket endpoint for OPENC3_CLOUD=local.
    # Uses OPENC3_BUCKET_URL when set, otherwise the in-cluster (or OPENC3_DEVEL) default.
    # When OPENC3_BUCKET_TLS is enabled the default becomes https:// and a plaintext
    # http:// endpoint is rejected so a misconfiguration fails closed instead of
    # silently sending credentials and mission data in the clear.
    def self.bucket_endpoint(devel: EnvHelper.set?('OPENC3_DEVEL'))
      url = ENV['OPENC3_BUCKET_URL'].to_s
      if url.empty?
        scheme = bucket_tls? ? 'https' : 'http'
        url = "#{scheme}://#{devel ? DEFAULT_DEVEL_BUCKET_HOST : DEFAULT_BUCKET_HOST}"
      end
      if bucket_tls?
        scheme = URI.parse(url).scheme.to_s.downcase
        unless scheme == 'https'
          raise Error, "OPENC3_BUCKET_TLS is enabled but OPENC3_BUCKET_URL '#{url}' is not https://"
        end
      end
      url
    end

    def self.env_file(key)
      value = ENV[key].to_s
      value.empty? ? nil : value
    end
    private_class_method :env_file
  end
end
