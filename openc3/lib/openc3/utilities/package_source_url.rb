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

require 'uri'
require 'openc3/utilities/logger'

module OpenC3
  # Policy for the URLs COSMOS downloads executable packages from (the
  # rubygems_url and pypi_url settings). Gems and wheels fetched from these
  # sources run inside COSMOS, so a source is only accepted when:
  #
  # * it is an https URL with a host (plain http is accepted only when the
  #   operator opts in with OPENC3_PACKAGE_SOURCE_ALLOW_HTTP, for an internal
  #   mirror that has no TLS, and every use is logged as a warning), and
  # * its host is on OPENC3_PACKAGE_SOURCE_ALLOWED_HOSTS when that is set, a
  #   comma separated list of approved mirror hosts (optionally host:port).
  #
  # The same check runs when a value is written (Admin Console, initsettings,
  # local mode files, scope seeding) and again when it is used, so a value that
  # reached Redis some other way is still rejected before it is handed to
  # RubyGems or pip.
  module PackageSourceUrl
    ALLOW_HTTP_ENV = 'OPENC3_PACKAGE_SOURCE_ALLOW_HTTP'
    ALLOWED_HOSTS_ENV = 'OPENC3_PACKAGE_SOURCE_ALLOWED_HOSTS'

    class Error < ArgumentError; end

    # @param url [String] package source url
    # @param env [Hash] environment holding the policy variables
    # @return [String] the url when it satisfies the policy
    # @raise [Error] describing why the url is not an acceptable package source
    def self.check!(url, env: ENV)
      uri = URI.parse(url.to_s)
      unless uri.is_a?(URI::HTTP) && !uri.host.to_s.empty?
        raise Error, "not an http(s) URL"
      end

      host = uri.host.downcase
      hosts = allowed_hosts(env)
      unless hosts.empty? || hosts.include?(host) || hosts.include?("#{host}:#{uri.port}")
        raise Error, "host '#{uri.host}' is not listed in #{ALLOWED_HOSTS_ENV}"
      end

      unless uri.is_a?(URI::HTTPS)
        unless allow_http?(env)
          raise Error, "plain http is not permitted, use https or set #{ALLOW_HTTP_ENV}=1 for an internal mirror"
        end

        Logger.warn("Package source '#{url}' is plain http; packages are not protected in transit (#{ALLOW_HTTP_ENV} is set)")
      end
      url
    rescue URI::InvalidURIError => e
      raise Error, e.message
    end

    # Check +url+ and fall back to +default+ when it fails, logging the reason.
    # The default is subject to the same policy, so a deployment that has
    # restricted the allowed hosts to its own mirror fails closed instead of
    # quietly reaching out to the public index.
    #
    # @param url [String] the resolved package source url
    # @param default [String] source to use when +url+ is rejected
    # @param label [String] setting name for the log message
    # @return [String] +url+ when valid, otherwise +default+
    # @raise [Error] when neither +url+ nor +default+ is permitted
    def self.validate(url, default:, label:, env: ENV)
      check!(url, env: env)
    rescue Error => e
      Logger.error("Invalid #{label} '#{url}' (#{e.message}); falling back to #{default}")
      begin
        check!(default, env: env)
      rescue Error => default_error
        raise Error, "#{label} '#{url}' rejected (#{e.message}) and default #{default} is not permitted either (#{default_error.message})"
      end
    end

    # @return [Array<String>] lowercased hosts from ALLOWED_HOSTS_ENV, empty when unset
    def self.allowed_hosts(env = ENV)
      env[ALLOWED_HOSTS_ENV].to_s.split(',').map { |host| host.strip.downcase }.reject(&:empty?)
    end

    # @return [Boolean] whether ALLOW_HTTP_ENV opts in to plain http sources
    def self.allow_http?(env = ENV)
      value = env[ALLOW_HTTP_ENV].to_s.strip.downcase
      !value.empty? && !%w(0 false no off).include?(value)
    end
  end
end
