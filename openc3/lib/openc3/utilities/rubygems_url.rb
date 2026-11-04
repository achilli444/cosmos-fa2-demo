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
  # Validates the user-configurable rubygems_url setting (and RUBYGEMS_URL ENV
  # fallback) before it is used as a Gem source. Gems and their dependencies are
  # executable code, so only https URLs with a host, no userinfo and no shell
  # metacharacters are accepted. Internal mirrors must present a certificate the
  # container trusts (SSL_CERT_FILE / SSL_CERT_DIR); cleartext http is rejected.
  module RubygemsUrl
    DEFAULT_URL = 'https://rubygems.org'
    ALLOWED_SCHEMES = ['https'].freeze
    ALLOWED_CHARACTERS = %r{\A[A-Za-z0-9\-._~:/%+]+\z}

    def self.valid?(url)
      return false unless url.is_a?(String) && url.match?(ALLOWED_CHARACTERS)

      uri = URI.parse(url)
      ALLOWED_SCHEMES.include?(uri.scheme) && !uri.host.to_s.empty? && uri.userinfo.nil?
    rescue URI::InvalidURIError
      false
    end

    # @return [String] url if valid, otherwise DEFAULT_URL (and the rejection is logged)
    def self.validate(url)
      return url if valid?(url)

      Logger.error "Invalid rubygems_url #{url.inspect}: must be an https URL with no userinfo or shell metacharacters. " \
                   "Falling back to #{DEFAULT_URL}"
      DEFAULT_URL
    end
  end
end
