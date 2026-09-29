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

module OpenC3
  # Validates the user-configurable pypi_url setting (and PYPI_URL ENV fallback)
  # before it is handed to a subprocess. Only absolute http(s) URLs with a host,
  # no userinfo and no whitespace or shell metacharacters are accepted.
  module PypiUrl
    DEFAULT_URL = 'https://pypi.org'
    ALLOWED_SCHEMES = ['http', 'https'].freeze
    # Conservative allowlist of URL characters. Deliberately excludes
    # whitespace, quotes, '@' and every shell metacharacter.
    ALLOWED_CHARACTERS = %r{\A[A-Za-z0-9\-._~:/%+]+\z}

    def self.valid?(url)
      return false unless url.is_a?(String) && url.match?(ALLOWED_CHARACTERS)

      uri = URI.parse(url)
      ALLOWED_SCHEMES.include?(uri.scheme) && !uri.host.to_s.empty? && uri.userinfo.nil?
    rescue URI::InvalidURIError
      false
    end

    # Returns the pip index URL ("<url>/simple") or nil if url is not valid
    def self.index_url(url)
      return nil unless valid?(url)

      "#{url}/simple"
    end
  end
end
