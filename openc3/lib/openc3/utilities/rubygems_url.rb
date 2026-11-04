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
  class RubygemsUrl
    DEFAULT = 'https://rubygems.org'

    # Validate that a resolved rubygems_url is an https URL before it is used as a
    # package source. The value can come from a user-writable setting or ENV, so
    # a malformed, non-http or plain-http value is rejected and replaced with the
    # default rather than passed through: packages fetched over http (or with
    # TLS verification disabled) can be swapped in transit, so only https
    # indexes are accepted.
    #
    # @param rubygems_url [String] the resolved url to validate
    # @return [String] the original url if valid, otherwise DEFAULT
    def self.validate(rubygems_url)
      uri = URI.parse(rubygems_url)
      unless uri.is_a?(URI::HTTPS) && !uri.host.to_s.empty?
        raise URI::InvalidURIError, "not an https URL"
      end
      rubygems_url
    rescue URI::InvalidURIError => e
      Logger.error("Invalid rubygems_url '#{rubygems_url}' (#{e.message}); falling back to #{DEFAULT}")
      DEFAULT
    end
  end
end
