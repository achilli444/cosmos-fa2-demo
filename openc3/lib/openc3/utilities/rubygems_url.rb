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

require 'openc3/utilities/package_source_url'

module OpenC3
  class RubygemsUrl
    DEFAULT = 'https://rubygems.org'

    # Validate a resolved rubygems_url against the PackageSourceUrl policy
    # (https, optional admin host allow-list) before it is used as a Gem
    # source. The value can come from a user-writable setting or ENV, so a
    # malformed or non-compliant value is rejected and replaced with the default
    # rather than passed through to RubyGems.
    #
    # @param rubygems_url [String] the resolved rubygems source url to validate
    # @return [String] the original url if valid, otherwise DEFAULT
    # @raise [PackageSourceUrl::Error] if DEFAULT is not permitted either
    def self.validate(rubygems_url)
      PackageSourceUrl.validate(rubygems_url, default: DEFAULT, label: 'rubygems_url')
    end

    # Raise rather than fall back, for validating a value before it is stored
    #
    # @param rubygems_url [String] a rubygems source url
    # @return [String] rubygems_url
    # @raise [PackageSourceUrl::Error] describing why the url is rejected
    def self.check!(rubygems_url)
      PackageSourceUrl.check!(rubygems_url)
    end
  end
end
