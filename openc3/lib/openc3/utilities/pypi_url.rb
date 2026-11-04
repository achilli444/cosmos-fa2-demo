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
  class PypiUrl
    # The pypi_url setting holds the base url; callers append /simple
    BASE_DEFAULT = 'https://pypi.org'
    DEFAULT = "#{BASE_DEFAULT}/simple"

    # Validate a resolved pypi_url against the PackageSourceUrl policy (https,
    # optional admin host allow-list) before it is handed to pip. The value can
    # come from a user-writable setting or ENV, so a malformed or non-compliant
    # value is rejected and replaced with the default rather than passed through
    # to pip.
    #
    # @param pypi_url [String] the resolved pypi index url to validate
    # @return [String] the original url if valid, otherwise DEFAULT
    # @raise [PackageSourceUrl::Error] if DEFAULT is not permitted either
    def self.validate(pypi_url)
      PackageSourceUrl.validate(pypi_url, default: DEFAULT, label: 'pypi_url')
    end

    # Raise rather than fall back, for validating a value before it is stored
    #
    # @param pypi_url [String] a pypi index base url
    # @return [String] pypi_url
    # @raise [PackageSourceUrl::Error] describing why the url is rejected
    def self.check!(pypi_url)
      PackageSourceUrl.check!(pypi_url)
    end
  end
end
