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

require 'spec_helper'
require 'openc3/utilities/pypi_url'

module OpenC3
  describe PypiUrl do
    describe "self.valid?" do
      it "accepts http and https URLs with a host" do
        expect(PypiUrl.valid?('https://pypi.org')).to be true
        expect(PypiUrl.valid?('http://pypi.org')).to be true
        expect(PypiUrl.valid?('https://mirror.example.com')).to be true
        expect(PypiUrl.valid?('https://mirror.example.com:8443/repository/pypi-proxy')).to be true
        expect(PypiUrl.valid?('http://10.0.0.5:3141/root/pypi')).to be true
        expect(PypiUrl.valid?('https://mirror.example.com/pypi%20mirror')).to be true
      end

      it "rejects nil and non-string values" do
        expect(PypiUrl.valid?(nil)).to be false
        expect(PypiUrl.valid?(123)).to be false
        expect(PypiUrl.valid?(['https://pypi.org'])).to be false
      end

      it "rejects empty and relative values" do
        expect(PypiUrl.valid?('')).to be false
        expect(PypiUrl.valid?('pypi.org')).to be false
        expect(PypiUrl.valid?('/simple')).to be false
        expect(PypiUrl.valid?('https://')).to be false
        expect(PypiUrl.valid?('https:///simple')).to be false
      end

      it "rejects non-http(s) schemes" do
        expect(PypiUrl.valid?('ftp://pypi.org')).to be false
        expect(PypiUrl.valid?('file:///etc/passwd')).to be false
        expect(PypiUrl.valid?('javascript:alert(1)')).to be false
        expect(PypiUrl.valid?('ssh://git@pypi.org')).to be false
      end

      it "rejects userinfo" do
        expect(PypiUrl.valid?('https://user:pass@pypi.org')).to be false
        expect(PypiUrl.valid?('https://user@pypi.org')).to be false
      end

      it "rejects whitespace and shell metacharacters" do
        [
          'https://pypi.org; touch /tmp/pwned #',
          'https://pypi.org;touch /tmp/pwned',
          'https://pypi.org && id',
          'https://pypi.org | id',
          'https://pypi.org`id`',
          'https://pypi.org$(id)',
          '$(id)',
          'https://pypi.org > /tmp/pwned',
          'https://pypi.org < /etc/passwd',
          "https://pypi.org\ntouch /tmp/pwned",
          "https://pypi.org\ttouch",
          'https://pypi.org "x"',
          "https://pypi.org 'x'",
          'https://pypi.org\\',
          'https://pypi.org?a=b',
          'https://pypi.org#frag',
          'https://pypi.org*',
          'https://pypi.org{a,b}',
          'https://pypi.org(a)',
        ].each do |url|
          expect(PypiUrl.valid?(url)).to be(false), "expected #{url.inspect} to be rejected"
        end
      end
    end

    describe "self.index_url" do
      it "appends /simple to a valid URL" do
        expect(PypiUrl.index_url('https://pypi.org')).to eql 'https://pypi.org/simple'
        expect(PypiUrl.index_url('https://mirror.example.com')).to eql 'https://mirror.example.com/simple'
      end

      it "returns nil for an invalid URL" do
        expect(PypiUrl.index_url(nil)).to be_nil
        expect(PypiUrl.index_url('https://pypi.org; touch /tmp/pwned #')).to be_nil
        expect(PypiUrl.index_url('$(id)')).to be_nil
      end
    end

    describe "DEFAULT_URL" do
      it "is a valid URL" do
        expect(PypiUrl.valid?(PypiUrl::DEFAULT_URL)).to be true
        expect(PypiUrl.index_url(PypiUrl::DEFAULT_URL)).to eql 'https://pypi.org/simple'
      end
    end
  end
end
