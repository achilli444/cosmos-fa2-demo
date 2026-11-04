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

require 'openc3/models/model'
require 'openc3/models/setting_model'
require 'openc3/utilities/store'

module OpenC3
  class NewsModel < Model
    PRIMARY_KEY = 'openc3_news'
    SETTING_NAME = 'news_feed'
    NEWS_URL = 'https://news.openc3.com'
    NEWS_ENDPOINT = '/news'

    def self.set(news)
      Store.set(PRIMARY_KEY, news)
    end

    def self.all()
      Store.get(PRIMARY_KEY)
    end

    def self.news_error(message)
      Store.set(PRIMARY_KEY, [{
        date: Time.now.utc.iso8601,
        title: 'News Error',
        body: message
      }].to_json)
    end

    # The feed is opt-in: nothing is fetched unless the news_feed setting has
    # been explicitly set to true (Admin Console or OPENC3_SETTING_NEWS_FEED).
    # An unset setting means off.
    def self.enabled?(scope: 'DEFAULT')
      setting = SettingModel.get(name: SETTING_NAME, scope: scope)
      return false unless setting

      setting['data'] == true
    end

    # Fetch the feed. This is the only place COSMOS contacts the news site, so
    # the request is kept minimal: a bare GET with no query parameters. The
    # installed version and edition are not sent.
    def self.update
      conn = Faraday.new(url: NEWS_URL)
      response = conn.get(NEWS_ENDPOINT)
      if response.success?
        set(response.body)
      else
        news_error("Error contacting OpenC3 news feed (status: #{response.status})")
      end
    rescue StandardError => e
      news_error("Error contacting OpenC3 news feed. #{e.message}")
    end
  end
end
