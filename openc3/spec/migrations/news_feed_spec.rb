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
ENV['OPENC3_NO_MIGRATE'] = 'true'
require 'openc3/migrations/20250108060000_news_feed'

module OpenC3
  describe NewsFeed do
    before(:each) do
      mock_redis()
    end

    describe "run" do
      it "creates the news_feed setting as off" do
        NewsFeed.run()
        expect(SettingModel.get(name: 'news_feed')['data']).to be false
      end

      it "leaves an existing opt-in alone" do
        SettingModel.set({ name: 'news_feed', data: true }, scope: 'DEFAULT')
        NewsFeed.run()
        expect(SettingModel.get(name: 'news_feed')['data']).to be true
      end
    end
  end
end
