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
require 'openc3/models/news_model'

module OpenC3
  describe NewsModel do
    before(:each) do
      mock_redis()
    end

    describe "self.enabled?" do
      it "is false when the setting was never created" do
        expect(NewsModel.enabled?).to be false
      end

      it "is false when the setting is false" do
        SettingModel.set({ name: 'news_feed', data: false }, scope: 'DEFAULT')
        expect(NewsModel.enabled?).to be false
      end

      it "is true only when the setting is explicitly true" do
        SettingModel.set({ name: 'news_feed', data: true }, scope: 'DEFAULT')
        expect(NewsModel.enabled?).to be true
      end
    end

    describe "self.update" do
      it "sends a bare GET with no version or edition parameters" do
        response = double('response', success?: true, body: '[{"title":"hi"}]')
        conn = double('conn')
        expect(Faraday).to receive(:new).with(url: 'https://news.openc3.com').and_return(conn)
        expect(conn).to receive(:get).with('/news').and_return(response)
        NewsModel.update()
        expect(NewsModel.all()).to eql '[{"title":"hi"}]'
      end

      it "never passes the installed VERSION or ENTERPRISE flag" do
        allow_any_instance_of(Faraday::Connection).to receive(:get) do |conn, _path, params|
          expect(conn.params).to be_empty
          expect(params).to be_nil
          double('response', success?: true, body: '[]')
        end
        NewsModel.update()
        expect(NewsModel.all()).to eql '[]'
      end

      it "records a news error on a non-success status" do
        response = double('response', success?: false, status: 503)
        allow_any_instance_of(Faraday::Connection).to receive(:get).and_return(response)
        NewsModel.update()
        news = JSON.parse(NewsModel.all())
        expect(news[0]['title']).to eql 'News Error'
        expect(news[0]['body']).to include 'status: 503'
      end

      it "records a news error if the feed can't be reached" do
        allow_any_instance_of(Faraday::Connection).to receive(:get).and_raise(Faraday::ConnectionFailed.new('no route'))
        NewsModel.update()
        news = JSON.parse(NewsModel.all())
        expect(news[0]['title']).to eql 'News Error'
        expect(news[0]['body']).to include 'no route'
      end
    end
  end
end
