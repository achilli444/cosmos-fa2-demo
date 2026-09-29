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

require 'rails_helper'

RSpec.describe RunningScriptChannel, type: :channel do
  let(:uuid) { 'test-uuid' }
  let(:broadcaster) { instance_double(RunningScriptReplayThread, start: nil, stop: nil) }

  def create_script(id, scope)
    OpenC3::ScriptStatusModel.new(
      name: id,
      state: 'running',
      scope: scope,
      filename: 'INST/procedures/test.rb',
      current_filename: 'INST/procedures/test.rb',
      line_no: 1,
      start_time: Time.now.utc.iso8601,
      username: 'test_user',
      user_full_name: 'Test Tester'
    ).create
  end

  # Seed the replay stream the way running_script.rb does, so subscribed()
  # exercises the real xrange backlog read
  def backlog(id, *events)
    events.each_with_index do |event, i|
      OpenC3::Topic.write_topic("running-script-channel:#{id}:replay", { 'data' => event.to_json }, "10#{i}-0")
    end
  end

  before(:each) do
    mock_redis
    # Connections without the url_authenticated identifier are treated as
    # authenticated (see ApplicationCable::Channel#connection_url_authenticated?)
    stub_connection uuid: uuid, scope: 'DEFAULT'
    RunningScriptChannel.class_variable_set(:@@broadcasters, {})
    allow(RunningScriptReplayThread).to receive(:new).and_return(broadcaster)
    allow(OpenC3::Logger).to receive(:warn)
  end

  after(:each) do
    RunningScriptChannel.class_variable_set(:@@broadcasters, {})
  end

  describe '#subscribed' do
    it 'streams a script that belongs to the connection scope' do
      create_script('42', 'DEFAULT')
      backlog('42', { 'type' => 'line', 'line_no' => 1 }, { 'type' => 'output', 'line' => 'hi' })
      subscribe id: '42'
      expect(subscription).to be_confirmed
      expected = [
        { 'type' => 'line', 'line_no' => 1 },
        { 'type' => 'output', 'line' => 'hi' },
      ]
      expect(transmissions).to eq(expected)
      expect(RunningScriptReplayThread).to have_received(:new).with("running-script-#{uuid}", '42', '101-0')
      expect(broadcaster).to have_received(:start)
    end

    it 'streams a completed script that belongs to the connection scope' do
      create_script('42', 'DEFAULT')
      OpenC3::ScriptStatusModel.get_model(name: '42', scope: 'DEFAULT').tap do |model|
        model.state = 'completed'
        model.end_time = Time.now.utc.iso8601
        model.update
      end
      backlog('42', { 'type' => 'complete' })
      subscribe id: '42'
      expect(subscription).to be_confirmed
      expect(transmissions).to eq([{ 'type' => 'complete' }])
    end

    it 'rejects a script id that belongs to another scope' do
      create_script('42', 'OTHER')
      backlog('42', { 'type' => 'output', 'line' => 'secret' })
      subscribe id: '42'
      expect(subscription).to be_rejected
      expect(transmissions).to be_empty
      expect(RunningScriptReplayThread).not_to have_received(:new)
    end

    it 'rejects an unknown script id' do
      backlog('42', { 'type' => 'output', 'line' => 'secret' })
      subscribe id: '42'
      expect(subscription).to be_rejected
      expect(transmissions).to be_empty
      expect(RunningScriptReplayThread).not_to have_received(:new)
    end

    it 'rejects a subscription without a script id' do
      create_script('42', 'DEFAULT')
      subscribe
      expect(subscription).to be_rejected
      expect(transmissions).to be_empty
    end

    it 'rejects a connection without a scope' do
      stub_connection uuid: uuid, scope: nil
      create_script('42', 'DEFAULT')
      subscribe id: '42'
      expect(subscription).to be_rejected
      expect(transmissions).to be_empty
    end
  end
end
