# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require "spec_helper"
require "openc3/utilities/store_queued"

module OpenC3
  describe StoreQueued do
    before(:each) do
      $store_queued = true
      mock_redis()
    end
    after(:each) do
      StoreQueued.shutdown
      $store_queued = false
    end

    it "batches store methods to execute in a pipeline" do
      StoreQueued.instance(0.1) # Set the update interval

      StoreQueued.hset("presence", "key", 10)
      sleep 0.05
      expect(Store.hget("presence", "key")).to eq "10"

      StoreQueued.hset("presence", "key1", 10)
      StoreQueued.hset("presence", "key2", 20)
      StoreQueued.hset("presence", "key3", 30)
      # Initially the values aren't there because they haven't been persisted
      expect(Store.hget("presence", "key1")).to be_nil
      expect(Store.hget("presence", "key2")).to be_nil
      expect(Store.hget("presence", "key3")).to be_nil
      sleep 0.15 # Wait past the UPDATE_INTERVAL
      # Now the values are persisted to the Store
      expect(Store.hget("presence", "key1")).to eq "10"
      expect(Store.hget("presence", "key2")).to eq "20"
      expect(Store.hget("presence", "key3")).to eq "30"
    end

    it "bounds the queue and drops (and counts) requests once it is full" do
      # Long update interval so the store thread does not drain the queue mid-test
      queued = StoreQueued.new(100, max_queue_size: 2)
      sleep 0.05 # Let the thread run its first (empty) cycle and go to sleep
      queued.hset("bounded", "key1", 1)
      queued.hset("bounded", "key2", 2)
      queued.hset("bounded", "key3", 3) # Dropped: queue is full
      expect(queued.dropped_count).to eq 1

      expect(Logger).to receive(:warn).with(/dropped 1 store request.*queue full at 2/)
      queued.process_queue
      expect(Store.hget("bounded", "key1")).to eq "1"
      expect(Store.hget("bounded", "key2")).to eq "2"
      expect(Store.hget("bounded", "key3")).to be_nil

      # Only report new drops
      expect(Logger).not_to receive(:warn)
      queued.process_queue
      queued.shutdown
    end

    it "reads the queue bound from OPENC3_STORE_QUEUE_MAX_SIZE" do
      expect(StoreQueued.max_queue_size_from_env).to eq StoreQueued::DEFAULT_MAX_QUEUE_SIZE
      ENV['OPENC3_STORE_QUEUE_MAX_SIZE'] = '5'
      expect(StoreQueued.max_queue_size_from_env).to eq 5
      ENV['OPENC3_STORE_QUEUE_MAX_SIZE'] = 'bogus'
      expect(StoreQueued.max_queue_size_from_env).to eq StoreQueued::DEFAULT_MAX_QUEUE_SIZE
    ensure
      ENV.delete('OPENC3_STORE_QUEUE_MAX_SIZE')
    end

    it "logs pipeline errors through the Logger instead of stdout" do
      expect(Logger).to receive(:error).with(/StoreQueued thread error \(db_shard=0\):\nCannotConnectError : redis down/).at_least(:once)
      queued = StoreQueued.new(0.05)
      allow(Store.instance).to receive(:hset).and_raise(Redis::CannotConnectError, "redis down")
      expect do
        queued.hset("outage", "key", 1)
        sleep 0.2
        queued.shutdown
      end.not_to output.to_stdout
    end

    it "logs a warning when the shutdown drain fails" do
      expect(Logger).to receive(:warn).with(/failed to drain 1 queued request\(s\) at shutdown \(db_shard=0\): redis down/)
      queued = StoreQueued.new(100) # Long interval so only shutdown drains the queue
      sleep 0.05
      allow(Store.instance).to receive(:hset).and_raise(Redis::CannotConnectError, "redis down")
      queued.hset("outage", "key", 1)
      expect { queued.shutdown }.not_to raise_error
    end
  end
end
