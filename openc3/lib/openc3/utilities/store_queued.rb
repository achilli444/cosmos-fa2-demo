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

require 'openc3/utilities/store'
require 'openc3/utilities/sleeper'
require 'openc3/utilities/logger'

module OpenC3
  class StoreQueued
    # Upper bound on queued store requests per instance. When Redis is
    # unavailable the queue stops growing at this size and newer requests are
    # dropped and counted instead of exhausting process memory.
    DEFAULT_MAX_QUEUE_SIZE = 100_000

    attr_reader :update_interval, :max_queue_size, :dropped_count

    # Variable that holds the singleton instances per db_shard
    @instances = []

    # Mutex used to ensure that only one instance is created
    @@instance_mutex = Mutex.new

    # Get the singleton instance for the given db_shard
    # Sets the update interval to 1 second by default
    def self.instance(update_interval = 1, db_shard: 0) # seconds
      @instances ||= []
      the_instance = @instances[db_shard]
      return the_instance if the_instance

      @@instance_mutex.synchronize do
        @instances ||= []
        @instances[db_shard] ||= self.new(update_interval, db_shard: db_shard)
        return @instances[db_shard]
      end
    end

    # Delegate all unknown class methods to delegate to the instance (db_shard 0)
    def self.method_missing(message, *args, **kwargs, &)
      self.instance.public_send(message, *args, **kwargs, &)
    end

    def self.max_queue_size_from_env
      size = ENV.fetch('OPENC3_STORE_QUEUE_MAX_SIZE', '').to_i
      size > 0 ? size : DEFAULT_MAX_QUEUE_SIZE
    end

    def initialize(update_interval, db_shard: 0, max_queue_size: self.class.max_queue_size_from_env)
      @update_interval = update_interval
      @db_shard = db_shard
      @max_queue_size = max_queue_size
      @store = store_instance()
      # Bounded queue to hold the store requests
      @store_queue = SizedQueue.new(@max_queue_size)
      @dropped_count = 0
      @reported_dropped_count = 0
      @dropped_mutex = Mutex.new
      # Sleeper used to delay update thread
      @update_sleeper = Sleeper.new

      at_exit() do
        shutdown()
      end

      # Thread used to call methods on the store
      @update_thread = OpenC3.safe_thread(self.class.to_s) do
        store_thread_body()
      end
    end

    def set_update_interval(interval)
      if interval > 0.0
        @update_interval = interval
      end
    end

    def process_queue
      unless @store_queue.empty?
        # Pipeline the requests to redis to improve performance
        @store.redis_pool.pipelined do
          while !@store_queue.empty?
            action = @store_queue.pop()
            @store.public_send(action.message, *action.args, **action.kwargs, &action.block)
          end
        end
      end
      report_dropped()
    end

    # Log how many requests were dropped since the last report. Called from the
    # store thread (never from the producer side) so a full EphemeralStoreQueued
    # log queue can't recurse back into itself.
    def report_dropped
      dropped = @dropped_mutex.synchronize do
        count = @dropped_count - @reported_dropped_count
        @reported_dropped_count = @dropped_count
        count
      end
      if dropped > 0
        Logger.warn("#{self.class} dropped #{dropped} store request(s) (db_shard=#{@db_shard}, queue full at #{@max_queue_size}, total dropped=#{@dropped_count})")
      end
    end

    def store_thread_body
      while true
        start_time = Time.now

        begin
          process_queue()
        rescue => e
          Logger.error("#{self.class} thread error (db_shard=#{@db_shard}):\n#{e.formatted}")
        end

        # Only check whether to update at a set interval
        run_time = Time.now - start_time
        sleep_time = @update_interval - run_time
        sleep_time = 0 if sleep_time < 0
        break if @update_sleeper.sleep(sleep_time)
      end
    end

    def shutdown
      @update_sleeper.cancel if @update_sleeper
      OpenC3.kill_thread(self, @update_thread) if @update_thread
      @update_thread = nil
      # Drain the queue before shutdown (best effort - Redis may already be unavailable)
      pending = @store_queue.size
      begin
        process_queue()
      rescue => e
        Logger.warn("#{self.class} failed to drain #{pending} queued request(s) at shutdown (db_shard=#{@db_shard}): #{e.message}")
      end
    end

    MessageStruct = Struct.new(:message, :args, :kwargs, :block)

    # Record the message for pipelining by the thread. If the queue is full the
    # request is dropped and counted rather than blocking the caller or growing
    # memory without bound.
    def method_missing(message, *args, **kwargs, &block)
      @store_queue.push(MessageStruct.new(message, args, kwargs, block), true)
    rescue ThreadError
      @dropped_mutex.synchronize { @dropped_count += 1 }
    end

    # Returns the store we're working with
    def store_instance
      Store.instance(db_shard: @db_shard)
    end

    def graceful_kill
      # Do nothing
    end
  end

  class EphemeralStoreQueued < StoreQueued
    def store_instance
      EphemeralStore.instance(db_shard: @db_shard)
    end
  end
end
