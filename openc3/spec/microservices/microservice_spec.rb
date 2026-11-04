# encoding: ascii-8bit

# Copyright 2022 Ball Aerospace & Technologies Corp.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# Modified by OpenC3, Inc.
# All changes Copyright 2026, OpenC3, Inc.
# All Rights Reserved
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/microservices/microservice'

# Override at_exit to do nothing for testing
saved_verbose = $VERBOSE; $VERBOSE = nil
def at_exit(*args, &block)
end
$VERBOSE = saved_verbose

module OpenC3
  describe Microservice do
    before(:all) do
      setup_system()
    end

    describe "self.run" do
      before(:each) do
        allow(MicroserviceModel).to receive(:get).and_return(nil)
        allow(MicroserviceStatusModel).to receive(:set).with(any_args)
      end

      it "expects SCOPE__TYPE__NAME parameter as ENV['OPENC3_MICROSERVICE_NAME']" do
        ENV.delete('OPENC3_MICROSERVICE_NAME')
        expect { Microservice.run }.to raise_error("Microservice must be named")
        ENV['OPENC3_MICROSERVICE_NAME'] = "DEFAULT"
        expect { Microservice.run }.to raise_error(/Name DEFAULT doesn't match convention/)
        ENV['OPENC3_MICROSERVICE_NAME'] = "DEFAULT_TYPE_NAME"
        expect { Microservice.run }.to raise_error(/Name DEFAULT_TYPE_NAME doesn't match convention/)
        ENV['OPENC3_MICROSERVICE_NAME'] = "DEFAULT__TYPE__NAME"
        Microservice.run
        sleep 0.3 # Allow the ThreadManager to shut down the microservice
      end

      it "logs a message when the run method returns cleanly" do
        ENV['OPENC3_MICROSERVICE_NAME'] = "DEFAULT__TYPE__NAME"
        expect(Logger).to receive(:info).with(/Microservice DEFAULT__TYPE__NAME run method returned cleanly and will now shutdown\./)
        Microservice.run
        sleep 0.3 # Allow the ThreadManager to shut down the microservice
      end
    end

    describe "plugin microservice startup" do
      before(:each) do
        allow(MicroserviceStatusModel).to receive(:set).with(any_args)
        # Avoid spawning the Metric update thread (would leak past the test)
        allow(Metric).to receive(:new).and_return(double("Metric").as_null_object)
        # Minimal plugin config; cmd is accessed during initialize
        @config = { 'cmd' => [], 'topics' => [], 'target_names' => [], 'secrets' => nil, 'plugin' => nil, 'work_dir' => nil }
        allow(MicroserviceModel).to receive(:get).and_return(@config)
        @saved_timeout = ENV.fetch('OPENC3_MICROSERVICE_STARTUP_BUCKET_TIMEOUT', nil)
      end

      after(:each) do
        if @saved_timeout.nil?
          ENV.delete('OPENC3_MICROSERVICE_STARTUP_BUCKET_TIMEOUT')
        else
          ENV['OPENC3_MICROSERVICE_STARTUP_BUCKET_TIMEOUT'] = @saved_timeout
        end
      end

      it "retries transient bucket failures during startup and then succeeds" do
        call_count = 0
        client = double("BucketClient")
        allow(client).to receive(:list_objects) do
          call_count += 1
          raise RuntimeError.new("connection timed out") if call_count < 3
          [] # Succeed on the third attempt with no files
        end
        allow(Bucket).to receive(:getClient).and_return(client)
        # Don't actually sleep between retries
        allow_any_instance_of(Microservice).to receive(:sleep)

        capture_io do
          Microservice.new("DEFAULT__TYPE__NAME", is_plugin: true)
        end
        expect(call_count).to eq(3)
      end

      it "syntax checks the ruby file without passing its name through a shell" do
        Dir.mktmpdir do |dir|
          # Shell metacharacters in the name must be treated as part of the filename, not interpreted
          filename = "micro;echo INJECTED && touch pwned.rb"
          File.write(File.join(dir, filename), "puts 'hello'\n")
          @config['cmd'] = ['ruby', filename]
          @config['work_dir'] = dir
          client = double("BucketClient")
          allow(client).to receive(:list_objects).and_return([])
          allow(Bucket).to receive(:getClient).and_return(client)
          expect(Open3).to receive(:capture2e).with('ruby', '-c', filename).and_wrap_original do |original, *args|
            output, status = original.call(*args)
            expect(output).to match(/Syntax OK/)
            [output, status]
          end

          capture_io do
            Microservice.new("DEFAULT__TYPE__NAME", is_plugin: true)
          end
          expect(File.exist?(File.join(dir, 'pwned.rb'))).to be false
        end
      end

      it "raises if the bucket stays unreachable past the startup timeout" do
        ENV['OPENC3_MICROSERVICE_STARTUP_BUCKET_TIMEOUT'] = '0'
        client = double("BucketClient")
        allow(client).to receive(:list_objects).and_raise("connection refused")
        allow(Bucket).to receive(:getClient).and_return(client)

        capture_io do
          expect do
            Microservice.new("DEFAULT__TYPE__NAME", is_plugin: true)
          end.to raise_error(/connection refused/)
        end
      end
    end
  end
end
