# encoding: ascii-8bit

# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is free software: you can modify and/or redistribute it
# under the terms of the GNU Affero General Public License
# as published by the Free Software Foundation; version 3 with
# attribution addendums as found in the LICENSE.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'openc3/microservices/plugin_microservice'
require 'tempfile'

# Override at_exit to do nothing for testing
saved_verbose = $VERBOSE; $VERBOSE = nil
def at_exit(*args, &block)
end
$VERBOSE = saved_verbose

module OpenC3
  describe PluginMicroservice do
    before(:all) do
      setup_system()
    end

    describe "run" do
      before(:each) do
        allow(MicroserviceStatusModel).to receive(:set).with(any_args)
        # Avoid spawning the Metric update thread (would leak past the test)
        allow(Metric).to receive(:new).and_return(double("Metric").as_null_object)
        client = double("BucketClient")
        allow(client).to receive(:list_objects).and_return([])
        allow(Bucket).to receive(:getClient).and_return(client)

        @exe = Tempfile.new(['plugin_cmd', '.sh'])
        @exe.write("#!/bin/sh\nexit 0\n")
        @exe.close
        File.chmod(0600, @exe.path)

        @config = { 'cmd' => [@exe.path, 'arg'], 'topics' => [], 'target_names' => [], 'secrets' => nil, 'plugin' => nil, 'work_dir' => Dir.tmpdir }
        allow(MicroserviceModel).to receive(:get).and_return(@config)
        @pwd = Dir.pwd
      end

      after(:each) do
        Dir.chdir(@pwd)
        @exe.unlink
        if @microservice
          @microservice.shutdown
          @microservice.instance_variable_get(:@microservice_status_thread)&.join
        end
      end

      def build_microservice
        capture_io { @microservice = PluginMicroservice.new("DEFAULT__USER__PLUGIN") }
        @microservice
      end

      it "makes the plugin executable without granting group or world write" do
        microservice = build_microservice()
        expect(microservice).to receive(:exec).with(@exe.path, 'arg')
        microservice.run
        mode = File.stat(@exe.path).mode & 0777
        expect(mode).to eq(0755)
        expect(mode & 0022).to eq(0), "plugin executable must not be group/world writable (mode #{mode.to_s(8)})"
      end

      it "does not chmod ruby commands" do
        @config['cmd'] = ['ruby', 'plugin.rb']
        microservice = build_microservice()
        expect(FileUtils).not_to receive(:chmod)
        expect(microservice).to receive(:exec).with('ruby', 'plugin.rb')
        microservice.run
      end

      it "still execs when chmod fails" do
        @config['cmd'] = ['/nonexistent/plugin_cmd']
        microservice = build_microservice()
        expect(microservice).to receive(:exec).with('/nonexistent/plugin_cmd')
        expect { microservice.run }.not_to raise_error
      end
    end
  end
end
