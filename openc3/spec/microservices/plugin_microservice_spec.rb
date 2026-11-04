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
# See the GNU Affero General Public License for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

require 'spec_helper'
require 'tempfile'
require 'openc3/microservices/plugin_microservice'

module OpenC3
  describe PluginMicroservice do
    before(:each) do
      @logger = double("Logger").as_null_object
      @orig_dir = Dir.pwd
      @work_dir = Dir.mktmpdir
      @cmd_file = File.join(@work_dir, 'start.sh')
      File.write(@cmd_file, "#!/bin/sh\n")
    end

    after(:each) do
      Dir.chdir(@orig_dir) # run chdirs into @work_dir
      FileUtils.rm_rf(@work_dir)
    end

    def build(cmd)
      ms = PluginMicroservice.allocate
      ms.instance_variable_set(:@name, 'DEFAULT__USER__PLUGIN')
      ms.instance_variable_set(:@scope, 'DEFAULT')
      ms.instance_variable_set(:@logger, @logger)
      ms.instance_variable_set(:@work_dir, @work_dir)
      ms.instance_variable_set(:@config, { 'cmd' => cmd })
      allow(ms).to receive(:exec)
      ms
    end

    describe "run" do
      it "makes the cmd executable without making it world-writable" do
        File.chmod(0666, @cmd_file)
        ms = build([@cmd_file])
        ms.run
        mode = File.stat(@cmd_file).mode & 0777
        expect(mode).to eq(0755)
        expect(File.executable?(@cmd_file)).to be true
        expect(mode & 0022).to eq(0) # not group or world writable
        expect(ms).to have_received(:exec).with(@cmd_file)
      end

      it "removes pre-existing group/world write permission" do
        File.chmod(0777, @cmd_file)
        build([@cmd_file]).run
        expect(File.stat(@cmd_file).mode & 0777).to eq(0755)
      end

      it "does not chmod ruby or commands that are not files" do
        expect(FileUtils).not_to receive(:chmod)
        build(['ruby', 'script.rb']).run
        build(['python', 'script.py']).run
      end

      it "logs a warning and still execs when chmod fails" do
        allow(FileUtils).to receive(:chmod).and_raise(Errno::EPERM.new(@cmd_file))
        ms = build([@cmd_file])
        expect(@logger).to receive(:warn).with(/could not make #{Regexp.escape(@cmd_file)} executable.*EPERM/, scope: 'DEFAULT')
        ms.run
        expect(ms).to have_received(:exec).with(@cmd_file)
      end
    end
  end
end
