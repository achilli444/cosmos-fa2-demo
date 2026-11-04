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

require 'openc3/microservices/microservice'
require 'openc3/topics/topic'

module OpenC3
  class PluginMicroservice < Microservice
    def initialize(name)
      super(name, is_plugin: true)
    end

    def run
      Dir.chdir @work_dir
      ensure_cmd_executable(@config["cmd"][0])

      # Fortify: Process Control
      # This is dangerous! However, plugins need to be able to run whatever they want.
      # Only admins can install plugins and they need to be vetted for content.
      # NOTE: In Enterprise each microservice gets its own container so the potential
      # footprint is much smaller. In Core you're in the same container
      # as all the other plugins.
      exec(*@config["cmd"])
    end

    private

    # Make sure a plugin-supplied command file is executable (owner rwx, others rx)
    # without making it writable by every other user in the container.
    def ensure_cmd_executable(cmd)
      return if cmd.nil? or cmd == 'ruby' or !File.file?(cmd)

      FileUtils.chmod(0755, cmd)
    rescue SystemCallError => e
      @logger.warn("Plugin microservice #{@name} could not make #{cmd} executable (#{e.class}: #{e.message})", scope: @scope)
    end
  end
end

OpenC3::PluginMicroservice.run if __FILE__ == $0
