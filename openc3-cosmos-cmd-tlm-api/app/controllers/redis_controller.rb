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

class RedisController < ApplicationController
  DISALLOWED_COMMANDS = [
    'AUTH' # Because changing the Redis ACL user will break cmd-tlm-api
  ]

  # Commands whose first argument is a key name. Only the key name of these
  # commands is written to the audit log; all other arguments and the command
  # result are never logged because they may carry secrets, session tokens or
  # other stored values (e.g. HGET <scope>__openc3__secrets <name>).
  KEY_COMMANDS = %w[
    GET SET DEL EXISTS EXPIRE TTL TYPE INCR DECR
    HGET HGETALL HSET HDEL HKEYS HLEN HEXISTS
    LRANGE LLEN LPUSH RPUSH LPOP RPOP
    SADD SREM SMEMBERS SCARD SISMEMBER
    ZADD ZRANGE ZREM ZCARD
    XADD XRANGE XREVRANGE XLEN XINFO
  ]

  def execute_raw
    return unless authorization('admin')

    args = request.body.read.split(' ').compact

    # Check that we allow this command
    command = args[0].upcase
    if DISALLOWED_COMMANDS.include? command
      render json: { status: 'error', message: "The #{command} command is not allowed." }, status: :unprocessable_entity
      return
    end

    db_shard = (params[:db_shard] || 0).to_i
    store = params[:ephemeral] ? OpenC3::EphemeralStore : OpenC3::Store
    audit = audit_description(command, args, store, db_shard)
    begin
      result = store.instance(db_shard: db_shard).public_send(command, args[1..-1])
    rescue StandardError => e
      OpenC3::Logger.info("Redis command failed (#{audit}): #{e.class}", user: username())
      raise
    end
    OpenC3::Logger.info("Redis command executed (#{audit}): result #{result_summary(result)}", user: username())
    render json: { :result => result }, status: :created
  end

  private

  def audit_description(command, args, store, db_shard)
    description = "#{store.name} db_shard #{db_shard}: #{command}"
    description += " #{args[1]}" if KEY_COMMANDS.include?(command) && args[1]
    description += " (#{args.length - 1} args)"
    description
  end

  def result_summary(result)
    case result
    when nil then 'nil'
    when String, Array, Hash then "#{result.class} (#{result.length})"
    when Integer, true, false then result.to_s
    else result.class.to_s
    end
  end
end
