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

require 'socket'
require 'openssl'
require 'tempfile'
require 'thread' # For Mutex
require 'timeout' # For Timeout::Error
require 'openc3/streams/stream'
require 'openc3/config/config_parser'

module OpenC3
  # Data {Stream} which reads and writes from Tcpip Sockets.
  class TcpipSocketStream < Stream
    attr_reader :write_socket

    # TLS settings applied by set_option and used by start_tls
    SSL_OPTIONS = %w[SSL SSL_CERT SSL_KEY SSL_CA_FILE SSL_VERIFY SSL_HOSTNAME].freeze

    # @param write_socket [Socket] Socket to write
    # @param read_socket [Socket] Socket to read
    # @param write_timeout [Float] Seconds to wait before aborting writes
    # @param read_timeout [Float|nil] Seconds to wait before aborting reads.
    #   Pass nil to block until the read is complete.
    def initialize(write_socket, read_socket, write_timeout, read_timeout)
      super()

      @write_socket  = write_socket
      @read_socket   = read_socket
      @write_timeout = ConfigParser.handle_nil(write_timeout)
      if @write_timeout
        @write_timeout = @write_timeout.to_f
      else
        Logger.warn("Warning: To avoid interface lock, write_timeout can not be nil. Setting to 10 seconds.")
        @write_timeout = 10.0
      end
      @read_timeout  = ConfigParser.handle_nil(read_timeout)
      @read_timeout  = @read_timeout.to_f if @read_timeout

      # Mutex on write is needed to protect from commands coming in from more
      # than one tool
      @write_mutex = Mutex.new
      @pipe_reader, @pipe_writer = IO.pipe
      @connected = false
      @ssl = false
      @ssl_cert = nil
      @ssl_key = nil
      @ssl_ca_file = nil
      @ssl_verify = true
      @ssl_hostname = nil
      @ssl_handshake_timeout = 5.0
    end

    # @return [Boolean] Whether the stream will be / is wrapped in TLS
    def ssl?
      @ssl
    end

    # Connect the stream
    def connect
      # If called directly this class is acting as a server and does not need to connect the sockets
      @connected = true
    end

    # @return [Boolean] Whether the sockets are connected
    def connected?
      @connected
    end

    # Disconnect by closing the sockets
    def disconnect
      OpenC3.close_socket(@write_socket)
      OpenC3.close_socket(@read_socket)
      @pipe_writer.write('.')
      @connected = false
    end

    # @return [String] Returns a binary string of data from the socket
    def read
      raise "Attempt to read from write only stream" unless @read_socket

      # No read mutex is needed because reads happen serially
      begin
        while true # Loop until we get some data
          data = @read_socket.read_nonblock(65535, exception: false)
          raise EOFError, 'end of file reached' unless data

          if data == :wait_readable or data == :wait_writable
            # Wait for the socket to be ready for reading or for the timeout
            begin
              result = IO.fast_select([@read_socket, @pipe_reader], nil, nil, @read_timeout)
              # If select returns something it means the socket is now available for
              # reading so retry the read. If it returns nil it means we timed out.
              # If the pipe is present that means we closed the socket
              if result
                if result.include?(@pipe_reader)
                  raise IOError
                else
                  next
                end
              else
                raise Timeout::Error, "Read Timeout"
              end
            rescue IOError, Errno::ENOTSOCK
              # These can happen with the socket being closed while waiting on select
              data = ''
            end
          end
          break
        end
      rescue Errno::ECONNRESET, Errno::ECONNABORTED, IOError, Errno::ENOTSOCK
        data = ''
      end
      data
    end

    # @return [String] Returns a binary string of data from the socket. Always returns immediately
    def read_nonblock
      # No read mutex is needed because reads happen serially
      begin
        data = @read_socket.read_nonblock(65535, exception: false)
        raise EOFError, 'end of file reached' unless data
        data = '' if data == :wait_readable or data == :wait_writable
      rescue Errno::EAGAIN, Errno::EWOULDBLOCK, Errno::ECONNRESET, Errno::ECONNABORTED, IOError
        data = ''
      end
      data
    end

    # @param data [String] A binary string of data to write to the socket
    def write(data)
      raise "Attempt to write to read only stream" unless @write_socket

      @write_mutex.synchronize do
        num_bytes_to_send = data.length
        total_bytes_sent = 0
        bytes_sent = 0
        data_to_send = data

        loop do
          begin
            bytes_sent = @write_socket.write_nonblock(data_to_send)
          rescue Errno::EAGAIN, Errno::EWOULDBLOCK, IO::WaitWritable, IO::WaitReadable
            # Wait for the socket to be ready for writing or for the timeout
            result = IO.fast_select(nil, [@write_socket], nil, @write_timeout)
            # If select returns something it means the socket is now available for
            # writing so retry the write. If it returns nil it means we timed out.
            if result
              retry
            else
              raise Timeout::Error, "Write Timeout"
            end
          end
          total_bytes_sent += bytes_sent
          break if total_bytes_sent >= num_bytes_to_send

          data_to_send = data[total_bytes_sent..-1]
        end
      end
    end

    # Supported Options
    # KEEPALIVE / KEEPCNT / KEEPIDLE / KEEPINTVL - TCP keepalive tuning
    # SSL - true to wrap the socket(s) in TLS (TLS 1.2 minimum)
    # SSL_CERT - PEM certificate (client certificate, or server certificate when accepting)
    # SSL_KEY - PEM private key matching SSL_CERT
    # SSL_CA_FILE - PEM certificate authority chain used to verify the peer
    # SSL_VERIFY - false to skip peer verification (default true; clients always verify unless false)
    # SSL_HOSTNAME - Hostname to verify in the server certificate (default: connect hostname)
    def set_option(option_name, option_values)
      option_name_upcase = option_name.upcase

      case option_name_upcase
      when 'KEEPALIVE'
        @write_socket.to_io.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
        @read_socket.to_io.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
      when 'KEEPCNT'
        @write_socket.to_io.setsockopt(Socket::SOL_TCP, Socket::TCP_KEEPCNT, Integer(option_values[0]))
        @read_socket.to_io.setsockopt(Socket::SOL_TCP, Socket::TCP_KEEPCNT, Integer(option_values[0]))
      when 'KEEPIDLE'
        @write_socket.to_io.setsockopt(Socket::SOL_TCP, Socket::TCP_KEEPIDLE, Integer(option_values[0]))
        @read_socket.to_io.setsockopt(Socket::SOL_TCP, Socket::TCP_KEEPIDLE, Integer(option_values[0]))
      when 'KEEPINTVL'
        @write_socket.to_io.setsockopt(Socket::SOL_TCP, Socket::TCP_KEEPINTVL, Integer(option_values[0]))
        @read_socket.to_io.setsockopt(Socket::SOL_TCP, Socket::TCP_KEEPINTVL, Integer(option_values[0]))
      when 'SSL'
        @ssl = ConfigParser.handle_true_false(option_values[0]) == true
      when 'SSL_CERT'
        @ssl = true
        @ssl_cert = OpenSSL::X509::Certificate.new(option_values[0])
      when 'SSL_KEY'
        @ssl = true
        @ssl_key = OpenSSL::PKey.read(option_values[0])
      when 'SSL_CA_FILE'
        @ssl = true
        @ssl_ca_file = Tempfile.new('ca_file')
        @ssl_ca_file.write(option_values[0])
        @ssl_ca_file.close
      when 'SSL_VERIFY'
        @ssl_verify = ConfigParser.handle_true_false(option_values[0]) == true
      when 'SSL_HOSTNAME'
        @ssl_hostname = option_values[0]
      end
    end

    # Wrap the connected socket(s) in TLS. Called by TcpipClientStream after the
    # TCP connect and by TcpipServerInterface after accept. No-op unless SSL was enabled.
    #
    # @param mode [:client, :server] Which side of the handshake to perform
    # @param hostname [String|nil] Hostname used for server certificate verification (client mode)
    def start_tls(mode, hostname = nil)
      return unless @ssl

      context = build_ssl_context(mode)
      if @write_socket and @write_socket == @read_socket
        @write_socket = @read_socket = wrap_socket(@write_socket, context, mode, hostname)
      else
        @write_socket = wrap_socket(@write_socket, context, mode, hostname) if @write_socket
        @read_socket = wrap_socket(@read_socket, context, mode, hostname) if @read_socket
      end
    end

    protected

    def build_ssl_context(mode)
      context = OpenSSL::SSL::SSLContext.new
      context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      if @ssl_cert and @ssl_key
        context.cert = @ssl_cert
        context.key = @ssl_key
      elsif mode == :server
        raise "SSL_CERT and SSL_KEY are required to accept TLS connections"
      end
      if @ssl_ca_file
        context.ca_file = @ssl_ca_file.path
      else
        context.cert_store = OpenSSL::X509::Store.new.tap(&:set_default_paths)
      end
      if mode == :server
        # Require a client certificate (mutual TLS) when a CA is configured
        context.verify_mode = @ssl_ca_file ? (OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT) : OpenSSL::SSL::VERIFY_NONE
      else
        context.verify_mode = @ssl_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        context.verify_hostname = @ssl_verify
        Logger.warn("TcpipSocketStream: SSL_VERIFY false disables server certificate verification") unless @ssl_verify
      end
      context
    end

    def wrap_socket(socket, context, mode, hostname)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, context)
      ssl_socket.sync_close = true
      if mode == :client
        name = @ssl_hostname || hostname
        ssl_socket.hostname = name if name and @ssl_verify and !name.match?(/\A[\d.]+\z/)
      end
      handshake(ssl_socket, mode)
      ssl_socket
    end

    def handshake(ssl_socket, mode)
      deadline = Time.now + @ssl_handshake_timeout
      loop do
        result = mode == :server ? ssl_socket.accept_nonblock(exception: false) : ssl_socket.connect_nonblock(exception: false)
        break unless result == :wait_readable or result == :wait_writable

        remaining = deadline - Time.now
        raise "TLS handshake timeout" if remaining <= 0

        if result == :wait_readable
          ssl_socket.to_io.wait_readable(remaining)
        else
          ssl_socket.to_io.wait_writable(remaining)
        end
      end
    end
  end
end
