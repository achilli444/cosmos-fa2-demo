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
require 'ipaddr'
require 'thread' # For Mutex
require 'timeout' # For Timeout::Error
require 'openc3/streams/tcpip_socket_stream'
require 'openc3/config/config_parser'
require 'openc3/utilities/logger'

module OpenC3
  # Data {Stream} which reads and writes to TCPIP sockets. This class creates
  # the actual sockets based on the constructor parameters. The rest of the
  # interface is implemented by the super class {TcpipSocketStream}.
  #
  # The sockets can optionally be wrapped in TLS. TLS always verifies the
  # peer certificate against the CA store (system store or ca_file) and
  # checks that the certificate matches the hostname, unless verify is
  # explicitly set to false.
  class TcpipClientStream < TcpipSocketStream
    # Keys accepted in the tls options Hash (constructor) and as OPTION
    # keywords (prefixed with TLS_) via set_option
    TLS_OPTION_KEYS = %i[ca_file cert key verify hostname].freeze

    # Build an OpenSSL::SSL::SSLContext which authenticates the server.
    #
    # @param ca_file [String|nil] PEM file path (or inline PEM) of the CA
    #   certificate(s) to trust. nil uses the OpenSSL default store, which
    #   honors SSL_CERT_FILE and SSL_CERT_DIR.
    # @param cert [String|nil] PEM file path (or inline PEM) of the client
    #   certificate for mutual TLS. Requires key.
    # @param key [String|nil] PEM file path (or inline PEM) of the client
    #   private key for mutual TLS.
    # @param verify [Boolean] Whether to verify the peer certificate and
    #   hostname. Defaults to true. Setting false is logged as a warning.
    # @return [OpenSSL::SSL::SSLContext]
    def self.build_ssl_context(ca_file: nil, cert: nil, key: nil, verify: true)
      context = OpenSSL::SSL::SSLContext.new
      # DEFAULT_PARAMS enables hostname verification and the default cert store
      context.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER)
      context.min_version = OpenSSL::SSL::TLS1_2_VERSION
      if ca_file
        store = OpenSSL::X509::Store.new
        pem = read_pem(ca_file)
        pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).each do |cert_pem|
          store.add_cert(OpenSSL::X509::Certificate.new(cert_pem))
        end
        context.cert_store = store
      end
      if cert or key
        raise ArgumentError, "TLS cert and key must both be given" unless cert and key

        context.cert = OpenSSL::X509::Certificate.new(read_pem(cert))
        context.key = OpenSSL::PKey.read(read_pem(key))
      end
      unless ConfigParser.handle_true_false(verify)
        Logger.warn("TLS peer verification disabled: the server certificate will not be authenticated")
        context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        context.verify_hostname = false
      end
      return context
    end

    # @param value [String] Inline PEM data or a path to a PEM file
    # @return [String] The PEM data
    def self.read_pem(value)
      value = value.to_s
      return value if value.include?('-----BEGIN')

      return File.read(value)
    end

    # @param hostname [String] The host to connect to
    # @param write_port [Integer|nil] The port to write. Pass nil to make this
    #   a read only stream.
    # @param read_port [Integer|nil] The port to read. Pass nil to make this
    #   a write only stream.
    # @param write_timeout [Float] Seconds to wait before aborting writes
    # @param read_timeout [Float|nil] Seconds to wait before aborting reads.
    #   Pass nil to block until the read is complete.
    # @param connect_timeout [Float|nil] Seconds to wait before aborting connect.
    #   Pass nil to block until the connection is complete.
    # @param tls [Boolean|Hash|nil] nil or false for plain TCP. true to wrap
    #   the sockets in TLS verified against the default CA store. A Hash with
    #   any of :ca_file, :cert, :key, :verify, :hostname (see
    #   {build_ssl_context}) for further configuration.
    def initialize(hostname, write_port, read_port, write_timeout, read_timeout, connect_timeout = 5.0, tls: nil)
      @tls_enabled = false
      @tls_options = {}
      case tls
      when Hash
        @tls_enabled = true
        tls.each { |name, value| set_tls_option(name, value) }
      when nil, false
        @tls_enabled = false
      else
        @tls_enabled = ConfigParser.handle_true_false(tls) ? true : false
      end
      @tls_hostname = hostname.to_s
      @hostname = hostname
      if @hostname.to_s.upcase == 'LOCALHOST'
        @hostname = '127.0.0.1'
      end
      @write_port = ConfigParser.handle_nil(write_port)
      @write_port = Integer(write_port) if @write_port
      @read_port  = ConfigParser.handle_nil(read_port)
      @read_port  = Integer(read_port) if @read_port

      @write_addr = nil
      @read_addr = nil
      begin
        @write_addr = Socket.pack_sockaddr_in(@write_port, @hostname) if @write_port
        @read_addr = Socket.pack_sockaddr_in(@read_port, @hostname) if @read_port
      rescue => error
        if /getaddrinfo/.match?(error.message)
          raise "Invalid hostname: #{@hostname}"
        else
          raise error
        end
      end

      write_socket = nil
      if @write_addr
        write_socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        write_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      end

      read_socket = nil
      if @read_addr
        if @write_port != @read_port
          read_socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          read_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
        else
          read_socket = write_socket
        end
      end

      @connect_timeout = ConfigParser.handle_nil(connect_timeout)
      @connect_timeout = @connect_timeout.to_f if @connect_timeout

      super(write_socket, read_socket, write_timeout, read_timeout)
    end

    # Connect the socket(s) and, if TLS is enabled, complete the TLS handshake
    # and verify the server certificate before any data is exchanged
    def connect
      connect_nonblock(@write_socket, @write_addr) if @write_socket
      connect_nonblock(@read_socket, @read_addr) if @read_socket and @read_socket != @write_socket
      start_tls() if @tls_enabled
      super()
    end

    # @return [Boolean] Whether the sockets are wrapped in TLS
    def tls?
      @tls_enabled
    end

    # TLS options are given as OPTION TLS_<NAME> <VALUE> on the interface:
    #   TLS true|false, TLS_CA_FILE, TLS_CERT, TLS_KEY, TLS_VERIFY true|false,
    #   TLS_HOSTNAME. Setting any TLS_ option enables TLS.
    def set_option(option_name, option_values)
      option_name_upcase = option_name.upcase
      if option_name_upcase == 'TLS'
        @tls_enabled = ConfigParser.handle_true_false(option_values[0]) ? true : false
      elsif option_name_upcase.start_with?('TLS_')
        @tls_enabled = true
        set_tls_option(option_name_upcase[4..-1].downcase, option_values[0])
      else
        super(option_name, option_values)
      end
    end

    protected

    def set_tls_option(name, value)
      name = name.to_sym
      raise ArgumentError, "Unknown TLS option #{name}. Valid options: #{TLS_OPTION_KEYS.join(', ')}" unless TLS_OPTION_KEYS.include?(name)

      @tls_options[name] = ConfigParser.handle_nil(value)
    end

    def start_tls
      hostname = @tls_options[:hostname] || @tls_hostname
      context = self.class.build_ssl_context(
        ca_file: @tls_options[:ca_file],
        cert: @tls_options[:cert],
        key: @tls_options[:key],
        verify: @tls_options.fetch(:verify, true)
      )
      write_ssl = tls_wrap(@write_socket, hostname, context) if @write_socket
      if @read_socket
        if @read_socket == @write_socket
          read_ssl = write_ssl
        else
          read_ssl = tls_wrap(@read_socket, hostname, context)
        end
      end
      @write_socket = write_ssl if @write_socket
      @read_socket = read_ssl if @read_socket
    end

    def tls_wrap(socket, hostname, context)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, context)
      ssl_socket.sync_close = true
      # SNI must be a DNS name, not an IP literal (RFC 6066)
      ssl_socket.hostname = hostname unless ip_address?(hostname)
      begin
        loop do
          case ssl_socket.connect_nonblock(exception: false)
          when :wait_readable
            raise "Connect timeout" unless socket.wait_readable(@connect_timeout)
          when :wait_writable
            raise "Connect timeout" unless socket.wait_writable(@connect_timeout)
          else
            break
          end
        end
        # Authenticate the server: its certificate must match the hostname we
        # intended to connect to (DNS or IP subjectAltName). Skipped only when
        # the operator explicitly disabled verification.
        ssl_socket.post_connection_check(hostname) if context.verify_mode == OpenSSL::SSL::VERIFY_PEER
      rescue OpenSSL::SSL::SSLError => e
        OpenC3.close_socket(ssl_socket)
        raise OpenSSL::SSL::SSLError, "TLS connection to #{hostname} failed: #{e.message}"
      rescue IOError, Errno::ENOTSOCK
        raise "Connect canceled"
      end
      return ssl_socket
    end

    def ip_address?(hostname)
      IPAddr.new(hostname)
      true
    rescue IPAddr::Error
      false
    end

    def connect_nonblock(socket, addr)
      socket.connect_nonblock(addr)
    rescue IO::WaitWritable
      begin
        _, sockets, _ = IO.select(nil, [socket], nil, @connect_timeout) # wait 3-way handshake completion
      rescue IOError, Errno::ENOTSOCK
        raise "Connect canceled"
      end
      if sockets and !sockets.empty?
        begin
          socket.connect_nonblock(addr) # check connection failure
        rescue IOError, Errno::ENOTSOCK
          raise "Connect canceled"
        rescue Errno::EINPROGRESS
          retry
        rescue Errno::EISCONN, Errno::EALREADY
        end
      else
        raise "Connect timeout"
      end
    rescue IOError, Errno::ENOTSOCK
      raise "Connect canceled"
    end
  end
end
