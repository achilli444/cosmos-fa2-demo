require 'aws-sdk-s3'
require 'openc3/utilities/transport_security'

if ENV['OPENC3_CLOUD'] == 'local'
  # The default endpoint follows TransportSecurity (https unless
  # OPENC3_PLAINTEXT_TRANSPORT is set); OPENC3_BUCKET_URL overrides it outright.
  bucket_host = ENV['OPENC3_DEVEL'] ? '127.0.0.1' : 'openc3-buckets'
  s3_config = {
    endpoint: ENV.fetch('OPENC3_BUCKET_URL', nil) || "#{OpenC3::TransportSecurity.http_scheme}://#{bucket_host}:9000",
    access_key_id: ENV.fetch('OPENC3_BUCKET_USERNAME', nil),
    secret_access_key: ENV.fetch('OPENC3_BUCKET_PASSWORD', nil),
    force_path_style: true,
    region: 'us-east-1',
    # Disable automatic checksum calculation for S3-compatible backends (versitygw)
    # that may not support the newer checksum features
    request_checksum_calculation: 'when_required',
    response_checksum_validation: 'when_required',
    # Disable chunked encoding - versitygw has bugs with STREAMING-*-PAYLOAD-TRAILER
    # See: https://github.com/versity/versitygw/issues/1692, #1694, #1695
    disable_request_compression: true
  }
  s3_config[:ssl_ca_bundle] = OpenC3::TransportSecurity.ca_file if OpenC3::TransportSecurity.ca_file
  Aws.config.update(s3: s3_config)
else # AWS
  Aws.config.update(
    s3: {
      endpoint: "https://s3.#{ENV.fetch('AWS_REGION', nil)}.amazonaws.com",
      force_path_style: true,
      region: ENV.fetch('AWS_REGION', nil)
    }
  )
end
