require 'aws-sdk-s3'
require 'openc3/utilities/tls_config'

if ENV['OPENC3_CLOUD'] == 'local'
  # OPENC3_BUCKET_TLS=1 defaults the endpoint to https:// and rejects a plaintext OPENC3_BUCKET_URL
  s3_config = {
    endpoint: OpenC3::TlsConfig.bucket_endpoint,
    access_key_id: ENV['OPENC3_BUCKET_USERNAME'],
    secret_access_key: ENV['OPENC3_BUCKET_PASSWORD'],
    force_path_style: true,
    region: 'us-east-1',
    ssl_verify_peer: true,
    # Disable automatic checksum calculation for S3-compatible backends (versitygw)
    # that may not support the newer checksum features
    request_checksum_calculation: 'when_required',
    response_checksum_validation: 'when_required',
    # Disable chunked encoding - versitygw has bugs with STREAMING-*-PAYLOAD-TRAILER
    # See: https://github.com/versity/versitygw/issues/1692, #1694, #1695
    disable_request_compression: true
  }
  ca_file = OpenC3::TlsConfig.bucket_ca_file
  s3_config[:ssl_ca_bundle] = ca_file if ca_file
  Aws.config.update(s3: s3_config)
else # AWS
  Aws.config.update(
    s3: {
      endpoint: "https://s3.#{ENV['AWS_REGION']}.amazonaws.com",
      force_path_style: true,
      region: ENV['AWS_REGION']
    }
  )
end
