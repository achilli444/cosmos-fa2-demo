require 'aws-sdk-s3'

if ENV['OPENC3_CLOUD'] == 'local'
  Aws.config.update(
    s3: {
      endpoint: ENV.fetch('OPENC3_BUCKET_URL', nil) || (ENV['OPENC3_DEVEL'] ? 'http://127.0.0.1:9000' : 'http://openc3-buckets:9000'),
      access_key_id: ENV.fetch('OPENC3_BUCKET_USERNAME', nil),
      secret_access_key: ENV.fetch('OPENC3_BUCKET_PASSWORD', nil),
      force_path_style: true,
      region: 'us-east-1',
      # Only add request checksums when the operation requires them; AwsBucket
      # explicitly requests SHA256 on writes (see @use_checksum) so that every
      # stored object carries a checksum the SDK can verify on read.
      request_checksum_calculation: 'when_required',
      # Validate response checksums (CRC32/SHA1/SHA256 headers) on every GET so
      # a corrupted or tampered download raises Aws::Errors::ChecksumError instead
      # of being returned silently. versitygw >= 1.8.0 returns x-amz-checksum-*
      # for objects uploaded with a checksum algorithm. (NIST IR 8270 PR.DS-6)
      response_checksum_validation: 'when_supported',
      # Disable chunked encoding - versitygw has bugs with STREAMING-*-PAYLOAD-TRAILER
      # See: https://github.com/versity/versitygw/issues/1692, #1694, #1695
      disable_request_compression: true
    }
  )
else # AWS
  Aws.config.update(
    s3: {
      endpoint: "https://s3.#{ENV.fetch('AWS_REGION', nil)}.amazonaws.com",
      force_path_style: true,
      region: ENV.fetch('AWS_REGION', nil)
    }
  )
end
