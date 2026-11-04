# Be sure to restart your server when you modify this file.

# Handle Cross-Origin Resource Sharing (CORS) for browsers calling this API
# from a web origin other than the one it is served from.
#
# Traefik serves the COSMOS frontend and this API from the same origin, so no
# CORS grant is needed for a normal deployment. Cross-origin access is only
# granted to the origins listed in OPENC3_ALLOWED_ORIGINS (comma separated,
# e.g. "https://cosmos.example.com,https://ops.example.com:2900"), falling
# back to OPENC3_EXTERNAL_URL. When neither is set no CORS headers are sent
# and browsers refuse cross-origin requests.

# Read more: https://github.com/cyu/rack-cors

module OpenC3Cors
  METHODS = [:get, :post, :put, :patch, :delete, :options, :head].freeze

  def self.allowed_origins(env = ENV)
    origins = env["OPENC3_ALLOWED_ORIGINS"].to_s.split(",").map(&:strip).reject(&:empty?)
    origins = [env["OPENC3_EXTERNAL_URL"].to_s.strip].reject(&:empty?) if origins.empty?
    origins
  end

  def self.configure(cors, allowed)
    return if allowed.empty?

    if allowed.include?("*")
      Rails.logger.warn("OPENC3_ALLOWED_ORIGINS contains '*': any web origin may call this API")
    end
    cors.allow do |resources|
      resources.origins(*allowed)
      resources.resource "*", headers: :any, methods: METHODS
    end
  end
end

allowed_origins = OpenC3Cors.allowed_origins
unless allowed_origins.empty?
  Rails.application.config.middleware.insert_before 0, Rack::Cors do |cors|
    OpenC3Cors.configure(cors, allowed_origins)
  end
end
