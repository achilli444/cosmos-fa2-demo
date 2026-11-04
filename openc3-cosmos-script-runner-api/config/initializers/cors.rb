# Be sure to restart your server when you modify this file.

# Handle Cross-Origin Resource Sharing (CORS) so the COSMOS frontend can call
# the API when it is served from a different origin (e.g. a development
# server). Only the origins listed in OPENC3_ALLOWED_ORIGINS (or the
# OPENC3_EXTERNAL_URL fallback) are allowed; see lib/allowed_origins.rb.

# Read more: https://github.com/cyu/rack-cors

require_relative "../../lib/allowed_origins"

allowed_origins = ScriptRunnerApi::AllowedOrigins.origins

if allowed_origins.any?
  Rails.application.config.middleware.insert_before 0, Rack::Cors do
    allow do
      origins(*allowed_origins)

      resource "*",
        headers: :any,
        methods: [:get, :post, :put, :patch, :delete, :options, :head]
    end
  end
end
