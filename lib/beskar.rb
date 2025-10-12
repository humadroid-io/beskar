require "beskar/version"
require "beskar/configuration"
require "beskar/middleware"
require "beskar/middleware/request_analyzer"
require "beskar/models/security_trackable_generic"
require "beskar/models/security_trackable_devise"
require "beskar/models/security_trackable_authenticable"
require "beskar/models/security_trackable"
require "beskar/services/rate_limiter"
require "beskar/services/device_detector"
require "beskar/services/geolocation_service"
require "beskar/services/account_locker"
require "beskar/services/ip_whitelist"
require "beskar/services/waf"
require "beskar/engine"

module Beskar
  class << self
    attr_accessor :configuration
  end

  def self.configure
    self.configuration ||= Configuration.new
    yield(configuration)
  end

  # Convenience method to access the rate limiter
  def self.rate_limiter
    Services::RateLimiter
  end

  # Check if a request should be rate limited
  def self.rate_limited?(request, user = nil)
    Services::RateLimiter.is_rate_limited?(request, user)
  end
end
