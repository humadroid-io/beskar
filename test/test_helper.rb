# Configure Rails Environment
ENV["RAILS_ENV"] = "test"

require_relative "../test/dummy/config/environment"
require "rails/test_help"

# Configure FactoryBot
require "factory_bot_rails"

# Configure Mocha for mocking
require "mocha/minitest"

# Simple test isolation helper
module TestHelper
  # Get unique IP address for each test method to prevent interference
  def self.unique_ip_for_test(test_name, suffix = 1)
    # Use test name hash for deterministic but unique IP
    hash = test_name.hash.abs % 200 + 10
    "192.168.#{hash}.#{suffix}"
  end
end

# Include FactoryBot methods in tests
class ActiveSupport::TestCase
  parallelize(workers: :number_of_processors)
  include FactoryBot::Syntax::Methods

  self.use_transactional_tests = true

  parallelize_setup do |worker|
    Rails.cache.clear
  end

  parallelize_teardown do |worker|
    Rails.cache.clear
  end
end

# Include FactoryBot in integration tests
class ActionDispatch::IntegrationTest
  include FactoryBot::Syntax::Methods

  # Per-worker setup for integration tests
  parallelize_setup do |worker|
    Rails.cache.clear
  end

  parallelize_teardown do |worker|
    Rails.cache.clear
  end

  setup do
    Rails.application.reload_routes_unless_loaded
  end

  # Helper method to get unique IP addresses per test method
  def worker_ip(suffix = 1)
    test_name = "#{self.class.name}##{@NAME}"
    TestHelper.unique_ip_for_test(test_name, suffix)
  end
end

FactoryBot.definition_file_paths = [ File.expand_path("factories", __dir__) ]
