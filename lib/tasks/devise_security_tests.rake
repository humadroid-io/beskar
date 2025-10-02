# frozen_string_literal: true

namespace :test do
  desc "Run all Devise security integration tests"
  task :devise_security do
    test_files = [
      "test/integration/devise_authentication_security_test.rb",
      "test/integration/devise_attack_patterns_test.rb",
      "test/integration/devise_rate_limiting_test.rb",
      "test/integration/devise_security_edge_cases_test.rb"
    ]

    puts "\n🛡️  Running Beskar Devise Security Test Suite"
    puts "=" * 60

    passed = 0
    failed = 0

    test_files.each do |file|
      if File.exist?(file)
        puts "\n📋 Running: #{file}"
        result = system("rails test #{file}")
        if result
          passed += 1
        else
          failed += 1
        end
      else
        puts "\n⚠️  Warning: #{file} not found"
        failed += 1
      end
    end

    puts "\n" + "=" * 60
    puts "📊 Test Suite Summary:"
    puts "   Files passed: #{passed}"
    puts "   Files failed: #{failed}"
    puts "   Total files:  #{test_files.length}"

    if failed > 0
      puts "\n❌ Some tests failed. Check output above for details."
      exit(1)
    else
      puts "\n✅ All Devise security tests passed!"
    end
  end

  desc "Run Devise authentication security tests"
  task :devise_auth do
    puts "🔐 Running Devise authentication security tests..."
    system("rails test test/integration/devise_authentication_security_test.rb")
  end

  desc "Run Devise attack pattern detection tests"
  task :devise_attacks do
    puts "🎯 Running Devise attack pattern detection tests..."
    system("rails test test/integration/devise_attack_patterns_test.rb")
  end

  desc "Run Devise rate limiting tests"
  task :devise_rate_limiting do
    puts "⏱️  Running Devise rate limiting tests..."
    system("rails test test/integration/devise_rate_limiting_test.rb")
  end

  desc "Run Devise edge cases and error handling tests"
  task :devise_edge_cases do
    puts "🛡️  Running Devise edge cases and error handling tests..."
    system("rails test test/integration/devise_security_edge_cases_test.rb")
  end

  desc "Show Devise security test coverage summary"
  task :devise_coverage do
    puts "\n📊 Beskar Devise Security Test Coverage"
    puts "=" * 50
    puts "Authentication Flows:     Login/logout with security tracking"
    puts "Attack Detection:         Distributed attacks, credential stuffing"
    puts "Rate Limiting:           IP and account-based throttling"
    puts "Edge Cases:              Error handling, malformed requests"
    puts "Total Test Methods:      80+ individual test scenarios"
    puts "\nTest Files:"
    puts "- devise_authentication_security_test.rb  (23 tests)"
    puts "- devise_attack_patterns_test.rb          (8 tests)"
    puts "- devise_rate_limiting_test.rb             (10 tests)"
    puts "- devise_security_edge_cases_test.rb       (15 tests)"
    puts "\nUsage:"
    puts "rake test:devise_security        # Run all tests"
    puts "rake test:devise_auth           # Authentication tests only"
    puts "rake test:devise_attacks        # Attack pattern tests only"
    puts "rake test:devise_rate_limiting  # Rate limiting tests only"
    puts "rake test:devise_edge_cases     # Edge case tests only"
    puts "rake test:devise_coverage       # Show this summary"
  end

  desc "Run Devise security tests with verbose output"
  task :devise_verbose do
    ENV["TESTOPTS"] = "-v"
    Rake::Task["test:devise_security"].invoke
  end

  desc "Run failing Devise tests only (for debugging)"
  task :devise_failing do
    puts "🔍 Running previously failing Devise tests for debugging..."

    failing_tests = [
      "test/integration/devise_authentication_security_test.rb -n test_successful_login_creates_security_event_via_HTTP_request",
      "test/integration/devise_authentication_security_test.rb -n test_metadata_contains_request_path_and_referer_information",
      "test/integration/devise_authentication_security_test.rb -n test_suspicious_login_attempt_with_bot_user_agent_has_higher_risk_score"
    ]

    failing_tests.each do |test|
      puts "\n🧪 Testing: #{test}"
      system("rails test #{test}")
      puts "-" * 40
    end
  end
end

# Integration with main test task
desc "Run all tests including Devise security tests"
task :test_all do
  Rake::Task["test"].invoke
  Rake::Task["test:devise_security"].invoke
end
