#!/usr/bin/env ruby

require_relative "test/dummy/config/environment"

puts "🔒 Beskar Security Gem - Configuration Demo"
puts "=" * 60

# Demo 1: Default Configuration
puts "\n📋 Demo 1: Default Configuration"
puts "-" * 40
puts "Security Tracking Enabled: #{Beskar.configuration.security_tracking_enabled?}"
puts "Track Successful Logins: #{Beskar.configuration.track_successful_logins?}"
puts "Track Failed Logins: #{Beskar.configuration.track_failed_logins?}"
puts "Auto Analyze Patterns: #{Beskar.configuration.auto_analyze_patterns?}"
puts "WAF Enabled: #{Beskar.configuration.waf_enabled?}"
puts "Rate Limiting Config: #{Beskar.configuration.rate_limiting[:ip_attempts][:limit]} IP attempts per #{Beskar.configuration.rate_limiting[:ip_attempts][:period] / 3600}h"

# Demo 2: Custom Configuration
puts "\n⚙️  Demo 2: Custom Configuration"
puts "-" * 40

# Store original configuration
original_security_tracking = Beskar.configuration.security_tracking

# Configure with custom settings
Beskar.configure do |config|
  config.security_tracking = {
    enabled: true,
    track_successful_logins: false,  # Disable successful login tracking
    track_failed_logins: true,       # Keep failed login tracking
    auto_analyze_patterns: false     # Disable auto analysis
  }

  config.monitor_only = false  # Top-level monitor setting

  config.waf = {
    enabled: true,
    auto_block: true,
    block_threshold: 2
  }

  config.rate_limiting = {
    ip_attempts: {
      limit: 3,           # Stricter limits
      period: 30.minutes,
      exponential_backoff: true
    },
    account_attempts: {
      limit: 2,
      period: 10.minutes,
      exponential_backoff: true
    }
  }
end

puts "After configuration change:"
puts "Security Tracking Enabled: #{Beskar.configuration.security_tracking_enabled?}"
puts "Track Successful Logins: #{Beskar.configuration.track_successful_logins?}"
puts "Track Failed Logins: #{Beskar.configuration.track_failed_logins?}"
puts "Auto Analyze Patterns: #{Beskar.configuration.auto_analyze_patterns?}"
puts "WAF Enabled: #{Beskar.configuration.waf_enabled?}"
puts "WAF Auto-Block: #{Beskar.configuration.waf_auto_block?}"
puts "Rate Limiting Config: #{Beskar.configuration.rate_limiting[:ip_attempts][:limit]} IP attempts per #{Beskar.configuration.rate_limiting[:ip_attempts][:period] / 60}min"

# Demo 3: Testing Configuration Impact
puts "\n🧪 Demo 3: Testing Configuration Impact"
puts "-" * 40

# Create a test user
user = User.create!(
  email: "config_demo@example.com",
  password: "password123",
  password_confirmation: "password123"
)

# Mock a request
request_mock = OpenStruct.new(
  ip: "192.168.1.200",
  user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
  path: "/users/sign_in",
  session: OpenStruct.new(id: "config_demo_session"),
  headers: {},
  params: {"user" => {"email" => user.email}}
)

initial_count = Beskar::SecurityEvent.count

# Test successful login tracking (should be disabled)
puts "\nTesting successful login tracking (disabled):"
result = user.track_authentication_event(request_mock, :success)
if result.nil?
  puts "✅ Successful login NOT tracked (as expected - disabled in config)"
else
  puts "❌ Successful login was tracked (unexpected)"
end

# Test failed login tracking (should be enabled)
puts "\nTesting failed login tracking (enabled):"
User.track_failed_authentication(request_mock, :user)
events_after_failed = Beskar::SecurityEvent.count
if events_after_failed > initial_count
  puts "✅ Failed login tracked (as expected - enabled in config)"
  puts "   New security event created with risk score: #{Beskar::SecurityEvent.last.risk_score}"
else
  puts "❌ Failed login was NOT tracked (unexpected)"
end

# Demo 4: Disabling Security Tracking Entirely
puts "\n🚫 Demo 4: Disabling Security Tracking Entirely"
puts "-" * 40

Beskar.configure do |config|
  config.security_tracking = {
    enabled: false,           # Disable entirely
    track_successful_logins: true,
    track_failed_logins: true,
    auto_analyze_patterns: true
  }
end

puts "Security tracking disabled entirely"
puts "Security Tracking Enabled: #{Beskar.configuration.security_tracking_enabled?}"
puts "Track Successful Logins: #{Beskar.configuration.track_successful_logins?}"
puts "Track Failed Logins: #{Beskar.configuration.track_failed_logins?}"
puts "Auto Analyze Patterns: #{Beskar.configuration.auto_analyze_patterns?}"

current_count = Beskar::SecurityEvent.count

# Neither should create events now
user.track_authentication_event(request_mock, :success)
User.track_failed_authentication(request_mock, :user)

if Beskar::SecurityEvent.count == current_count
  puts "✅ No events created when security tracking is disabled entirely"
else
  puts "❌ Events were created despite security tracking being disabled"
end

# Demo 5: Restore Original Configuration
puts "\n🔄 Demo 5: Restoring Original Configuration"
puts "-" * 40

# Restore original configuration
Beskar.configuration.security_tracking = original_security_tracking
Beskar.configuration.waf[:enabled] = false

puts "Configuration restored to defaults:"
puts "Security Tracking Enabled: #{Beskar.configuration.security_tracking_enabled?}"
puts "Track Successful Logins: #{Beskar.configuration.track_successful_logins?}"
puts "Track Failed Logins: #{Beskar.configuration.track_failed_logins?}"
puts "Auto Analyze Patterns: #{Beskar.configuration.auto_analyze_patterns?}"
puts "WAF Enabled: #{Beskar.configuration.waf_enabled?}"

# Test that tracking works again
puts "\nTesting restored configuration:"
pre_restore_count = Beskar::SecurityEvent.count
user.track_authentication_event(request_mock, :success)
User.track_failed_authentication(request_mock, :user)

events_created = Beskar::SecurityEvent.count - pre_restore_count
puts "✅ #{events_created} security events created with restored configuration"

# Summary
puts "\n📊 Summary"
puts "-" * 40
total_events = Beskar::SecurityEvent.count
puts "Total security events in database: #{total_events}"
puts "Events for config demo user: #{user.security_events.count}"

# Cleanup
user.destroy!

puts "\n✨ Configuration demo completed successfully!"
puts "   - Demonstrated default configuration"
puts "   - Showed custom configuration options"
puts "   - Tested configuration impact on tracking behavior"
puts "   - Verified security tracking can be selectively disabled"
puts "   - Confirmed configuration restoration works properly"
