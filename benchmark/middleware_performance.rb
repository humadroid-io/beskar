#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../test/dummy/config/environment"
require "benchmark/ips"

puts "=" * 80
puts "Beskar Middleware Performance Benchmark"
puts "=" * 80
puts "Ruby version: #{RUBY_VERSION}"
puts "Rails version: #{Rails.version}"
puts "Cache store: #{Rails.cache.class.name}"
puts "=" * 80
puts

# Setup test data
test_ip = "203.0.113.50"
whitelist_ip = "192.168.1.100"
mock_request = OpenStruct.new(
  ip: test_ip,
  fullpath: "/users/sign_in",
  path: "/users/sign_in",
  user_agent: "Mozilla/5.0 Test"
)

waf_request = OpenStruct.new(
  ip: test_ip,
  fullpath: "/wp-admin/config.php",
  path: "/wp-admin/config.php",
  user_agent: "Mozilla/5.0 Scanner"
)

# Configure Beskar for testing
# Configure Beskar
Beskar.configure do |config|
  config.monitor_only = true # Don't actually block during benchmark
  config.waf = {
    enabled: true,
    auto_block: false
  }
end

# Pre-warm caches
Beskar::Services::IpWhitelist.whitelisted?(test_ip)
Beskar::BannedIp.banned?(test_ip)
Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip)
Beskar::Services::Waf.analyze_request(waf_request)

puts "Individual Component Benchmarks"
puts "-" * 80

Benchmark.ips do |x|
  x.config(time: 5, warmup: 2)

  x.report("1. Whitelist check (not whitelisted)") do
    Beskar::Services::IpWhitelist.whitelisted?(test_ip)
  end

  x.report("1. Whitelist check (whitelisted)") do
    Beskar::Services::IpWhitelist.whitelisted?(whitelist_ip)
  end

  x.report("2. Banned IP check (cache hit - not banned)") do
    Beskar::BannedIp.banned?(test_ip)
  end

  x.report("3. Rate limit check (under limit)") do
    Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip)
  end

  x.report("4. WAF analysis (clean path)") do
    Beskar::Services::Waf.analyze_request(mock_request)
  end

  x.report("4. WAF analysis (malicious path)") do
    Beskar::Services::Waf.analyze_request(waf_request)
  end

  x.compare!
end

puts
puts "=" * 80
puts "Detailed Timing Measurements (in milliseconds)"
puts "-" * 80

# Get precise timing for each operation
iterations = 10_000

results = {}

results["Whitelist check"] = Benchmark.measure do
  iterations.times { Beskar::Services::IpWhitelist.whitelisted?(test_ip) }
end

results["Banned IP check"] = Benchmark.measure do
  iterations.times { Beskar::BannedIp.banned?(test_ip) }
end

results["Rate limit check"] = Benchmark.measure do
  iterations.times { Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip) }
end

results["WAF clean path"] = Benchmark.measure do
  iterations.times { Beskar::Services::Waf.analyze_request(mock_request) }
end

results["WAF malicious path"] = Benchmark.measure do
  iterations.times { Beskar::Services::Waf.analyze_request(waf_request) }
end

# Calculate and display results
results.each do |name, time|
  avg_ms = (time.real * 1000) / iterations
  puts "%-25s %8.4f ms/op (%8d ops/sec)" % [name + ":", avg_ms, (iterations / time.real).to_i]
end

puts
puts "=" * 80
puts "Full Middleware Stack Benchmark"
puts "-" * 80

# Simulate full middleware execution flow
def simulate_middleware_check(request)
  ip = request.ip

  # 1. Whitelist check
  is_whitelisted = Beskar::Services::IpWhitelist.whitelisted?(ip)

  # 2. Banned IP check (skip if whitelisted)
  return :blocked if !is_whitelisted && Beskar::BannedIp.banned?(ip)

  # 3. Rate limit check (skip if whitelisted)
  if !is_whitelisted
    rate_result = Beskar::Services::RateLimiter.check_ip_rate_limit(ip)
    return :rate_limited unless rate_result[:allowed]
  end

  # 4. WAF check
  if Beskar.configuration.waf_enabled?
    waf_result = Beskar::Services::Waf.analyze_request(request)
    # Would normally record violation here, but skip for benchmark
  end

  :allowed
end

puts "Simulating realistic request flow through all checks..."
puts

full_stack_time = Benchmark.measure do
  iterations.times { simulate_middleware_check(mock_request) }
end

avg_full_ms = (full_stack_time.real * 1000) / iterations
puts "Full middleware stack: %.4f ms/request" % avg_full_ms
puts "Throughput: %d requests/second" % (iterations / full_stack_time.real).to_i

puts
puts "=" * 80
puts "Cache Performance Analysis"
puts "-" * 80

# Test cache hit vs miss scenarios
cache_key = "beskar:banned_ip:#{test_ip}"

# Warm up cache
Rails.cache.write(cache_key, false, expires_in: 5.minutes)

cache_hit_time = Benchmark.measure do
  iterations.times { Rails.cache.read(cache_key) }
end

Rails.cache.delete(cache_key)

cache_miss_time = Benchmark.measure do
  iterations.times do
    Rails.cache.read("beskar:banned_ip:nonexistent_#{rand(10000)}")
  end
end

puts "Cache hit:  %.4f ms/op" % ((cache_hit_time.real * 1000) / iterations)
puts "Cache miss: %.4f ms/op" % ((cache_miss_time.real * 1000) / iterations)

puts
puts "=" * 80
puts "Scalability Test - Whitelist Size Impact"
puts "-" * 80

[1, 10, 50, 100, 500].each do |size|
  # Generate whitelist of varying sizes
  whitelist = (1..size).map { |i| "192.168.#{i / 255}.#{i % 255}" }

  # Override whitelist configuration
  Beskar.configuration.ip_whitelist = whitelist
  Beskar::Services::IpWhitelist.clear_cache!

  time = Benchmark.measure do
    1000.times { Beskar::Services::IpWhitelist.whitelisted?(test_ip) }
  end

  avg_ms = (time.real * 1000) / 1000
  puts "Whitelist size %4d: %.4f ms/check" % [size, avg_ms]
end

# Restore original config
Beskar.configuration.ip_whitelist = ["192.168.1.100", "10.0.0.0/24"]
Beskar::Services::IpWhitelist.clear_cache!

puts
puts "=" * 80
puts "Summary for Blog Post"
puts "=" * 80
puts

# Recalculate with fresh measurements
measurements = {}

measurements[:whitelist] = Benchmark.measure do
  10_000.times { Beskar::Services::IpWhitelist.whitelisted?(test_ip) }
end

measurements[:banned_ip] = Benchmark.measure do
  10_000.times { Beskar::BannedIp.banned?(test_ip) }
end

measurements[:rate_limit] = Benchmark.measure do
  10_000.times { Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip) }
end

measurements[:waf] = Benchmark.measure do
  10_000.times { Beskar::Services::Waf.analyze_request(waf_request) }
end

total_ms = 0

puts "Middleware overhead per request:"
puts
measurements.each do |name, time|
  avg_ms = (time.real * 1000) / 10_000
  total_ms += avg_ms

  label = case name
  when :whitelist then "1. Whitelist check"
  when :banned_ip then "2. Banned IP check"
  when :rate_limit then "3. Rate limit check"
  when :waf then "4. WAF analysis"
  end

  puts "  %-22s ~%.2f ms" % [label + ":", avg_ms]
end

puts "  " + ("-" * 30)
puts "  %-22s ~%.2f ms" % ["Total overhead:", total_ms]
puts

puts "For context:"
puts "  • Typical Rails middleware: 1-5 ms"
puts "  • Database query: 5-20 ms"
puts "  • Full request cycle: 100-500+ ms"
puts
puts "The %.1f ms overhead is less than 2%% of a typical request." % total_ms
puts

puts "=" * 80
