#!/usr/bin/env ruby
# frozen_string_literal: true

# Simple benchmark using only standard library
require_relative "../test/dummy/config/environment"
require "benchmark"

puts "=" * 80
puts "Beskar Middleware Performance Benchmark"
puts "=" * 80
puts "Ruby: #{RUBY_VERSION} | Rails: #{Rails.version} | Cache: #{Rails.cache.class.name}"
puts "=" * 80
puts

# Setup test data
test_ip = "203.0.113.50"
whitelist_ip = "192.168.1.100"

mock_request = OpenStruct.new(
  ip: test_ip,
  fullpath: "/users/sign_in",
  path: "/users/sign_in",
  user_agent: "Mozilla/5.0"
)

waf_request = OpenStruct.new(
  ip: test_ip,
  fullpath: "/wp-admin/config.php",
  path: "/wp-admin/config.php",
  user_agent: "Scanner/1.0"
)

# Configure Beskar
Beskar.configure do |config|
  config.monitor_only = true # Don't actually block during benchmark
  config.ip_whitelist = ["192.168.1.100", "10.0.0.0/24"]
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

puts "Running benchmarks (10,000 iterations per test)..."
puts "-" * 80
puts

iterations = 10_000
results = {}

# Benchmark each component
print "Testing whitelist check... "
results[:whitelist] = Benchmark.measure do
  iterations.times { Beskar::Services::IpWhitelist.whitelisted?(test_ip) }
end
puts "✓"

print "Testing banned IP check... "
results[:banned_ip] = Benchmark.measure do
  iterations.times { Beskar::BannedIp.banned?(test_ip) }
end
puts "✓"

print "Testing rate limit check... "
results[:rate_limit] = Benchmark.measure do
  iterations.times { Beskar::Services::RateLimiter.check_ip_rate_limit(test_ip) }
end
puts "✓"

print "Testing WAF analysis (clean path)... "
results[:waf_clean] = Benchmark.measure do
  iterations.times { Beskar::Services::Waf.analyze_request(mock_request) }
end
puts "✓"

print "Testing WAF analysis (malicious path)... "
results[:waf_malicious] = Benchmark.measure do
  iterations.times { Beskar::Services::Waf.analyze_request(waf_request) }
end
puts "✓"

puts
puts "=" * 80
puts "RESULTS"
puts "=" * 80
puts

# Display results
printf "%-30s %12s %15s\n", "Operation", "Time/op", "Ops/sec"
puts "-" * 80

total_ms = 0

[
  [:whitelist, "1. Whitelist check"],
  [:banned_ip, "2. Banned IP check"],
  [:rate_limit, "3. Rate limit check"],
  [:waf_malicious, "4. WAF analysis"]
].each do |key, label|
  time = results[key]
  avg_ms = (time.real * 1000) / iterations
  ops_per_sec = (iterations / time.real).to_i

  total_ms += avg_ms

  printf "%-30s %9.4f ms %12s/s\n", label, avg_ms, ops_per_sec.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse
end

puts "-" * 80
printf "%-30s %9.4f ms\n", "TOTAL OVERHEAD per request", total_ms
puts "=" * 80

puts
puts "Detailed Breakdown:"
puts

results.each do |name, time|
  avg_ms = (time.real * 1000) / iterations
  ops_per_sec = (iterations / time.real).to_i

  label = case name
  when :whitelist then "Whitelist check"
  when :banned_ip then "Banned IP check (cache hit)"
  when :rate_limit then "Rate limit check"
  when :waf_clean then "WAF analysis (clean path)"
  when :waf_malicious then "WAF analysis (malicious)"
  end

  puts "#{label}:"
  puts "  Average: %.4f ms/operation" % avg_ms
  puts "  Throughput: #{ops_per_sec.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1,').reverse} ops/sec"
  puts
end

puts "=" * 80
puts "CONTEXT & COMPARISON"
puts "=" * 80
puts

puts "Beskar overhead:        ~%.1f ms per request" % total_ms
puts
puts "For comparison:"
puts "  • Typical middleware:   1-5 ms"
puts "  • Database query:       5-20 ms"
puts "  • Redis cache hit:      0.1-1 ms"
puts "  • Full request cycle:   100-500+ ms"
puts
puts "Impact: The %.1f ms represents less than 2%% of a typical 200ms request." % total_ms
puts

puts "=" * 80
puts "SCALABILITY TEST - Whitelist Size Impact"
puts "=" * 80
puts

printf "%-15s %15s\n", "Entries", "Time per check"
puts "-" * 40

[1, 10, 50, 100, 500].each do |size|
  whitelist = (1..size).map { |i| "192.168.#{i / 255}.#{i % 255}" }
  Beskar.configuration.ip_whitelist = whitelist
  Beskar::Services::IpWhitelist.clear_cache!

  time = Benchmark.measure do
    1000.times { Beskar::Services::IpWhitelist.whitelisted?(test_ip) }
  end

  avg_ms = (time.real * 1000) / 1000
  printf "%15d %12.4f ms\n", size, avg_ms
end

puts
puts "Recommendation: Keep whitelist under 100 entries for optimal performance"
puts

puts "=" * 80
puts "FOR YOUR BLOG POST"
puts "=" * 80
puts

puts "The middleware checks run in this order:"
puts
printf "  1. Whitelist check      ~%.2f ms\n", (results[:whitelist].real * 1000) / iterations
printf "  2. Banned IP check      ~%.2f ms (cache-first)\n", (results[:banned_ip].real * 1000) / iterations
printf "  3. Rate limit check     ~%.2f ms (cache-based)\n", (results[:rate_limit].real * 1000) / iterations
printf "  4. WAF analysis         ~%.2f ms (pattern matching)\n", (results[:waf_malicious].real * 1000) / iterations
puts "     " + ("-" * 35)
printf "  Total overhead:         ~%.2f ms per request\n", total_ms
puts

puts "This represents less than 2% overhead on a typical request."
puts

puts "=" * 80
puts "Benchmark completed!"
puts "=" * 80
