Beskar.configure do |config|
  # Global monitor-only mode - creates ban records but doesn't enforce them
  config.monitor_only = true

  # WAF Configuration with auto-blocking enabled
  config.waf[:enabled] = true
  config.waf[:auto_block] = true                # Automatically create ban records after threshold
  config.waf[:block_threshold] = 3              # Create ban after 3 violations
  config.waf[:violation_window] = 1.hour        # Count violations within this window
  config.waf[:block_durations] = [              # Escalating ban durations
    1.hour,
    6.hours,
    24.hours,
    7.days
  ]
  config.waf[:permanent_block_after] = 10       # Permanent ban after 10 violations
  config.waf[:create_security_events] = true    # Create SecurityEvent records

  # Enable geolocation with MaxMind City database (if available)
  # In CI/environments without the database, falls back to mock provider
  city_db_path = Rails.root.join('config', 'GeoLite2-City.mmdb').to_s

  config.geolocation[:provider] = File.exist?(city_db_path) ? :maxmind : :mock
  config.geolocation[:maxmind_city_db_path] = File.exist?(city_db_path) ? city_db_path : nil
  config.geolocation[:cache_ttl] = 4.hours

  # Optional: Configure rate limiting (these are already the defaults)
  # config.rate_limiting[:ip_attempts][:limit] = 10
  # config.rate_limiting[:ip_attempts][:period] = 1.hour
  # config.rate_limiting[:ip_attempts][:exponential_backoff] = true

  # config.rate_limiting[:account_attempts][:limit] = 5
  # config.rate_limiting[:account_attempts][:period] = 15.minutes
  # config.rate_limiting[:account_attempts][:exponential_backoff] = true

  # config.rate_limiting[:global_attempts][:limit] = 100
  # config.rate_limiting[:global_attempts][:period] = 1.minute
  # config.rate_limiting[:global_attempts][:exponential_backoff] = false

  # Optional: Configure security tracking (already enabled by default)
  # config.security_tracking[:enabled] = true
  # config.security_tracking[:track_successful_logins] = true
  # config.security_tracking[:track_failed_logins] = true
  # config.security_tracking[:auto_analyze_patterns] = true

  # Optional: Configure IP whitelist (add your development IPs if needed)
  # config.ip_whitelist = ['127.0.0.1', '::1']
end
