# frozen_string_literal: true

Beskar.configure do |config|
  # ============================================================================
  # Web Application Firewall (WAF) - ENABLED IN MONITOR MODE BY DEFAULT
  # ============================================================================
  # Detects and logs vulnerability scanning attempts (WordPress, phpMyAdmin, etc.)
  # Start in monitor-only mode to observe patterns before enabling blocking.
  #
  # MONITOR-ONLY MODE - Set at the top level (affects all blocking features)
  config.monitor_only = true               # LOG ONLY - does not block (recommended to start)

  config.waf = {
    enabled: true,                        # Master switch for WAF
    auto_block: true,                     # Auto-block IPs after threshold (when monitor_only=false)
    block_threshold: 3,                   # Number of violations before blocking
    violation_window: 1.hour,             # Time window for counting violations
    block_durations: [1.hour, 6.hours, 24.hours, 7.days], # Escalating ban durations
    permanent_block_after: 5,             # Permanent ban after N violations (nil = never)
    create_security_events: true          # Log violations to SecurityEvent table
  }

  # After monitoring for 24-48 hours, review logs and disable monitor_only:
  # config.monitor_only = false

  # View WAF activity in logs:
  # tail -f log/production.log | grep "Beskar::WAF"

  # Query violations that would be blocked:
  # Beskar::SecurityEvent.where(event_type: 'waf_violation')
  #   .where("metadata->>'would_be_blocked' = ?", 'true').count

  # ============================================================================
  # IP Whitelisting (RECOMMENDED)
  # ============================================================================
  # Trusted IPs bypass all blocking (bans, rate limits, WAF) while still
  # logging activity for audit purposes.
  #
  # config.ip_whitelist = [
  #   "192.168.1.100",      # Single IP address
  #   "10.0.0.0/24",        # CIDR notation - entire subnet
  #   "172.16.0.0/16"       # Larger CIDR range
  #   # Add your office IPs, monitoring services, trusted partners, etc.
  # ]

  # ============================================================================
  # Security Event Tracking (OPTIONAL)
  # ============================================================================
  # Track authentication events for risk analysis and threat detection.
  # Disable if you don't need historical security event data.
  #
  # config.security_tracking = {
  #   enabled: true,                    # Master switch for all tracking
  #   track_successful_logins: true,    # Track successful authentications
  #   track_failed_logins: true,        # Track failed authentication attempts
  #   auto_analyze_patterns: true       # Enable automatic pattern analysis
  # }

  # ============================================================================
  # Rate Limiting (OPTIONAL)
  # ============================================================================
  # Protect against brute force attacks by limiting authentication attempts.
  #
  # config.rate_limiting = {
  #   ip_attempts: {
  #     limit: 10,                    # Max attempts per IP
  #     period: 1.hour,               # Time window
  #     exponential_backoff: true     # Increase delay after each attempt
  #   },
  #   account_attempts: {
  #     limit: 5,                     # Max attempts per account
  #     period: 15.minutes,
  #     exponential_backoff: true
  #   },
  #   global_attempts: {
  #     limit: 100,                   # System-wide limit (DDoS protection)
  #     period: 1.minute,
  #     exponential_backoff: false
  #   }
  # }

  # ============================================================================
  # Risk-Based Account Locking (OPTIONAL)
  # ============================================================================
  # Automatically lock accounts when authentication risk score is too high.
  # Requires Devise :lockable module.
  #
  # config.risk_based_locking = {
  #   enabled: false,                 # Disabled by default
  #   risk_threshold: 75,             # Lock if risk score >= this (0-100)
  #   lock_strategy: :devise_lockable, # Strategy: :devise_lockable, :custom, :none
  #   auto_unlock_time: 1.hour,       # Time until automatic unlock
  #   notify_user: true,              # Send notification on lock
  #   log_lock_events: true           # Create security events for locks
  # }

  # ============================================================================
  # IP Geolocation (OPTIONAL)
  # ============================================================================
  # Enhance risk assessment with geographic information.
  # Requires MaxMind GeoLite2-City database (free with registration).
  # Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  #
  # config.geolocation = {
  #   provider: :maxmind,
  #   maxmind_city_db_path: Rails.root.join('db', 'geoip', 'GeoLite2-City.mmdb').to_s,
  #   cache_ttl: 4.hours
  # }
end
