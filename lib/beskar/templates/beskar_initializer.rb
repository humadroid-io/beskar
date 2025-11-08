# frozen_string_literal: true

Beskar.configure do |config|
  # ============================================================================
  # Dashboard Authentication (REQUIRED)
  # ============================================================================
  # Configure how users authenticate to access the Beskar dashboard.
  # This is REQUIRED and must be set for all environments.
  #
  # The authenticate_admin callback receives the request object and is executed
  # in the controller context, giving you access to all controller methods
  # (cookies, session, authenticate_or_request_with_http_basic, etc.).
  # The block should return truthy value to allow access, falsey to deny.
  #
  # Example 1: Devise with admin role
  # config.authenticate_admin = ->(request) do
  #   user = request.env['warden']&.authenticate(scope: :user)
  #   user&.admin?
  # end
  #
  # Example 2: Simple token-based authentication
  # config.authenticate_admin = ->(request) do
  #   request.headers['Authorization'] == "Bearer #{ENV['BESKAR_ADMIN_TOKEN']}"
  # end
  #
  # Example 3: For development/testing only (NOT for production!)
  # config.authenticate_admin = ->(request) do
  #   Rails.env.development? || Rails.env.test?
  # end
  #
  # Example 4: HTTP Basic Auth (uses controller method)
  # config.authenticate_admin = ->(request) do
  #   authenticate_or_request_with_http_basic do |username, password|
  #     username == ENV['BESKAR_USERNAME'] && password == ENV['BESKAR_PASSWORD']
  #   end
  # end
  #
  # Example 5: Cookie-based authentication (uses controller cookies)
  # config.authenticate_admin = ->(request) do
  #   cookies.signed[:admin_token] == ENV['BESKAR_ADMIN_TOKEN']
  # end

  # ============================================================================
  # Web Application Firewall (WAF) - ENABLED IN MONITOR MODE BY DEFAULT
  # ============================================================================
  # Detects and logs vulnerability scanning attempts (WordPress, phpMyAdmin, etc.)
  # Start in monitor-only mode to observe patterns before enabling blocking.
  #
  # MONITOR-ONLY MODE - Set at the top level (affects all blocking features)
  config.monitor_only = true               # LOG ONLY - does not block (recommended to start)

  config.waf[:enabled] = true                        # Master switch for WAF
  config.waf[:auto_block] = true                     # Auto-block IPs after threshold (when monitor_only=false)
  config.waf[:block_threshold] = 3                   # Number of violations before blocking
  config.waf[:violation_window] = 1.hour             # Time window for counting violations
  config.waf[:block_durations] = [1.hour, 6.hours, 24.hours, 7.days] # Escalating ban durations
  config.waf[:permanent_block_after] = 5             # Permanent ban after N violations (nil = never)
  config.waf[:create_security_events] = true         # Log violations to SecurityEvent table

  # Rails Exception Detection - NEW FEATURE
  # Detects potential scanning through Rails exceptions:
  # - ActionController::UnknownFormat (e.g., /users/1.exe)
  # - ActionDispatch::RemoteIp::IpSpoofAttackError (IP spoofing attempts)
  # - ActiveRecord::RecordNotFound (record enumeration scans)

  # Exclude certain paths from RecordNotFound detection to avoid false positives
  # Example: Exclude all post URLs from triggering WAF on 404s
  config.waf[:record_not_found_exclusions] = [
    # %r{/posts/.*},                  # Don't flag missing posts as scanning
    # %r{/articles/\d+},              # Don't flag missing articles
    # %r{/public/.*},                 # Ignore public content paths
  ]

  # After monitoring for 24-48 hours, review logs and disable monitor_only:
  # config.monitor_only = false

  # View WAF activity in logs:
  # tail -f log/production.log | grep "Beskar::WAF"

  # The WAF now detects:
  # - Traditional vulnerability scans (WordPress, phpMyAdmin, etc.)
  # - Rails-specific attacks via exceptions:
  #   * Unknown format requests (potential scanners testing endpoints)
  #   * IP spoofing attempts (conflicting IP headers)
  #   * Record enumeration (testing non-existent IDs)

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
