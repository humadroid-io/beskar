# Beskar

**Beskar** is a comprehensive, Rails-native security engine designed to provide multi-layered, proactive protection for modern web applications. It defends against common threats, bot activity, and account takeovers without requiring external dependencies, integrating seamlessly into your application as a natural extension of the framework.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Dashboard Authentication (REQUIRED)](#dashboard-authentication-required)
  - [Add to Your User Model](#add-to-your-user-model)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Risk-Based Account Locking](#risk-based-account-locking-with-devise-lockable)
  - [Rate Limiting](#rate-limiting)
  - [IP Whitelisting](#ip-whitelisting)
  - [Web Application Firewall (WAF)](#web-application-firewall-waf)
  - [IP Blocking and Banning](#ip-blocking-and-banning)
  - [Security Events](#security-events)
  - [Middleware Integration](#middleware-integration)
- [WAF Pattern Reference](#waf-pattern-reference)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Features

-   **Devise Integration:** Seamless integration with Devise authentication for automatic login tracking and security analysis.
-   **Risk-Based Account Locking:** Automatically locks accounts when authentication risk scores exceed configurable thresholds, preventing compromised account access.
-   **Smart Rate Limiting:** Distributed rate limiting using Rails.cache with IP-based and account-based throttling with exponential backoff.
-   **Brute Force Detection:** Advanced pattern recognition to detect single account attacks vs credential stuffing attempts, with automatic IP banning.
-   **IP Whitelisting:** Allow trusted IPs (office networks, partners, security scanners) to bypass blocking while maintaining full audit logs. Supports individual IPs and CIDR notation.
-   **Persistent IP Blocking:** Hybrid cache + database blocking system that survives application restarts. Auto-bans IPs after authentication abuse or excessive rate limiting violations.
-   **Web Application Firewall (WAF):** Real-time detection and blocking of vulnerability scanning attempts across 10 attack categories including Rails exception analysis (WordPress, PHP admin panels, config files, path traversal, framework debug, CMS detection, common exploits, UnknownFormat, IP spoofing, RecordNotFound enumeration). Includes escalating ban durations, monitor-only mode, and configurable exclusion patterns.
-   **Security Event Tracking:** Comprehensive logging of authentication events with risk scoring and metadata extraction.
-   **IP Geolocation:** MaxMind GeoLite2-City database integration for country/city location, coordinates, timezone, and enhanced risk scoring (configurable, database not included due to licensing).
-   **Geographic Anomaly Detection:** Haversine-based impossible travel detection and location-based risk assessment.
-   **Advanced Bot Detection:** Multi-layered defense using JavaScript challenges and invisible honeypots to filter out malicious bots while allowing legitimate ones.
-   **Modular Architecture:** Devise-specific code is isolated in separate services for maintainability and extensibility.
-   **Rails-Native Architecture:** Built as a mountable `Rails::Engine`, it leverages `ActiveJob` and `Rails.cache` for high performance and low overhead.
-   **Security Dashboard:** A mountable web interface for monitoring security events, managing IP bans, and viewing statistics. Features configurable authentication, real-time filtering, and export capabilities. See [Dashboard Authentication](#dashboard-authentication) section below.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'beskar'
```

And then execute:

```bash
bundle install
```

Run the installation task to set up Beskar:

```bash
bin/rails beskar:install
```

This will:
- Copy all necessary migrations to your application
- Create `config/initializers/beskar.rb` with sensible defaults
- Display next steps for completing the setup

Then run the database migrations:

```bash
bin/rails db:migrate
```

### Quick Start

**1. Configure Dashboard Authentication (Required)**

Before using Beskar, you must configure authentication for the dashboard. See the [Dashboard Authentication](#dashboard-authentication) section below for details and examples.

**2. Enable WAF Monitoring**

By default, Beskar enables the **Web Application Firewall (WAF) in monitor-only mode**. This means:
- ✅ Vulnerability scans are detected and logged
- ✅ Security events are created for analysis
- ⚠️ No requests are blocked yet (safe to enable in production)

After monitoring for 24-48 hours, review the logs and disable monitor-only mode to enable active blocking:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  config.monitor_only = true # Change this to false to enable blocking
  config.waf[:enabled] = true
  # ... rest of configuration
end
```

### Dashboard Authentication (REQUIRED)

**⚠️ IMPORTANT: Dashboard authentication must be configured for all environments.**

The Beskar dashboard requires authentication to prevent unauthorized access. You must configure how users authenticate to access the dashboard by setting up the `authenticate_admin` callback:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  # REQUIRED: Configure dashboard authentication
  config.authenticate_admin = ->(request) do
    # Return truthy to allow access, falsey to deny

    # Example 1: Devise with admin role (recommended for production)
    user = request.env['warden']&.authenticate(scope: :user)
    user&.admin?
  end
end
```

**Why this is required:** Previous versions allowed unauthenticated access in development/test environments, which could lead to production security issues. Now, authentication must be explicitly configured for all environments to prevent accidental exposure.

**Other Authentication Strategies:**

```ruby
# Token-based authentication
config.authenticate_admin = ->(request) do
  request.headers['Authorization'] == "Bearer #{ENV['BESKAR_ADMIN_TOKEN']}"
end

# HTTP Basic Auth
config.authenticate_admin = ->(request) do
  authenticate_or_request_with_http_basic do |username, password|
    username == ENV['BESKAR_USERNAME'] && password == ENV['BESKAR_PASSWORD']
  end
end

# Development/Testing bypass (use with caution!)
config.authenticate_admin = ->(request) do
  Rails.env.development? || Rails.env.test?
end
```

**Accessing the Dashboard:**

After configuring authentication, mount the engine in your routes:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  mount Beskar::Engine => "/beskar"
end
```

Then visit `http://localhost:3000/beskar` to access the dashboard.

**Dashboard Features:**
- 📊 Security event monitoring with filtering and search
- 🚫 IP ban management (view, extend, unban)
- 📈 Statistics and risk distribution analysis
- 📥 Export capabilities (CSV/JSON)
- 🔒 CSRF protection and secure by default

### Add to Your User Model

Include the `SecurityTrackable` concern in your Devise user model:

```ruby
# app/models/user.rb
class User < ApplicationRecord
  include Beskar::Models::SecurityTrackable

  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  # ... other Devise modules
end
```

## Configuration

You can configure Beskar in the initializer file created by the installer.

> **Note:** Dashboard authentication setup is covered in the [Dashboard Authentication](#dashboard-authentication-required) section above.

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  # === Dashboard Authentication (REQUIRED) ===
  # See "Dashboard Authentication" section above for examples and details
  config.authenticate_admin = ->(request) do
    user = request.env['warden']&.authenticate(scope: :user)
    user&.admin?
  end

  # === Security Tracking ===
  # Controls what security events are tracked and analyzed
  config.security_tracking = {
    enabled: true,                    # Master switch - disables all tracking when false
    track_successful_logins: true,    # Track successful authentication events
    track_failed_logins: true,        # Track failed authentication attempts
    auto_analyze_patterns: true       # Enable automatic pattern analysis for threats
  }

  # === Rate Limiting ===
  config.rate_limiting = {
    ip_attempts: {
      limit: 10,                    # Max attempts per IP
      period: 1.hour,               # Time window
      exponential_backoff: true     # Enable exponential backoff
    },
    account_attempts: {
      limit: 5,                     # Max attempts per account
      period: 15.minutes,           # Time window
      exponential_backoff: true
    },
    global_attempts: {
      limit: 100,                   # System-wide limit
      period: 1.minute,
      exponential_backoff: false
    }
  }

  # === IP Whitelisting ===
  # See "IP Whitelisting" section below for detailed examples
  config.ip_whitelist = []  # Add trusted IPs here (supports CIDR notation)

  # === Web Application Firewall (WAF) ===
  # See "Web Application Firewall" section below for production examples
  # Defaults shown here - use [:key] syntax to preserve other defaults
  config.waf[:enabled] = true                        # Master switch for WAF
  # config.waf[:auto_block] = true                   # Default: true
  # config.waf[:block_threshold] = 3                 # Default: 3 (production often uses 2)
  # config.waf[:violation_window] = 1.hour           # Default: 1 hour
  # config.waf[:block_durations] = [1.hour, 6.hours, 24.hours, 7.days] # Escalating bans
  # config.waf[:permanent_block_after] = 5           # Permanent after 5 violations
  # config.waf[:create_security_events] = true       # Log to SecurityEvent table
  # config.waf[:record_not_found_exclusions] = []    # Regex patterns for false positives

  # === Risk-Based Account Locking ===
  # Automatically lock accounts when authentication risk score exceeds threshold
  config.risk_based_locking = {
    enabled: false,                    # Master switch for risk-based locking
    risk_threshold: 75,                # Lock account if risk score >= this value (0-100)
    lock_strategy: :devise_lockable,   # Strategy: :devise_lockable, :custom, :none
    auto_unlock_time: 1.hour,          # Time until automatic unlock (if supported)
    notify_user: true,                 # Send notification on lock (future feature)
    log_lock_events: true              # Create security event for locks
  }

  # === IP Geolocation ===
  # Configure IP geolocation for enhanced risk assessment
  # Note: You must provide your own MaxMind GeoLite2-City database due to licensing
  # Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  config.geolocation = {
    provider: :maxmind,                # Provider: :maxmind or :mock (for testing)
    maxmind_city_db_path: Rails.root.join('db', 'geoip', 'GeoLite2-City.mmdb').to_s,
    cache_ttl: 4.hours                 # How long to cache geolocation results
  }
end

```

## Usage

> **Note:** If you haven't already, see the [Add to Your User Model](#add-to-your-user-model) section in Quick Start for setting up `SecurityTrackable`.

### Risk-Based Account Locking (with Devise Lockable)

Beskar can automatically lock user accounts when the calculated risk score exceeds a configured threshold. This prevents compromised accounts from being accessed even after successful authentication.

**Setup with Devise Lockable:**

1. Enable the `:lockable` module in your User model:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :lockable  # Add this for risk-based locking

  include Beskar::Models::SecurityTrackable
end
```

2. Generate and run the migration to add lockable columns:

```bash
rails generate devise User  # This will add lockable columns if not present
# Or manually add:
# - failed_attempts (integer)
# - unlock_token (string)
# - locked_at (datetime)
rails db:migrate
```

3. Enable risk-based locking in your initializer:

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  config.risk_based_locking = {
    enabled: true,                     # Enable the feature
    risk_threshold: 75,                # Lock when risk >= 75
    lock_strategy: :devise_lockable,   # Use Devise's lockable module
    auto_unlock_time: 1.hour,          # Automatic unlock after 1 hour
    notify_user: true,                 # Log notification intent
    log_lock_events: true              # Create security events
  }
end
```

**How it works:**

- After each successful authentication, Beskar calculates a risk score (0-100) based on:
  - Geographic anomalies (impossible travel, country changes)
  - Device fingerprints (suspicious user agents, bot signatures)
  - Login patterns (velocity, time of day, recent failures)
  - IP reputation and geolocation risk

- **Adaptive Learning:** The system learns from user behavior:
  - After 2+ successful logins from an IP, that location becomes "established"
  - If a user unlocks and logs in successfully, that pattern is trusted
  - Risk scores are reduced to 30% for established patterns (capped at 25)
  - This prevents repeated locks after users validate their login context

- If the risk score meets or exceeds the configured threshold, the account is automatically locked
- The user session is terminated immediately to prevent access
- A security event is logged with the lock reason and risk details (always logged for audit trail)
- The account remains locked until manually unlocked or the auto-unlock time expires (if supported)

**Example Adaptive Flow:**
1. User travels to new location → High risk (85) → Account locked
2. User unlocks account → Validates legitimacy
3. User logs in from same location → Pattern established → Risk reduced to 25 → Login succeeds ✅
4. Future logins from this location → Normal risk → No more locks

See `ADAPTIVE_LEARNING.md` for detailed documentation.

**Lock Reasons:**

The system identifies specific reasons for locking:
- `:impossible_travel` - Login from location requiring impossible travel speed
- `:suspicious_device` - Bot signature or suspicious user agent detected
- `:geographic_anomaly` - Country change or high-risk location
- `:high_risk_authentication` - General high-risk authentication pattern

**Manual Lock/Unlock Operations:**

```ruby
# Manually lock an account based on risk
locker = Beskar::Services::AccountLocker.new(
  user,
  risk_score: 85,
  reason: :suspicious_device,
  metadata: { ip_address: request.ip }
)

if locker.should_lock?
  locker.lock!  # Lock the account
end

# Check if account is locked
locker.locked?  # => true/false

# Manually unlock
locker.unlock!
```

### Security Event Tracking

Beskar automatically tracks login attempts and creates security events with rich metadata:

```ruby
# Check recent failed attempts for a user
user.recent_failed_attempts(within: 1.hour)

# Check if user has suspicious login patterns
user.suspicious_login_pattern?

# Get recent successful logins
user.recent_successful_logins(within: 24.hours)

# Access security events
user.security_events.login_failures.recent
```

### Rate Limiting

Check if a request should be rate limited:

```ruby
# In a controller or middleware
if Beskar.rate_limited?(request, current_user)
  render json: { error: 'Rate limit exceeded' }, status: 429
  return
end

# Manual rate limiting check
rate_limiter = Beskar::Services::RateLimiter.new(request.ip, current_user)
unless rate_limiter.allowed?
  # Handle rate limiting
  time_until_reset = rate_limiter.time_until_reset
end
```

### Security Events Analysis

Security events are automatically created and include:

- **Event Type**: `login_success`, `login_failure`
- **IP Address**: Client IP with proxy detection
- **User Agent**: Browser and device information
- **Risk Score**: 0-100 based on various factors
- **Metadata**: Device info, geolocation, timestamps
- **Attack Patterns**: Detection of brute force, credential stuffing, etc.

### Attack Pattern Detection

Beskar can identify different types of attacks:

```ruby
rate_limiter = Beskar::Services::RateLimiter.new(ip_address, user)
attack_type = rate_limiter.attack_pattern_type

case attack_type
when :brute_force_single_account
  # Single IP attacking one account
when :distributed_single_account
  # Multiple IPs attacking one account
when :single_ip_multiple_accounts
  # One IP attacking multiple accounts (credential stuffing)
when :mixed_attack_pattern
  # Complex attack pattern
end
```

### IP Whitelisting

Whitelist trusted IPs to bypass all security blocking while maintaining full audit logs:

```ruby
# In config/initializers/beskar.rb
Beskar.configure do |config|
  config.ip_whitelist = [
    "203.0.113.0/24",      # Office network (CIDR notation)
    "198.51.100.50",       # VPN gateway (single IP)
    "2001:db8::1"          # IPv6 address
  ]
end
```

**How it works:**
- Whitelisted IPs bypass **all blocking** (banned IPs, rate limits, WAF violations)
- All requests from whitelisted IPs are **still logged** for audit purposes
- Supports individual IPs and CIDR notation (IPv4 and IPv6)
- Configuration is validated on startup
- Efficient caching for high-performance checks

**Check if an IP is whitelisted:**
```ruby
if Beskar::Services::IpWhitelist.whitelisted?(request.ip)
  # IP is trusted - allow but log activity
end

# Clear whitelist cache after config changes
Beskar::Services::IpWhitelist.clear_cache!
```

### Web Application Firewall (WAF)

Beskar's WAF detects and blocks vulnerability scanning attempts across 10 attack categories:

**Attack Categories Detected:**
1. **WordPress Scans** (High Severity) - `/wp-admin`, `/wp-login.php`, `/xmlrpc.php`
2. **PHP Admin Panels** (High Severity) - `/phpmyadmin`, `/admin.php`, `/phpinfo.php`
3. **Config Files** (Critical Severity) - `/.env`, `/.git`, `/database.yml`
4. **Path Traversal** (Critical Severity) - `/../../../etc/passwd`, URL encoded variants
5. **Framework Debug** (Medium Severity) - `/rails/info/routes`, `/__debug__`, `/telescope`
6. **CMS Detection** (Medium Severity) - `/joomla`, `/drupal`, `/magento`
7. **Common Exploits** (Critical Severity) - `/shell.php`, `/c99.php`, `/webshell`
8. **ActionController::UnknownFormat** (Medium Severity) - Detects requests for unusual formats like `/users/1.exe`, `/api/data.bat` that trigger Rails format exceptions, indicating potential scanning
9. **ActionDispatch::RemoteIp::IpSpoofAttackError** (Critical Severity) - Detects IP spoofing attempts when conflicting IP headers are present
10. **ActiveRecord::RecordNotFound** (Low Severity) - Detects potential record enumeration scans like `/admin/users/999999`, with configurable exclusions to prevent false positives

**Configuration Examples:**

```ruby
# Production - Stricter protection (recommended after monitoring)
Beskar.configure do |config|
  config.waf[:enabled] = true
  config.waf[:auto_block] = true
  config.waf[:block_threshold] = 2              # Stricter: 2 violations (default is 3)
  config.waf[:violation_window] = 30.minutes    # Shorter window for faster response
  config.waf[:block_durations] = [6.hours, 24.hours, 7.days, 30.days]  # Longer bans
  config.waf[:permanent_block_after] = 4        # Permanent ban sooner

  # Exclude certain paths from RecordNotFound detection to prevent false positives
  config.waf[:record_not_found_exclusions] = [
    %r{/posts/.*},                # Don't flag missing blog posts as scanning
    %r{/articles/\d+},            # Don't flag missing articles
    %r{/public/.*}                # Ignore public content paths
  ]
end

# Development - Monitor only (recommended initially)
Beskar.configure do |config|
  config.monitor_only = true              # Log but never block
  config.waf[:enabled] = true
  config.waf[:create_security_events] = true

  config.ip_whitelist = ["127.0.0.1", "::1"]  # Whitelist localhost
end
```

**Blocking Behavior:**

With **default settings** (threshold: 3):
- **First violation**: Logged, violation count incremented
- **Threshold reached (3rd violation)**: IP automatically banned for 1 hour
- **Repeat violations**: Ban duration escalates: 1h → 6h → 24h → 7d → **permanent**
- **Permanent block**: After 5 violations (configurable), IP is permanently banned

> **Production Tip:** After monitoring for 24-48 hours, consider using `block_threshold: 2` for more aggressive protection against persistent attackers.
- **Monitor mode**: Logs all violations but never blocks (useful for tuning)
- **Exception-based violations**: Rails exceptions (UnknownFormat, RecordNotFound, IP spoofing) count toward the same threshold
- **Mixed violations**: Regular WAF patterns and exception detections accumulate together

**Check WAF status:**
```ruby
# Check if WAF detected threats
violation_count = Beskar::Services::Waf.get_violation_count(ip_address)

# Reset violations (admin action)
Beskar::Services::Waf.reset_violations(ip_address)

# Analyze a request without blocking
waf_analysis = Beskar::Services::Waf.analyze_request(request)
if waf_analysis
  puts "Detected: #{waf_analysis[:patterns].map { |p| p[:description] }}"
  puts "Severity: #{waf_analysis[:highest_severity]}"
  puts "Risk Score: #{waf_analysis[:risk_score]}"
end
```

### IP Blocking and Banning

Beskar uses a hybrid cache + database blocking system that persists across application restarts.

**Automatic IP Banning Thresholds:**

| Trigger | Threshold | Time Window | Ban Duration | Configurable |
|---------|-----------|-------------|--------------|--------------|
| **Failed Authentication** | 10 attempts | 1 hour | 1 hour (escalating) | Via rate_limiting config |
| **Rate Limit Violations** | 5 violations | 1 hour | 1 hour (escalating) | Via rate_limiting config |
| **WAF Violations** | 3 violations | 1 hour | 1 hour (escalating) | Via waf[:block_threshold] |

> **Note:** All ban durations escalate on repeat offenses: 1h → 6h → 24h → 7d → permanent

**Manual IP Management:**

```ruby
# Ban an IP address
Beskar::BannedIp.ban!(
  "203.0.113.50",
  reason: "manual_block",
  duration: 24.hours,
  details: "Suspicious activity reported by admin",
  metadata: { reporter: "admin@example.com", ticket: "#12345" }
)

# Permanent ban
Beskar::BannedIp.ban!(
  "203.0.113.51",
  reason: "confirmed_attack",
  permanent: true,
  details: "Confirmed malicious actor"
)

# Check if IP is banned
Beskar::BannedIp.banned?("203.0.113.50")  # => true

# Unban an IP
Beskar::BannedIp.unban!("203.0.113.50")

# Extend existing ban
ban = Beskar::BannedIp.find_by(ip_address: "203.0.113.50")
ban.extend_ban!(12.hours)  # Add 12 hours to current expiry
```

**Query banned IPs:**

```ruby
# Get all active bans
Beskar::BannedIp.active

# Get permanent bans
Beskar::BannedIp.permanent

# Get expired bans (not enforced but in database)
Beskar::BannedIp.expired

# Find bans by reason
Beskar::BannedIp.where(reason: 'waf_violation')
Beskar::BannedIp.where(reason: 'authentication_abuse')
Beskar::BannedIp.where(reason: 'rate_limit_abuse')

# Cleanup expired bans from database
removed_count = Beskar::BannedIp.cleanup_expired!
```

**Preload cache on startup:**

The cache is automatically preloaded when your app starts, but you can manually trigger it:

```ruby
# In config/initializers/beskar.rb (optional - happens automatically)
Rails.application.config.after_initialize do
  Beskar::BannedIp.preload_cache!
end
```

### Security Events and Monitoring

**Query WAF violations:**

```ruby
# Recent WAF violations
waf_events = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where('created_at > ?', 24.hours.ago)
  .order(created_at: :desc)

# High-risk WAF events
high_risk = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where('risk_score >= ?', 80)
  .includes(:user)

# Group by IP to find repeat offenders
repeat_offenders = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where('created_at > ?', 7.days.ago)
  .group(:ip_address)
  .having('COUNT(*) >= ?', 5)
  .count

# WAF violations by pattern type
waf_events.each do |event|
  patterns = event.metadata['waf_analysis']['patterns']
  patterns.each do |pattern|
    puts "#{event.ip_address}: #{pattern['category']} - #{pattern['description']}"
  end
end
```

**Scheduled maintenance:**

```ruby
# In a background job (e.g., daily)
class SecurityCleanupJob < ApplicationJob
  def perform
    # Remove expired bans from database
    removed = Beskar::BannedIp.cleanup_expired!
    Rails.logger.info "Cleaned up #{removed} expired IP bans"

    # Archive old security events (optional)
    Beskar::SecurityEvent.where('created_at < ?', 90.days.ago).delete_all

    # Generate security report (example)
    report = {
      active_bans: Beskar::BannedIp.active.count,
      permanent_bans: Beskar::BannedIp.permanent.count,
      waf_violations_today: Beskar::SecurityEvent.where(
        event_type: 'waf_violation',
        created_at: 24.hours.ago..Time.current
      ).count
    }

    # Send to monitoring service
    Rails.logger.info "Security Report: #{report}"
  end
end
```

### Middleware Integration

Beskar automatically injects its middleware (`Beskar::Middleware::RequestAnalyzer`) into the Rails stack to provide comprehensive request-level protection.

**Request Processing Order:**

Every request passes through these security checks in order:

1. **Whitelist Check** - Determine if IP is whitelisted (bypasses blocking but still logs)
2. **Banned IP Check** - Block immediately if IP is banned (403 Forbidden)
3. **Rate Limiting** - Check rate limits (429 Too Many Requests if exceeded)
4. **WAF Analysis** - Scan for vulnerability patterns (403 Forbidden if detected and threshold met)
5. **Request Processing** - Continue to application if all checks pass

**Features:**
- **Early exit** - Banned IPs are blocked immediately for performance
- **Whitelist bypass** - Trusted IPs bypass all blocking but activity is logged
- **Auto-blocking** - See [Automatic IP Banning Thresholds](#ip-blocking-and-banning) section for details
- **Custom error pages** - Returns helpful 403/429 error responses
- **Response headers** - Adds `X-Beskar-Blocked` and `X-Beskar-Rate-Limited` headers
- **Graceful degradation** - Continues working if cache is unavailable

**Middleware Logs:**

The middleware generates structured log messages for monitoring:

```
[Beskar::Middleware] Blocked request from banned IP: 203.0.113.50
[Beskar::Middleware] Rate limit exceeded for IP: 203.0.113.51
[Beskar::Middleware] WAF violation from whitelisted IP 192.168.1.100 (not blocking): WordPress vulnerability scan
[Beskar::Middleware] 🔒 Auto-blocked IP 203.0.113.52 after 3 WAF violations (duration: 1 hours)
[Beskar::Middleware] 🔒 Auto-blocked IP 203.0.113.53 for authentication brute force (15 failures)
```

Security events are logged to the `beskar_security_events` table for analysis and will be visualized in the forthcoming security dashboard.

## WAF Pattern Reference

| Category | Severity | Example Patterns | Risk Score |
|----------|----------|------------------|------------|
| WordPress Scans | High | `/wp-admin`, `/wp-login.php`, `/xmlrpc.php` | 80 |
| PHP Admin Panels | High | `/phpmyadmin`, `/admin.php`, `/phpinfo.php` | 80 |
| Config Files | **Critical** | `/.env`, `/.git`, `/database.yml`, `/config.php` | **95** |
| Path Traversal | **Critical** | `/../../../etc/passwd`, `%2e%2e/` | **95** |
| Framework Debug | Medium | `/rails/info/routes`, `/__debug__`, `/telescope` | 60 |
| CMS Detection | Medium | `/joomla`, `/drupal`, `/magento` | 60 |
| Common Exploits | **Critical** | `/shell.php`, `/c99.php`, `/webshell` | **95** |

**Pattern matching is:**
- Case-insensitive
- Works on full path including query strings
- Detects URL-encoded variants
- Can match multiple patterns per request

## Security Best Practices

### 1. Start with Monitor Mode

When first enabling WAF, use monitor-only mode to tune thresholds:

```ruby
config.monitor_only = true  # Log but don't block
config.waf[:enabled] = true
config.waf[:create_security_events] = true
```

After reviewing logs for false positives, enable blocking:

```ruby
config.monitor_only = false
config.waf[:enabled] = true
config.waf[:auto_block] = true
```

### 2. Whitelist Carefully

Only whitelist truly trusted IPs:

```ruby
# ✅ Good - Documented, legitimate sources
config.ip_whitelist = [
  "203.0.113.0/24",    # Office network - IT approved
  "198.51.100.50"      # VPN gateway - documented in wiki
]

# ❌ Bad - Whitelisting unknown IPs
config.ip_whitelist = ["0.0.0.0/0"]  # Never do this!
```

### 3. Regular Maintenance

Set up a scheduled job to clean up old data:

```ruby
# Schedule daily via cron or Sidekiq
SecurityCleanupJob.perform_later

# Or in initializer for quick cleanup on restart
Rails.application.config.after_initialize do
  Beskar::BannedIp.cleanup_expired! if Rails.env.production?
end
```

### 4. Monitor Security Events

Set up alerts for high-risk events:

```ruby
# Example monitoring
high_risk_count = Beskar::SecurityEvent
  .where('created_at > ?', 1.hour.ago)
  .where('risk_score >= ?', 80)
  .count

alert_service.notify if high_risk_count > 10
```

### 5. Document Whitelist Changes

Keep a record of why each IP is whitelisted:

```ruby
# config/initializers/beskar.rb
config.ip_whitelist = [
  "203.0.113.0/24",    # Office HQ network (added 2024-01-15, ticket #1234)
  "198.51.100.50",     # Partner API server (added 2024-02-01, contract #5678)
  "192.0.2.10"         # Security scanner (added 2024-03-01, vendor: SecurityCo)
]
```

### 6. Test WAF in Staging

Before deploying to production, test WAF rules in staging to catch false positives.

### 7. Review Ban Reasons

Periodically review banned IPs to ensure blocking is working correctly:

```ruby
# Check recent auto-bans
recent_bans = Beskar::BannedIp
  .where('created_at > ?', 7.days.ago)
  .group(:reason)
  .count

# Review specific ban details
waf_bans = Beskar::BannedIp.where(reason: 'waf_violation')
waf_bans.each do |ban|
  puts "#{ban.ip_address}: #{ban.details} (violations: #{ban.violation_count})"
end
```

## Troubleshooting

### Issue: Legitimate users being blocked

**Solution:** Add their IP to whitelist or reduce WAF `block_threshold`:

```ruby
config.waf[:block_threshold] = 5  # Increase from default 3
```

Or whitelist specific IPs:
```ruby
config.ip_whitelist = ["user.ip.address.here"]
```

### Issue: Too many false positives

**Solution:** Enable monitor-only mode and review patterns:

```ruby
config.monitor_only = true  # This is a global setting, not WAF-specific

# Review what's being flagged
Beskar::SecurityEvent.where(event_type: 'waf_violation').last(20).each do |event|
  puts "Path: #{event.metadata['request_path']}"
  puts "Patterns: #{event.metadata['waf_analysis']['patterns']}"
end
```

### Issue: Banned IPs persist after restart

**Solution:** This is intentional (database persistence). To unban:

```ruby
Beskar::BannedIp.unban!("ip.address.here")

# Or unban all expired
Beskar::BannedIp.cleanup_expired!
```

### Issue: Performance concerns

**Solution:** Beskar uses cache-first architecture. Ensure cache is configured:

```ruby
# config/environments/production.rb
config.cache_store = :redis_cache_store, { url: ENV['REDIS_URL'] }
```

Check cache health:
```ruby
Rails.cache.read("test_key")  # Should work
Beskar::BannedIp.preload_cache!  # Reload from database if needed
```

## Migration from Previous Versions

If upgrading from a version without WAF/IP blocking features:

```bash
# Run new migrations
rails db:migrate

# Preload cache with existing bans (if any)
rails runner "Beskar::BannedIp.preload_cache!"

# Test in development first
RAILS_ENV=development rails server

# Review logs for any issues
tail -f log/development.log | grep Beskar
```

## Performance Characteristics

- **Whitelist check**: O(n) where n = whitelist size, cached, < 1ms
- **Banned IP check**: O(1) cache lookup, < 1ms
- **Rate limit check**: O(1) cache lookup, < 1ms
- **WAF analysis**: O(m) where m = number of patterns, < 5ms
- **Total middleware overhead**: Typically < 10ms per request

**Scalability:**
- Handles 1000s of requests/second
- Cache-first architecture minimizes database queries
- Efficient pattern matching with compiled regexes
- Parallel test execution: 352 tests run in < 3 seconds

## Development

After checking out the repo, run `bundle install` to install dependencies. The gem contains a dummy Rails application in `test/dummy` for development and testing.

To run the test suite, use the standard Rails command:

```bash
# From the gem's root directory
$ bin/rails test
```

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/prograis/beskar](https://github.com/prograils/beskar).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Just be nice to each other.
