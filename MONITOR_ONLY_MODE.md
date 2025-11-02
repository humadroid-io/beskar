# WAF Monitor-Only Mode

## Overview

Monitor-only mode is a global setting that allows Beskar to detect, log, and create ban records for all security violations **without actually blocking any requests**. This applies to WAF, rate limiting, and IP bans. This is ideal for:

- **Testing Beskar in production** without risking false positives blocking legitimate users
- **Analyzing attack patterns** and seeing which IPs would be banned
- **Gathering real data** with actual ban records created (but not enforced)
- **Verifying the library works** by seeing ban records and security events
- **Gradual rollout** of security protection

## Configuration

```ruby
# config/initializers/beskar.rb
Beskar.configure do |config|
  # Global monitor-only mode (affects ALL blocking features)
  config.monitor_only = true    # ⚠️ Creates bans/events but DOESN'T block requests

  config.waf[:enabled] = true              # Enable WAF detection
  config.waf[:auto_block] = true           # Creates ban records (enforced when monitor_only is false)
  config.waf[:block_threshold] = 3         # Threshold for creating bans
  config.waf[:violation_window] = 1.hour
  config.waf[:create_security_events] = true
end
```

## What Happens in Monitor-Only Mode

### 1. Ban Records ARE Created
Even in monitor-only mode, `Beskar::BannedIp` records are created in the database. This allows you to:
- See exactly which IPs would be banned
- Verify the system is working correctly
- Query banned IPs without actually blocking them
- Test your thresholds with real data

### 2. Security Events ARE Created
All `Beskar::SecurityEvent` records are created normally, with metadata indicating monitor-only mode.

### 3. Requests ARE NOT Blocked
Despite having ban records, requests continue to be processed normally.

## What Gets Logged

### 1. Every Violation (with Mode Indicator)

```
[Beskar::WAF] 🚨 Vulnerability scan detected [MONITOR-ONLY MODE] 
(3 violations) - IP: 203.0.113.50, Severity: critical, 
Patterns: Configuration file access attempt, Path: /.env
```

The `[MONITOR-ONLY MODE]` tag appears on every violation log so you can easily identify them.

### 2. Explicit "Would Block" Messages

When violation count reaches the threshold, you'll see:

```
[Beskar::WAF] 🔍 MONITOR-ONLY: IP 203.0.113.50 WOULD BE BLOCKED 
(threshold reached: 3/3 violations) - Duration would be: 1.0 hours, 
Severity: critical, Patterns: Configuration file access attempt. 
To enable blocking, set config.monitor_only = false
```

### 3. Middleware-Level Logging

The middleware also explicitly logs when it would have blocked:

```
[Beskar::Middleware] 🔍 MONITOR-ONLY: Would block IP 203.0.113.50 
after 3 WAF violations, but monitor_only=true. Request proceeding normally.
```

## Security Event Metadata

All WAF violations in monitor-only mode include rich metadata for analysis:

```ruby
event = Beskar::SecurityEvent.where(event_type: 'waf_violation').last

event.metadata
# => {
#   "monitor_only_mode" => true,
#   "would_be_blocked" => true,          # Would this have been blocked?
#   "violation_count" => 3,
#   "block_threshold" => 3,
#   "severity" => "critical",
#   "patterns_matched" => ["Configuration file access attempt"],
#   "waf_analysis" => { ... }
# }
```

## Analyzing Monitor-Only Data

### Query IPs that would have been blocked:

```ruby
# Find all IPs that have been banned (but not enforced due to monitor-only)
banned_ips = Beskar::BannedIp.active.where(reason: 'waf_violation')

puts "IPs that are banned (not enforced in monitor-only): #{banned_ips.count}"
banned_ips.each do |ban|
  puts "  #{ban.ip_address}: #{ban.violation_count} violations, expires: #{ban.expires_at || 'permanent'}"
end

# You can also check security events
would_be_blocked = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where("metadata->>'monitor_only_mode' = ?", 'true')
  .where("metadata->>'would_be_blocked' = ?", 'true')
  .group(:ip_address)
  .count
```

### Analyze attack patterns:

```ruby
# Most common attack patterns detected
patterns = Beskar::SecurityEvent
  .where(event_type: 'waf_violation')
  .where("created_at > ?", 24.hours.ago)
  .pluck(:metadata)
  .flat_map { |m| m['patterns_matched'] }
  .tally
  .sort_by { |_, count| -count }

patterns.each do |pattern, count|
  puts "#{pattern}: #{count} attempts"
end
# => Configuration file access attempt: 45
#    WordPress vulnerability scan: 23
#    Path traversal attempt: 12
```

### Calculate blocking impact:

```ruby
# How many IPs are currently banned (but not enforced)?
active_bans = Beskar::BannedIp.active
puts "#{active_bans.count} IPs are currently banned"

# See ban details
active_bans.each do |ban|
  puts "IP: #{ban.ip_address}"
  puts "  Reason: #{ban.reason}"
  puts "  Violations: #{ban.violation_count}"
  puts "  Expires: #{ban.expires_at || 'PERMANENT'}"
end

# How many total requests would have been denied?
total_requests = Beskar::SecurityEvent
  .where(event_type: 'waf_violation', ip_address: blocked_ips)
  .where("created_at > ?", 24.hours.ago)
  .count

puts "#{total_requests} requests would have been blocked in the last 24h"
```

## Transitioning to Active Blocking

### Step 1: Monitor for 24-48 hours

```ruby
# Enable monitor-only mode (global setting)
config.monitor_only = true
```

### Step 2: Review the logs

Look for:
- False positives (legitimate traffic being flagged)
- Attack volume and patterns
- Actual ban records created (query `Beskar::BannedIp.all`)
- Security events with full metadata

### Step 3: Whitelist any false positives

```ruby
config.ip_whitelist = [
  "192.168.1.0/24",  # Office network
  "203.0.113.42"     # Partner API server
]
```

### Step 4: Enable blocking

```ruby
# Turn off monitor-only mode (bans will now be enforced)
config.monitor_only = false
```

### Step 5: Continue monitoring

Watch for actual blocks:

```
[Beskar::WAF] 🔒 Auto-blocked IP 203.0.113.50 after 3 violations (duration: 1 hours)
[Beskar::Middleware] 🔒 Blocking IP 203.0.113.50 after 3 WAF violations
```

## Log Filtering

### View only monitor-only violations:

```bash
# Production logs
tail -f log/production.log | grep "MONITOR-ONLY"
```

### View all WAF activity:

```bash
tail -f log/production.log | grep "Beskar::WAF"
```

### View would-be blocks:

```bash
tail -f log/production.log | grep "WOULD BE BLOCKED"
```

## Best Practices

1. **Start with monitor-only** - Always enable monitor_only=true for at least 24 hours in production
2. **Review before blocking** - Analyze the data before turning on auto-blocking
3. **Set appropriate thresholds** - Adjust `block_threshold` based on your monitor-only data
4. **Whitelist proactively** - Add known-good IPs to the whitelist before enabling blocking
5. **Monitor actively** - Set up alerts for "WOULD BE BLOCKED" messages to understand impact
6. **Keep security events** - Don't delete old WAF events; they're valuable for trend analysis

## Example Workflow

```ruby
# Week 1: Monitor only
Beskar.configure do |config|
  config.monitor_only = true  # Global monitor-only mode

  config.waf[:enabled] = true
  config.waf[:block_threshold] = 3
end

# After reviewing logs and confirming no false positives...

# Week 2: Enable blocking with higher threshold
Beskar.configure do |config|
  config.monitor_only = false  # ✅ Now actually blocking (enforcing bans)

  config.waf[:enabled] = true
  config.waf[:block_threshold] = 5   # Start conservative
  config.waf[:auto_block] = true
end

# Week 3: Tune threshold based on real blocking data
Beskar.configure do |config|
  config.monitor_only = false  # Keep blocking enabled

  config.waf[:enabled] = true
  config.waf[:block_threshold] = 3   # Tighten security
  config.waf[:auto_block] = true
end
```

## Troubleshooting

### Not seeing "MONITOR-ONLY" in logs?

Check your configuration:
```ruby
Beskar.configuration.monitor_only?  # => should return true
```

### Not seeing ban records?

Check if bans are being created:
```ruby
Beskar::BannedIp.where(ip_address: "203.0.113.50").first
# Should show the ban record even in monitor-only mode
```

Ensure you're exceeding the threshold:
```ruby
Beskar::Services::Waf.get_violation_count("203.0.113.50")  # => should be >= threshold
```

### Security events not being created?

Check:
```ruby
Beskar.configuration.waf[:create_security_events]  # => should be true
```
