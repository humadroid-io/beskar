module Beskar
  class Configuration
    attr_accessor :enable_waf, :waf_ruleset, :rate_limiting, :security_tracking, :risk_based_locking, :geolocation, :ip_whitelist, :waf, :authentication_models

    def initialize
      @enable_waf = false # Default to off (deprecated, use @waf[:enabled] instead)
      @waf_ruleset = :default
      @ip_whitelist = [] # Array of IP addresses or CIDR ranges
      
      # Authentication models configuration
      # Auto-detect by default, or can be explicitly configured
      @authentication_models = {
        devise: [], # Will be auto-detected: [:devise_user, :admin, etc.]
        rails_auth: [], # Will be auto-detected: [:user, etc.]
        auto_detect: true # Set to false to use only explicitly configured models
      }
      
      @waf = {
        enabled: false,                  # Master switch for WAF
        auto_block: true,                # Automatically block IPs after threshold
        block_threshold: 3,              # Number of violations before blocking
        violation_window: 1.hour,        # Time window to count violations
        block_durations: [1.hour, 6.hours, 24.hours, 7.days], # Escalating block durations
        permanent_block_after: 5,        # Permanent block after N violations (nil = never)
        create_security_events: true,    # Create SecurityEvent records
        monitor_only: false              # If true, log but don't block (even if auto_block is true)
      }
      @security_tracking = {
        enabled: true,
        track_successful_logins: true,
        track_failed_logins: true,
        auto_analyze_patterns: true
      }
      @rate_limiting = {
        ip_attempts: {
          limit: 10,
          period: 1.hour,
          exponential_backoff: true
        },
        account_attempts: {
          limit: 5,
          period: 15.minutes,
          exponential_backoff: true
        },
        global_attempts: {
          limit: 100,
          period: 1.minute,
          exponential_backoff: false
        }
      }
      @risk_based_locking = {
        enabled: false,                    # Master switch for risk-based locking
        risk_threshold: 75,                # Lock account if risk score >= this value
        lock_strategy: :devise_lockable,   # Strategy: :devise_lockable, :custom, :none
        auto_unlock_time: 1.hour,          # Time until automatic unlock (if supported by strategy)
        notify_user: true,                 # Send notification on lock
        log_lock_events: true,             # Create security event for locks
        immediate_signout: false           # Sign out user immediately via Warden callback (requires :lockable)
      }
      @geolocation = {
        provider: :mock,                   # Provider: :maxmind, :mock
        maxmind_city_db_path: nil,         # Path to MaxMind GeoLite2-City.mmdb or GeoIP2-City.mmdb
        cache_ttl: 4.hours                 # How long to cache geolocation results
      }
    end

    def security_tracking_enabled?
      @security_tracking[:enabled]
    end

    def track_successful_logins?
      security_tracking_enabled? && @security_tracking[:track_successful_logins]
    end

    def track_failed_logins?
      security_tracking_enabled? && @security_tracking[:track_failed_logins]
    end

    def auto_analyze_patterns?
      security_tracking_enabled? && @security_tracking[:auto_analyze_patterns]
    end

    # Risk-based locking configuration helpers
    def risk_based_locking_enabled?
      @risk_based_locking[:enabled]
    end

    def risk_threshold
      @risk_based_locking[:risk_threshold] || 75
    end

    def lock_strategy
      @risk_based_locking[:lock_strategy] || :devise_lockable
    end

    def auto_unlock_time
      @risk_based_locking[:auto_unlock_time] || 1.hour
    end

    def notify_user_on_lock?
      @risk_based_locking[:notify_user] != false
    end

    def log_lock_events?
      @risk_based_locking[:log_lock_events] != false
    end

    def immediate_signout?
      @risk_based_locking[:immediate_signout] == true
    end

    # Geolocation configuration helpers
    def geolocation_provider
      @geolocation[:provider] || :mock
    end

    def maxmind_city_db_path
      @geolocation[:maxmind_city_db_path]
    end

    def geolocation_cache_ttl
      @geolocation[:cache_ttl] || 4.hours
    end

    # WAF configuration helpers
    def waf_enabled?
      # Support both old enable_waf and new waf[:enabled]
      @enable_waf || (@waf && @waf[:enabled])
    end

    def waf_auto_block?
      waf_enabled? && @waf[:auto_block] && !@waf[:monitor_only]
    end

    def waf_monitor_only?
      @waf[:monitor_only] == true
    end

    # IP Whitelist configuration helpers
    def ip_whitelist_enabled?
      @ip_whitelist.is_a?(Array) && @ip_whitelist.any?
    end

    # Authentication models helpers
    def devise_scopes
      return @authentication_models[:devise] unless @authentication_models[:auto_detect]
      
      # Auto-detect Devise models
      detected = []
      if defined?(Devise)
        Devise.mappings.keys.each do |scope|
          detected << scope
        end
      end
      
      # Merge with explicitly configured models
      (detected + Array(@authentication_models[:devise])).uniq
    end

    def rails_auth_scopes
      return @authentication_models[:rails_auth] unless @authentication_models[:auto_detect]
      
      # Auto-detect Rails authentication models (has_secure_password)
      detected = []
      if defined?(ActiveRecord::Base)
        # Try to find models with has_secure_password
        # This is a heuristic - models that have password_digest column
        ActiveRecord::Base.descendants.each do |model|
          next unless model.table_exists?
          if model.column_names.include?('password_digest')
            scope = model.name.underscore.to_sym
            detected << scope unless devise_scopes.include?(scope)
          end
        rescue => e
          # Ignore errors during detection
          Rails.logger.debug "[Beskar] Error detecting Rails auth model #{model.name}: #{e.message}"
        end
      end
      
      # Merge with explicitly configured models
      (detected + Array(@authentication_models[:rails_auth])).uniq
    end

    def all_auth_scopes
      (devise_scopes + rails_auth_scopes).uniq
    end

    def model_class_for_scope(scope)
      scope.to_s.camelize.constantize
    rescue NameError
      nil
    end
  end
end
