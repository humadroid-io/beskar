module Beskar
  class BannedIp < ApplicationRecord
    # Serialize metadata as JSON
    serialize :metadata, coder: JSON

    validates :ip_address, presence: true, uniqueness: true
    validates :reason, presence: true
    validates :banned_at, presence: true

    # Ensure metadata is always a hash
    after_initialize do
      self.metadata ||= {}
    end

    # Cache management callbacks
    after_save :update_cache
    after_destroy :clear_cache

    scope :active, -> { where("expires_at IS NULL OR expires_at > ?", Time.current) }
    scope :permanent, -> { where(permanent: true) }
    scope :temporary, -> { where(permanent: false) }
    scope :expired, -> { where("expires_at IS NOT NULL AND expires_at <= ?", Time.current) }
    scope :by_reason, ->(reason) { where(reason: reason) }

    # Check if a ban is currently active
    def active?
      permanent? || (expires_at.present? && expires_at > Time.current)
    end

    # Check if ban has expired
    def expired?
      !permanent? && expires_at.present? && expires_at <= Time.current
    end

    # Extend ban duration (for repeat offenders)
    def extend_ban!(additional_time = nil)
      self.violation_count += 1

      if permanent?
        # Already permanent, just increment violation count
      elsif additional_time
        self.expires_at = [expires_at || Time.current, Time.current].max + additional_time
      else
        # Calculate exponential backoff based on violation count
        # 1 hour, 6 hours, 24 hours, 7 days, permanent
        duration = case violation_count
        when 1 then 1.hour
        when 2 then 6.hours
        when 3 then 24.hours
        when 4 then 7.days
        else
          self.permanent = true
          nil
        end

        if duration
          self.expires_at = Time.current + duration
        end
      end
      save!
    end

    # Unban an IP address
    def unban!
      destroy
    end

    # Class methods for ban management
    class << self
      # Ban an IP address
      def ban!(ip_address, reason:, duration: nil, permanent: false, details: nil, metadata: {})
        # Retry logic to handle race conditions when multiple requests try to ban the same IP
        retries = 0
        max_retries = 2

        begin
          banned_ip = find_or_initialize_by(ip_address: ip_address)

          if banned_ip.persisted?
            # Existing ban - extend it
            banned_ip.extend_ban!(duration)
            banned_ip.details = details if details
            # Deep stringify keys to avoid duplicate key issues
            if metadata.any?
              banned_ip.metadata = banned_ip.metadata.deep_stringify_keys.merge(metadata.deep_stringify_keys)
            end
          else
            # New ban
            banned_ip.assign_attributes(
              reason: reason,
              banned_at: Time.current,
              expires_at: permanent ? nil : (Time.current + (duration || 1.hour)),
              permanent: permanent,
              details: details,
              metadata: metadata
            )
          end
          banned_ip.save!

          # Update cache
          cache_key = "beskar:banned_ip:#{ip_address}"
          Rails.cache.write(cache_key, true, expires_in: permanent ? nil : (duration || 1.hour))

          banned_ip
        rescue ActiveRecord::RecordInvalid => e
          # Race condition: another request created the record between find and save
          if e.message.include?("Ip address has already been taken") && retries < max_retries
            retries += 1
            # Small random delay to reduce contention (1-10ms)
            sleep(rand(1..10) / 1000.0)
            retry
          else
            # Re-raise if it's a different validation error or we've exceeded retries
            raise
          end
        end
      end

      # Check if an IP is banned (cache-first approach)
      def banned?(ip_address)
        # Check cache first for performance
        cache_key = "beskar:banned_ip:#{ip_address}"
        cached_result = Rails.cache.read(cache_key)
        return true if cached_result == true
        return false if cached_result == false

        # Check database
        banned_record = active.find_by(ip_address: ip_address)
        is_banned = banned_record&.active? || false

        # Update cache
        if is_banned && banned_record
          ttl = banned_record.permanent? ? 30.days : (banned_record.expires_at - Time.current).to_i
          Rails.cache.write(cache_key, true, expires_in: ttl)
        else
          Rails.cache.write(cache_key, false, expires_in: 5.minutes)
        end

        is_banned
      end

      # Unban an IP address
      def unban!(ip_address)
        banned_ip = find_by(ip_address: ip_address)
        if banned_ip
          banned_ip.destroy
          # Clear cache
          Rails.cache.delete("beskar:banned_ip:#{ip_address}")
          true
        else
          false
        end
      end

      # Load all active bans into cache (called on app startup)
      def preload_cache!
        active.find_each do |banned_ip|
          cache_key = "beskar:banned_ip:#{banned_ip.ip_address}"
          ttl = banned_ip.permanent? ? 30.days : [(banned_ip.expires_at - Time.current).to_i, 60].max
          Rails.cache.write(cache_key, true, expires_in: ttl)
        end
      end

      # Clean up expired bans
      def cleanup_expired!
        expired.destroy_all
      end
    end

    private

    def update_cache
      return unless active?

      cache_key = "beskar:banned_ip:#{ip_address}"
      ttl = calculate_cache_ttl
      Rails.cache.write(cache_key, true, expires_in: ttl)
    end

    def clear_cache
      Rails.cache.delete("beskar:banned_ip:#{ip_address}")
    end

    def calculate_cache_ttl
      return nil if permanent? || expires_at.nil?

      (expires_at - Time.current).to_i
    end
  end
end
