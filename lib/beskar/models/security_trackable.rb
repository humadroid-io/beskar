module Beskar
  module Models
    module SecurityTrackable
      extend ActiveSupport::Concern

      included do
        has_many :security_events, class_name: "Beskar::SecurityEvent", as: :user, dependent: :destroy

        # Hook into Devise callbacks if Devise is present and available
        if defined?(Devise) && respond_to?(:after_database_authentication)
          # Track successful authentications
          after_database_authentication :track_successful_login
        end
      end

      module ClassMethods
        def track_failed_authentication(request, scope)
          # Skip tracking if disabled in configuration
          unless Beskar.configuration.track_failed_logins?
            Rails.logger.debug "[Beskar] Failed login tracking disabled in configuration"
            return
          end

          # Create a security event for failed authentication
          # We don't have a specific user, so we'll track by IP/session
          metadata = {
            scope: scope.to_s,
            attempted_email: request.params.dig("devise_user", "email") || request.params.dig(scope, "email"),
            timestamp: Time.current.iso8601,
            session_id: request.session.id,
            request_path: request.path,
            referer: request.referer,
            accept_language: request.headers["Accept-Language"],
            x_forwarded_for: request.headers["X-Forwarded-For"],
            x_real_ip: request.headers["X-Real-IP"],
            device_info: Beskar::Services::DeviceDetector.detect(request.user_agent),
            geolocation: Beskar::Services::GeolocationService.locate(request.ip)
          }

          attempted_email = request.params.dig("devise_user", "email") || request.params.dig(scope, "email")

          Beskar::SecurityEvent.create!(
            user: nil,
            event_type: "login_failure",
            ip_address: request.ip,
            user_agent: request.user_agent,
            attempted_email: attempted_email,
            metadata: metadata,
            risk_score: calculate_failure_risk_score(request)
          )

          # Trigger rate limiting check
          Beskar::Services::RateLimiter.check_authentication_attempt(request, :failure)
        end

        private

        def calculate_failure_risk_score(request)
          score = 10 # Base score for failed login

          # Use device detector for more comprehensive risk assessment
          device_detector = Beskar::Services::DeviceDetector.new
          score += device_detector.calculate_user_agent_risk(request.user_agent)

          # Additional failure-specific risk factors
          if request.params.dig("user", "password")&.length.to_i > 50
            score += 10
            Rails.logger.info "Suspicious password length: #{request.params.dig("user", "password")&.length}, adding 10 risk"
          end

          # Use geolocation service for location-based risk
          geolocation_service = Beskar::Services::GeolocationService.new
          geo_score = geolocation_service.calculate_location_risk(request.ip)
          score += geo_score
          Rails.logger.info "Geolocation risk: #{geo_score}, adding #{geo_score} risk"

          [ score, 100 ].min # Cap at 100
        end
      end

      def track_successful_login
        # Skip tracking if disabled in configuration
        unless Beskar.configuration.track_successful_logins?
          Rails.logger.debug "[Beskar] Successful login tracking disabled in configuration"
          return
        end

        if current_request = request_from_context
          track_authentication_event(current_request, :success)
        end
      rescue => e
        Rails.logger.warn "[Beskar] Failed to track successful login: #{e.message}"
        nil
      end

      def track_authentication_event(request, result)
        return unless request

        # Check if tracking is enabled for this event type
        if result == :success && !Beskar.configuration.track_successful_logins?
          Rails.logger.debug "[Beskar] Successful login tracking disabled in configuration"
          return
        elsif result == :failure && !Beskar.configuration.track_failed_logins?
          Rails.logger.debug "[Beskar] Failed login tracking disabled in configuration"
          return
        end

        event_type = result == :success ? "login_success" : "login_failure"

        security_event = security_events.build(
          event_type: event_type,
          ip_address: request.ip,
          user_agent: request.user_agent,
          attempted_email: self.email,
          metadata: extract_security_context(request),
          risk_score: calculate_risk_score(request, result)
        )

        if security_event.save
          # Perform background security analysis
          analyze_suspicious_patterns_async if result == :success && Beskar.configuration.auto_analyze_patterns?

          # Update rate limiting
          Beskar::Services::RateLimiter.check_authentication_attempt(request, result, self)

          # Check risk-based locking after successful authentication
          # This prevents compromised accounts from being used even after successful login
          if result == :success
            check_and_lock_if_high_risk(security_event, request)
          end
        end

        security_event
      end

      def analyze_suspicious_patterns_async
        # Skip analysis if disabled in configuration
        unless Beskar.configuration.auto_analyze_patterns?
          Rails.logger.debug "[Beskar] Auto pattern analysis disabled in configuration"
          return
        end

        # Queue background job for detailed analysis
        Beskar::SecurityAnalysisJob.perform_later(self.id, "login_success") if defined?(Beskar::SecurityAnalysisJob)
      rescue => e
        Rails.logger.warn "[Beskar] Failed to queue security analysis: #{e.message}"
      end

      def recent_failed_attempts(within: 1.hour)
        security_events.where(
          event_type: "login_failure",
          created_at: within.ago..Time.current
        )
      end

      def recent_successful_logins(within: 24.hours)
        security_events.where(
          event_type: "login_success",
          created_at: within.ago..Time.current
        )
      end

      def suspicious_login_pattern?
        # Check for rapid successive attempts
        recent_attempts = recent_failed_attempts(within: 5.minutes)
        return true if recent_attempts.count >= 3

        # Check for geographic anomalies
        recent_logins = recent_successful_logins(within: 4.hours).includes(:security_events)
        return true if geographic_anomaly_detected?(recent_logins)

        false
      end

      # PUBLIC method called from Warden callback in engine.rb
      # Checks if account was just locked due to high risk and signs out if needed
      def check_high_risk_lock_and_signout(auth)
        return unless Beskar.configuration.risk_based_locking_enabled?

        # Check if there's a very recent lock event (within last 5 seconds)
        recent_lock = security_events
          .where(event_type: [ "account_locked", "lock_attempted" ])
          .where("created_at >= ?", 5.seconds.ago)
          .exists?

        if recent_lock
          Rails.logger.warn "[Beskar] High-risk lock detected, signing out user #{id}"
          auth.logout
          throw :warden, message: :account_locked_due_to_high_risk
        end
      end

      private

      def request_from_context
        # Try to get request from various contexts
        if defined?(Current) && Current.respond_to?(:request)
          Current.request
        elsif Thread.current[:request]
          Thread.current[:request]
        elsif defined?(ActionController::Base) && ActionController::Base.respond_to?(:current_request)
          ActionController::Base.current_request
        elsif defined?(Warden) && Warden::Manager.respond_to?(:current_request)
          Warden::Manager.current_request
        end
      rescue => e
        Rails.logger.debug "[Beskar] Could not get request from context: #{e.message}"
        nil
      end

      def extract_security_context(request)
        {
          timestamp: Time.current.iso8601,
          session_id: request.session.id,
          request_path: request.path,
          referer: request.referer,
          accept_language: request.headers["Accept-Language"],
          x_forwarded_for: request.headers["X-Forwarded-For"],
          x_real_ip: request.headers["X-Real-IP"],
          device_info: Beskar::Services::DeviceDetector.detect(request.user_agent),
          geolocation: Beskar::Services::GeolocationService.locate(request.ip)
        }
      end



      def calculate_risk_score(request, result)
        base_score = result == :success ? 1 : 25
        score = base_score

        # Use dedicated services for risk assessment
        device_detector = Beskar::Services::DeviceDetector.new
        score += device_detector.calculate_user_agent_risk(request.user_agent)

        # Mobile device login during late hours
        if device_detector.mobile?(request.user_agent) && Time.current.hour.between?(22, 6)
          score += 5
          Rails.logger.info "Mobile device login during late hours: #{request.user_agent}, adding 5 risk"
        end

        # Account-specific risk factors
        if recent_failed_attempts(within: 10.minutes).count >= 2
          score += 20
          Rails.logger.info "Recent failed attempts: #{recent_failed_attempts(within: 10.minutes).count}, adding 20 risk"
        end

        # ADAPTIVE LEARNING: Check if this is an established pattern
        # If user has successfully logged in from this context before (especially after unlock),
        # reduce the risk score significantly
        if result == :success && established_pattern?(request)
          Rails.logger.info "[Beskar] Established pattern detected, reducing risk score"
          score = [ score * 0.3, 25 ].min.to_i # Reduce to 30% of original, cap at 25
        end

        # Geographic risk assessment
        geolocation_service = Beskar::Services::GeolocationService.new
        recent_locations = recent_successful_logins(within: 4.hours).map do |event|
          event.metadata&.dig("geolocation")
        end.compact

        # Don't apply geographic risk if this location is established
        unless location_established?(request.ip)
          score += geolocation_service.calculate_location_risk(
            request.ip,
            recent_locations,
            recent_successful_logins(within: 4.hours).last&.created_at&.to_i
          )
        end

        [ score, 100 ].min # Cap at 100
      end

      def geographic_anomaly_detected?(recent_logins)
        # Placeholder for geographic anomaly detection
        # Would implement haversine formula and impossible travel detection
        false
      end

      # Check if the account should be locked based on risk score
      # This is called after successful authentication to prevent use of compromised accounts
      def check_and_lock_if_high_risk(security_event, request)
        return unless Beskar.configuration.risk_based_locking_enabled?
        return unless security_event.risk_score

        locker = Beskar::Services::AccountLocker.new(
          self,
          risk_score: security_event.risk_score,
          reason: determine_lock_reason(security_event),
          metadata: {
            ip_address: request.ip,
            user_agent: request.user_agent,
            security_event_id: security_event.id,
            geolocation: security_event.geolocation,
            device_info: security_event.device_info
          }
        )

        if locker.lock_if_necessary!
          Rails.logger.warn "[Beskar] Account locked due to high risk score: #{security_event.risk_score} (threshold: #{Beskar.configuration.risk_threshold})"

          # Sign out the user immediately if using Warden/Devise
          sign_out_after_lock if defined?(Warden)
        end
      end

      # Determine the specific reason for locking
      def determine_lock_reason(security_event)
        metadata = security_event.metadata || {}

        # Check for impossible travel
        if metadata.dig("geolocation", "impossible_travel")
          return :impossible_travel
        end

        # Check for suspicious device
        device_info = metadata["device_info"] || {}
        if device_info["bot_signature"] || device_info["suspicious"]
          return :suspicious_device
        end

        # Check for geographic anomaly
        geolocation = metadata["geolocation"] || {}
        if geolocation["country_change"] || geolocation["high_risk_country"]
          return :geographic_anomaly
        end

        # Default to high risk authentication
        :high_risk_authentication
      end

      # Sign out user after lock (for immediate protection)
      # This method doesn't actually sign out - that's handled by Warden callback in engine.rb
      # It just flags that a lock occurred by creating the lock event
      # The Warden callback detects the recent lock event and performs the actual sign-out
      def sign_out_after_lock
        Rails.logger.debug "[Beskar] Account locked - Warden callback will handle sign-out"
      end

      # ADAPTIVE LEARNING: Check if this login pattern is established
      # A pattern is "established" if the user has successfully logged in
      # from similar context multiple times, especially after being unlocked
      def established_pattern?(request)
        return false unless security_events.any?

        current_ip = request.ip
        # Future enhancement: could also match on user_agent for stricter pattern matching

        # Look for successful logins from this IP
        # in the past 30 days (configurable timeframe for learning)
        historical_logins = security_events
          .where(event_type: "login_success")
          .where(ip_address: current_ip)
          .where("created_at >= ?", 30.days.ago)
          .where("created_at < ?", 5.minutes.ago) # Exclude current login

        # Need at least 2 successful logins from this context
        return false if historical_logins.count < 2

        # Check if there was an unlock event followed by successful logins
        # from this same context - this indicates user legitimized this pattern
        recent_unlock_or_lock = security_events
          .where(event_type: [ "account_locked", "account_unlocked", "lock_attempted" ])
          .where("created_at >= ?", 7.days.ago)
          .order(created_at: :desc)
          .first

        if recent_unlock_or_lock
          # Check for successful logins after unlock/lock from same IP
          logins_after_unlock = security_events
            .where(event_type: "login_success")
            .where(ip_address: current_ip)
            .where("created_at > ?", recent_unlock_or_lock.created_at)
            .count

          # If user unlocked and successfully logged in from same IP/context,
          # that's a strong signal this is legitimate
          return true if logins_after_unlock >= 1
        end

        # Pattern is established if there are 3+ successful logins
        # from this context over time
        historical_logins.count >= 3
      end

      # Check if a location (IP) is established/trusted
      # A location is established if user has successfully logged in from it
      # multiple times over a period of time
      def location_established?(ip_address)
        return false unless security_events.any?

        successful_logins_from_ip = security_events
          .where(event_type: "login_success")
          .where(ip_address: ip_address)
          .where("created_at >= ?", 30.days.ago)
          .where("created_at < ?", 5.minutes.ago) # Exclude current login
          .count

        # Location is established if there are 2+ successful logins
        # This is more lenient than full pattern matching
        successful_logins_from_ip >= 2
      end
    end
  end
end
