module Beskar
  module Models
    # Devise-specific security tracking functionality
    # This module hooks into Devise/Warden callbacks and provides
    # Devise-specific authentication tracking and account locking
    module SecurityTrackableDevise
      extend ActiveSupport::Concern

      included do
        # Include the generic functionality first
        include Beskar::Models::SecurityTrackableGeneric

        # Hook into Devise callbacks if Devise is present and available
        if defined?(Devise) && respond_to?(:after_database_authentication)
          # Track successful authentications
          after_database_authentication :track_successful_login
        end
      end

      # Track successful login via Devise callback
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

      # PUBLIC method called from Warden callback in engine.rb
      # Checks if account was just locked due to high risk and signs out if needed
      def check_high_risk_lock_and_signout(auth)
        return unless Beskar.configuration.risk_based_locking_enabled?

        # Check if there's a very recent lock event (within last 5 seconds)
        recent_lock = security_events
          .where(event_type: ["account_locked", "lock_attempted"])
          .where("created_at >= ?", 5.seconds.ago)
          .exists?

        if recent_lock
          Rails.logger.warn "[Beskar] High-risk lock detected, signing out user #{id}"
          auth.logout
          throw :warden, message: :account_locked_due_to_high_risk
        end
      end

      private

      # Devise-specific: Try to get request from various Warden/Devise contexts
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

      # Devise-specific: Handle high risk lock by creating lock event
      # The actual sign-out is handled by Warden callback in engine.rb
      def handle_high_risk_lock(security_event, request)
        Rails.logger.debug "[Beskar] Devise account locked - Warden callback will handle sign-out"
        # The lock event is already created by AccountLocker service
        # The Warden callback will detect it and perform the actual sign-out
      end
    end
  end
end
