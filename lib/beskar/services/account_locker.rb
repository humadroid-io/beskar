# frozen_string_literal: true

module Beskar
  module Services
    # Service for locking user accounts based on risk scores
    #
    # This service provides a modular approach to account locking that can work
    # with Devise's lockable module or custom locking implementations. It keeps
    # Devise-specific code isolated for maintainability.
    #
    # @example Basic usage with Devise lockable
    #   locker = Beskar::Services::AccountLocker.new(user, risk_score: 85, reason: :high_risk_login)
    #   locker.lock_if_necessary!
    #
    # @example Check if account should be locked
    #   if locker.should_lock?
    #     locker.lock!
    #   end
    #
    class AccountLocker
      attr_reader :user, :risk_score, :reason, :metadata

      # Initialize the account locker
      #
      # @param user [ActiveRecord::Base] The user to potentially lock
      # @param risk_score [Integer] The calculated risk score (0-100)
      # @param reason [Symbol] The reason for potential lock (:high_risk_login, :impossible_travel, etc.)
      # @param metadata [Hash] Additional context for the lock decision
      def initialize(user, risk_score:, reason: :high_risk_authentication, metadata: {})
        @user = user
        @risk_score = risk_score
        @reason = reason
        @metadata = metadata
      end

      # Check if account should be locked based on configuration
      #
      # @return [Boolean] true if account should be locked
      def should_lock?
        return false unless Beskar.configuration.risk_based_locking_enabled?
        return false unless user
        return false if user_already_locked?

        risk_score >= Beskar.configuration.risk_threshold
      end

      # Lock the account if necessary (based on should_lock? check)
      #
      # @return [Boolean] true if account was locked, false otherwise
      def lock_if_necessary!
        return false unless should_lock?
        lock!
      end

      # Lock the account using the configured strategy
      #
      # @return [Boolean] true if lock was successful, false otherwise
      def lock!
        return false unless user

        strategy = Beskar.configuration.lock_strategy

        result = case strategy
        when :devise_lockable
          lock_with_devise_lockable
        when :custom
          lock_with_custom_strategy
        else
          Beskar::Logger.warn("Unknown lock strategy: #{strategy}", component: :AccountLocker)
          false
        end

        # Always log lock events when risk-based locking is enabled
        # This creates an audit trail even if actual locking fails
        if Beskar.configuration.log_lock_events?
          log_lock_event(result)
        end

        if result
          notify_user if Beskar.configuration.notify_user_on_lock?
        end

        result
      end

      # Unlock the account using the configured strategy
      #
      # @return [Boolean] true if unlock was successful
      def unlock!
        return false unless user

        strategy = Beskar.configuration.lock_strategy

        result = case strategy
        when :devise_lockable
          unlock_with_devise_lockable
        when :custom
          unlock_with_custom_strategy
        else
          false
        end

        # Log unlock event for adaptive learning
        if result && Beskar.configuration.log_lock_events?
          log_unlock_event
        end

        result
      end

      # Check if user is currently locked
      #
      # @return [Boolean] true if user is locked
      def locked?
        user_already_locked?
      end

      private

      # Check if user is already locked
      def user_already_locked?
        return false unless user

        if user.respond_to?(:access_locked?)
          user.access_locked?
        elsif user.respond_to?(:locked_at)
          user.locked_at.present?
        else
          false
        end
      end

      # Lock account using Devise's lockable module
      def lock_with_devise_lockable
        unless devise_lockable_available?
          Beskar::Logger.warn("Devise lockable not available for #{user.class.name}", component: :AccountLocker)
          return false
        end

        begin
          # Use Devise's lock_access! method
          user.lock_access!(send_instructions: false)
          
          # Set automatic unlock time if configured and supported
          if Beskar.configuration.auto_unlock_time && user.respond_to?(:locked_at=)
            user.update_column(:locked_at, Time.current)
          end

          Beskar::Logger.info("Locked account #{user.id} (#{user.class.name}) - Risk: #{risk_score}, Reason: #{reason}", component: :AccountLocker)
          true
        rescue => e
          Beskar::Logger.error("Failed to lock account: #{e.message}", component: :AccountLocker)
          false
        end
      end

      # Unlock account using Devise's lockable module
      def unlock_with_devise_lockable
        unless devise_lockable_available?
          Beskar::Logger.warn("Devise lockable not available for #{user.class.name}", component: :AccountLocker)
          return false
        end

        begin
          user.unlock_access!
          Beskar::Logger.info("Unlocked account #{user.id} (#{user.class.name})", component: :AccountLocker)
          true
        rescue => e
          Beskar::Logger.error("Failed to unlock account: #{e.message}", component: :AccountLocker)
          false
        end
      end

      # Lock account using custom strategy (to be implemented by application)
      def lock_with_custom_strategy
        # Applications can implement this by:
        # 1. Adding a locked_by_beskar column to users table
        # 2. Checking this in authentication callbacks
        # 3. Implementing unlock logic

        Beskar::Logger.warn("Custom lock strategy not implemented", component: :AccountLocker)
        false
      end

      # Unlock using custom strategy
      def unlock_with_custom_strategy
        Beskar::Logger.warn("Custom unlock strategy not implemented", component: :AccountLocker)
        false
      end

      # Check if Devise lockable is available for this user
      def devise_lockable_available?
        defined?(Devise) &&
          user.class.respond_to?(:devise_modules) &&
          user.class.devise_modules.include?(:lockable) &&
          user.respond_to?(:lock_access!)
      end

      # Log the lock event to security events
      # Always logs, even if actual lock fails, to maintain audit trail
      def log_lock_event(lock_succeeded = true)
        return unless user.respond_to?(:security_events)

        begin
          event_type = lock_succeeded ? 'account_locked' : 'lock_attempted'
          
          user.security_events.create!(
            event_type: event_type,
            ip_address: metadata[:ip_address] || 'system',
            user_agent: metadata[:user_agent] || 'beskar_system',
            risk_score: risk_score,
            metadata: {
              reason: reason,
              risk_threshold: Beskar.configuration.risk_threshold,
              lock_strategy: Beskar.configuration.lock_strategy,
              auto_unlock_time: Beskar.configuration.auto_unlock_time,
              locked_at: Time.current.iso8601,
              lock_succeeded: lock_succeeded,
              additional_context: metadata
            }
          )
        rescue => e
          Beskar::Logger.warn("Failed to log lock event: #{e.message}", component: :AccountLocker)
        end
      end

      # Log unlock event for adaptive learning
      # This helps establish patterns - if user unlocks and logs in successfully,
      # that context becomes "established" and trusted
      def log_unlock_event
        return unless user.respond_to?(:security_events)

        begin
          user.security_events.create!(
            event_type: 'account_unlocked',
            ip_address: metadata[:ip_address] || 'system',
            user_agent: metadata[:user_agent] || 'beskar_system',
            risk_score: 0, # Unlock has no risk
            metadata: {
              unlocked_at: Time.current.iso8601,
              unlock_method: 'manual',
              additional_context: metadata
            }
          )
        rescue => e
          Beskar::Logger.warn("Failed to log unlock event: #{e.message}", component: :AccountLocker)
        end
      end

      # Notify user about account lock
      def notify_user
        # This would integrate with ActionMailer or notification system
        # For now, just log it
        Beskar::Logger.info("User #{user.id} should be notified of account lock", component: :AccountLocker)
        
        # Future implementation:
        # if defined?(Beskar::AccountLockMailer)
        #   Beskar::AccountLockMailer.account_locked(user, risk_score, reason).deliver_later
        # end
      end
    end
  end
end
