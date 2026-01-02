module Beskar
  class BannedIpManager
    attr_reader :banned_ip, :errors

    def initialize(params)
      @params = params
      @errors = []
      @banned_ip = nil
    end

    def create
      @banned_ip = BannedIp.new(base_attributes)
      configure_ban_duration

      @banned_ip.save
    end

    def success?
      @banned_ip&.persisted?
    end

    private

    def base_attributes
      {
        ip_address: @params[:ip_address],
        reason: @params[:reason],
        details: @params[:details],
        violation_count: @params[:violation_count] || 1,
        metadata: @params[:metadata] || {},
        banned_at: Time.current
      }
    end

    def configure_ban_duration
      return set_permanent_ban if permanent_ban?

      set_temporary_ban
    end

    def permanent_ban?
      @params[:ban_type] == "permanent"
    end

    def set_permanent_ban
      @banned_ip.permanent = true
      @banned_ip.expires_at = nil
    end

    def set_temporary_ban
      @banned_ip.permanent = false
      @banned_ip.expires_at = calculate_expiry_time
    end

    def calculate_expiry_time
      return custom_expiry_time if custom_expiry_time.present?
      return preset_duration_expiry if preset_duration.present?

      default_expiry_time
    end

    def custom_expiry_time
      @params[:expires_at]
    end

    def preset_duration
      @params[:duration]
    end

    def preset_duration_expiry
      Time.current + preset_duration.to_i.seconds
    end

    def default_expiry_time
      24.hours.from_now
    end
  end
end
