require "csv"

module Beskar
  class BannedIpsController < ApplicationController
    before_action :set_banned_ip, only: [:show, :edit, :update, :destroy, :extend]

    def index
      @banned_ips = Beskar::BannedIp.order(banned_at: :desc)

      # Apply filters
      apply_filters!

      # Paginate results
      @pagination = paginate(@banned_ips, per_page: params[:per_page]&.to_i || 25)
      @banned_ips = @pagination[:records]

      # Get filter options
      @ban_reasons = Beskar::BannedIp.distinct.pluck(:reason).compact.sort
      @ban_statuses = ["active", "expired", "permanent", "temporary"]
    end

    def show
      # Get related security events for this IP
      @related_events = Beskar::SecurityEvent
        .where(ip_address: @banned_ip.ip_address)
        .order(created_at: :desc)
        .limit(20)

      # Calculate statistics
      @stats = {
        total_events: @related_events.count,
        avg_risk_score: @related_events.average(:risk_score)&.round(1) || 0,
        max_risk_score: @related_events.maximum(:risk_score) || 0,
        first_seen: @related_events.minimum(:created_at),
        last_seen: @related_events.maximum(:created_at)
      }
    end

    def new
      @banned_ip = Beskar::BannedIp.new
      @suggested_ip = params[:ip_address]
      @suggested_reason = params[:reason]
    end

    def create
      manager = BannedIpManager.new(create_params)
      manager.create

      if manager.success?
        redirect_to banned_ip_path(manager.banned_ip),
          notice: "IP address #{manager.banned_ip.ip_address} has been banned successfully."
      else
        @banned_ip = manager.banned_ip
        render :new
      end
    end

    def edit
    end

    def update
      if @banned_ip.update(banned_ip_params)
        redirect_to banned_ip_path(@banned_ip),
          notice: "Ban for IP #{@banned_ip.ip_address} has been updated."
      else
        render :edit
      end
    end

    def destroy
      ip_address = @banned_ip.ip_address
      @banned_ip.destroy

      redirect_to banned_ips_path,
        notice: "IP address #{ip_address} has been unbanned."
    end

    def extend
      # Default to 24 hours if no duration specified (e.g., from index page)
      duration_param = params[:duration] || "24h"

      duration = case duration_param
      when "1h"
        1.hour
      when "6h"
        6.hours
      when "24h"
        24.hours
      when "7d"
        7.days
      when "30d"
        30.days
      when "permanent"
        nil
      else
        24.hours
      end

      if duration_param == "permanent"
        @banned_ip.update!(permanent: true, expires_at: nil)
        message = "Ban for IP #{@banned_ip.ip_address} is now permanent."
      else
        # Ensure the ban can be extended (not already permanent)
        if @banned_ip.permanent?
          redirect_to banned_ip_path(@banned_ip), alert: "Cannot extend a permanent ban."
          return
        end

        @banned_ip.extend_ban!(duration)
        duration_text = (duration_param == "24h") ? "24 hours" : duration_param.gsub(/(\d+)([hd])/, '\1 \2').gsub("h", "hour(s)").gsub("d", "day(s)")
        message = "Ban for IP #{@banned_ip.ip_address} has been extended by #{duration_text}."
      end

      redirect_to banned_ip_path(@banned_ip), notice: message
    rescue => e
      Rails.logger.error "Failed to extend ban: #{e.message}"
      redirect_to banned_ip_path(@banned_ip), alert: "Failed to extend ban: #{e.message}"
    end

    def bulk_action
      case params[:bulk_action]
      when "unban"
        unban_selected
      when "make_permanent"
        make_permanent_selected
      when "extend"
        extend_selected
      else
        redirect_to banned_ips_path, alert: "Unknown action."
      end
    end

    def export
      @banned_ips = Beskar::BannedIp.all
      apply_filters!

      respond_to do |format|
        format.csv do
          send_data generate_csv(@banned_ips),
            filename: "banned-ips-#{Date.current}.csv",
            type: "text/csv"
        end
        format.json do
          render json: @banned_ips.as_json(except: [:updated_at])
        end
      end
    end

    private

    def set_banned_ip
      @banned_ip = Beskar::BannedIp.find(params[:id])
    end

    def banned_ip_params
      params.require(:banned_ip).permit(
        :ip_address, :reason, :details, :permanent,
        :expires_at, :violation_count, metadata: {}
      )
    end

    def create_params
      banned_ip_params.to_h.merge(
        ban_type: params[:ban_type],
        duration: params[:duration]
      ).symbolize_keys
    end

    def apply_filters!
      # Filter by status
      case params[:status]
      when "active"
        @banned_ips = @banned_ips.active
      when "expired"
        @banned_ips = @banned_ips.expired
      when "permanent"
        @banned_ips = @banned_ips.permanent
      when "temporary"
        @banned_ips = @banned_ips.temporary
      end

      # Filter by reason
      if params[:reason].present?
        @banned_ips = @banned_ips.by_reason(params[:reason])
      end

      # Filter by IP address (partial match)
      if params[:ip_search].present?
        @banned_ips = @banned_ips.where("ip_address LIKE ?", "%#{params[:ip_search]}%")
      end

      # Filter by date range
      if params[:banned_after].present?
        begin
          date = Date.parse(params[:banned_after])
          @banned_ips = @banned_ips.where("banned_at >= ?", date.beginning_of_day)
        rescue ArgumentError
          # Invalid date, ignore
        end
      end

      if params[:banned_before].present?
        begin
          date = Date.parse(params[:banned_before])
          @banned_ips = @banned_ips.where("banned_at <= ?", date.end_of_day)
        rescue ArgumentError
          # Invalid date, ignore
        end
      end
    end

    def unban_selected
      if params[:ip_ids].present?
        banned_ips = Beskar::BannedIp.where(id: params[:ip_ids])
        count = banned_ips.count

        banned_ips.destroy_all

        redirect_to banned_ips_path,
          notice: "#{count} IP(s) have been unbanned."
      else
        redirect_to banned_ips_path, alert: "No IPs selected."
      end
    end

    def make_permanent_selected
      if params[:ip_ids].present?
        count = Beskar::BannedIp.where(id: params[:ip_ids])
          .update_all(permanent: true, expires_at: nil)

        redirect_to banned_ips_path,
          notice: "#{count} ban(s) have been made permanent."
      else
        redirect_to banned_ips_path, alert: "No IPs selected."
      end
    end

    def extend_selected
      if params[:ip_ids].present? && params[:duration].present?
        banned_ips = Beskar::BannedIp.where(id: params[:ip_ids])

        duration = case params[:duration]
        when "24h" then 24.hours
        when "7d" then 7.days
        when "30d" then 30.days
        else 24.hours
        end

        banned_ips.each do |banned_ip|
          banned_ip.extend_ban!(duration)
        end

        redirect_to banned_ips_path,
          notice: "#{banned_ips.count} ban(s) have been extended."
      else
        redirect_to banned_ips_path, alert: "No IPs selected or duration not specified."
      end
    end

    def generate_csv(banned_ips)
      require "csv"

      CSV.generate(headers: true) do |csv|
        csv << ["IP Address", "Reason", "Banned At", "Expires At", "Status", "Violation Count", "Details"]

        banned_ips.find_each do |ban|
          csv << [
            ban.ip_address,
            ban.reason,
            ban.banned_at.strftime("%Y-%m-%d %H:%M:%S"),
            ban.expires_at&.strftime("%Y-%m-%d %H:%M:%S") || (ban.permanent? ? "Never (Permanent)" : "-"),
            ban.active? ? "Active" : "Expired",
            ban.violation_count,
            ban.details || "-"
          ]
        end
      end
    end
  end
end
