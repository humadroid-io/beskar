module Beskar
  class DashboardController < ApplicationController
    def index
      # Time ranges for statistics
      @time_range = params[:time_range] || "24h"
      @start_time = calculate_start_time(@time_range)

      # Overview statistics
      @stats = {
        total_events: Beskar::SecurityEvent.where("created_at >= ?", @start_time).count,
        failed_logins: Beskar::SecurityEvent.where("created_at >= ?", @start_time).login_failures.count,
        blocked_ips: Beskar::BannedIp.active.count,
        high_risk_events: Beskar::SecurityEvent.where("created_at >= ?", @start_time).high_risk.count,
        critical_threats: Beskar::SecurityEvent.where("created_at >= ?", @start_time).critical_risk.count
      }

      # Recent activity
      @recent_events = Beskar::SecurityEvent
        .includes(:user)
        .order(created_at: :desc)
        .limit(10)

      # Top threat IPs
      @top_threat_ips = Beskar::SecurityEvent
        .where("created_at >= ?", @start_time)
        .group(:ip_address)
        .select("ip_address, COUNT(*) as event_count, AVG(risk_score) as avg_risk_score, MAX(risk_score) as max_risk_score")
        .having("COUNT(*) > 1")
        .order("event_count DESC, avg_risk_score DESC")
        .limit(5)

      # Event types distribution
      @event_distribution = Beskar::SecurityEvent
        .where("created_at >= ?", @start_time)
        .group(:event_type)
        .count
        .sort_by { |_, count| -count }

      # Risk score distribution
      @risk_distribution = {
        low: Beskar::SecurityEvent.where("created_at >= ? AND risk_score < 30", @start_time).count,
        medium: Beskar::SecurityEvent.where("created_at >= ? AND risk_score BETWEEN 30 AND 60", @start_time).count,
        high: Beskar::SecurityEvent.where("created_at >= ? AND risk_score BETWEEN 61 AND 85", @start_time).count,
        critical: Beskar::SecurityEvent.where("created_at >= ? AND risk_score > 85", @start_time).count
      }

      # Currently active bans
      @active_bans = Beskar::BannedIp.active.order(banned_at: :desc).limit(5)
    end

    private

    def calculate_start_time(range)
      case range
      when "1h"
        1.hour.ago
      when "6h"
        6.hours.ago
      when "24h"
        24.hours.ago
      when "7d"
        7.days.ago
      when "30d"
        30.days.ago
      else
        24.hours.ago
      end
    end
  end
end
