module Beskar
  module Services
    class Waf
      # Common vulnerability scan patterns
      VULNERABILITY_PATTERNS = {
        rails_exceptions: {
          patterns: [
            %r{/(?:users?|posts?|articles?|comments?|api/v\d+/\w+)/\d+\.(?:exe|bat|cmd|com|scr|vbs|jar|app|deb|rpm)$}i,  # Rails resources with executable extensions
            %r{/(?:users?|posts?|articles?|comments?|api/v\d+/\w+)\.(?:asp|aspx|jsp|do|action|cgi|pl|py|rb)$}i,  # Rails routes with server-side script extensions
            %r{\?format=(?:exe|bat|cmd|com|scr|vbs|jar|asp|aspx|jsp|php)$}i  # Suspicious format in query params
          ],
          severity: :medium,
          description: "Potential Rails exception triggering attempt"
        },
        ip_spoofing: {
          patterns: [
            %r{X-Forwarded-For.*X-Forwarded-For}i,  # Multiple X-Forwarded-For headers in path (suspicious)
            %r{Client-IP.*X-Forwarded-For}i  # Conflicting IP headers in path
          ],
          severity: :high,
          description: "Potential IP spoofing attempt"
        },
        record_scanning: {
          patterns: [
            %r{/(?:user|admin|account|profile|order|payment|invoice|document|file|download)/\d{6,}}i,  # Large IDs that likely don't exist
            %r{/(?:user|admin|account|profile)/(?:test|admin|root|administrator|superuser)}i,  # Common test usernames
            %r{/api/v\d+/(?:users?|accounts?|orders?|payments?)/(?:999999|123456|0|null|undefined)}i  # Obviously fake API IDs
          ],
          severity: :low,
          description: "Potential record enumeration/scanning"
        },
        wordpress: {
          patterns: [
            %r{/wp-admin}i,
            %r{/wp-login\.php}i,
            %r{/wp-content/.*\.php}i,  # PHP files in wp-content are suspicious
            %r{/wp-includes}i,
            %r{/xmlrpc\.php}i,
            %r{/wp-config\.php}i,
            %r{/wp-config\.bak}i,
            %r{/wordpress}i
          ],
          severity: :high,
          description: "WordPress vulnerability scan"
        },
        wordpress_static: {
          patterns: [
            %r{/wp-content/.*\.(?:css|js|jpe?g|png|gif|svg|webp|ico|woff2?|ttf|eot|map)$}i,  # Static files in wp-content
            %r{/wp-content/(?:uploads|themes|plugins)/[^.]*$}i  # Directory listing attempts
          ],
          severity: :low,
          description: "WordPress static file probe"
        },
        php_admin: {
          patterns: [
            %r{/phpmyadmin}i,
            %r{/pma}i,
            %r{/admin\.php}i,
            %r{/administrator}i,
            %r{/admin/config\.php}i,
            %r{/phpinfo\.php}i
          ],
          severity: :high,
          description: "PHP admin panel scan"
        },
        config_files: {
          patterns: [
            %r{/\.env},
            %r{/\.git},
            %r{/config\.php}i,
            %r{/configuration\.php}i,
            %r{/settings\.php}i,
            %r{/database\.yml},
            %r{/credentials\.yml}i
          ],
          severity: :critical,
          description: "Configuration file access attempt"
        },
        path_traversal: {
          patterns: [
            %r{/etc/passwd},
            %r{/etc/shadow},
            %r{/etc/hosts},
            %r{\.\./},
            %r{\.\.\\},
            %r{%2e%2e/}i,
            %r{%252e%252e/}i
          ],
          severity: :critical,
          description: "Path traversal attempt"
        },
        framework_debug: {
          patterns: [
            %r{/rails/info/routes},
            %r{/__debug__},
            %r{/debug},
            %r{/telescope},
            %r{/_profiler},
            %r{/\.well-known}
          ],
          severity: :medium,
          description: "Framework debug endpoint scan"
        },
        cms_scan: {
          patterns: [
            %r{/joomla}i,
            %r{/drupal}i,
            %r{/magento}i,
            %r{/prestashop}i,
            %r{/typo3}i
          ],
          severity: :medium,
          description: "CMS detection scan"
        },
        common_exploits: {
          patterns: [
            %r{/shell\.php}i,
            %r{/cmd\.php}i,
            %r{/backdoor}i,
            %r{/c99\.php}i,
            %r{/r57\.php}i,
            %r{/webshell}i
          ],
          severity: :critical,
          description: "Common exploit file access"
        }
      }.freeze

      # Configuration for RecordNotFound exclusion patterns
      # These patterns will not trigger WAF violations
      RECORD_NOT_FOUND_EXCLUSIONS = [
        # Add default exclusions here if needed
        # %r{/posts/.*},  # Example: exclude all posts paths
      ].freeze

      class << self
        # Analyze a request for vulnerability scanning patterns
        def analyze_request(request)
          path = request.fullpath || request.path
          return nil if path.blank?

          detected_patterns = []

          VULNERABILITY_PATTERNS.each do |category, config|
            config[:patterns].each do |pattern|
              if path.match?(pattern)
                detected_patterns << {
                  category: category,
                  pattern: pattern.source,
                  severity: config[:severity],
                  description: config[:description],
                  matched_path: path
                }
              end
            end
          end

          if detected_patterns.any?
            {
              threat_detected: true,
              patterns: detected_patterns,
              highest_severity: calculate_highest_severity(detected_patterns),
              ip_address: request.ip,
              user_agent: request.user_agent,
              timestamp: Time.current
            }
          end
        end

        # Analyze Rails exceptions as potential security threats
        def analyze_exception(exception, request)
          case exception
          when ActionController::UnknownFormat
            {
              threat_detected: true,
              patterns: [{
                category: :unknown_format,
                pattern: "ActionController::UnknownFormat",
                severity: :medium,
                description: "Unknown format requested - potential scanner",
                matched_path: request.fullpath
              }],
              highest_severity: :medium,
              ip_address: request.ip,
              user_agent: request.user_agent,
              timestamp: Time.current,
              exception_class: exception.class.name,
              exception_message: exception.message
            }
          when ActionDispatch::RemoteIp::IpSpoofAttackError
            {
              threat_detected: true,
              patterns: [{
                category: :ip_spoof,
                pattern: "ActionDispatch::RemoteIp::IpSpoofAttackError",
                severity: :critical,
                description: "IP spoofing attack detected",
                matched_path: request.fullpath
              }],
              highest_severity: :critical,
              ip_address: request.ip,
              user_agent: request.user_agent,
              timestamp: Time.current,
              exception_class: exception.class.name,
              exception_message: exception.message
            }
          when ActiveRecord::RecordNotFound
            # Check if this path should be excluded from WAF
            if should_exclude_record_not_found?(request.fullpath)
              return nil
            end

            {
              threat_detected: true,
              patterns: [{
                category: :record_not_found,
                pattern: "ActiveRecord::RecordNotFound",
                severity: :low,
                description: "Record not found - potential enumeration scan",
                matched_path: request.fullpath
              }],
              highest_severity: :low,
              ip_address: request.ip,
              user_agent: request.user_agent,
              timestamp: Time.current,
              exception_class: exception.class.name,
              exception_message: exception.message
            }
          when ActionDispatch::Http::MimeNegotiation::InvalidType
            {
              threat_detected: true,
              patterns: [{
                category: :invalid_mime_type,
                pattern: "ActionDispatch::Http::MimeNegotiation::InvalidType",
                severity: :medium,
                description: "Invalid MIME type requested - potential scanner",
                matched_path: request.fullpath
              }],
              highest_severity: :medium,
              ip_address: request.ip,
              user_agent: request.user_agent,
              timestamp: Time.current,
              exception_class: exception.class.name,
              exception_message: exception.message
            }
          end
        end

        # Check if a RecordNotFound exception should be excluded from WAF
        def should_exclude_record_not_found?(path)
          return false if path.blank?

          # Check configured exclusions
          exclusions = waf_config[:record_not_found_exclusions] || []
          all_exclusions = RECORD_NOT_FOUND_EXCLUSIONS + exclusions

          all_exclusions.any? { |pattern| path.match?(pattern) }
        end

        # Check if request should be blocked based on violation history
        def should_block?(ip_address)
          config = waf_config
          return false unless config[:enabled]
          return false unless config[:auto_block]

          # Get current risk score (with decay applied)
          current_score = get_current_score(ip_address)
          threshold = config[:score_threshold] || 150

          current_score >= threshold
        end

        # Record a WAF violation
        def record_violation(ip_address, analysis_result, whitelisted: false)
          config = waf_config
          return unless config[:enabled]

          Beskar::Logger.debug("[WAF] Recording violation for IP: #{ip_address}, whitelisted: #{whitelisted}", component: :WAF)

          # Get current violations and add new one
          cache_key = "beskar:waf_violations:#{ip_address}"
          violations = Rails.cache.read(cache_key) || []

          # Calculate risk score for this violation
          risk_score = severity_to_risk_score(analysis_result[:highest_severity])

          # Create new violation record
          new_violation = {
            timestamp: Time.current.to_i,
            score: risk_score,
            severity: analysis_result[:highest_severity],
            category: analysis_result[:patterns].first[:category],
            description: analysis_result[:patterns].first[:description],
            path: analysis_result[:patterns].first[:matched_path]
          }

          violations << new_violation

          # Prune old violations (outside violation window and max tracked)
          violations = prune_violations(violations, config)

          # Calculate current score with decay
          current_score = calculate_current_score(violations, config)

          Beskar::Logger.debug("[WAF] Violation recorded for #{ip_address}: score=#{risk_score}, current_total=#{current_score.round(2)}, violations_count=#{violations.size}", component: :WAF)

          # Store violations with TTL from config
          ttl = config[:violation_window] || 6.hours
          Rails.cache.write(cache_key, violations, expires_in: ttl)

          # Log the violation
          log_violation(ip_address, analysis_result, current_score, violations.size)

          # Create security event if configured
          if config[:create_security_events]
            create_security_event(ip_address, analysis_result, current_score)
          end

          # Check if we should auto-block (skip if whitelisted)
          threshold = config[:score_threshold] || 150

          Beskar::Logger.debug("[WAF] Auto-block check: whitelisted=#{whitelisted}, auto_block=#{config[:auto_block]}, score=#{current_score.round(2)}, threshold=#{threshold}", component: :WAF)

          if !whitelisted && config[:auto_block] && current_score >= threshold
            Beskar::Logger.info("[WAF] Score threshold reached for #{ip_address}, creating ban record", component: :WAF)
            # Always create the ban record (even in monitor-only mode)
            auto_block_ip(ip_address, analysis_result, current_score)

            # But also log monitor-only message if in monitor mode
            if Beskar.configuration.monitor_only?
              log_monitor_only_action(ip_address, analysis_result, current_score, threshold)
            end
          else
            Beskar::Logger.debug("[WAF] Not auto-blocking: conditions not met", component: :WAF)
          end

          current_score
        end

        # Get current risk score for an IP (with decay applied)
        def get_current_score(ip_address)
          violations = get_violations(ip_address)
          calculate_current_score(violations, waf_config)
        end

        # Get violations for an IP
        def get_violations(ip_address)
          cache_key = "beskar:waf_violations:#{ip_address}"
          Rails.cache.read(cache_key) || []
        end

        # Get violation count for an IP (number of violations tracked)
        def get_violation_count(ip_address)
          get_violations(ip_address).size
        end

        # Reset violations for an IP
        def reset_violations(ip_address)
          cache_key = "beskar:waf_violations:#{ip_address}"
          Rails.cache.delete(cache_key)
        end

        private

        # Calculate current cumulative score with decay applied
        def calculate_current_score(violations, config)
          return 0.0 if violations.empty?
          return violations.sum { |v| v[:score] } unless config[:decay_enabled]

          now = Time.current.to_i
          decay_rates = config[:decay_rates] || {}

          violations.sum do |v|
            age_seconds = now - v[:timestamp]
            age_minutes = age_seconds / 60.0

            # Get half-life for this severity (in minutes)
            half_life = decay_rates[v[:severity]] || 60

            # Exponential decay: score * (1/2)^(age/half_life)
            # Equivalent to: score * e^(-ln(2) * age / half_life)
            decay_factor = Math.exp(-Math.log(2) * age_minutes / half_life)

            v[:score] * decay_factor
          end
        end

        # Prune violations that are outside the window or exceed max tracked
        def prune_violations(violations, config)
          now = Time.current.to_i
          window_seconds = (config[:violation_window] || 6.hours).to_i
          max_tracked = config[:max_violations_tracked] || 50

          # Remove violations outside the time window
          recent = violations.select do |v|
            (now - v[:timestamp]) <= window_seconds
          end

          # Keep only the most recent violations if we exceed max_tracked
          if recent.size > max_tracked
            recent.sort_by { |v| -v[:timestamp] }.first(max_tracked)
          else
            recent
          end
        end

        # Get WAF configuration
        def waf_config
          Beskar.configuration.waf || {}
        end

        # Calculate highest severity from detected patterns
        def calculate_highest_severity(patterns)
          severities = patterns.map { |p| p[:severity] }
          return :critical if severities.include?(:critical)
          return :high if severities.include?(:high)
          return :medium if severities.include?(:medium)
          :low
        end

        # Log WAF violation
        def log_violation(ip_address, analysis_result, current_score, violation_count)
          severity_emoji = {
            critical: "🚨",
            high: "⚠️",
            medium: "⚡",
            low: "ℹ️"
          }

          emoji = severity_emoji[analysis_result[:highest_severity]] || "🔍"
          waf_config
          monitor_mode_notice = Beskar.configuration.monitor_only? ? " [MONITOR-ONLY MODE]" : ""

          Beskar::Logger.warn("#{emoji} Vulnerability scan detected#{monitor_mode_notice} " \
            "(score: #{current_score.round(2)}, violations: #{violation_count}) - " \
            "IP: #{ip_address}, " \
            "Severity: #{analysis_result[:highest_severity]}, " \
            "Patterns: #{analysis_result[:patterns].map { |p| p[:description] }.join(", ")}, " \
            "Path: #{analysis_result[:patterns].first[:matched_path]}", component: :WAF)
        end

        # Log what would happen in monitor-only mode (but don't actually block)
        def log_monitor_only_action(ip_address, analysis_result, current_score, threshold)
          config = waf_config
          duration = calculate_block_duration(current_score, config)

          Beskar::Logger.warn("🔍 MONITOR-ONLY: IP #{ip_address} WOULD BE BLOCKED " \
            "(score threshold reached: #{current_score.round(2)}/#{threshold}) - " \
            "Duration would be: #{duration ? "#{duration / 3600.0} hours" : "PERMANENT"}, " \
            "Severity: #{analysis_result[:highest_severity]}, " \
            "Patterns: #{analysis_result[:patterns].map { |p| p[:description] }.join(", ")}. " \
            "To enable blocking, set config.monitor_only = false", component: :WAF)
        end

        # Create security event for WAF violation
        def create_security_event(ip_address, analysis_result, current_score)
          config = waf_config
          violation_count = get_violation_count(ip_address)
          threshold = config[:score_threshold] || 150
          would_be_blocked = current_score >= threshold

          Beskar::SecurityEvent.create!(
            event_type: "waf_violation",
            ip_address: ip_address,
            user_agent: analysis_result[:user_agent],
            risk_score: severity_to_risk_score(analysis_result[:highest_severity]),
            metadata: {
              waf_analysis: analysis_result,
              patterns_matched: analysis_result[:patterns].map { |p| p[:description] },
              severity: analysis_result[:highest_severity],
              monitor_only_mode: Beskar.configuration.monitor_only?,
              would_be_blocked: would_be_blocked,
              violation_count: violation_count,
              current_score: current_score.round(2),
              score_threshold: threshold
            }
          )
        rescue => e
          Beskar::Logger.error("Failed to create security event: #{e.message}", component: :WAF)
        end

        # Auto-block an IP after threshold violations
        def auto_block_ip(ip_address, analysis_result, current_score)
          config = waf_config
          duration = calculate_block_duration(current_score, config)
          violation_count = get_violation_count(ip_address)

          Beskar::Logger.debug("[WAF] Attempting to ban IP #{ip_address} with duration: #{duration.inspect}", component: :WAF)

          begin
            banned_ip = Beskar::BannedIp.ban!(
              ip_address,
              reason: "waf_violation",
              duration: duration,
              permanent: duration.nil?,
              details: "WAF score: #{current_score.round(2)} (#{violation_count} violations) - #{analysis_result[:patterns].map { |p| p[:description] }.join(", ")}",
              metadata: {
                violation_count: violation_count,
                risk_score: current_score.round(2),
                patterns: analysis_result[:patterns],
                highest_severity: analysis_result[:highest_severity],
                blocked_at: Time.current
              }
            )

            Beskar::Logger.warn("🔒 Auto-blocked IP #{ip_address} " \
              "with score #{current_score.round(2)} (#{violation_count} violations) " \
              "(duration: #{duration ? "#{duration / 3600} hours" : "permanent"}), " \
              "Ban ID: #{banned_ip.id}", component: :WAF)
          rescue => e
            Beskar::Logger.error("[WAF] Failed to create ban for #{ip_address}: #{e.class} - #{e.message}", component: :WAF)
            raise
          end
        end

        # Calculate block duration based on cumulative score
        def calculate_block_duration(current_score, config)
          permanent_threshold = config[:permanent_block_after]
          return nil if permanent_threshold && current_score >= permanent_threshold

          # Default escalating durations: 1h, 6h, 24h, 7d
          base_durations = config[:block_durations] || [1.hour, 6.hours, 24.hours, 7.days]
          score_threshold = config[:score_threshold] || 150

          # Calculate how many times over the threshold we are
          # 150-300 = 1x = 1 hour
          # 300-450 = 2x = 6 hours
          # 450-600 = 3x = 24 hours
          # 600+ = 4x = 7 days
          multiplier = ((current_score / score_threshold).floor - 1).clamp(0, base_durations.length - 1)
          base_durations[multiplier]
        end

        # Convert severity level to risk score
        def severity_to_risk_score(severity)
          case severity
          when :critical then 95
          when :high then 80
          when :medium then 60
          when :low then 30
          else 50
          end
        end
      end
    end
  end
end
