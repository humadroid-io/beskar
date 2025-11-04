module Beskar
  module Services
    class Waf
      # Common vulnerability scan patterns
      VULNERABILITY_PATTERNS = {
        rails_exceptions: {
          patterns: [
            %r{/(?:users?|posts?|articles?|comments?|api/v\d+/\w+)/\d+\.(?:exe|bat|cmd|com|scr|vbs|jar|app|deb|rpm)$}i,  # Rails resources with executable extensions
            %r{/(?:users?|posts?|articles?|comments?|api/v\d+/\w+)\.(?:asp|aspx|jsp|do|action|cgi|pl|py|rb)$}i,  # Rails routes with server-side script extensions
            %r{\?format=(?:exe|bat|cmd|com|scr|vbs|jar|asp|aspx|jsp|php)$}i,  # Suspicious format in query params
          ],
          severity: :medium,
          description: "Potential Rails exception triggering attempt"
        },
        ip_spoofing: {
          patterns: [
            %r{X-Forwarded-For.*X-Forwarded-For}i,  # Multiple X-Forwarded-For headers in path (suspicious)
            %r{Client-IP.*X-Forwarded-For}i,  # Conflicting IP headers in path
          ],
          severity: :high,
          description: "Potential IP spoofing attempt"
        },
        record_scanning: {
          patterns: [
            %r{/(?:user|admin|account|profile|order|payment|invoice|document|file|download)/\d{6,}}i,  # Large IDs that likely don't exist
            %r{/(?:user|admin|account|profile)/(?:test|admin|root|administrator|superuser)}i,  # Common test usernames
            %r{/api/v\d+/(?:users?|accounts?|orders?|payments?)/(?:999999|123456|0|null|undefined)}i,  # Obviously fake API IDs
          ],
          severity: :low,
          description: "Potential record enumeration/scanning"
        },
        wordpress: {
          patterns: [
            %r{/wp-admin}i,
            %r{/wp-login\.php}i,
            %r{/wp-content}i,
            %r{/wp-includes}i,
            %r{/xmlrpc\.php}i,
            %r{/wp-config\.php}i,
            %r{/wp-config\.bak}i,
            %r{/wordpress}i
          ],
          severity: :high,
          description: "WordPress vulnerability scan"
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
          else
            nil
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
          else
            nil
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

          # Check violation count in cache
          violation_count = get_violation_count(ip_address)
          threshold = config[:block_threshold] || 3

          violation_count >= threshold
        end

        # Record a WAF violation
        def record_violation(ip_address, analysis_result, whitelisted: false)
          config = waf_config
          return unless config[:enabled]

          Beskar::Logger.debug("[WAF] Recording violation for IP: #{ip_address}, whitelisted: #{whitelisted}", component: :WAF)

          # Increment violation count
          cache_key = "beskar:waf_violations:#{ip_address}"
          current_count = Rails.cache.read(cache_key) || 0
          new_count = current_count + 1

          Beskar::Logger.debug("[WAF] Violation count for #{ip_address}: #{current_count} -> #{new_count}", component: :WAF)

          # Store with TTL from config (default 1 hour)
          ttl = config[:violation_window] || 1.hour
          Rails.cache.write(cache_key, new_count, expires_in: ttl)

          Beskar::Logger.debug("[WAF] Cached violation count with TTL: #{ttl} seconds", component: :WAF)

          # Log the violation
          log_violation(ip_address, analysis_result, new_count)

          # Create security event if configured
          if config[:create_security_events]
            create_security_event(ip_address, analysis_result)
          end

          # Check if we should auto-block (skip if whitelisted, in monitor-only mode)
          threshold = config[:block_threshold] || 3

          Beskar::Logger.debug("[WAF] Auto-block check: whitelisted=#{whitelisted}, auto_block=#{config[:auto_block]}, count=#{new_count}, threshold=#{threshold}", component: :WAF)

          if !whitelisted && config[:auto_block] && new_count >= threshold
            Beskar::Logger.info("[WAF] Threshold reached for #{ip_address}, creating ban record", component: :WAF)
            # Always create the ban record (even in monitor-only mode)
            auto_block_ip(ip_address, analysis_result, new_count)

            # But also log monitor-only message if in monitor mode
            if Beskar.configuration.monitor_only?
              log_monitor_only_action(ip_address, analysis_result, new_count, threshold)
            end
          else
            Beskar::Logger.debug("[WAF] Not auto-blocking: conditions not met", component: :WAF)
          end

          new_count
        end

        # Get current violation count for an IP
        def get_violation_count(ip_address)
          cache_key = "beskar:waf_violations:#{ip_address}"
          Rails.cache.read(cache_key) || 0
        end

        # Reset violations for an IP
        def reset_violations(ip_address)
          cache_key = "beskar:waf_violations:#{ip_address}"
          Rails.cache.delete(cache_key)
        end

        private

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
        def log_violation(ip_address, analysis_result, violation_count)
          severity_emoji = {
            critical: "🚨",
            high: "⚠️",
            medium: "⚡",
            low: "ℹ️"
          }

          emoji = severity_emoji[analysis_result[:highest_severity]] || "🔍"
          config = waf_config
          monitor_mode_notice = Beskar.configuration.monitor_only? ? " [MONITOR-ONLY MODE]" : ""

          Beskar::Logger.warn("#{emoji} Vulnerability scan detected#{monitor_mode_notice} " \
            "(#{violation_count} violations) - " \
            "IP: #{ip_address}, " \
            "Severity: #{analysis_result[:highest_severity]}, " \
            "Patterns: #{analysis_result[:patterns].map { |p| p[:description] }.join(', ')}, " \
            "Path: #{analysis_result[:patterns].first[:matched_path]}", component: :WAF)
        end

        # Log what would happen in monitor-only mode (but don't actually block)
        def log_monitor_only_action(ip_address, analysis_result, violation_count, threshold)
          config = waf_config
          duration = calculate_block_duration(violation_count, config)

          Beskar::Logger.warn("🔍 MONITOR-ONLY: IP #{ip_address} WOULD BE BLOCKED " \
            "(threshold reached: #{violation_count}/#{threshold} violations) - " \
            "Duration would be: #{duration ? "#{duration / 3600.0} hours" : 'PERMANENT'}, " \
            "Severity: #{analysis_result[:highest_severity]}, " \
            "Patterns: #{analysis_result[:patterns].map { |p| p[:description] }.join(', ')}. " \
            "To enable blocking, set config.monitor_only = false", component: :WAF)
        end

        # Create security event for WAF violation
        def create_security_event(ip_address, analysis_result)
          config = waf_config
          violation_count = get_violation_count(ip_address)
          threshold = config[:block_threshold] || 3
          would_be_blocked = violation_count >= threshold

          Beskar::SecurityEvent.create!(
            event_type: 'waf_violation',
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
              block_threshold: threshold
            }
          )
        rescue => e
          Beskar::Logger.error("Failed to create security event: #{e.message}", component: :WAF)
        end

        # Auto-block an IP after threshold violations
        def auto_block_ip(ip_address, analysis_result, violation_count)
          config = waf_config
          duration = calculate_block_duration(violation_count, config)

          Beskar::Logger.debug("[WAF] Attempting to ban IP #{ip_address} with duration: #{duration.inspect}", component: :WAF)

          begin
            banned_ip = Beskar::BannedIp.ban!(
              ip_address,
              reason: 'waf_violation',
              duration: duration,
              permanent: duration.nil?,
              details: "WAF violations: #{violation_count} - #{analysis_result[:patterns].map { |p| p[:description] }.join(', ')}",
              metadata: {
                violation_count: violation_count,
                patterns: analysis_result[:patterns],
                highest_severity: analysis_result[:highest_severity],
                blocked_at: Time.current
              }
            )

            Beskar::Logger.warn("🔒 Auto-blocked IP #{ip_address} " \
              "after #{violation_count} violations " \
              "(duration: #{duration ? "#{duration / 3600} hours" : 'permanent'}), " \
              "Ban ID: #{banned_ip.id}", component: :WAF)
          rescue => e
            Beskar::Logger.error("[WAF] Failed to create ban for #{ip_address}: #{e.class} - #{e.message}", component: :WAF)
            raise
          end
        end

        # Calculate block duration based on violation count
        def calculate_block_duration(violation_count, config)
          return nil if config[:permanent_block_after] && violation_count >= config[:permanent_block_after]

          # Default escalating durations: 1h, 6h, 24h, 7d, permanent
          base_durations = config[:block_durations] || [1.hour, 6.hours, 24.hours, 7.days]
          index = [violation_count - (config[:block_threshold] || 3), base_durations.length - 1].min
          base_durations[index]
        end

        # Convert severity level to risk score
        def severity_to_risk_score(severity)
          case severity
          when :critical then 95
          when :high then 80
          when :medium then 60
          when :low then 40
          else 50
          end
        end
      end
    end
  end
end
