module Beskar
  module Middleware
    class RequestAnalyzer
      def initialize(app)
        @app = app
      end

      def call(env)
        request = ActionDispatch::Request.new(env)
        ip_address = request.ip

        Beskar::Logger.debug("[RequestAnalyzer] Processing request from IP: #{ip_address}, Path: #{request.path}", component: :Middleware)

        # 1. Check if IP is whitelisted (whitelisted IPs skip blocking but still get logged)
        is_whitelisted = Beskar::Services::IpWhitelist.whitelisted?(ip_address)

        # 2. Check if IP is banned (early exit for blocked IPs, unless whitelisted or in monitor-only mode)
        if !is_whitelisted && Beskar::BannedIp.banned?(ip_address)
          if Beskar.configuration.monitor_only?
            Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block request from banned IP: #{ip_address}, but monitor_only=true. Request proceeding normally.", component: :Middleware)
          else
            Beskar::Logger.warn("Blocked request from banned IP: #{ip_address}", component: :Middleware)
            return blocked_response("Your IP address has been blocked due to suspicious activity.")
          end
        end

        # 3. Check rate limiting (unless whitelisted)
        if !is_whitelisted && rate_limited?(request)
          # Auto-block after excessive rate limiting violations (even in monitor-only mode - we create the ban record)
          if should_auto_block_rate_limit?(ip_address)
            Beskar::BannedIp.ban!(
              ip_address,
              reason: 'rate_limit_abuse',
              duration: 1.hour,
              details: 'Excessive rate limit violations'
            )
          end

          if Beskar.configuration.monitor_only?
            Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block rate limit exceeded for IP: #{ip_address}, but monitor_only=true. Request proceeding normally.", component: :Middleware)
          else
            Beskar::Logger.warn("Rate limit exceeded for IP: #{ip_address}", component: :Middleware)
            return rate_limit_response
          end
        end

        # 4. Check WAF patterns (vulnerability scans)
        if Beskar.configuration.waf_enabled?
          Beskar::Logger.debug("[RequestAnalyzer] WAF enabled, analyzing request", component: :Middleware)
          waf_analysis = Beskar::Services::Waf.analyze_request(request)

          if waf_analysis
            Beskar::Logger.debug("[RequestAnalyzer] WAF detected threat: #{waf_analysis[:patterns].map { |p| p[:description] }.join(', ')}", component: :Middleware)
            # Log the violation (and create security event if configured)
            # Pass whitelist status to prevent auto-blocking whitelisted IPs
            violation_count = Beskar::Services::Waf.record_violation(ip_address, waf_analysis, whitelisted: is_whitelisted)
            Beskar::Logger.debug("[RequestAnalyzer] Violation count after recording: #{violation_count}", component: :Middleware)

            # Log even for whitelisted IPs (but don't block)
            if is_whitelisted
              Beskar::Logger.info("WAF violation from whitelisted IP #{ip_address} " \
                "(not blocking): #{waf_analysis[:patterns].map { |p| p[:description] }.join(', ')}", component: :Middleware)
            else
              # Check if we should block
              should_block = Beskar::Services::Waf.should_block?(ip_address)
              Beskar::Logger.debug("[RequestAnalyzer] Should block IP #{ip_address}?: #{should_block}", component: :Middleware)

              if Beskar.configuration.monitor_only?
                # Monitor-only mode: Just log, don't block (but ban record was created by WAF.record_violation)
                if should_block
                  Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block IP #{ip_address} " \
                    "after #{violation_count} WAF violations, but monitor_only=true. " \
                    "Request proceeding normally.", component: :Middleware)
                end
              elsif should_block && !Beskar.configuration.monitor_only?
                # Actually block the request (not in monitor-only mode)
                Beskar::Logger.warn("🔒 Blocking IP #{ip_address} " \
                  "after #{violation_count} WAF violations", component: :Middleware)
                # Block already handled by WAF.record_violation auto-block logic
                # But we return 403 immediately
                return blocked_response("Access denied due to suspicious activity.")
              end
            end
          else
            Beskar::Logger.debug("[RequestAnalyzer] No WAF threat detected for path: #{request.path}", component: :Middleware)
          end
        else
          Beskar::Logger.debug("[RequestAnalyzer] WAF is disabled", component: :Middleware)
        end

        # 5. Process the request normally (will raise 404 if route not found)
        Beskar::Logger.debug("[RequestAnalyzer] Passing request to application", component: :Middleware)
        @app.call(env)
      rescue ActionController::UnknownFormat => e
        # Analyze unknown format as potential scanner
        if Beskar.configuration.waf_enabled?
          handle_rails_exception(request, e, ip_address, is_whitelisted)
        end
        # Re-raise to allow normal error handling
        raise
      rescue ActionDispatch::RemoteIp::IpSpoofAttackError => e
        # Handle IP spoofing attack
        if Beskar.configuration.waf_enabled?
          handle_rails_exception(request, e, ip_address, is_whitelisted)
        end
        # Re-raise to allow normal error handling
        raise
      rescue ActiveRecord::RecordNotFound => e
        # Analyze record not found as potential enumeration scan
        if Beskar.configuration.waf_enabled?
          handle_rails_exception(request, e, ip_address, is_whitelisted)
        end
        # Re-raise to allow normal error handling
        raise
      rescue ActionDispatch::Http::MimeNegotiation::InvalidType => e
        # Analyze invalid MIME type as potential scanner
        if Beskar.configuration.waf_enabled?
          handle_rails_exception(request, e, ip_address, is_whitelisted)
        end
        # Re-raise to allow normal error handling
        raise
      rescue ActionController::RoutingError => e
        # If WAF is enabled, log 404s as potential scanning attempts
        if Beskar.configuration.waf_enabled?
          log_404_for_waf(request, e)
        end
        # Re-raise to allow normal 404 handling
        raise
      end

      private

      def rate_limited?(request)
        # Check both IP rate limit and authentication abuse
        ip_check = Beskar::Services::RateLimiter.check_ip_rate_limit(request.ip)
        auth_abused = authentication_brute_force?(request.ip)

        !ip_check[:allowed] || auth_abused
      end

      def should_auto_block_rate_limit?(ip_address)
        # Check how many times this IP has been rate limited in the past hour
        cache_key = "beskar:rate_limit_violations:#{ip_address}"
        violations = Rails.cache.read(cache_key) || 0
        violations += 1
        Rails.cache.write(cache_key, violations, expires_in: 1.hour)

        # Block after 5 rate limit violations in an hour
        violations >= 5
      end

      def authentication_brute_force?(ip_address)
        # Check authentication failure count from RateLimiter
        cache_key = "beskar:ip_auth_failures:#{ip_address}"

        # Get current failure count and timestamp
        failure_data = Rails.cache.read(cache_key)
        return false unless failure_data.is_a?(Hash)

        # Count recent failures (within the configured period)
        config = Beskar.configuration.rate_limiting[:ip_attempts] || {}
        period = config[:period] || 1.hour
        limit = config[:limit] || 10

        now = Time.current.to_i
        recent_failures = failure_data.select { |timestamp, _| now - timestamp.to_i < period.to_i }

        # If too many auth failures, it's brute force
        if recent_failures.length >= limit
          # Auto-ban for authentication abuse (create ban record even in monitor-only mode)
          Beskar::BannedIp.ban!(
            ip_address,
            reason: 'authentication_abuse',
            duration: 1.hour,
            details: "#{recent_failures.length} failed authentication attempts in #{period / 60} minutes",
            metadata: { failure_count: recent_failures.length, detection_time: Time.current }
          )

          if Beskar.configuration.monitor_only?
            Beskar::Logger.warn("🔍 MONITOR-ONLY: Would auto-block IP #{ip_address} " \
              "for authentication brute force (#{recent_failures.length} failures), but monitor_only=true", component: :Middleware)
          else
            Beskar::Logger.warn("🔒 Auto-blocked IP #{ip_address} " \
              "for authentication brute force (#{recent_failures.length} failures)", component: :Middleware)
          end

          return true
        end

        false
      end

      def handle_rails_exception(request, exception, ip_address, is_whitelisted)
        # Analyze the exception using WAF
        waf_analysis = Beskar::Services::Waf.analyze_exception(exception, request)

        if waf_analysis
          Beskar::Logger.debug("[RequestAnalyzer] WAF detected threat from exception: #{exception.class.name}", component: :Middleware)

          # Record the violation (similar to regular WAF violations)
          violation_count = Beskar::Services::Waf.record_violation(ip_address, waf_analysis, whitelisted: is_whitelisted)

          # Log for whitelisted IPs
          if is_whitelisted
            Beskar::Logger.info("Exception-based WAF violation from whitelisted IP #{ip_address} " \
              "(not blocking): #{exception.class.name} - #{waf_analysis[:patterns].first[:description]}", component: :Middleware)
          else
            # Check if we should block
            should_block = Beskar::Services::Waf.should_block?(ip_address)

            if Beskar.configuration.monitor_only?
              if should_block
                Beskar::Logger.warn("🔍 MONITOR-ONLY: Would block IP #{ip_address} " \
                  "after #{violation_count} WAF violations (exception: #{exception.class.name}), " \
                  "but monitor_only=true. Request proceeding normally.", component: :Middleware)
              end
            elsif should_block && !Beskar.configuration.monitor_only?
              Beskar::Logger.warn("🔒 Blocking IP #{ip_address} " \
                "after #{violation_count} WAF violations (exception: #{exception.class.name})", component: :Middleware)
              # Note: We don't return blocked response here as exception is already raised
              # The ban record is created by WAF.record_violation
            end
          end
        end
      end

      def log_404_for_waf(request, error)
        # 404s on suspicious paths might indicate scanning
        path = request.fullpath || request.path

        # Only log if it matches WAF patterns (already analyzed in analyze_request)
        waf_analysis = Beskar::Services::Waf.analyze_request(request)

        if waf_analysis
          Beskar::Logger.info("404 on suspicious path from #{request.ip}: #{path} " \
            "(WAF patterns: #{waf_analysis[:patterns].map { |p| p[:description] }.join(', ')})", component: :Middleware)
        end
      end

      def blocked_response(message = "Forbidden")
        [
          403,
          {
            "Content-Type" => "text/html",
            "X-Beskar-Blocked" => "true"
          },
          [render_blocked_page(message)]
        ]
      end

      def rate_limit_response
        [
          429,
          {
            "Content-Type" => "text/html",
            "Retry-After" => "3600",
            "X-Beskar-Rate-Limited" => "true"
          },
          [render_rate_limit_page]
        ]
      end

      def render_blocked_page(message)
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Access Denied</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              h1 { color: #d32f2f; }
              p { color: #666; }
            </style>
          </head>
          <body>
            <h1>Access Denied</h1>
            <p>#{message}</p>
            <p>If you believe this is an error, please contact the site administrator.</p>
          </body>
          </html>
        HTML
      end

      def render_rate_limit_page
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Too Many Requests</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              h1 { color: #ff9800; }
              p { color: #666; }
            </style>
          </head>
          <body>
            <h1>Too Many Requests</h1>
            <p>You have exceeded the rate limit. Please try again later.</p>
          </body>
          </html>
        HTML
      end
    end
  end
end
