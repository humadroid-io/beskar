require "test_helper"

class WafTest < ActiveSupport::TestCase
  def setup
    Rails.cache.clear
    Beskar.configuration.waf = {
      enabled: true,
      auto_block: true,
      score_threshold: 150,
      violation_window: 6.hours,
      create_security_events: true,
      decay_enabled: true,
      decay_rates: {
        critical: 360,
        high: 120,
        medium: 45,
        low: 15
      },
      max_violations_tracked: 50
    }
  end

  def teardown
    Rails.cache.clear
    Beskar.configuration.waf = {enabled: false}
  end

  def create_mock_request(path, ip: "192.168.1.100", user_agent: "TestBot/1.0")
    mock_request = mock
    mock_request.stubs(:fullpath).returns(path)
    mock_request.stubs(:path).returns(path.split("?").first)
    mock_request.stubs(:ip).returns(ip)
    mock_request.stubs(:user_agent).returns(user_agent)
    mock_request
  end

  # WordPress vulnerability scans
  test "analyze_request detects wp-admin access" do
    request = create_mock_request("/wp-admin/index.php")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal 1, result[:patterns].length
    assert_equal :wordpress, result[:patterns].first[:category]
    assert_equal :high, result[:highest_severity]
  end

  test "analyze_request detects wp-login.php" do
    request = create_mock_request("/wp-login.php")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_includes result[:patterns].map { |p| p[:category] }, :wordpress
  end

  test "analyze_request detects xmlrpc.php" do
    request = create_mock_request("/xmlrpc.php")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
  end

  # PHP admin panel scans
  test "analyze_request detects phpmyadmin access" do
    request = create_mock_request("/phpmyadmin/")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :php_admin, result[:patterns].first[:category]
  end

  test "analyze_request detects admin.php" do
    request = create_mock_request("/admin.php")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
  end

  # Configuration file access
  test "analyze_request detects .env file access" do
    request = create_mock_request("/.env")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :config_files, result[:patterns].first[:category]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects .git directory access" do
    request = create_mock_request("/.git/config")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects config.php" do
    request = create_mock_request("/config.php")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
  end

  # Path traversal attempts
  test "analyze_request detects /etc/passwd access" do
    request = create_mock_request("/etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :path_traversal, result[:patterns].first[:category]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects ../ path traversal" do
    request = create_mock_request("/files/../../etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :path_traversal, result[:patterns].first[:category]
  end

  test "analyze_request detects URL encoded path traversal" do
    request = create_mock_request("/files/%2e%2e/etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
  end

  # Framework debug endpoints
  test "analyze_request detects Rails debug routes" do
    request = create_mock_request("/rails/info/routes")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :framework_debug, result[:patterns].first[:category]
  end

  test "analyze_request detects __debug__ endpoint" do
    request = create_mock_request("/__debug__/")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
  end

  # Common exploits
  test "analyze_request detects shell.php" do
    request = create_mock_request("/shell.php")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert_equal :common_exploits, result[:patterns].first[:category]
    assert_equal :critical, result[:highest_severity]
  end

  test "analyze_request detects c99.php" do
    request = create_mock_request("/c99.php")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
  end

  # Legitimate paths should not trigger
  test "analyze_request allows legitimate paths" do
    legitimate_paths = [
      "/",
      "/users",
      "/posts/123",
      "/api/v1/data",
      "/about",
      "/contact"
    ]

    legitimate_paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)

      assert_nil result, "Path #{path} should not trigger WAF"
    end
  end

  test "analyze_request returns nil for blank paths" do
    request = create_mock_request("")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_nil result
  end

  # Violation tracking
  test "record_violation accumulates risk score" do
    ip = "10.0.0.100"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    # WordPress scan has :high severity = 80 points
    score1 = Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 80, score1.round

    score2 = Beskar::Services::Waf.record_violation(ip, analysis)
    assert_in_delta 160, score2, 5 # Allow for slight decay

    score3 = Beskar::Services::Waf.record_violation(ip, analysis)
    assert_in_delta 240, score3, 10 # Allow for more decay
  end

  test "get_violation_count returns number of tracked violations" do
    ip = "10.0.0.101"

    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip)

    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    # Record violations
    Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 1, Beskar::Services::Waf.get_violation_count(ip)

    Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 2, Beskar::Services::Waf.get_violation_count(ip)
  end

  test "reset_violations clears violations" do
    ip = "10.0.0.102"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    # Record some violations
    5.times { Beskar::Services::Waf.record_violation(ip, analysis) }
    assert_equal 5, Beskar::Services::Waf.get_violation_count(ip)

    # Reset should clear them
    Beskar::Services::Waf.reset_violations(ip)
    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip)
  end

  # Auto-blocking
  test "should_block? returns false when score below threshold" do
    ip = "10.0.0.103"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    # High severity = 80 points, threshold is 150
    Beskar::Services::Waf.record_violation(ip, analysis)

    assert_equal false, Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns true when score meets threshold" do
    ip = "10.0.0.104"
    request = create_mock_request("/.env", ip: ip) # Critical = 95 points
    analysis = Beskar::Services::Waf.analyze_request(request)

    # Record two critical violations: 95 + 95 = 190 > 150
    Beskar::Services::Waf.record_violation(ip, analysis)
    Beskar::Services::Waf.record_violation(ip, analysis)

    assert Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns true when score exceeds threshold" do
    ip = "10.0.0.105"
    request = create_mock_request("/.env", ip: ip) # Critical = 95 points
    analysis = Beskar::Services::Waf.analyze_request(request)

    # Record three critical violations: 95 + 95 + 95 = 285 > 150
    3.times { Beskar::Services::Waf.record_violation(ip, analysis) }

    assert Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns false when WAF disabled" do
    Beskar.configuration.waf[:enabled] = false
    ip = "10.0.0.106"
    request = create_mock_request("/.env", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    # Record enough violations to exceed threshold
    3.times { Beskar::Services::Waf.record_violation(ip, analysis) }

    assert_equal false, Beskar::Services::Waf.should_block?(ip)
  end

  test "should_block? returns false when auto_block disabled" do
    Beskar.configuration.waf[:auto_block] = false
    ip = "10.0.0.107"
    request = create_mock_request("/.env", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    # Record enough violations to exceed threshold
    3.times { Beskar::Services::Waf.record_violation(ip, analysis) }

    assert_equal false, Beskar::Services::Waf.should_block?(ip)
  end

  # Security event creation
  test "record_violation creates security event when configured" do
    Beskar.configuration.waf[:create_security_events] = true

    ip = "10.0.0.108"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    assert_difference "Beskar::SecurityEvent.count", 1 do
      Beskar::Services::Waf.record_violation(ip, analysis)
    end

    event = Beskar::SecurityEvent.last
    assert_equal "waf_violation", event.event_type
    assert_equal ip, event.ip_address
    assert event.risk_score >= 80 # high severity
  end

  test "record_violation does not create security event when disabled" do
    Beskar.configuration.waf[:create_security_events] = false

    ip = "10.0.0.109"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    assert_no_difference "Beskar::SecurityEvent.count" do
      Beskar::Services::Waf.record_violation(ip, analysis)
    end
  end

  # Auto-blocking on threshold
  test "record_violation auto-blocks IP after score threshold reached" do
    Beskar.configuration.waf[:auto_block] = true
    Beskar.configuration.waf[:score_threshold] = 150

    ip = "10.0.0.110"
    request = create_mock_request("/.env", ip: ip) # Critical = 95 points
    analysis = Beskar::Services::Waf.analyze_request(request)

    # First violation should not block (95 < 150)
    Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal false, Beskar::BannedIp.banned?(ip)

    # Second violation should trigger block (95 + 95 = 190 > 150)
    assert_difference "Beskar::BannedIp.count", 1 do
      Beskar::Services::Waf.record_violation(ip, analysis)
    end

    assert Beskar::BannedIp.banned?(ip)

    banned_ip = Beskar::BannedIp.find_by(ip_address: ip)
    assert_equal "waf_violation", banned_ip.reason
  end

  # Case sensitivity
  test "analyze_request is case insensitive for patterns" do
    paths = [
      "/WP-ADMIN/index.php",
      "/Wp-Admin/index.php",
      "/wp-ADMIN/index.php"
    ]

    paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)

      assert_not_nil result, "Path #{path} should trigger WAF"
      assert result[:threat_detected]
    end
  end

  # Multiple pattern matching
  test "analyze_request detects multiple patterns in single request" do
    # This path might match both wordpress and path_traversal
    request = create_mock_request("/wp-admin/../../etc/passwd")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil result
    assert result[:threat_detected]
    assert result[:patterns].length >= 1
  end

  # Severity calculation
  test "highest_severity returns critical when critical pattern detected" do
    request = create_mock_request("/.env")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_equal :critical, result[:highest_severity]
  end

  test "highest_severity returns high when only high patterns detected" do
    request = create_mock_request("/wp-admin/")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_equal :high, result[:highest_severity]
  end

  test "highest_severity returns medium when only medium patterns detected" do
    request = create_mock_request("/rails/info/routes")
    result = Beskar::Services::Waf.analyze_request(request)

    assert_equal :medium, result[:highest_severity]
  end

  # Violation window expiry
  test "violations expire after violation_window" do
    Beskar.configuration.waf[:violation_window] = 0.1.seconds

    ip = "10.0.0.111"
    request = create_mock_request("/wp-admin/", ip: ip)
    analysis = Beskar::Services::Waf.analyze_request(request)

    Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 1, Beskar::Services::Waf.get_violation_count(ip)

    sleep(0.2) # Wait for violation window to expire

    # Cache should have expired
    assert_equal 0, Beskar::Services::Waf.get_violation_count(ip)
  end

  # WordPress static files (low severity)
  test "analyze_request detects wp-content static files with low severity" do
    static_paths = [
      "/wp-content/themes/theme/style.css",
      "/wp-content/uploads/2024/image.jpg",
      "/wp-content/uploads/photo.png",
      "/wp-content/plugins/plugin/script.js",
      "/wp-content/themes/theme/font.woff2",
      "/wp-content/uploads/icon.svg"
    ]

    static_paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)

      assert_not_nil result, "Path #{path} should trigger WAF"
      assert result[:threat_detected]
      assert_equal :wordpress_static, result[:patterns].first[:category], "Path #{path} should be wordpress_static"
      assert_equal :low, result[:highest_severity], "Path #{path} should have low severity"
    end
  end

  test "analyze_request detects wp-content PHP files with high severity" do
    # Note: avoid shell.php, c99.php etc. as they match common_exploits (critical)
    php_paths = [
      "/wp-content/plugins/plugin.php",
      "/wp-content/uploads/script.php",
      "/wp-content/themes/functions.php"
    ]

    php_paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)

      assert_not_nil result, "Path #{path} should trigger WAF"
      assert result[:threat_detected]
      assert_includes result[:patterns].map { |p| p[:category] }, :wordpress, "Path #{path} should match wordpress pattern"
      assert_equal :high, result[:highest_severity], "Path #{path} should have high severity"
    end
  end

  test "analyze_request detects path traversal in wp-content with critical severity" do
    # Path traversal should override the low-severity static pattern
    traversal_paths = [
      "/wp-content/../../etc/passwd",
      "/wp-content/uploads/../../../etc/shadow",
      "/wp-content/themes/%2e%2e/config"
    ]

    traversal_paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)

      assert_not_nil result, "Path #{path} should trigger WAF"
      assert result[:threat_detected]
      assert_equal :critical, result[:highest_severity], "Path #{path} should have critical severity due to path traversal"
      assert_includes result[:patterns].map { |p| p[:category] }, :path_traversal, "Path #{path} should match path_traversal"
    end
  end

  test "analyze_request detects wp-content directory listing with low severity" do
    directory_paths = [
      "/wp-content/uploads/",
      "/wp-content/themes/",
      "/wp-content/plugins/"
    ]

    directory_paths.each do |path|
      request = create_mock_request(path)
      result = Beskar::Services::Waf.analyze_request(request)

      assert_not_nil result, "Path #{path} should trigger WAF"
      assert result[:threat_detected]
      assert_equal :low, result[:highest_severity], "Path #{path} should have low severity"
    end
  end

  # Low severity risk score (30 points)
  test "low severity generates 30 point risk score" do
    ip = "10.0.0.120"
    request = create_mock_request("/wp-content/uploads/image.jpg", ip: ip) # Low severity
    analysis = Beskar::Services::Waf.analyze_request(request)

    assert_not_nil analysis
    assert_equal :low, analysis[:highest_severity]

    score = Beskar::Services::Waf.record_violation(ip, analysis)
    assert_equal 30, score.round, "Low severity should contribute 30 points"
  end

  test "low severity requires 5 violations to reach threshold" do
    Beskar.configuration.waf[:score_threshold] = 150

    ip = "10.0.0.121"
    request = create_mock_request("/wp-content/uploads/image.jpg", ip: ip) # Low = 30 points
    analysis = Beskar::Services::Waf.analyze_request(request)

    # 4 violations = 120 points (below 150 threshold)
    4.times { Beskar::Services::Waf.record_violation(ip, analysis) }
    assert_equal false, Beskar::BannedIp.banned?(ip), "4 low-severity violations should not trigger ban"

    # 5th violation = 150 points (meets threshold)
    Beskar::Services::Waf.record_violation(ip, analysis)
    assert Beskar::BannedIp.banned?(ip), "5 low-severity violations should trigger ban"
  end

  test "severity_to_risk_score returns correct values" do
    # Test via the behavior since it's a private method
    severities = {
      critical: 95,
      high: 80,
      medium: 60,
      low: 30
    }

    paths_for_severity = {
      critical: "/.env",
      high: "/wp-admin/",
      medium: "/rails/info/routes",
      low: "/wp-content/uploads/image.jpg"
    }

    severities.each do |severity, expected_score|
      ip = "10.0.0.#{130 + severities.keys.index(severity)}"
      request = create_mock_request(paths_for_severity[severity], ip: ip)
      analysis = Beskar::Services::Waf.analyze_request(request)

      assert_not_nil analysis, "Expected analysis for #{severity} path"
      assert_equal severity, analysis[:highest_severity], "Expected #{severity} severity"

      score = Beskar::Services::Waf.record_violation(ip, analysis)
      assert_equal expected_score, score.round, "#{severity} severity should contribute #{expected_score} points"
    end
  end
end
