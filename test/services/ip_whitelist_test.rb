require "test_helper"

class IpWhitelistTest < ActiveSupport::TestCase
  def setup
    Rails.cache.clear
    # Clear any cached whitelist entries
    Beskar::Services::IpWhitelist.clear_cache!
  end

  def teardown
    # Reset configuration to defaults
    Beskar.configuration.ip_whitelist = []
    Beskar::Services::IpWhitelist.clear_cache!
  end

  test "whitelisted? returns false when whitelist is empty" do
    Beskar.configuration.ip_whitelist = []
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.1.1")
  end

  test "whitelisted? returns false when whitelist is nil" do
    Beskar.configuration.ip_whitelist = nil
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.1.1")
  end

  test "whitelisted? matches single IP address" do
    Beskar.configuration.ip_whitelist = ["192.168.1.100"]

    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.1.101")
  end

  test "whitelisted? matches multiple IP addresses" do
    Beskar.configuration.ip_whitelist = ["192.168.1.100", "10.0.0.50", "172.16.0.1"]

    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")
    assert Beskar::Services::IpWhitelist.whitelisted?("10.0.0.50")
    assert Beskar::Services::IpWhitelist.whitelisted?("172.16.0.1")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.1.101")
  end

  test "whitelisted? matches CIDR notation /24" do
    Beskar.configuration.ip_whitelist = ["192.168.1.0/24"]

    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.1")
    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")
    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.254")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.2.1")
  end

  test "whitelisted? matches CIDR notation /16" do
    Beskar.configuration.ip_whitelist = ["10.0.0.0/16"]

    assert Beskar::Services::IpWhitelist.whitelisted?("10.0.0.1")
    assert Beskar::Services::IpWhitelist.whitelisted?("10.0.255.255")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("10.1.0.1")
  end

  test "whitelisted? matches CIDR notation /32 (single IP)" do
    Beskar.configuration.ip_whitelist = ["192.168.1.100/32"]

    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.1.101")
  end

  test "whitelisted? matches mixed individual IPs and CIDR ranges" do
    Beskar.configuration.ip_whitelist = [
      "192.168.1.100",           # Single IP
      "10.0.0.0/24",             # /24 range
      "172.16.0.0/16"            # /16 range
    ]

    # Individual IP
    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.1.101")

    # /24 range
    assert Beskar::Services::IpWhitelist.whitelisted?("10.0.0.1")
    assert Beskar::Services::IpWhitelist.whitelisted?("10.0.0.255")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("10.0.1.1")

    # /16 range
    assert Beskar::Services::IpWhitelist.whitelisted?("172.16.0.1")
    assert Beskar::Services::IpWhitelist.whitelisted?("172.16.255.255")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("172.17.0.1")
  end

  test "whitelisted? handles IPv6 addresses" do
    Beskar.configuration.ip_whitelist = ["2001:db8::1"]

    assert Beskar::Services::IpWhitelist.whitelisted?("2001:db8::1")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("2001:db8::2")
  end

  test "whitelisted? handles IPv6 CIDR notation" do
    Beskar.configuration.ip_whitelist = ["2001:db8::/32"]

    assert Beskar::Services::IpWhitelist.whitelisted?("2001:db8::1")
    assert Beskar::Services::IpWhitelist.whitelisted?("2001:db8:ffff::1")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("2001:db9::1")
  end

  test "whitelisted? returns false for invalid IP addresses" do
    Beskar.configuration.ip_whitelist = ["192.168.1.100"]

    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("invalid-ip")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("999.999.999.999")
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?(nil)
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("")
  end

  test "whitelisted? handles whitespace in IP addresses" do
    Beskar.configuration.ip_whitelist = ["192.168.1.100"]

    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100  ")
    assert Beskar::Services::IpWhitelist.whitelisted?("  192.168.1.100")
    assert Beskar::Services::IpWhitelist.whitelisted?(" 192.168.1.100 ")
  end

  test "validate_configuration! passes with valid configuration" do
    Beskar.configuration.ip_whitelist = [
      "192.168.1.100",
      "10.0.0.0/24",
      "172.16.0.0/16"
    ]

    assert_nothing_raised do
      Beskar::Services::IpWhitelist.validate_configuration!
    end
  end

  test "validate_configuration! raises error for invalid IP" do
    Beskar.configuration.ip_whitelist = ["invalid-ip"]

    error = assert_raises(Beskar::Services::IpWhitelist::ConfigurationError) do
      Beskar::Services::IpWhitelist.validate_configuration!
    end

    assert_match(/invalid ip/i, error.message)
  end

  test "validate_configuration! raises error for invalid CIDR" do
    Beskar.configuration.ip_whitelist = ["192.168.1.0/999"]

    error = assert_raises(Beskar::Services::IpWhitelist::ConfigurationError) do
      Beskar::Services::IpWhitelist.validate_configuration!
    end

    assert_match(/Entry 0/i, error.message)
  end

  test "clear_cache! clears cached entries" do
    Beskar.configuration.ip_whitelist = ["192.168.1.100"]

    # First check should cache the result
    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")

    # Change configuration
    Beskar.configuration.ip_whitelist = ["10.0.0.1"]

    # Without clearing cache, old config might still be used
    Beskar::Services::IpWhitelist.clear_cache!

    # Now should use new configuration
    assert_equal false, Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")
    assert Beskar::Services::IpWhitelist.whitelisted?("10.0.0.1")
  end

  test "whitelist_entries returns array" do
    Beskar.configuration.ip_whitelist = ["192.168.1.100"]

    entries = Beskar::Services::IpWhitelist.whitelist_entries
    assert_instance_of Array, entries
    assert_equal ["192.168.1.100"], entries
  end

  test "whitelist_entries handles string configuration" do
    # In case someone sets it as a string instead of array
    Beskar.configuration.ip_whitelist = "192.168.1.100"

    entries = Beskar::Services::IpWhitelist.whitelist_entries
    assert_instance_of Array, entries
  end

  test "whitelisted? handles overlapping ranges" do
    Beskar.configuration.ip_whitelist = [
      "192.168.1.0/24",
      "192.168.1.100"   # This is already in the /24 range
    ]

    # Should still work correctly
    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.100")
    assert Beskar::Services::IpWhitelist.whitelisted?("192.168.1.50")
  end

  test "whitelisted? performance with multiple ranges" do
    # Test with many ranges to ensure performance is acceptable
    ranges = (1..50).map { |i| "10.#{i}.0.0/24" }
    Beskar.configuration.ip_whitelist = ranges

    # Should be fast even with many ranges
    start_time = Time.now
    100.times do
      Beskar::Services::IpWhitelist.whitelisted?("10.25.0.100")
    end
    elapsed = Time.now - start_time

    # Should complete in reasonable time (adjust threshold as needed)
    assert elapsed < 1.0, "Whitelist checking took too long: #{elapsed}s"
  end
end
