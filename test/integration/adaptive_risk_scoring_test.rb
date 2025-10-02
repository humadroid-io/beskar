require 'test_helper'
require 'ostruct'

class AdaptiveRiskScoringTest < ActionDispatch::IntegrationTest
  setup do
    @user = DeviseUser.create!(
      email: 'adaptive@example.com',
      password: 'password123',
      password_confirmation: 'password123'
    )

    # Reset configuration
    Beskar.configuration = Beskar::Configuration.new
    Beskar.configuration.security_tracking[:enabled] = true
    Beskar.configuration.risk_based_locking[:enabled] = true
    Beskar.configuration.risk_based_locking[:risk_threshold] = 50
    Beskar.configuration.risk_based_locking[:log_lock_events] = true
    
    # Clear security events
    Beskar::SecurityEvent.delete_all
  end

  teardown do
    @user&.destroy
    Beskar::SecurityEvent.delete_all
  end

  test "should reduce risk score for established login patterns" do
    test_ip = '203.0.113.100'
    
    # Create historical successful logins from this IP (establish pattern)
    3.times do |i|
      @user.security_events.create!(
        event_type: 'login_success',
        ip_address: test_ip,
        user_agent: 'Mozilla/5.0',
        risk_score: 10,
        created_at: (10 - i).days.ago
      )
    end

    # Create a mock request
    mock_request = OpenStruct.new(
      ip: test_ip,
      user_agent: 'Mozilla/5.0',
      session: OpenStruct.new(id: 'test_session'),
      path: '/devise_users/sign_in',
      referer: nil,
      headers: { 'Accept-Language' => 'en', 'X-Forwarded-For' => nil, 'X-Real-IP' => nil }
    )

    # Check that pattern is established
    assert @user.send(:established_pattern?, mock_request), "Pattern should be established"
    
    # Calculate risk score - should be reduced
    # Base risk would be higher, but established pattern reduces it
    risk_score = @user.send(:calculate_risk_score, mock_request, :success)
    
    # With established pattern, risk should be significantly reduced
    assert risk_score < 30, "Risk score should be reduced for established pattern, got #{risk_score}"
  end

  test "should recognize location as established after multiple logins" do
    test_ip = '203.0.113.200'
    
    # Create 2 successful logins from this IP
    2.times do |i|
      @user.security_events.create!(
        event_type: 'login_success',
        ip_address: test_ip,
        user_agent: 'Mozilla/5.0',
        risk_score: 10,
        created_at: (5 - i).days.ago
      )
    end

    # Location should be established
    assert @user.send(:location_established?, test_ip), "Location should be established after 2+ logins"
    
    # New IP should not be established
    assert_not @user.send(:location_established?, '203.0.113.201'), "New IP should not be established"
  end

  test "should establish pattern after unlock and successful login" do
    test_ip = '203.0.113.150'
    
    # User was locked from this IP
    @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: test_ip,
      user_agent: 'Mozilla/5.0',
      risk_score: 80,
      created_at: 2.days.ago
    )

    # User unlocked their account
    @user.security_events.create!(
      event_type: 'account_unlocked',
      ip_address: 'system',
      user_agent: 'system',
      risk_score: 0,
      created_at: 2.days.ago + 1.hour
    )

    # User successfully logged in from same IP after unlock
    @user.security_events.create!(
      event_type: 'login_success',
      ip_address: test_ip,
      user_agent: 'Mozilla/5.0',
      risk_score: 5,
      created_at: 2.days.ago + 2.hours
    )

    # Add one more older login to meet minimum threshold
    @user.security_events.create!(
      event_type: 'login_success',
      ip_address: test_ip,
      user_agent: 'Mozilla/5.0',
      risk_score: 10,
      created_at: 5.days.ago
    )

    # Create mock request
    mock_request = OpenStruct.new(ip: test_ip, user_agent: 'Mozilla/5.0')

    # Pattern should be established because user unlocked and logged in successfully
    assert @user.send(:established_pattern?, mock_request), 
      "Pattern should be established after unlock + successful login from same IP"
  end

  test "should not establish pattern with insufficient historical data" do
    test_ip = '203.0.113.250'
    
    # Only 1 successful login (not enough)
    @user.security_events.create!(
      event_type: 'login_success',
      ip_address: test_ip,
      user_agent: 'Mozilla/5.0',
      risk_score: 10,
      created_at: 5.days.ago
    )

    mock_request = OpenStruct.new(ip: test_ip)

    assert_not @user.send(:established_pattern?, mock_request), 
      "Pattern should not be established with only 1 login"
  end

  test "should not establish pattern for old historical data" do
    test_ip = '203.0.113.251'
    
    # 3 logins but all older than 30 days
    3.times do |i|
      @user.security_events.create!(
        event_type: 'login_success',
        ip_address: test_ip,
        user_agent: 'Mozilla/5.0',
        risk_score: 10,
        created_at: (35 + i).days.ago
      )
    end

    mock_request = OpenStruct.new(ip: test_ip)

    assert_not @user.send(:established_pattern?, mock_request), 
      "Pattern should not be established with data older than 30 days"
  end

  test "lock events should always be logged even if locking fails" do
    # Disable actual locking but keep logging
    Beskar.configuration.risk_based_locking[:lock_strategy] = :devise_lockable
    
    initial_event_count = @user.security_events.count

    locker = Beskar::Services::AccountLocker.new(
      @user,
      risk_score: 85,
      reason: :high_risk_authentication,
      metadata: { ip_address: '203.0.113.1', user_agent: 'Test' }
    )

    # Attempt to lock (will fail because :lockable not enabled in test)
    locker.lock!

    # Event should still be created (as 'lock_attempted')
    assert_equal initial_event_count + 1, @user.security_events.count, 
      "Lock event should be created even if actual locking fails"
    
    last_event = @user.security_events.last
    assert_includes ['account_locked', 'lock_attempted'], last_event.event_type
  end

  test "unlock events should be logged for adaptive learning" do
    initial_count = @user.security_events.count

    locker = Beskar::Services::AccountLocker.new(
      @user,
      risk_score: 0,
      metadata: { ip_address: '203.0.113.1' }
    )

    # Mock unlock (won't actually unlock without :lockable)
    # But we can test the unlock event logging directly
    locker.send(:log_unlock_event)

    assert_equal initial_count + 1, @user.security_events.count
    
    unlock_event = @user.security_events.last
    assert_equal 'account_unlocked', unlock_event.event_type
    assert_equal 0, unlock_event.risk_score
  end

  test "adaptive learning flow - lock, unlock, successful login reduces risk" do
    test_ip = '203.0.113.175'
    
    # Step 1: Create some historical data
    @user.security_events.create!(
      event_type: 'login_success',
      ip_address: test_ip,
      user_agent: 'Mozilla/5.0',
      risk_score: 10,
      created_at: 10.days.ago
    )

    # Step 2: Simulate a lock event (high risk detected)
    @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: test_ip,
      user_agent: 'Mozilla/5.0',
      risk_score: 85,
      created_at: 1.day.ago,
      metadata: { reason: :geographic_anomaly }
    )

    # Step 3: User unlocks account
    @user.security_events.create!(
      event_type: 'account_unlocked',
      ip_address: 'system',
      user_agent: 'system',
      risk_score: 0,
      created_at: 1.day.ago + 1.hour
    )

    # Step 4: User successfully logs in from same IP
    @user.security_events.create!(
      event_type: 'login_success',
      ip_address: test_ip,
      user_agent: 'Mozilla/5.0',
      risk_score: 20,
      created_at: 1.day.ago + 2.hours
    )

    # Step 5: Now simulate another login from same IP
    mock_request = OpenStruct.new(
      ip: test_ip,
      user_agent: 'Mozilla/5.0',
      session: OpenStruct.new(id: 'test'),
      path: '/devise_users/sign_in',
      referer: nil,
      headers: { 'Accept-Language' => 'en', 'X-Forwarded-For' => nil, 'X-Real-IP' => nil }
    )

    # Pattern should be established (unlock + successful login from same IP)
    assert @user.send(:established_pattern?, mock_request), 
      "Pattern should be established after unlock + successful login"

    # Calculate risk - should be significantly reduced
    risk_score = @user.send(:calculate_risk_score, mock_request, :success)
    
    # Risk should be reduced to <= 25 (30% of base + adjustments, capped)
    assert risk_score <= 25, 
      "Risk score should be <= 25 for established pattern after unlock, got #{risk_score}"
  end

  test "location should not be established from different IP" do
    established_ip = '203.0.113.1'
    different_ip = '203.0.113.2'
    
    # Establish pattern for first IP
    3.times do |i|
      @user.security_events.create!(
        event_type: 'login_success',
        ip_address: established_ip,
        user_agent: 'Mozilla/5.0',
        risk_score: 10,
        created_at: (10 - i).days.ago
      )
    end

    # First IP should be established
    assert @user.send(:location_established?, established_ip)
    
    # Different IP should not be established
    assert_not @user.send(:location_established?, different_ip)
  end
end
