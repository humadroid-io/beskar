require 'test_helper'
require 'ostruct'

class WardenSignoutTest < ActionDispatch::IntegrationTest
  setup do
    @user = DeviseUser.create!(
      email: 'warden_test@example.com',
      password: 'password123',
      password_confirmation: 'password123'
    )

    # Configure for high-risk locking
    Beskar.configuration = Beskar::Configuration.new
    Beskar.configuration.security_tracking[:enabled] = true
    Beskar.configuration.risk_based_locking[:enabled] = true
    Beskar.configuration.risk_based_locking[:risk_threshold] = 40  # Very sensitive
    Beskar.configuration.risk_based_locking[:log_lock_events] = true
    
    Beskar::SecurityEvent.delete_all
  end

  teardown do
    @user&.destroy
    Beskar::SecurityEvent.delete_all
  end

  test "user_was_just_locked? detects recent lock events" do
    # Create a security event (simulating authentication)
    security_event = @user.security_events.create!(
      event_type: 'login_success',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 50
    )

    # Create a lock event
    @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 85
    )

    # Should detect the recent lock
    assert Beskar::Engine.user_was_just_locked?(@user, security_event), 
      "Should detect lock event created within 10 seconds"
  end

  test "user_was_just_locked? ignores old lock events" do
    security_event = @user.security_events.create!(
      event_type: 'login_success',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 50
    )

    # Create an old lock event
    old_lock = @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 85,
      created_at: 1.minute.ago
    )

    # Update the timestamp to be old (can't set in create! due to ActiveRecord)
    old_lock.update_column(:created_at, 1.minute.ago)

    # Should NOT detect old locks
    assert_not Beskar::Engine.user_was_just_locked?(@user, security_event),
      "Should ignore lock events older than 10 seconds"
  end

  test "user_was_just_locked? returns false when locking disabled" do
    Beskar.configuration.risk_based_locking[:enabled] = false

    security_event = @user.security_events.create!(
      event_type: 'login_success',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 50
    )

    @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 85
    )

    assert_not Beskar::Engine.user_was_just_locked?(@user, security_event),
      "Should return false when risk-based locking is disabled"
  end

  test "user_was_just_locked? handles nil security_event" do
    assert_not Beskar::Engine.user_was_just_locked?(@user, nil),
      "Should handle nil security event gracefully"
  end

  test "check_high_risk_lock_and_signout detects recent locks" do
    # Create recent lock event
    @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 85
    )

    # Create mock Warden auth object
    mock_auth = OpenStruct.new(logout_called: false)
    def mock_auth.logout
      self.logout_called = true
    end

    # Should throw :warden when lock detected
    assert_throws(:warden) do
      @user.check_high_risk_lock_and_signout(mock_auth)
    end

    # Verify logout was called
    assert mock_auth.logout_called, "logout should have been called"
  end

  test "check_high_risk_lock_and_signout ignores old locks" do
    # Create old lock event
    old_lock = @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 85,
      created_at: 10.seconds.ago
    )
    old_lock.update_column(:created_at, 10.seconds.ago)

    # Create mock auth
    mock_auth = Object.new

    # Should not throw or call logout
    assert_nothing_raised do
      @user.check_high_risk_lock_and_signout(mock_auth)
    end
  end

  test "check_high_risk_lock_and_signout respects configuration" do
    Beskar.configuration.risk_based_locking[:enabled] = false

    # Create recent lock
    @user.security_events.create!(
      event_type: 'account_locked',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 85
    )

    mock_auth = Object.new

    # Should not throw when disabled
    assert_nothing_raised do
      @user.check_high_risk_lock_and_signout(mock_auth)
    end
  end

  test "lock_attempted events also trigger signout" do
    # Even if lock fails, attempted lock should trigger signout
    @user.security_events.create!(
      event_type: 'lock_attempted',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 85
    )

    mock_auth = OpenStruct.new(logout_called: false)
    def mock_auth.logout
      self.logout_called = true
    end

    assert_throws(:warden) do
      @user.check_high_risk_lock_and_signout(mock_auth)
    end

    assert mock_auth.logout_called, "logout should have been called"
  end

  test "multiple lock events within window all trigger detection" do
    security_event = @user.security_events.create!(
      event_type: 'login_success',
      ip_address: '203.0.113.1',
      user_agent: 'Test',
      risk_score: 50
    )

    # Create multiple lock events
    3.times do
      @user.security_events.create!(
        event_type: 'account_locked',
        ip_address: '203.0.113.1',
        user_agent: 'Test',
        risk_score: 85
      )
    end

    # Should detect at least one
    assert Beskar::Engine.user_was_just_locked?(@user, security_event)
  end

  test "user without security_events association handled gracefully" do
    # Create a simple object without the association
    simple_user = Object.new

    assert_nothing_raised do
      result = Beskar::Engine.user_was_just_locked?(simple_user, nil)
      assert_not result
    end
  end
end
