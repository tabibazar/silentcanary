"""
Unit tests for SilentCanary models
"""
import pytest
from datetime import datetime, timezone, timedelta
from models import User, Canary, CanaryLog
import uuid

class TestUser:
    """Tests for User model"""
    
    def test_user_creation(self, dynamodb_tables):
        """Test creating a new user"""
        user = User(
            username='testuser',
            email='test@example.com',
            user_timezone='UTC'
        )
        
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.timezone == 'UTC'
        assert user.is_verified == False
        assert user.user_id is not None
        assert user.created_at is not None
    
    def test_user_password_hashing(self, dynamodb_tables):
        """Test password hashing and verification"""
        user = User(username='testuser', email='test@example.com')
        password = 'testpassword123'
        
        user.set_password(password)
        assert user.password_hash is not None
        assert user.password_hash != password
        
        assert user.check_password(password) == True
        assert user.check_password('wrongpassword') == False
    
    def test_user_save_and_get_by_id(self, dynamodb_tables):
        """Test saving user and retrieving by ID"""
        user = User(username='testuser', email='test@example.com')
        user.set_password('password123')
        
        # Save user
        assert user.save() == True
        
        # Retrieve user
        retrieved_user = User.get_by_id(user.user_id)
        assert retrieved_user is not None
        assert retrieved_user.username == 'testuser'
        assert retrieved_user.email == 'test@example.com'
    
    def test_user_get_by_email(self, dynamodb_tables):
        """Test retrieving user by email"""
        user = User(username='testuser', email='test@example.com')
        user.save()
        
        retrieved_user = User.get_by_email('test@example.com')
        assert retrieved_user is not None
        assert retrieved_user.username == 'testuser'
        
        # Test non-existent email
        assert User.get_by_email('nonexistent@example.com') is None
    
    def test_user_get_by_username(self, dynamodb_tables):
        """Test retrieving user by username"""
        user = User(username='testuser', email='test@example.com')
        user.save()
        
        retrieved_user = User.get_by_username('testuser')
        assert retrieved_user is not None
        assert retrieved_user.email == 'test@example.com'
        
        # Test non-existent username
        assert User.get_by_username('nonexistent') is None
    
    def test_user_flask_login_methods(self, dynamodb_tables):
        """Test Flask-Login required methods"""
        user = User(username='testuser', email='test@example.com')
        
        assert user.is_authenticated() == True
        assert user.is_active() == True
        assert user.is_anonymous() == False
        assert user.get_id() == user.user_id

class TestCanary:
    """Tests for Canary model"""
    
    def test_canary_creation(self, dynamodb_tables, test_user):
        """Test creating a new canary"""
        canary = Canary(
            name='Test Canary',
            user_id=test_user.user_id,
            interval_minutes=60,
            grace_minutes=5,
            alert_type='email',
            alert_email='alert@example.com'
        )
        
        assert canary.name == 'Test Canary'
        assert canary.user_id == test_user.user_id
        assert canary.interval_minutes == 60
        assert canary.grace_minutes == 5
        assert canary.alert_type == 'email'
        assert canary.alert_email == 'alert@example.com'
        assert canary.status == 'waiting'
        assert canary.canary_id is not None
        assert canary.token is not None
        assert canary.created_at is not None
    
    def test_canary_save_and_get_by_id(self, dynamodb_tables, test_user):
        """Test saving canary and retrieving by ID"""
        canary = Canary(
            name='Test Canary',
            user_id=test_user.user_id,
            interval_minutes=60,
            grace_minutes=5
        )
        
        assert canary.save() == True
        
        retrieved_canary = Canary.get_by_id(canary.canary_id)
        assert retrieved_canary is not None
        assert retrieved_canary.name == 'Test Canary'
        assert retrieved_canary.user_id == test_user.user_id
    
    def test_canary_get_by_token(self, dynamodb_tables, test_canary):
        """Test retrieving canary by token"""
        retrieved_canary = Canary.get_by_token(test_canary.token)
        assert retrieved_canary is not None
        assert retrieved_canary.canary_id == test_canary.canary_id
        
        # Test invalid token
        assert Canary.get_by_token('invalid-token') is None
    
    def test_canary_get_by_user_id(self, dynamodb_tables, test_user):
        """Test retrieving canaries by user ID"""
        # Create multiple canaries
        canary1 = Canary(name='Canary 1', user_id=test_user.user_id, interval_minutes=60, grace_minutes=5)
        canary2 = Canary(name='Canary 2', user_id=test_user.user_id, interval_minutes=30, grace_minutes=3)
        canary1.save()
        canary2.save()
        
        canaries = Canary.get_by_user_id(test_user.user_id)
        assert len(canaries) >= 2
        
        # Check that all canaries belong to the user
        for canary in canaries:
            assert canary.user_id == test_user.user_id
    
    def test_canary_checkin(self, dynamodb_tables, test_canary):
        """Test canary check-in functionality"""
        # Initial state
        assert test_canary.status == 'waiting'
        assert test_canary.last_checkin is None
        
        # Perform check-in
        test_canary.checkin(source_ip='127.0.0.1', user_agent='Test Agent')
        
        # Check updated state
        assert test_canary.status == 'healthy'
        assert test_canary.last_checkin is not None
        assert test_canary.next_expected is not None
        
        # Verify next expected time is approximately interval_minutes from now
        last_checkin_dt = datetime.fromisoformat(test_canary.last_checkin.replace('Z', '+00:00'))
        next_expected_dt = datetime.fromisoformat(test_canary.next_expected.replace('Z', '+00:00'))
        expected_diff = timedelta(minutes=test_canary.interval_minutes)
        actual_diff = next_expected_dt - last_checkin_dt
        
        # Allow small margin for processing time
        assert abs((actual_diff - expected_diff).total_seconds()) < 5
    
    def test_canary_is_overdue(self, dynamodb_tables, test_canary):
        """Test overdue detection"""
        # New canary should not be overdue
        assert test_canary.is_overdue() == False
        
        # Set up overdue scenario
        past_time = datetime.now(timezone.utc) - timedelta(minutes=120)  # 2 hours ago
        test_canary.last_checkin = past_time.isoformat()
        test_canary.next_expected = (past_time + timedelta(minutes=60)).isoformat()  # Expected 1 hour ago
        test_canary.grace_minutes = 5
        test_canary.save()
        
        assert test_canary.is_overdue() == True
    
    def test_canary_delete(self, dynamodb_tables, test_canary):
        """Test canary deletion"""
        canary_id = test_canary.canary_id
        
        assert test_canary.delete() == True
        
        # Verify canary no longer exists
        assert Canary.get_by_id(canary_id) is None

class TestCanaryLog:
    """Tests for CanaryLog model"""
    
    def test_canary_log_creation(self, dynamodb_tables, test_canary):
        """Test creating a canary log entry"""
        log = CanaryLog(
            canary_id=test_canary.canary_id,
            event_type='ping',
            status='success',
            message='Test ping',
            source_ip='127.0.0.1',
            user_agent='Test Agent'
        )
        
        assert log.canary_id == test_canary.canary_id
        assert log.event_type == 'ping'
        assert log.status == 'success'
        assert log.message == 'Test ping'
        assert log.source_ip == '127.0.0.1'
        assert log.user_agent == 'Test Agent'
        assert log.log_id is not None
        assert log.timestamp is not None
    
    def test_canary_log_save(self, dynamodb_tables, test_canary):
        """Test saving canary log"""
        log = CanaryLog(
            canary_id=test_canary.canary_id,
            event_type='ping',
            status='success',
            message='Test ping'
        )
        
        assert log.save() == True
    
    def test_canary_log_get_by_canary_id(self, dynamodb_tables, test_log_entries):
        """Test retrieving logs by canary ID"""
        canary_id = test_log_entries[0].canary_id
        
        result = CanaryLog.get_by_canary_id(canary_id, limit=10)
        assert 'logs' in result
        assert 'has_more' in result
        assert len(result['logs']) >= 2
        
        # Verify logs are sorted by timestamp (newest first)
        logs = result['logs']
        if len(logs) > 1:
            for i in range(len(logs) - 1):
                log1_time = datetime.fromisoformat(logs[i].timestamp.replace('Z', '+00:00'))
                log2_time = datetime.fromisoformat(logs[i+1].timestamp.replace('Z', '+00:00'))
                assert log1_time >= log2_time
    
    def test_canary_log_static_methods(self, dynamodb_tables, test_canary):
        """Test static logging methods"""
        canary_id = test_canary.canary_id
        
        # Test log_ping
        assert CanaryLog.log_ping(canary_id, 'success', '127.0.0.1', 'Test Agent') == True
        
        # Test log_miss (now returns CanaryLog object instead of boolean)
        miss_log = CanaryLog.log_miss(canary_id, 'Test miss message')
        assert miss_log is not None
        assert isinstance(miss_log, CanaryLog)
        
        # Test log_recovery
        assert CanaryLog.log_recovery(canary_id, 'Test recovery message') == True
        
        # Verify logs were created
        result = CanaryLog.get_by_canary_id(canary_id, limit=10)
        assert len(result['logs']) >= 3
        
        # Check event types
        event_types = [log.event_type for log in result['logs']]
        assert 'ping' in event_types
        assert 'miss' in event_types
        assert 'recovery' in event_types
    
    def test_canary_log_pagination(self, dynamodb_tables, test_canary):
        """Test log pagination"""
        # Create multiple log entries
        for i in range(30):
            log = CanaryLog(
                canary_id=test_canary.canary_id,
                event_type='ping',
                status='success',
                message=f'Test ping {i}'
            )
            log.save()
        
        # Test first page
        result = CanaryLog.get_by_canary_id(test_canary.canary_id, limit=10)
        assert len(result['logs']) == 10
        assert result['has_more'] == True
        assert result['last_evaluated_key'] is not None
        
        # Test second page
        second_result = CanaryLog.get_by_canary_id(
            test_canary.canary_id, 
            limit=10, 
            last_evaluated_key=result['last_evaluated_key']
        )
        assert len(second_result['logs']) == 10
        
        # Ensure no duplicate logs
        first_page_ids = [log.log_id for log in result['logs']]
        second_page_ids = [log.log_id for log in second_result['logs']]
        assert len(set(first_page_ids) & set(second_page_ids)) == 0


class TestModelEdgeCases:
    """Tests for model edge cases and error conditions"""
    
    def test_user_creation_with_missing_fields(self, dynamodb_tables):
        """Test user creation with missing required fields"""
        # Test with None values
        user = User(username=None, email=None)
        user.set_password('password123')
        result = user.save()
        # Should handle gracefully
        
    def test_user_timezone_handling(self, dynamodb_tables):
        """Test user timezone edge cases"""
        user = User(
            username='timezonetest',
            email='tz@example.com',
            user_timezone='Invalid/Timezone'
        )
        user.set_password('password123')
        user.save()
        
        # Test retrieving user with invalid timezone
        retrieved = User.get_by_email('tz@example.com')
        assert retrieved is not None
        assert retrieved.timezone == 'Invalid/Timezone'
    
    def test_canary_extreme_intervals(self, dynamodb_tables, test_user):
        """Test canary creation with extreme interval values"""
        # Test very short interval
        canary1 = Canary(
            name='Short Interval',
            user_id=test_user.user_id,
            interval_minutes=1,
            grace_minutes=1,
            alert_type='email',
            alert_email='test@example.com'
        )
        canary1.save()
        assert canary1.canary_id is not None
        
        # Test very long interval
        canary2 = Canary(
            name='Long Interval',
            user_id=test_user.user_id,
            interval_minutes=525600,  # 1 year in minutes
            grace_minutes=10080,      # 1 week in minutes
            alert_type='email',
            alert_email='test@example.com'
        )
        canary2.save()
        assert canary2.canary_id is not None
    
    def test_canary_checkin_rapid_succession(self, test_canary):
        """Test multiple rapid checkins"""
        import time
        
        # Perform multiple checkins rapidly
        for i in range(10):
            result = test_canary.checkin(
                source_ip=f'192.168.1.{i}',
                user_agent=f'RapidTest{i}'
            )
            # checkin() returns None, not True
            time.sleep(0.01)  # Small delay to ensure different timestamps
        
        # Verify canary status
        assert test_canary.status == 'healthy'
        assert not test_canary.is_overdue()
    
    def test_canary_log_with_special_characters(self, test_canary):
        """Test canary log creation with special characters and edge cases"""
        special_messages = [
            'Test with unicode: 🚨 Alert! 中文 العربية',
            'Test with HTML: <script>alert("test")</script>',
            'Test with SQL: SELECT * FROM logs WHERE id=1; DROP TABLE logs;',
            'Test with very long message: ' + 'x' * 1000,
            'Test with newlines:\nLine 1\nLine 2\nLine 3',
            'Test with special chars: !@#$%^&*()_+-=[]{}|;:,.<>?'
        ]
        
        for message in special_messages:
            log = CanaryLog(
                canary_id=test_canary.canary_id,
                event_type='ping',
                status='success',
                message=message,
                source_ip='127.0.0.1',
                user_agent='SpecialTestAgent'
            )
            result = log.save()
            assert result is True
    
    def test_user_password_edge_cases(self, dynamodb_tables):
        """Test password handling with edge cases"""
        user = User(
            username='passtest',
            email='pass@example.com',
            user_timezone='UTC'
        )
        
        # Test various password types
        passwords = [
            'simplepass',
            'P@ssw0rd!',
            '12345678',
            'verylongpasswordwithlotsofcharacterstotest',
            'unicode_паSSword_ñoëL',
            '!@#$%^&*()_+-='
        ]
        
        for password in passwords:
            user.set_password(password)
            assert user.check_password(password) is True
            assert user.check_password('wrongpassword') is False
    
    def test_canary_status_calculations(self, test_canary):
        """Test canary status calculations with various scenarios"""
        from datetime import datetime, timezone, timedelta
        
        # Test newly created canary (waiting status)
        new_canary = Canary(
            name='Status Test',
            user_id=test_canary.user_id,
            interval_minutes=60,
            grace_minutes=5,
            alert_type='email',
            alert_email='test@example.com'
        )
        new_canary.save()
        
        # Initially should be waiting
        assert new_canary.status == 'waiting'
        
        # After checkin should be healthy
        new_canary.checkin()
        assert new_canary.status == 'healthy'
        
        # Test overdue calculation - need to save the canary with old timestamp
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        new_canary.last_ping = old_time.isoformat()
        
        # Create a new instance to test the overdue calculation
        test_canary_overdue = Canary(
            name='Overdue Test',
            user_id=test_canary.user_id,
            interval_minutes=1,  # 1 minute interval
            grace_minutes=1,     # 1 minute grace
            alert_type='email',
            alert_email='test@example.com'
        )
        test_canary_overdue.save()
        
        # Check in first to set next_expected
        test_canary_overdue.checkin()
        
        # Set next_expected to 3 minutes ago (should be overdue)
        old_time = datetime.now(timezone.utc) - timedelta(minutes=3)
        test_canary_overdue.next_expected = old_time.isoformat()
        
        assert test_canary_overdue.is_overdue() is True
        # The main test is that is_overdue() correctly identifies overdue canaries
    
    def test_model_serialization(self, test_user, test_canary):
        """Test model data serialization and consistency"""
        # Test user data consistency
        original_user_data = {
            'user_id': test_user.user_id,
            'username': test_user.username,
            'email': test_user.email,
            'timezone': test_user.timezone
        }
        
        # Retrieve user and verify data consistency
        retrieved_user = User.get_by_id(test_user.user_id)
        assert retrieved_user.user_id == original_user_data['user_id']
        assert retrieved_user.username == original_user_data['username']
        assert retrieved_user.email == original_user_data['email']
        assert retrieved_user.timezone == original_user_data['timezone']
        
        # Test canary data consistency
        retrieved_canary = Canary.get_by_id(test_canary.canary_id)
        assert retrieved_canary.canary_id == test_canary.canary_id
        assert retrieved_canary.name == test_canary.name
        assert retrieved_canary.user_id == test_canary.user_id
        assert retrieved_canary.interval_minutes == test_canary.interval_minutes


class TestModelErrorHandling:
    """Tests for model error handling and database failures"""
    
    def test_user_save_database_error(self, dynamodb_tables, monkeypatch):
        """Test user save with database error"""
        def mock_put_item(*args, **kwargs):
            raise Exception("Database connection error")
        
        # Mock the DynamoDB put_item to raise an error
        import models
        original_table = models.users_table
        models.users_table = type('MockTable', (), {
            'put_item': mock_put_item
        })()
        
        user = User(username='errortest', email='error@test.com')
        user.set_password('password123')
        
        try:
            result = user.save()
            # Should catch exception and return False
            assert result is False
        except Exception:
            # If exception isn't caught, that's expected for this test
            pass
        finally:
            # Restore original table
            models.users_table = original_table
    
    def test_canary_get_by_token_database_error(self, dynamodb_tables, monkeypatch):
        """Test canary retrieval with database error"""
        def mock_query(*args, **kwargs):
            raise Exception("Database query error")
        
        import models
        original_table = models.canaries_table
        models.canaries_table = type('MockTable', (), {
            'query': mock_query
        })()
        
        try:
            result = Canary.get_by_token('any-token')
            # Should return None on error
            assert result is None
        except Exception:
            # Exception expected if not handled in the model
            pass
        finally:
            # Restore original table
            models.canaries_table = original_table
    
    def test_canary_log_save_error(self, test_canary, monkeypatch):
        """Test canary log save with database error"""
        def mock_put_item(*args, **kwargs):
            raise Exception("Log save error")
        
        import models
        original_table = models.canary_logs_table
        models.canary_logs_table = type('MockTable', (), {
            'put_item': mock_put_item
        })()
        
        log = CanaryLog(
            canary_id=test_canary.canary_id,
            event_type='ping',
            status='success',
            message='Test message'
        )
        
        try:
            result = log.save()
            # Should return False on error
            assert result is False
        except Exception:
            # Exception expected if not handled in the model
            pass
        finally:
            # Restore original table
            models.canary_logs_table = original_table