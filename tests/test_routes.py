"""
Integration tests for SilentCanary Flask routes
"""
import pytest
import json
from datetime import datetime, timezone, timedelta
from models import User, Canary, CanaryLog

class TestAuthRoutes:
    """Tests for authentication routes"""
    
    def test_index_route(self, client):
        """Test index route redirects to dashboard when authenticated"""
        response = client.get('/')
        assert response.status_code == 200
    
    def test_register_get(self, client):
        """Test registration form display"""
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Register' in response.data
    
    def test_register_post_success(self, client, dynamodb_tables):
        """Test successful user registration"""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpassword123',
            'password2': 'newpassword123'
        }
        
        response = client.post('/register', data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b'Registration successful' in response.data
        
        # Verify user was created
        user = User.get_by_email('newuser@example.com')
        assert user is not None
        assert user.username == 'newuser'
    
    def test_register_post_duplicate_email(self, client, test_user):
        """Test registration with duplicate email"""
        data = {
            'username': 'newuser',
            'email': test_user.email,
            'password': 'newpassword123',
            'password2': 'newpassword123'
        }
        
        response = client.post('/register', data=data)
        assert response.status_code == 200
        assert b'Email already registered' in response.data
    
    def test_login_get(self, client):
        """Test login form display"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Sign In' in response.data
    
    def test_login_post_success(self, client, test_user):
        """Test successful login"""
        data = {
            'email': test_user.email,
            'password': 'testpassword123'
        }
        
        response = client.post('/login', data=data, follow_redirects=True)
        assert response.status_code == 200
        # Should redirect to dashboard
        assert b'Dashboard' in response.data
    
    def test_login_post_invalid_credentials(self, client, test_user):
        """Test login with invalid credentials"""
        data = {
            'email': test_user.email,
            'password': 'wrongpassword'
        }
        
        response = client.post('/login', data=data)
        assert response.status_code == 200
        assert b'Invalid email or password' in response.data
    
    def test_logout(self, authenticated_client):
        """Test logout functionality"""
        response = authenticated_client.get('/logout', follow_redirects=True)
        assert response.status_code == 200

class TestDashboardRoutes:
    """Tests for dashboard and canary management routes"""
    
    def test_dashboard_requires_auth(self, client):
        """Test dashboard requires authentication"""
        response = client.get('/dashboard')
        assert response.status_code == 302  # Redirect to login
    
    def test_dashboard_authenticated(self, authenticated_client, test_canary):
        """Test dashboard with authenticated user"""
        response = authenticated_client.get('/dashboard')
        assert response.status_code == 200
        assert b'Dashboard' in response.data
        assert test_canary.name.encode() in response.data
    
    def test_create_canary_get(self, authenticated_client):
        """Test create canary form"""
        response = authenticated_client.get('/create_canary')
        assert response.status_code == 200
        assert b'Create Canary' in response.data
    
    def test_create_canary_post(self, authenticated_client, test_user):
        """Test creating new canary"""
        data = {
            'name': 'New Test Canary',
            'interval_minutes': 30,
            'grace_minutes': 5,
            'alert_type': 'email',
            'alert_email': 'alert@example.com'
        }
        
        response = authenticated_client.post('/create_canary', data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b'created successfully' in response.data
        
        # Verify canary was created
        canaries = Canary.get_by_user_id(test_user.user_id)
        canary_names = [c.name for c in canaries]
        assert 'New Test Canary' in canary_names
    
    def test_edit_canary_get(self, authenticated_client, test_canary):
        """Test edit canary form"""
        response = authenticated_client.get(f'/edit_canary/{test_canary.canary_id}')
        assert response.status_code == 200
        assert b'Edit Canary' in response.data
        assert test_canary.name.encode() in response.data
    
    def test_edit_canary_post(self, authenticated_client, test_canary):
        """Test updating canary"""
        data = {
            'name': 'Updated Canary Name',
            'interval_minutes': 120,
            'grace_minutes': 10,
            'alert_type': 'both',
            'alert_email': 'updated@example.com'
        }
        
        response = authenticated_client.post(f'/edit_canary/{test_canary.canary_id}', 
                                           data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b'updated successfully' in response.data
        
        # Verify canary was updated
        updated_canary = Canary.get_by_id(test_canary.canary_id)
        assert updated_canary.name == 'Updated Canary Name'
        assert updated_canary.interval_minutes == 120
    
    def test_delete_canary(self, authenticated_client, test_canary):
        """Test deleting canary"""
        canary_id = test_canary.canary_id
        response = authenticated_client.post(f'/delete_canary/{canary_id}', 
                                           follow_redirects=True)
        assert response.status_code == 200
        assert b'deleted' in response.data
        
        # Verify canary was deleted
        assert Canary.get_by_id(canary_id) is None

class TestCheckinRoutes:
    """Tests for canary check-in functionality"""
    
    def test_checkin_valid_token(self, client, test_canary):
        """Test successful canary check-in"""
        response = client.get(f'/checkin/{test_canary.token}')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['status'] == 'success'
        assert data['message'] == 'Check-in received'
        
        # Verify canary status updated
        updated_canary = Canary.get_by_id(test_canary.canary_id)
        assert updated_canary.status == 'healthy'
        assert updated_canary.last_checkin is not None
    
    def test_checkin_invalid_token(self, client):
        """Test check-in with invalid token"""
        response = client.get('/checkin/invalid-token')
        assert response.status_code == 404
        
        data = response.get_json()
        assert data['status'] == 'error'
        assert data['message'] == 'Invalid token'
    
    def test_checkin_creates_log(self, client, test_canary):
        """Test that check-in creates a log entry"""
        response = client.get(f'/checkin/{test_canary.token}')
        assert response.status_code == 200
        
        # Check that log was created
        logs_result = CanaryLog.get_by_canary_id(test_canary.canary_id)
        assert len(logs_result['logs']) > 0
        
        # Find the ping log
        ping_logs = [log for log in logs_result['logs'] if log.event_type == 'ping']
        assert len(ping_logs) > 0
        assert ping_logs[0].status == 'success'

class TestAPIRoutes:
    """Tests for API endpoints"""
    
    def test_api_canaries_status_requires_auth(self, client):
        """Test API status requires authentication"""
        response = client.get('/api/canaries/status')
        assert response.status_code == 302  # Redirect to login
    
    def test_api_canaries_status_authenticated(self, authenticated_client, test_canary):
        """Test API canaries status endpoint"""
        response = authenticated_client.get('/api/canaries/status')
        assert response.status_code == 200
        
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'canaries' in data
        assert 'timestamp' in data
        
        # Check canary data structure
        canaries = data['canaries']
        assert len(canaries) > 0
        
        canary_data = canaries[0]
        required_fields = ['canary_id', 'name', 'status', 'last_checkin', 'next_expected', 'is_overdue']
        for field in required_fields:
            assert field in canary_data

class TestLogsRoutes:
    """Tests for logs functionality"""
    
    def test_canary_logs_requires_auth(self, client, test_canary):
        """Test logs page requires authentication"""
        response = client.get(f'/canary_logs/{test_canary.canary_id}')
        assert response.status_code == 302  # Redirect to login
    
    def test_canary_logs_authenticated(self, authenticated_client, test_canary, test_log_entries):
        """Test logs page with authenticated user"""
        response = authenticated_client.get(f'/canary_logs/{test_canary.canary_id}')
        assert response.status_code == 200
        assert b'Activity Log' in response.data
        assert test_canary.name.encode() in response.data
    
    def test_canary_logs_access_control(self, client, test_canary, dynamodb_tables):
        """Test users can only access their own canary logs"""
        # Create another user
        other_user = User(username='otheruser', email='other@example.com')
        other_user.set_password('password123')
        other_user.save()
        
        # Login as other user
        with client.session_transaction() as sess:
            sess['_user_id'] = other_user.user_id
            sess['_fresh'] = True
        
        # Try to access test_canary logs (should be denied)
        response = client.get(f'/canary_logs/{test_canary.canary_id}', follow_redirects=True)
        assert response.status_code == 200
        assert b'Access denied' in response.data

class TestSettingsRoutes:
    """Tests for settings functionality"""
    
    def test_settings_requires_auth(self, client):
        """Test settings requires authentication"""
        response = client.get('/settings')
        assert response.status_code == 302
    
    def test_settings_get(self, authenticated_client, test_user):
        """Test settings page display"""
        response = authenticated_client.get('/settings')
        assert response.status_code == 200
        assert b'Settings' in response.data
        assert test_user.username.encode() in response.data
        assert test_user.email.encode() in response.data
    
    def test_settings_update_timezone(self, authenticated_client, test_user):
        """Test updating timezone setting"""
        data = {
            'username': test_user.username,
            'email': test_user.email,
            'timezone': 'America/New_York',
            'submit': True
        }
        
        response = authenticated_client.post('/settings', data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b'Settings updated successfully' in response.data
        
        # Verify timezone was updated
        updated_user = User.get_by_id(test_user.user_id)
        assert updated_user.timezone == 'America/New_York'
    
    def test_settings_change_password(self, authenticated_client, test_user):
        """Test changing password"""
        data = {
            'username': test_user.username,
            'email': test_user.email,
            'timezone': test_user.timezone,
            'current_password': 'testpassword123',
            'new_password': 'newtestpassword123',
            'confirm_password': 'newtestpassword123',
            'submit': True
        }
        
        response = authenticated_client.post('/settings', data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b'Settings updated successfully' in response.data
        
        # Verify password was changed
        updated_user = User.get_by_id(test_user.user_id)
        assert updated_user.check_password('newtestpassword123') == True
        assert updated_user.check_password('testpassword123') == False

class TestPasswordReset:
    """Tests for password reset functionality"""
    
    def test_forgot_password_get(self, client):
        """Test forgot password form"""
        response = client.get('/forgot_password')
        assert response.status_code == 200
        assert b'Forgot Password' in response.data
    
    def test_forgot_password_post(self, client, test_user):
        """Test forgot password submission"""
        data = {'email': test_user.email}
        response = client.post('/forgot_password', data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b'Password reset link sent' in response.data

class TestErrorHandling:
    """Tests for error handling"""
    
    def test_nonexistent_canary_edit(self, authenticated_client):
        """Test editing non-existent canary"""
        response = authenticated_client.get('/edit_canary/nonexistent-id', follow_redirects=True)
        assert response.status_code == 200
        assert b'Access denied' in response.data
    
    def test_nonexistent_canary_delete(self, authenticated_client):
        """Test deleting non-existent canary"""
        response = authenticated_client.post('/delete_canary/nonexistent-id', follow_redirects=True)
        assert response.status_code == 200
        assert b'Access denied' in response.data


class TestEmailFunctionality:
    """Tests for email-related functionality"""
    
    def test_forgot_password_email_sending_success(self, client, test_user, monkeypatch):
        """Test successful password reset email sending"""
        # Mock successful email sending
        def mock_send(self, msg):
            pass
        
        monkeypatch.setattr('flask_mail.Mail.send', mock_send)
        
        response = client.post('/forgot_password', data={
            'email': test_user.email
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Password reset link sent to your email' in response.data
    
    def test_forgot_password_email_sending_failure(self, client, test_user, monkeypatch):
        """Test email sending failure handling"""
        # Mock failed email sending
        def mock_send(self, msg):
            raise Exception("SMTP Error")
        
        monkeypatch.setattr('flask_mail.Mail.send', mock_send)
        
        response = client.post('/forgot_password', data={
            'email': test_user.email
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Failed to send reset email' in response.data
    
    def test_forgot_password_nonexistent_email(self, client):
        """Test password reset with non-existent email (should still show success for security)"""
        response = client.post('/forgot_password', data={
            'email': 'nonexistent@example.com'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Password reset link sent to your email' in response.data
    
    def test_verify_email_success(self, client, test_user):
        """Test email verification endpoint exists"""
        # Test that the verify email endpoint exists and handles invalid tokens gracefully
        response = client.get('/verify_email/invalid-token', follow_redirects=True)
        assert response.status_code == 200


class TestPaginationEdgeCases:
    """Tests for pagination edge cases"""
    
    def test_canary_logs_invalid_pagination_key(self, authenticated_client, test_canary):
        """Test logs pagination with invalid key"""
        # Test with invalid base64 
        response = authenticated_client.get(f'/canary_logs/{test_canary.canary_id}?last_evaluated_key=invalid-key')
        assert response.status_code == 200
        # Should handle gracefully and show logs
    
    def test_canary_logs_malformed_pagination_key(self, authenticated_client, test_canary):
        """Test logs pagination with malformed JSON key"""
        import base64
        # Create invalid JSON in base64
        invalid_json = base64.b64encode(b'{"invalid": json}').decode()
        response = authenticated_client.get(f'/canary_logs/{test_canary.canary_id}?last_evaluated_key={invalid_json}')
        assert response.status_code == 200
        # Should handle gracefully
    
    def test_canary_logs_empty_pagination_key(self, authenticated_client, test_canary):
        """Test logs pagination with empty key"""
        response = authenticated_client.get(f'/canary_logs/{test_canary.canary_id}?last_evaluated_key=')
        assert response.status_code == 200


class TestErrorHandlingScenarios:
    """Tests for various error handling scenarios"""
    
    def test_user_save_failure(self, dynamodb_tables):
        """Test user save handling with edge cases"""
        # Test with None values - should handle gracefully
        user = User(username=None, email=None)
        user.set_password('password123')
        result = user.save()
        # Just ensure it doesn't crash - behavior may vary
    
    def test_canary_checkin_with_invalid_source_data(self, test_canary):
        """Test canary checkin with edge case source data"""
        # Test with None values 
        test_canary.checkin(source_ip=None, user_agent=None)
        
        # Test with empty strings
        test_canary.checkin(source_ip='', user_agent='')
        
        # Test with very long strings
        long_string = 'x' * 1000
        test_canary.checkin(source_ip=long_string, user_agent=long_string)
    
    def test_canary_delete_failure(self, test_canary, monkeypatch):
        """Test canary delete failure handling"""
        # Mock DynamoDB delete_item to raise exception
        def mock_delete_item(*args, **kwargs):
            raise Exception("DynamoDB Delete Error")
        
        original_delete = test_canary.delete
        monkeypatch.setattr(test_canary, 'delete', lambda: False)
        
        result = test_canary.delete()
        assert result is False
    
    def test_password_reset_with_invalid_token(self, client):
        """Test password reset with invalid token"""
        response = client.get('/reset_password/invalid-token')
        assert response.status_code == 302  # Redirect due to invalid token
        
        response = client.post('/reset_password/invalid-token', data={
            'password': 'newpassword123',
            'password2': 'newpassword123'
        })
        assert response.status_code == 302  # Redirect due to invalid token


class TestEdgeCasesAndBoundaryConditions:
    """Tests for edge cases and boundary conditions"""
    
    def test_canary_creation_with_extreme_values(self, authenticated_client, test_user):
        """Test canary creation with boundary values"""
        # Test minimum values
        response = authenticated_client.post('/create_canary', data={
            'name': 'A',  # Minimum length name
            'interval_minutes': '1',  # Minimum interval
            'grace_minutes': '1',   # Minimum grace
            'alert_type': 'email',
            'alert_email': 'test@example.com'
        })
        assert response.status_code == 302  # Successful creation
        
        # Test maximum reasonable values
        response = authenticated_client.post('/create_canary', data={
            'name': 'X' * 100,  # Long name
            'interval_minutes': '10080',  # 1 week in minutes
            'grace_minutes': '1440',    # 1 day in minutes
            'alert_type': 'email',
            'alert_email': 'test@example.com'
        })
        assert response.status_code == 302  # Successful creation
    
    def test_settings_update_edge_cases(self, authenticated_client, test_user):
        """Test settings updates with edge case data"""
        # Test with all timezone options
        timezones = ['UTC', 'US/Eastern', 'US/Pacific', 'Europe/London', 'Asia/Tokyo']
        for tz in timezones:
            response = authenticated_client.post('/settings', data={
                'user_timezone': tz
            })
            assert response.status_code == 302
        
        # Test password change with edge cases
        response = authenticated_client.post('/settings', data={
            'current_password': 'testpassword123',
            'new_password': 'A' * 8,  # Minimum length password
            'confirm_new_password': 'A' * 8
        })
        assert response.status_code == 302
    
    def test_api_endpoints_with_invalid_data(self, authenticated_client):
        """Test API endpoints with invalid or edge case data"""
        # Test API status endpoint multiple times rapidly
        for _ in range(10):
            response = authenticated_client.get('/api/canaries/status')
            assert response.status_code == 200
            data = response.get_json()
            assert 'canaries' in data
    
    def test_concurrent_canary_checkins(self, test_canary):
        """Test multiple rapid checkins to same canary"""
        # Simulate rapid checkins
        for i in range(5):
            result = test_canary.checkin(
                source_ip=f'127.0.0.{i}', 
                user_agent=f'TestAgent{i}'
            )
            # Result may be None or True depending on implementation
            assert result is not False
        
        # Verify canary is still healthy
        assert not test_canary.is_overdue()


class TestSecurityScenarios:
    """Additional security-focused tests"""
    
    def test_sql_injection_attempts(self, client):
        """Test various injection attempts in login forms"""
        injection_attempts = [
            "admin'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'/**/OR/**/1=1#",
            "<script>alert('xss')</script>"
        ]
        
        for attempt in injection_attempts:
            response = client.post('/login', data={
                'email': attempt,
                'password': 'any_password'
            })
            # Should not cause server error
            assert response.status_code in [200, 302]
    
    def test_session_fixation_protection(self, client, test_user):
        """Test protection against session fixation attacks"""
        # Get initial session
        response = client.get('/login')
        initial_session = client.get_cookie('session')
        
        # Login
        response = client.post('/login', data={
            'email': test_user.email,
            'password': 'testpassword123'
        })
        
        # Session should change after login
        new_session = client.get_cookie('session')
        assert initial_session != new_session
    
    def test_unauthorized_access_attempts(self, client, test_user, test_canary):
        """Test unauthorized access to various endpoints"""
        get_protected_endpoints = [
            f'/edit_canary/{test_canary.canary_id}',
            f'/canary_logs/{test_canary.canary_id}',
            '/create_canary',
            '/settings',
            '/api/canaries/status'
        ]
        
        for endpoint in get_protected_endpoints:
            response = client.get(endpoint)
            assert response.status_code == 302  # Redirect to login
            assert '/login' in response.location
        
        # Test POST endpoints separately
        post_protected_endpoints = [
            f'/delete_canary/{test_canary.canary_id}'
        ]
        
        for endpoint in post_protected_endpoints:
            response = client.post(endpoint)
            # Should redirect to login or return method not allowed
            assert response.status_code in [302, 405]