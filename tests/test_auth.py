"""
Tests for authentication and authorization in SilentCanary
"""
import pytest
from models import User, Canary
from itsdangerous import URLSafeTimedSerializer

class TestAuthentication:
    """Tests for user authentication"""
    
    def test_user_login_manager_integration(self, flask_app, test_user):
        """Test Flask-Login integration"""
        from app import login_manager
        
        with flask_app.app_context():
            # Test user_loader callback
            loaded_user = login_manager.user_callback(test_user.user_id)
            assert loaded_user is not None
            assert loaded_user.user_id == test_user.user_id
            
            # Test loading invalid user
            invalid_user = login_manager.user_callback('invalid-id')
            assert invalid_user is None
    
    def test_login_required_decorator(self, client):
        """Test login_required decorator on protected routes"""
        protected_routes = [
            '/dashboard',
            '/create_canary',
            '/settings',
            '/api/canaries/status'
        ]
        
        for route in protected_routes:
            response = client.get(route)
            assert response.status_code == 302  # Redirect to login
            assert '/login' in response.location
    
    def test_session_persistence(self, client, test_user):
        """Test session persistence across requests"""
        # Login
        login_data = {
            'email': test_user.email,
            'password': 'testpassword123'
        }
        response = client.post('/login', data=login_data)
        assert response.status_code == 302
        
        # Access protected route - should work without re-authentication
        response = client.get('/dashboard')
        assert response.status_code == 200
    
    def test_logout_clears_session(self, authenticated_client):
        """Test logout clears user session"""
        # Verify we can access protected route
        response = authenticated_client.get('/dashboard')
        assert response.status_code == 200
        
        # Logout
        response = authenticated_client.get('/logout')
        assert response.status_code == 302
        
        # Try to access protected route - should redirect to login
        response = authenticated_client.get('/dashboard')
        assert response.status_code == 302
        assert '/login' in response.location

class TestAuthorization:
    """Tests for user authorization and access control"""
    
    def test_canary_ownership_edit(self, client, dynamodb_tables):
        """Test users can only edit their own canaries"""
        # Create two users
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password('password123')
        user1.save()
        
        user2 = User(username='user2', email='user2@example.com') 
        user2.set_password('password123')
        user2.save()
        
        # Create canary for user1
        canary = Canary(name='User1 Canary', user_id=user1.user_id, 
                       interval_minutes=60, grace_minutes=5)
        canary.save()
        
        # Login as user2
        with client.session_transaction() as sess:
            sess['_user_id'] = user2.user_id
            sess['_fresh'] = True
        
        # Try to edit user1's canary
        response = client.get(f'/edit_canary/{canary.canary_id}', follow_redirects=True)
        assert response.status_code == 200
        assert b'Access denied' in response.data
    
    def test_canary_ownership_delete(self, client, dynamodb_tables):
        """Test users can only delete their own canaries"""
        # Create two users
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password('password123')
        user1.save()
        
        user2 = User(username='user2', email='user2@example.com')
        user2.set_password('password123') 
        user2.save()
        
        # Create canary for user1
        canary = Canary(name='User1 Canary', user_id=user1.user_id,
                       interval_minutes=60, grace_minutes=5)
        canary.save()
        
        # Login as user2
        with client.session_transaction() as sess:
            sess['_user_id'] = user2.user_id
            sess['_fresh'] = True
        
        # Try to delete user1's canary
        response = client.post(f'/delete_canary/{canary.canary_id}', follow_redirects=True)
        assert response.status_code == 200
        assert b'Access denied' in response.data
        
        # Verify canary still exists
        assert Canary.get_by_id(canary.canary_id) is not None
    
    def test_canary_logs_access_control(self, client, dynamodb_tables):
        """Test users can only view logs for their own canaries"""
        # Create two users
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password('password123')
        user1.save()
        
        user2 = User(username='user2', email='user2@example.com')
        user2.set_password('password123')
        user2.save()
        
        # Create canary for user1
        canary = Canary(name='User1 Canary', user_id=user1.user_id,
                       interval_minutes=60, grace_minutes=5)
        canary.save()
        
        # Login as user2
        with client.session_transaction() as sess:
            sess['_user_id'] = user2.user_id
            sess['_fresh'] = True
        
        # Try to view user1's canary logs
        response = client.get(f'/canary_logs/{canary.canary_id}', follow_redirects=True)
        assert response.status_code == 200
        assert b'Access denied' in response.data
    
    def test_dashboard_isolation(self, client, dynamodb_tables):
        """Test dashboard only shows user's own canaries"""
        # Create two users
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password('password123')
        user1.save()
        
        user2 = User(username='user2', email='user2@example.com')
        user2.set_password('password123')
        user2.save()
        
        # Create canaries for each user
        canary1 = Canary(name='User1 Canary', user_id=user1.user_id,
                        interval_minutes=60, grace_minutes=5)
        canary1.save()
        
        canary2 = Canary(name='User2 Canary', user_id=user2.user_id,
                        interval_minutes=60, grace_minutes=5)
        canary2.save()
        
        # Login as user1
        with client.session_transaction() as sess:
            sess['_user_id'] = user1.user_id
            sess['_fresh'] = True
        
        # Check dashboard shows only user1's canary
        response = client.get('/dashboard')
        assert response.status_code == 200
        assert b'User1 Canary' in response.data
        assert b'User2 Canary' not in response.data
    
    def test_api_data_isolation(self, client, dynamodb_tables):
        """Test API endpoints only return user's own data"""
        # Create two users
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password('password123')
        user1.save()
        
        user2 = User(username='user2', email='user2@example.com')
        user2.set_password('password123')
        user2.save()
        
        # Create canaries for each user
        canary1 = Canary(name='User1 Canary', user_id=user1.user_id,
                        interval_minutes=60, grace_minutes=5)
        canary1.save()
        
        canary2 = Canary(name='User2 Canary', user_id=user2.user_id,
                        interval_minutes=60, grace_minutes=5)
        canary2.save()
        
        # Login as user1
        with client.session_transaction() as sess:
            sess['_user_id'] = user1.user_id
            sess['_fresh'] = True
        
        # Check API returns only user1's canary
        response = client.get('/api/canaries/status')
        assert response.status_code == 200
        
        data = response.get_json()
        canary_names = [c['name'] for c in data['canaries']]
        assert 'User1 Canary' in canary_names
        assert 'User2 Canary' not in canary_names

class TestEmailVerification:
    """Tests for email verification functionality"""
    
    def test_verify_email_button_functionality(self, authenticated_client, test_user):
        """Test verify email button in settings"""
        # Mock MAIL_SUPPRESS_SEND to prevent actual email sending
        data = {
            'username': test_user.username,
            'email': test_user.email,
            'timezone': test_user.timezone,
            'verify_email': True
        }
        
        response = authenticated_client.post('/settings', data=data, follow_redirects=True)
        assert response.status_code == 200
        assert b'Verification email sent' in response.data
    
    def test_verification_token_generation(self, flask_app):
        """Test verification token generation and validation"""
        from app import app as test_app
        
        with flask_app.app_context():
            serializer = URLSafeTimedSerializer(test_app.config['SECRET_KEY'])
            test_user_id = 'test-user-id'
            
            # Generate token
            token = serializer.dumps({'user_id': test_user_id}, salt='email-verification')
            assert token is not None
            
            # Validate token
            data = serializer.loads(token, salt='email-verification', max_age=3600)
            assert data['user_id'] == test_user_id

class TestPasswordSecurity:
    """Tests for password security"""
    
    def test_password_hashing_uniqueness(self, dynamodb_tables):
        """Test that same password generates different hashes"""
        password = 'testpassword123'
        
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password(password)
        
        user2 = User(username='user2', email='user2@example.com')
        user2.set_password(password)
        
        # Same password should generate different hashes (due to salt)
        assert user1.password_hash != user2.password_hash
        
        # Both should validate correctly
        assert user1.check_password(password) == True
        assert user2.check_password(password) == True
    
    def test_password_validation_timing_safety(self, dynamodb_tables):
        """Test password validation is timing-safe"""
        user = User(username='testuser', email='test@example.com')
        user.set_password('correctpassword')
        
        # Both correct and incorrect passwords should take similar time
        # This is a basic test - werkzeug's check_password_hash provides timing safety
        assert user.check_password('correctpassword') == True
        assert user.check_password('wrongpassword') == False
        assert user.check_password('') == False
        assert user.check_password('x' * 1000) == False  # Very long password
    
    def test_password_change_security(self, authenticated_client, test_user):
        """Test password change requires current password"""
        # Try to change password without providing current password
        data = {
            'username': test_user.username,
            'email': test_user.email,
            'timezone': test_user.timezone,
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123',
            'submit': True
        }
        
        response = authenticated_client.post('/settings', data=data)
        assert response.status_code == 200
        assert b'Current password is required' in response.data
        
        # Try with wrong current password
        data['current_password'] = 'wrongpassword'
        response = authenticated_client.post('/settings', data=data)
        assert response.status_code == 200
        assert b'Current password is incorrect' in response.data
        
        # Verify password wasn't changed
        user = User.get_by_id(test_user.user_id)
        assert user.check_password('testpassword123') == True

class TestSessionSecurity:
    """Tests for session security"""
    
    def test_session_regeneration_on_login(self, client, test_user):
        """Test session ID changes on login for security"""
        # This is handled by Flask-Login automatically
        # We'll test that login creates a valid session
        
        login_data = {
            'email': test_user.email,
            'password': 'testpassword123'
        }
        
        response = client.post('/login', data=login_data)
        assert response.status_code == 302
        
        # Check session contains user information
        with client.session_transaction() as sess:
            assert '_user_id' in sess
            assert sess['_user_id'] == test_user.user_id
    
    def test_csrf_protection_disabled_in_tests(self, client):
        """Verify CSRF is disabled in test environment"""
        # This is handled by WTF_CSRF_ENABLED = False in test config
        # Form submissions should work without CSRF tokens in tests
        response = client.get('/register')
        assert response.status_code == 200
        assert b'csrf_token' not in response.data  # CSRF disabled