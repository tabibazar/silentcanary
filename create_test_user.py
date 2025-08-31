#!/usr/bin/env python3
"""
Script to create a test user for testing login functionality
"""
from models import User

def create_test_user():
    """Create a test user"""
    try:
        # Check if user already exists
        existing_user = User.get_by_email('test@example.com')
        if existing_user:
            print("Test user already exists!")
            return existing_user
        
        # Create new user
        user = User(
            username='testuser',
            email='test@example.com',
            user_timezone='UTC'
        )
        user.set_password('TestPassword123')
        user.save()
        
        print(f"✅ Created test user:")
        print(f"   Email: {user.email}")
        print(f"   Username: {user.username}")
        print(f"   User ID: {user.user_id}")
        
        return user
        
    except Exception as e:
        print(f"❌ Error creating test user: {e}")
        return None

if __name__ == '__main__':
    create_test_user()