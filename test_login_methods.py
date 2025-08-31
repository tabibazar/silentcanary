#!/usr/bin/env python3
"""
Test script to verify login functionality components
"""
from models import User

def test_login_methods():
    """Test the login-related methods"""
    try:
        # Test getting user by email
        print("Testing User.get_by_email()...")
        user = User.get_by_email('test@example.com')
        if user:
            print(f"✅ Found user: {user.username} ({user.email})")
            
            # Test password checking
            print("Testing password verification...")
            if user.check_password('TestPassword123'):
                print("✅ Password check successful")
            else:
                print("❌ Password check failed")
                
            if user.check_password('wrongpassword'):
                print("❌ Password check should have failed but didn't!")
            else:
                print("✅ Password check correctly rejected wrong password")
                
        else:
            print("❌ User not found")
            
    except Exception as e:
        print(f"❌ Error testing login methods: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_login_methods()