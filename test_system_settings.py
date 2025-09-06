#!/usr/bin/env python3
"""
Test script to check SystemSettings data in DynamoDB
"""

import sys
import os
sys.path.append('/app')

from models import SystemSettings
from app import app

def test_system_settings():
    """Check if SystemSettings are saved correctly"""
    print("🔧 Testing SystemSettings...")
    
    with app.app_context():
        try:
            # Get current settings
            settings = SystemSettings.get_settings()
            
            print(f"📋 Current System Settings:")
            print(f"   reCAPTCHA Site Key: '{settings.recaptcha_site_key}'")
            print(f"   reCAPTCHA Secret Key: '{settings.recaptcha_secret_key}'")
            print(f"   reCAPTCHA Enabled: {settings.recaptcha_enabled}")
            
            # Test if registration template would show reCAPTCHA
            if settings and settings.recaptcha_enabled and settings.recaptcha_site_key:
                print("✅ reCAPTCHA should be visible on registration page")
            else:
                print("❌ reCAPTCHA will NOT be visible on registration page")
                if not settings:
                    print("   - No settings object found")
                if not settings.recaptcha_enabled:
                    print("   - reCAPTCHA is not enabled")
                if not settings.recaptcha_site_key:
                    print("   - No site key configured")
            
            return True
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    success = test_system_settings()
    if not success:
        sys.exit(1)