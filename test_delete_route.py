#!/usr/bin/env python3
"""
Test script to verify delete pattern route works directly
"""

import sys
import os
sys.path.append('/app')

from models import SmartAlert, Canary
from app import app
import traceback

def test_delete_route():
    """Test delete pattern route directly"""
    print("🧪 Testing Delete Pattern Route")
    print("=" * 40)
    
    with app.app_context():
        with app.test_client() as client:
            try:
                # Find a canary with pattern data
                all_canaries = Canary.get_active_canaries()
                test_canary = None
                
                for canary in all_canaries:
                    smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                    if smart_alert and smart_alert.is_enabled and smart_alert.pattern_data:
                        test_canary = canary
                        break
                
                if not test_canary:
                    print("❌ No canary with pattern data found")
                    return False
                
                print(f"📋 Testing route with canary: {test_canary.name}")
                
                # Test the route (without authentication - will redirect)
                response = client.post(f'/delete_pattern_data/{test_canary.canary_id}')
                print(f"📊 Response status: {response.status_code}")
                print(f"📍 Response location: {response.headers.get('Location', 'No redirect')}")
                
                if response.status_code == 302:
                    print("✅ Route exists and responds (redirected to login as expected)")
                    return True
                else:
                    print(f"❌ Unexpected response: {response.status_code}")
                    return False
                
            except Exception as e:
                print(f"❌ Route test exception: {e}")
                traceback.print_exc()
                return False

if __name__ == "__main__":
    success = test_delete_route()
    if success:
        print("\n🎉 Delete route test PASSED!")
    else:
        print("\n💥 Delete route test FAILED!")
        sys.exit(1)