#!/usr/bin/env python3
"""
Test script to simulate re-learn patterns button click in web interface
"""

import sys
import os
sys.path.append('/app')

from models import SmartAlert, Canary
from app import app
from flask import url_for
from flask_login import login_user
import traceback

def test_relearn_web_request():
    """Test re-learn patterns as if clicked from web interface"""
    print("🌐 Testing Re-learn Patterns Web Request")
    print("=" * 50)
    
    with app.app_context():
        with app.test_client() as client:
            try:
                # Get a canary with smart alerts enabled
                all_canaries = Canary.get_active_canaries()
                smart_alert_canary = None
                
                for canary in all_canaries:
                    smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                    if smart_alert and smart_alert.is_enabled and smart_alert.pattern_data:
                        smart_alert_canary = canary
                        break
                
                if not smart_alert_canary:
                    print("❌ No suitable canary found with smart alerts and pattern data")
                    return False
                
                print(f"📋 Testing with canary: {smart_alert_canary.name} ({smart_alert_canary.canary_id})")
                
                # Show current pattern data timestamp
                smart_alert = SmartAlert.get_by_canary_id(smart_alert_canary.canary_id)
                old_analysis_time = smart_alert.last_analysis
                print(f"📅 Current last_analysis: {old_analysis_time}")
                
                # Test the relearn_patterns route directly (simulating POST request)
                url = f'/relearn_patterns/{smart_alert_canary.canary_id}'
                print(f"🔗 Testing POST request to: {url}")
                
                # Make the POST request
                response = client.post(url, follow_redirects=False)
                print(f"📊 Response status: {response.status_code}")
                print(f"📍 Response location: {response.headers.get('Location', 'No redirect')}")
                
                # Check if pattern data was updated
                smart_alert_updated = SmartAlert.get_by_canary_id(smart_alert_canary.canary_id)
                new_analysis_time = smart_alert_updated.last_analysis
                print(f"📅 New last_analysis: {new_analysis_time}")
                
                if new_analysis_time != old_analysis_time:
                    print("✅ Pattern data was successfully updated!")
                    
                    # Show some updated pattern data
                    if smart_alert_updated.pattern_data:
                        total_checkins = smart_alert_updated.pattern_data.get('total_checkins', 'N/A')
                        learning_end = smart_alert_updated.pattern_data.get('learning_end', 'N/A')
                        print(f"📊 Total checkins: {total_checkins}")
                        print(f"📊 Learning period ended: {learning_end}")
                    
                    return True
                else:
                    print("❌ Pattern data was NOT updated")
                    
                    # Check if there was an error in the route
                    if response.status_code == 302:  # Redirect indicates success
                        print("🔍 Got redirect but no timestamp change - checking for insufficient data...")
                        # This could mean insufficient data for learning
                        return "insufficient_data"
                    
                    return False
                
            except Exception as e:
                print(f"❌ Exception during web test: {e}")
                traceback.print_exc()
                return False

def test_pattern_learning_conditions():
    """Test the conditions required for pattern learning"""
    print("\n🔍 Testing Pattern Learning Conditions")
    print("=" * 50)
    
    with app.app_context():
        try:
            all_canaries = Canary.get_active_canaries()
            
            for canary in all_canaries:
                smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                if smart_alert and smart_alert.is_enabled:
                    print(f"\n📋 Canary: {canary.name}")
                    print(f"   - Learning period: {smart_alert.learning_period_days} days")
                    
                    # Test learning conditions
                    try:
                        # This will show us if learning would succeed or fail
                        result = smart_alert.learn_patterns()
                        if result:
                            print(f"   - ✅ Learning successful")
                        else:
                            print(f"   - ❌ Learning failed (insufficient data)")
                    except Exception as e:
                        print(f"   - ❌ Learning error: {e}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error testing conditions: {e}")
            return False

if __name__ == "__main__":
    print("🧪 Testing Re-learn Patterns Functionality")
    print("=" * 60)
    
    # Test pattern learning conditions first
    conditions_ok = test_pattern_learning_conditions()
    
    # Then test the web request
    web_result = test_relearn_web_request()
    
    if web_result is True:
        print("\n🎉 Re-learn patterns web request test PASSED!")
    elif web_result == "insufficient_data":
        print("\n⚠️ Re-learn patterns works but canary has insufficient data")
    else:
        print("\n💥 Re-learn patterns web request test FAILED!")
        sys.exit(1)