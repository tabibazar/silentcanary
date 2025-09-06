#!/usr/bin/env python3
"""
Test script to manually trigger smart alert functionality
"""

import sys
import os
sys.path.append('/app')

from models import SmartAlert, Canary, CanaryLog
from app import check_failed_canaries, send_smart_alert_notifications
from datetime import datetime, timezone, timedelta
from flask import Flask

# Create Flask app context
app = Flask(__name__)
app.config['TESTING'] = True

def test_smart_alerts():
    """Test smart alert functionality"""
    print("🧪 Testing Smart Alert Functionality")
    print("=" * 50)
    
    with app.app_context():
        # Find all canaries with smart alerts
        print("📋 Checking for canaries with smart alerts enabled...")
        
        try:
            # Get all canaries
            all_canaries = Canary.get_all_canaries()
            print(f"Total canaries in system: {len(all_canaries)}")
            
            smart_alert_canaries = []
            for canary in all_canaries:
                smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                if smart_alert and smart_alert.is_enabled:
                    smart_alert_canaries.append((canary, smart_alert))
                    print(f"✅ Smart alert enabled: {canary.name}")
                    print(f"   - Canary ID: {canary.canary_id}")
                    print(f"   - Sensitivity: {float(smart_alert.sensitivity) * 100}%")
                    print(f"   - Learning period: {smart_alert.learning_period_days} days")
                    print(f"   - Has pattern data: {bool(smart_alert.pattern_data)}")
                    if smart_alert.pattern_data:
                        print(f"   - Total check-ins: {smart_alert.pattern_data.get('total_checkins', 0)}")
                    print()
            
            if not smart_alert_canaries:
                print("❌ No smart alerts enabled. Please enable smart alerts on at least one canary first.")
                return False
            
            # Test manual smart alert check
            print("🔍 Running manual smart alert check...")
            try:
                check_failed_canaries()
                print("✅ Smart alert check completed successfully")
                return True
            except Exception as e:
                print(f"❌ Smart alert check failed: {e}")
                return False
                
        except Exception as e:
            print(f"❌ Error during test: {e}")
            import traceback
            traceback.print_exc()
            return False

def create_test_anomaly(canary_id):
    """Create a test anomaly condition by manipulating smart alert data"""
    print(f"⚠️ Creating test anomaly for canary {canary_id}")
    
    try:
        smart_alert = SmartAlert.get_by_canary_id(canary_id)
        if not smart_alert:
            print("❌ No smart alert found for canary")
            return False
        
        # Force an anomaly by setting last_alert_sent to None and manipulating pattern
        smart_alert.last_alert_sent = None
        
        # Check if it would trigger an anomaly
        current_time = datetime.now(timezone.utc)
        is_anomalous = smart_alert.is_anomaly(current_time)
        
        print(f"Would trigger anomaly: {is_anomalous}")
        return is_anomalous
        
    except Exception as e:
        print(f"❌ Error creating test anomaly: {e}")
        return False

if __name__ == "__main__":
    success = test_smart_alerts()
    if success:
        print("🎉 Smart alert test completed successfully!")
    else:
        print("💥 Smart alert test failed!")
        sys.exit(1)