#!/usr/bin/env python3
"""
Debug script to test re-learn patterns functionality
"""

import sys
import os
sys.path.append('/app')

from models import SmartAlert, Canary, CanaryLog
from datetime import datetime, timezone, timedelta
from flask import Flask
import traceback

# Create Flask app context
app = Flask(__name__)
app.config['TESTING'] = True

def debug_relearn_patterns():
    """Debug re-learn patterns functionality"""
    print("🔍 Debugging Re-learn Patterns Functionality")
    print("=" * 50)
    
    with app.app_context():
        # Find all canaries with smart alerts
        print("📋 Checking for canaries with smart alerts enabled...")
        
        try:
            # Get all canaries
            all_canaries = Canary.get_active_canaries()
            print(f"Total canaries in system: {len(all_canaries)}")
            
            smart_alert_canaries = []
            for canary in all_canaries:
                smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                if smart_alert and smart_alert.is_enabled:
                    smart_alert_canaries.append((canary, smart_alert))
                    print(f"✅ Smart alert enabled: {canary.name}")
                    print(f"   - Canary ID: {canary.canary_id}")
                    print(f"   - Learning period: {smart_alert.learning_period_days} days")
                    
                    # Get recent logs to check data availability
                    logs_result = CanaryLog.get_by_canary_id(canary.canary_id, limit=10)
                    recent_logs = logs_result.get('logs', [])
                    success_logs = [log for log in recent_logs if log.event_type == 'ping' and log.status == 'success']
                    print(f"   - Recent successful check-ins: {len(success_logs)}")
                    
                    if len(success_logs) >= 3:
                        print(f"   - Sufficient data for pattern learning")
                    else:
                        print(f"   - ⚠️ Insufficient data for pattern learning (need at least 3)")
                    print()
            
            if not smart_alert_canaries:
                print("❌ No smart alerts enabled. Please enable smart alerts on at least one canary first.")
                return False
            
            # Test pattern learning for the first canary
            canary, smart_alert = smart_alert_canaries[0]
            print(f"🧪 Testing pattern learning for: {canary.name}")
            
            # Show current pattern data
            print("📊 Current pattern data:")
            if smart_alert.pattern_data:
                for key, value in smart_alert.pattern_data.items():
                    print(f"   - {key}: {value}")
            else:
                print("   - No pattern data exists")
            
            print("\n🔄 Attempting to re-learn patterns...")
            
            try:
                result = smart_alert.learn_patterns()
                if result:
                    print("✅ Pattern learning succeeded!")
                    
                    # Show updated pattern data
                    print("📊 Updated pattern data:")
                    if smart_alert.pattern_data:
                        for key, value in smart_alert.pattern_data.items():
                            print(f"   - {key}: {value}")
                else:
                    print("❌ Pattern learning failed - insufficient data or other issue")
                    
                return result
                
            except Exception as e:
                print(f"❌ Exception during pattern learning: {e}")
                traceback.print_exc()
                return False
                
        except Exception as e:
            print(f"❌ Error during debug test: {e}")
            traceback.print_exc()
            return False

if __name__ == "__main__":
    success = debug_relearn_patterns()
    if success:
        print("\n🎉 Re-learn patterns debug test completed successfully!")
    else:
        print("\n💥 Re-learn patterns debug test failed!")
        sys.exit(1)