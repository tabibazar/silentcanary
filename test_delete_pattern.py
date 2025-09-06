#!/usr/bin/env python3
"""
Test script to verify delete pattern data functionality
"""

import sys
import os
sys.path.append('/app')

from models import SmartAlert, Canary
from app import app
import traceback

def test_delete_pattern_functionality():
    """Test delete pattern data functionality"""
    print("🗑️ Testing Delete Pattern Data Functionality")
    print("=" * 50)
    
    with app.app_context():
        try:
            # Find a canary with smart alerts and pattern data
            all_canaries = Canary.get_active_canaries()
            test_canary = None
            
            for canary in all_canaries:
                smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                if smart_alert and smart_alert.is_enabled and smart_alert.pattern_data:
                    test_canary = canary
                    break
            
            if not test_canary:
                print("❌ No suitable canary found with smart alerts and pattern data")
                return False
            
            print(f"📋 Testing with canary: {test_canary.name} ({test_canary.canary_id})")
            
            # Get the smart alert
            smart_alert = SmartAlert.get_by_canary_id(test_canary.canary_id)
            
            # Show current data
            print(f"📊 Current pattern data:")
            if smart_alert.pattern_data:
                total_checkins = smart_alert.pattern_data.get('total_checkins', 'N/A')
                last_analysis = smart_alert.last_analysis
                print(f"   - Total checkins: {total_checkins}")
                print(f"   - Last analysis: {last_analysis}")
                print(f"   - Alert enabled: {smart_alert.is_enabled}")
            
            # Test the delete operation
            print(f"\n🗑️ Testing pattern data deletion...")
            
            # Save current state for comparison
            old_pattern_data = smart_alert.pattern_data
            old_analysis = smart_alert.last_analysis
            
            # Clear pattern data
            smart_alert.pattern_data = None
            smart_alert.last_analysis = None
            smart_alert.last_alert_sent = None
            
            if smart_alert.save():
                print("✅ Pattern data deletion succeeded!")
                
                # Verify the changes
                updated_smart_alert = SmartAlert.get_by_canary_id(test_canary.canary_id)
                print(f"📊 After deletion:")
                print(f"   - Pattern data: {updated_smart_alert.pattern_data}")
                print(f"   - Last analysis: {updated_smart_alert.last_analysis}")
                print(f"   - Alert enabled: {updated_smart_alert.is_enabled}")
                
                # Restore data for testing
                print(f"\n🔄 Restoring data for continued testing...")
                updated_smart_alert.pattern_data = old_pattern_data
                updated_smart_alert.last_analysis = old_analysis
                if updated_smart_alert.save():
                    print("✅ Data restored successfully")
                else:
                    print("⚠️ Failed to restore data")
                
                return True
            else:
                print("❌ Pattern data deletion failed")
                return False
                
        except Exception as e:
            print(f"❌ Exception during delete test: {e}")
            traceback.print_exc()
            return False

if __name__ == "__main__":
    success = test_delete_pattern_functionality()
    if success:
        print("\n🎉 Delete pattern data test PASSED!")
    else:
        print("\n💥 Delete pattern data test FAILED!")
        sys.exit(1)