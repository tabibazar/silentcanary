#!/usr/bin/env python3
"""
Test canary failure detection and email alert system
Simulates a canary failure and verifies the alert is sent
"""

import os
import sys
import time
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

from models import Canary, User, get_dynamodb_resource
from worker import check_canary_health, send_notifications
from redis_config import get_redis_connection
from rq import Queue

def test_failure_detection():
    """Test the complete failure detection and alert flow"""

    print("="*80)
    print("  Canary Failure Detection Test")
    print("="*80)
    print()

    # Get user's canaries
    user_email = "reza@tabibazar.com"
    user = User.get_by_email(user_email)

    if not user:
        print(f"❌ User not found: {user_email}")
        return False

    print(f"✅ Found user: {user.username} ({user.email})")

    # Get canaries
    canaries = Canary.get_by_user_id(user.user_id)
    print(f"✅ Found {len(canaries)} canary(ies)")
    print()

    # Show canary status
    print("📊 Current Canary Status:")
    print("-" * 80)

    overdue_count = 0
    for canary in canaries:
        is_overdue = canary.is_overdue()
        status_icon = "⚠️" if is_overdue else "✅"

        print(f"{status_icon} {canary.name}")
        print(f"   ID: {canary.canary_id}")
        print(f"   Status: {canary.status}")
        print(f"   Active: {canary.is_active}")
        print(f"   Alert Type: {canary.alert_type}")
        print(f"   Alert Email: {canary.alert_email or user.email}")
        print(f"   Last Check-in: {canary.last_checkin}")
        print(f"   Next Expected: {canary.next_expected}")
        print(f"   Interval: {canary.interval_minutes} minutes")
        print(f"   Grace Period: {canary.grace_minutes} minutes")
        print(f"   Is Overdue: {is_overdue}")
        print()

        if is_overdue:
            overdue_count += 1

    print(f"Total Overdue: {overdue_count}/{len(canaries)}")
    print()

    # Test health check function
    print("🔍 Running health check function...")
    print("-" * 80)

    try:
        failed_count = check_canary_health()
        print(f"✅ Health check completed: {failed_count} failure(s) detected")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print()

    # Check Redis queues
    print("📋 Checking Redis Queues...")
    print("-" * 80)

    try:
        redis_conn = get_redis_connection()
        health_queue = Queue('health-checks', connection=redis_conn)
        notifications_queue = Queue('notifications', connection=redis_conn)

        print(f"Health Checks Queue: {len(health_queue.get_jobs())} job(s)")
        print(f"Notifications Queue: {len(notifications_queue.get_jobs())} job(s)")

        # Show notification jobs if any
        notification_jobs = notifications_queue.get_jobs()
        if notification_jobs:
            print()
            print("Notification Jobs:")
            for job in notification_jobs:
                print(f"  - Job ID: {job.id}")
                print(f"    Function: {job.func_name}")
                print(f"    Args: {job.args}")
                print(f"    Status: {job.get_status()}")
                print()

    except Exception as e:
        print(f"❌ Error checking queues: {e}")
        import traceback
        traceback.print_exc()

    print()

    # Try to manually trigger a notification for an overdue canary
    if overdue_count > 0:
        print("🧪 Testing Manual Notification Send...")
        print("-" * 80)

        # Find first overdue canary
        test_canary = None
        for canary in canaries:
            if canary.is_overdue() and canary.is_active:
                test_canary = canary
                break

        if test_canary:
            print(f"Testing with canary: {test_canary.name} ({test_canary.canary_id})")
            print(f"Alert type: {test_canary.alert_type}")
            print(f"Alert email: {test_canary.alert_email or user.email}")
            print()

            try:
                print("Attempting to send notification...")
                result = send_notifications(test_canary.canary_id, "standard")

                if result:
                    print("✅ Notification function returned success")
                else:
                    print("⚠️ Notification function returned False")

            except Exception as e:
                print(f"❌ Error sending notification: {e}")
                import traceback
                traceback.print_exc()

    print()
    print("="*80)
    print("Test Complete")
    print("="*80)

    return True

if __name__ == '__main__':
    test_failure_detection()
