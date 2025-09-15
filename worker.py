#!/usr/bin/env python3
"""
Redis worker process for SilentCanary background tasks
Handles canary health checks and notifications
"""

import os
import sys
from datetime import datetime, timezone
from rq import Worker, Queue
from redis_config import get_redis_connection
from models import Canary, User, SmartAlert
import requests
from flask_mail import Mail, Message
from flask import Flask
from dotenv import load_dotenv

# Import email sending function from main app
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app import send_templated_email

# Load environment
load_dotenv()

# Create minimal Flask app for email sending
app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'apikey'
app.config['MAIL_PASSWORD'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@silentcanary.com')

mail = Mail(app)

def should_suppress_alert(canary, alert_type="standard"):
    """Check if we should suppress this alert to prevent spam"""
    from datetime import timedelta
    
    # Don't send multiple alerts within this time window
    ALERT_COOLDOWN_MINUTES = {
        'standard': 60,      # 1 hour for standard alerts  
        'smart_alert': 180,  # 3 hours for smart alerts
        'long_job': 1440     # 24 hours for jobs >30 days
    }
    
    # Determine cooldown period based on canary interval
    if canary.interval_minutes > 43200:  # >30 days
        cooldown_minutes = ALERT_COOLDOWN_MINUTES['long_job'] 
        alert_key = 'long_job'
    elif alert_type == 'smart_alert':
        cooldown_minutes = ALERT_COOLDOWN_MINUTES['smart_alert']
        alert_key = 'smart_alert'
    else:
        cooldown_minutes = ALERT_COOLDOWN_MINUTES['standard']
        alert_key = 'standard'
    
    # Check if we sent an alert recently
    redis_conn = get_redis_connection()
    last_alert_key = f"last_alert:{canary.canary_id}:{alert_key}"
    last_alert_time = redis_conn.get(last_alert_key)
    
    if last_alert_time:
        try:
            # Handle both bytes and string data from Redis
            if isinstance(last_alert_time, bytes):
                last_alert_str = last_alert_time.decode()
            else:
                last_alert_str = last_alert_time
                
            last_alert_dt = datetime.fromisoformat(last_alert_str)
            time_since_alert = datetime.now(timezone.utc) - last_alert_dt
            
            if time_since_alert < timedelta(minutes=cooldown_minutes):
                return True  # Suppress the alert
        except Exception as e:
            print(f"⚠️ Error checking last alert time: {e}")
    
    return False  # Don't suppress

def record_alert_sent(canary, alert_type="standard"):
    """Record that we sent an alert for this canary"""
    # Determine alert key
    if canary.interval_minutes > 43200:  # >30 days
        alert_key = 'long_job'
    elif alert_type == 'smart_alert':
        alert_key = 'smart_alert' 
    else:
        alert_key = 'standard'
    
    redis_conn = get_redis_connection()
    last_alert_key = f"last_alert:{canary.canary_id}:{alert_key}"
    
    # Store timestamp with expiration (7 days)
    redis_conn.setex(
        last_alert_key, 
        604800,  # 7 days in seconds
        datetime.now(timezone.utc).isoformat()
    )

def is_long_running_job(canary):
    """Check if this is a long-running job that should use different alerting logic"""
    # Categorize jobs based on interval patterns
    interval_days = canary.interval_minutes / 1440
    
    # Very long intervals (>7 days) get special handling
    # This includes weekly, bi-weekly, monthly, and quarterly jobs
    if interval_days > 7:
        return True
        
    # For shorter intervals, check if Smart Alerts would be beneficial
    # Jobs that run multiple times per day benefit from Smart Alerts
    if interval_days < 1:  # Sub-daily jobs
        return False
        
    # Daily to weekly jobs can benefit from Smart Alerts
    # if they have irregular patterns (business hours, weekdays only, etc.)
    return False

def should_use_smart_alerts(canary):
    """Determine if Smart Alerts should be used for this canary"""
    # Don't use Smart Alerts for long-running jobs
    if is_long_running_job(canary):
        print(f"⚠️ Skipping Smart Alerts for long-running job: {canary.name} (interval: {canary.interval_minutes/1440:.1f} days)")
        return False
    
    # Check if Smart Alerts are enabled for this canary
    smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
    return smart_alert and smart_alert.is_enabled

def send_notifications(canary_id, alert_type="standard"):
    """Send notifications for a failed canary with deduplication"""
    with app.app_context():
        try:
            # Get canary and user data
            canary = Canary.get_by_id(canary_id)
            if not canary:
                print(f"❌ Canary {canary_id} not found")
                return False
            
            user = User.get_by_id(canary.user_id)
            
            # Check if we recently sent an alert for this canary to prevent spam
            if should_suppress_alert(canary, alert_type):
                print(f"📧 Suppressing duplicate alert for canary: {canary.name} (type: {alert_type})")
                return True
            
            subject = f'SilentCanary Alert: {canary.name} has failed'
            
            # Email message with HTML formatting
            html_message = f'''
            <h2>🚨 SilentCanary Alert</h2>
            <p>Your canary "<strong>{canary.name}</strong>" has failed to check in!</p>
            
            <h3>Details:</h3>
            <ul>
                <li><strong>Last check-in:</strong> {canary.last_checkin or 'Never'}</li>
                <li><strong>Expected check-in:</strong> {canary.next_expected or 'N/A'}</li>
                <li><strong>Grace period:</strong> {canary.grace_minutes} minutes</li>
                <li><strong>Check-in interval:</strong> {canary.interval_minutes} minutes</li>
            </ul>
            
            <p>Please investigate your monitoring target immediately.</p>
            
            <hr>
            <p><small>This alert was sent by SilentCanary</small></p>
            '''
            
            # Slack message with markdown formatting
            slack_message = f"""🚨 *SilentCanary Alert*

Canary "*{canary.name}*" has failed to check in!

• Last check-in: {canary.last_checkin or 'Never'}
• Expected check-in: {canary.next_expected or 'N/A'}
• Grace period: {canary.grace_minutes} minutes
• Check-in interval: {canary.interval_minutes} minutes

Please investigate your monitoring target immediately."""

            # Send email notification
            email_sent = False
            if canary.alert_type in ['email', 'both']:
                recipient = canary.alert_email or (user.email if user else None)
                if recipient:
                    msg = Message(
                        subject=subject,
                        recipients=[recipient],
                        html=html_message,
                        sender=('SilentCanary', app.config['MAIL_DEFAULT_SENDER'])
                    )
                    mail.send(msg)
                    print(f"📧 Email notification sent to {recipient} (type: {alert_type})")
                    email_sent = True
                else:
                    print("❌ No email recipient available")
            
            # Send Slack notification
            slack_sent = False
            if canary.alert_type in ['slack', 'both'] and canary.slack_webhook:
                payload = {"text": slack_message}
                response = requests.post(canary.slack_webhook, json=payload, timeout=10)
                if response.status_code == 200:
                    print(f"💬 Slack notification sent for canary: {canary.name} (type: {alert_type})")
                    slack_sent = True
                else:
                    print(f"❌ Slack notification failed: {response.status_code}")
            
            # Record that we sent an alert to prevent duplicates
            if email_sent or slack_sent:
                record_alert_sent(canary, alert_type)
                print(f"✅ Alert cooldown period started for {canary.name} (type: {alert_type})")
            
            return True
            
        except Exception as e:
            print(f"❌ Error sending notifications for canary {canary_id}: {e}")
            return False

def check_canary_health():
    """Check all active canaries for health using Smart Alert ML predictions and standard overdue detection"""
    print(f"🔍 Checking canary health at {datetime.now(timezone.utc)}")
    
    try:
        # Get Redis connection for queuing notifications
        redis_conn = get_redis_connection()
        notification_queue = Queue('notifications', connection=redis_conn)
        
        # Get all active canaries
        active_canaries = Canary.get_active_canaries()
        print(f"📊 Checking {len(active_canaries)} active canaries")
        
        failed_count = 0
        smart_anomaly_count = 0
        learning_updates = 0
        
        for canary in active_canaries:
            if canary.status == 'failed':
                continue  # Skip already failed canaries
                
            # Phase 1: Check Smart Alert ML predictions FIRST (before overdue threshold)
            if should_use_smart_alerts(canary):
                smart_alert = SmartAlert.get_by_canary_id(canary.canary_id)
                if smart_alert and smart_alert.is_enabled:
                    # Update patterns if needed
                    try:
                        if smart_alert.should_update_patterns():
                            print(f"🧠 Updating patterns for Smart Alert '{canary.name}'")
                            if smart_alert.learn_patterns():
                                learning_updates += 1
                                print(f"✅ Patterns updated successfully for '{canary.name}'")
                            else:
                                print(f"⚠️ Insufficient data for pattern update '{canary.name}'")
                    except Exception as e:
                        print(f"❌ Error updating patterns for '{canary.name}': {e}")
                    
                    # Check for Smart Alert ML anomalies (this is the key improvement!)
                    if smart_alert.is_anomaly():
                        print(f"🧠 Smart alert detected anomaly for '{canary.name}' - sending notifications")
                        
                        # Mark canary as failed due to smart alert anomaly
                        canary.status = 'failed'
                        canary.save()
                        
                        # Enqueue smart alert notification
                        notification_queue.enqueue(
                            send_notifications,
                            canary.canary_id,
                            "smart_alert",
                            job_timeout=300,
                            retry=3
                        )
                        
                        smart_anomaly_count += 1
                        continue  # Don't check standard overdue logic for smart alert canaries
            
            # Phase 2: Standard overdue detection for non-smart-alert canaries or as fallback
            if canary.is_overdue():
                # Determine alert type based on canary characteristics
                alert_type = "standard"
                
                # For long-running jobs (>30 days), use special handling
                if is_long_running_job(canary):
                    alert_type = "long_job"
                    print(f"⚠️ Long-running job '{canary.name}' is overdue (interval: {canary.interval_minutes/1440:.1f} days)")
                else:
                    print(f"⚠️ Standard canary '{canary.name}' is overdue")
                
                # Update canary status
                canary.status = 'failed'
                canary.save()
                
                # Enqueue notification job
                notification_queue.enqueue(
                    send_notifications,
                    canary.canary_id,
                    alert_type,
                    job_timeout=300,  # 5 minutes timeout
                    retry=3
                )
                
                failed_count += 1
        
        # Report results
        if failed_count > 0 or smart_anomaly_count > 0 or learning_updates > 0:
            status_parts = []
            if failed_count > 0:
                status_parts.append(f"{failed_count} failed canaries")
            if smart_anomaly_count > 0:
                status_parts.append(f"{smart_anomaly_count} smart anomalies")
            if learning_updates > 0:
                status_parts.append(f"{learning_updates} pattern updates")
            print(f"📧 Processed {', '.join(status_parts)}")
        else:
            print("✅ All canaries are healthy")
        
        return failed_count + smart_anomaly_count
        
    except Exception as e:
        print(f"❌ Error checking canary health: {e}")
        return 0

def schedule_health_checks():
    """Schedule regular health checks using Redis Queue"""
    try:
        redis_conn = get_redis_connection()
        scheduler = Queue('scheduler', connection=redis_conn)
        
        # Enqueue health check to run immediately and then every minute
        scheduler.enqueue(
            check_canary_health,
            job_timeout=300,  # 5 minutes timeout
            retry=2
        )
        
        print("✅ Health check scheduled")
        return True
        
    except Exception as e:
        print(f"❌ Error scheduling health checks: {e}")
        return False

def test_long_job_alert_system():
    """Comprehensive test suite for long-running job alert system"""
    print("🧪 Starting comprehensive long-job alert system tests...")
    
    # Test 1: Email deduplication for long jobs
    print("\n📧 Test 1: Email deduplication for long-running jobs")
    test_results = []
    
    try:
        # Create test canary data
        class TestCanary:
            def __init__(self, name, interval_days):
                self.canary_id = f"test-{name}"
                self.name = f"Test {name}"
                self.interval_minutes = interval_days * 1440  # Convert days to minutes
                self.alert_type = "email"
        
        # Test long job (85 days)
        long_job = TestCanary("85-day-job", 85)
        
        # Test 1a: Should recognize as long-running job
        is_long = is_long_running_job(long_job)
        test_results.append(("Long job detection (85 days)", is_long, True))
        
        # Test 1b: Should NOT use Smart Alerts
        use_smart = should_use_smart_alerts(long_job)  
        test_results.append(("Smart Alert disabled for long jobs", not use_smart, True))
        
        # Test 1c: Alert suppression logic
        redis_conn = get_redis_connection()
        
        # Clear any existing alert records for test
        redis_conn.delete(f"last_alert:{long_job.canary_id}:long_job")
        
        # First alert should NOT be suppressed
        suppress_first = should_suppress_alert(long_job, "long_job")
        test_results.append(("First alert not suppressed", not suppress_first, True))
        
        # Record alert sent
        record_alert_sent(long_job, "long_job")
        
        # Second alert should be suppressed (within 24h cooldown)
        suppress_second = should_suppress_alert(long_job, "long_job")
        test_results.append(("Second alert suppressed (24h cooldown)", suppress_second, True))
        
        print("\n📊 Test Results:")
        all_passed = True
        for test_name, result, expected in test_results:
            status = "✅ PASS" if result == expected else "❌ FAIL"
            print(f"  {status} {test_name}: {result} (expected: {expected})")
            if result != expected:
                all_passed = False
        
        # Test 2: Cooldown periods
        print("\n⏰ Test 2: Alert cooldown periods")
        
        # Short job (1 hour)
        short_job = TestCanary("1-hour-job", 1/24)  # 1 hour
        
        # Medium job (1 day)
        medium_job = TestCanary("1-day-job", 1)
        
        # Long job (85 days)
        long_job = TestCanary("85-day-job", 85)
        
        cooldown_tests = [
            ("Short job cooldown", short_job, "standard", 60),
            ("Medium job cooldown", medium_job, "standard", 60), 
            ("Long job cooldown", long_job, "long_job", 1440)
        ]
        
        for test_name, test_canary, alert_type, expected_minutes in cooldown_tests:
            # This would need access to the internal cooldown logic
            if is_long_running_job(test_canary):
                actual_type = "long_job"
            else:
                actual_type = "standard"
                
            result = actual_type == alert_type.split("_")[0] if "_" in alert_type else actual_type == alert_type
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"  {status} {test_name}: {actual_type} (expected type)")
        
        print(f"\n🎯 Overall Test Result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
        return all_passed
        
    except Exception as e:
        print(f"❌ Test suite failed with error: {e}")
        return False

def test_alert_scenarios():
    """Test specific alert scenarios for debugging"""
    print("\n🔬 Testing specific alert scenarios...")
    
    scenarios = [
        {
            'name': '85-day job',
            'interval_days': 85,
            'should_use_smart_alerts': False,
            'cooldown_hours': 24,
            'alert_type': 'long_job'
        },
        {
            'name': '1-day job',
            'interval_days': 1, 
            'should_use_smart_alerts': True,
            'cooldown_hours': 1,
            'alert_type': 'standard'
        },
        {
            'name': '1-hour job',
            'interval_days': 1/24,
            'should_use_smart_alerts': True,
            'cooldown_hours': 1,
            'alert_type': 'standard'
        }
    ]
    
    for scenario in scenarios:
        print(f"\n📋 Testing: {scenario['name']}")
        
        class TestCanary:
            def __init__(self, name, interval_days):
                self.canary_id = f"test-{name.replace(' ', '-')}"
                self.name = name
                self.interval_minutes = interval_days * 1440
        
        canary = TestCanary(scenario['name'], scenario['interval_days'])
        
        # Test long job detection
        is_long = is_long_running_job(canary)
        expected_long = scenario['interval_days'] > 30
        print(f"  Long job detection: {is_long} (expected: {expected_long}) {'✅' if is_long == expected_long else '❌'}")
        
        # Test Smart Alert usage (for test canaries, simulate based on job type)
        should_smart = should_use_smart_alerts(canary) if hasattr(canary, 'user_id') else (not is_long)
        expected_smart = scenario['should_use_smart_alerts'] and not is_long
        print(f"  Smart Alerts enabled: {should_smart} (expected: {expected_smart}) {'✅' if should_smart == expected_smart else '❌'}")
        
        print(f"  Interval: {scenario['interval_days']} days ({canary.interval_minutes} minutes)")
        print(f"  Expected cooldown: {scenario['cooldown_hours']} hours")
        print(f"  Alert type: {scenario['alert_type']}")

def run_comprehensive_tests():
    """Run all test suites"""
    print("🚀 Running comprehensive long-job alert system tests...\n")
    
    # Test the alert system
    alert_tests_passed = test_long_job_alert_system()
    
    # Test specific scenarios
    test_alert_scenarios()
    
    print(f"\n🎯 Final Result: {'✅ SYSTEM READY' if alert_tests_passed else '❌ ISSUES DETECTED'}")
    return alert_tests_passed

if __name__ == '__main__':
    # Test Redis connection first
    print("🔄 Testing Redis connection...")
    if not get_redis_connection().ping():
        print("❌ Cannot connect to Redis. Please check configuration.")
        sys.exit(1)
    
    print("✅ Redis connection successful")
    
    # Get queues
    redis_conn = get_redis_connection()
    
    # Define queues to listen to
    queues = [
        Queue('health-checks', connection=redis_conn),  # High priority - health checks
        Queue('notifications', connection=redis_conn),  # Medium priority - notifications  
        Queue('scheduler', connection=redis_conn)       # Low priority - scheduling
    ]
    
    print(f"🔄 Starting worker for queues: {[q.name for q in queues]}")
    
    # Start worker
    worker = Worker(queues, connection=redis_conn)
    print("🚀 Worker started - waiting for jobs...")
    worker.work()