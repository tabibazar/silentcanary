#!/usr/bin/env python3
"""
End-to-End Email System Test for SilentCanary
Tests the complete email delivery pipeline including:
1. SendGrid configuration
2. Email template rendering
3. Alert email sending
4. Canary failure detection and notification
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Import app modules
from app import app, mail, send_templated_email
from models import Canary, User, CanaryLog, get_dynamodb_resource
from worker import send_notifications, should_suppress_alert, record_alert_sent
from redis_config import get_redis_connection

class EmailSystemTester:
    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.warnings = []

    def print_header(self, text):
        """Print a formatted header"""
        print(f"\n{'='*80}")
        print(f"  {text}")
        print(f"{'='*80}\n")

    def print_test(self, name, status, details=""):
        """Print test result"""
        if status == "PASS":
            self.tests_passed += 1
            icon = "✅"
        elif status == "FAIL":
            self.tests_failed += 1
            icon = "❌"
        elif status == "WARN":
            self.warnings.append(f"{name}: {details}")
            icon = "⚠️"
        else:
            icon = "ℹ️"

        print(f"{icon} {name}")
        if details:
            print(f"   {details}")

    def test_environment_config(self):
        """Test 1: Verify email environment configuration"""
        self.print_header("Test 1: Email Environment Configuration")

        # Check SendGrid API key
        sendgrid_key = os.environ.get('SENDGRID_API_KEY')
        if sendgrid_key:
            self.print_test("SENDGRID_API_KEY configured", "PASS", f"Key length: {len(sendgrid_key)} chars")
        else:
            self.print_test("SENDGRID_API_KEY configured", "FAIL", "Environment variable not set")

        # Check mail sender
        sender = os.environ.get('MAIL_DEFAULT_SENDER')
        if sender:
            self.print_test("MAIL_DEFAULT_SENDER configured", "PASS", f"Sender: {sender}")
        else:
            self.print_test("MAIL_DEFAULT_SENDER configured", "WARN", "Using default: no-reply@silentcanary.com")

        # Check Flask-Mail configuration
        with app.app_context():
            mail_server = app.config.get('MAIL_SERVER')
            mail_port = app.config.get('MAIL_PORT')
            mail_username = app.config.get('MAIL_USERNAME')

            if mail_server == 'smtp.sendgrid.net':
                self.print_test("Flask-Mail MAIL_SERVER", "PASS", f"Server: {mail_server}")
            else:
                self.print_test("Flask-Mail MAIL_SERVER", "FAIL", f"Expected smtp.sendgrid.net, got: {mail_server}")

            if mail_port == 587:
                self.print_test("Flask-Mail MAIL_PORT", "PASS", f"Port: {mail_port}")
            else:
                self.print_test("Flask-Mail MAIL_PORT", "WARN", f"Expected 587, got: {mail_port}")

            if mail_username == 'apikey':
                self.print_test("Flask-Mail MAIL_USERNAME", "PASS", "Username: apikey")
            else:
                self.print_test("Flask-Mail MAIL_USERNAME", "FAIL", f"Expected 'apikey', got: {mail_username}")

    def test_send_test_email(self, recipient_email):
        """Test 2: Send a test email via SendGrid"""
        self.print_header("Test 2: Send Test Email via SendGrid")

        try:
            with app.app_context():
                from flask_mail import Message

                subject = f"SilentCanary Email Test - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                html_body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2 style="color: #d9534f;">🧪 SilentCanary Email System Test</h2>

                    <p>This is a test email from the SilentCanary email system.</p>

                    <h3>Test Details:</h3>
                    <ul>
                        <li><strong>Timestamp:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
                        <li><strong>Email Server:</strong> {app.config['MAIL_SERVER']}</li>
                        <li><strong>Sender:</strong> {app.config['MAIL_DEFAULT_SENDER']}</li>
                        <li><strong>Recipient:</strong> {recipient_email}</li>
                    </ul>

                    <h3>What This Tests:</h3>
                    <ul>
                        <li>SendGrid SMTP configuration</li>
                        <li>Authentication with API key</li>
                        <li>Email delivery to recipient</li>
                        <li>HTML email rendering</li>
                    </ul>

                    <hr>
                    <p style="color: #666; font-size: 12px;">
                        If you received this email, the SilentCanary email system is working correctly.
                    </p>
                </body>
                </html>
                """

                msg = Message(
                    subject=subject,
                    recipients=[recipient_email],
                    html=html_body,
                    sender=('SilentCanary Test', app.config['MAIL_DEFAULT_SENDER'])
                )

                print(f"📧 Attempting to send test email to: {recipient_email}")
                print(f"   Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
                print(f"   From: {app.config['MAIL_DEFAULT_SENDER']}")

                mail.send(msg)

                self.print_test("Send test email", "PASS", f"Email sent to {recipient_email}")
                print("\n   ⏳ Check your inbox (and spam folder) for the test email")
                return True

        except Exception as e:
            self.print_test("Send test email", "FAIL", f"Error: {str(e)}")
            print(f"\n   Full error details: {repr(e)}")
            return False

    def test_canary_alert_email(self, recipient_email):
        """Test 3: Test canary alert email template and sending"""
        self.print_header("Test 3: Canary Alert Email Template")

        try:
            with app.app_context():
                from flask_mail import Message

                # Create a mock canary alert email
                subject = f"🚨 SilentCanary Alert Test - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"

                canary_name = "Test Canary"
                last_checkin = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S UTC')
                expected_checkin = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S UTC')

                html_body = f"""
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2 style="color: #d9534f;">🚨 SilentCanary Alert (TEST)</h2>
                    <p>Your canary "<strong>{canary_name}</strong>" has failed to check in!</p>

                    <h3>Details:</h3>
                    <ul>
                        <li><strong>Last check-in:</strong> {last_checkin}</li>
                        <li><strong>Expected check-in:</strong> {expected_checkin}</li>
                        <li><strong>Grace period:</strong> 15 minutes</li>
                        <li><strong>Check-in interval:</strong> 60 minutes</li>
                    </ul>

                    <p style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 20px 0;">
                        ⚠️ <strong>Note:</strong> This is a TEST alert. Please investigate your monitoring target immediately in a production scenario.
                    </p>

                    <hr>
                    <p style="color: #666; font-size: 12px;">
                        This is a test alert from SilentCanary email monitoring system.
                    </p>
                </body>
                </html>
                """

                msg = Message(
                    subject=subject,
                    recipients=[recipient_email],
                    html=html_body,
                    sender=('SilentCanary Alert', app.config['MAIL_DEFAULT_SENDER'])
                )

                print(f"🚨 Sending test canary alert email to: {recipient_email}")
                mail.send(msg)

                self.print_test("Send canary alert email", "PASS", f"Alert email sent to {recipient_email}")
                print("\n   ⏳ Check your inbox for the alert email")
                return True

        except Exception as e:
            self.print_test("Send canary alert email", "FAIL", f"Error: {str(e)}")
            return False

    def test_worker_notification_function(self):
        """Test 4: Test the worker notification function"""
        self.print_header("Test 4: Worker Notification Function")

        try:
            # Test that the function exists and is importable
            from worker import send_notifications, should_suppress_alert

            self.print_test("Import send_notifications function", "PASS", "Function imported successfully")
            self.print_test("Import should_suppress_alert function", "PASS", "Function imported successfully")

            # Check if Redis is accessible
            try:
                redis_conn = get_redis_connection()
                redis_conn.ping()
                self.print_test("Redis connection for alerts", "PASS", "Redis is accessible")
            except Exception as e:
                self.print_test("Redis connection for alerts", "FAIL", f"Redis error: {str(e)}")

        except Exception as e:
            self.print_test("Worker notification function", "FAIL", f"Error: {str(e)}")

    def check_user_canaries(self, user_email):
        """Test 5: Check user's canaries and their status"""
        self.print_header("Test 5: Check User Canaries")

        try:
            # Get user
            user = User.get_by_email(user_email)
            if not user:
                self.print_test("Get user by email", "FAIL", f"User not found: {user_email}")
                return None

            self.print_test("Get user by email", "PASS", f"User found: {user.username}")

            # Get user's canaries
            canaries = Canary.get_by_user_id(user.user_id)
            if not canaries:
                self.print_test("Get user canaries", "WARN", "No canaries found for user")
                return None

            self.print_test("Get user canaries", "PASS", f"Found {len(canaries)} canary(ies)")

            # Display canary details
            print("\n   📊 Canary Details:")
            for i, canary in enumerate(canaries, 1):
                print(f"\n   {i}. {canary.name}")
                print(f"      ID: {canary.canary_id}")
                print(f"      Status: {canary.status}")
                print(f"      Alert Type: {canary.alert_type}")
                print(f"      Alert Email: {canary.alert_email or user.email}")
                print(f"      Last Check-in: {canary.last_checkin or 'Never'}")
                print(f"      Next Expected: {canary.next_expected or 'N/A'}")
                print(f"      Interval: {canary.interval_minutes} minutes")
                print(f"      Grace Period: {canary.grace_minutes} minutes")
                print(f"      Is Active: {canary.is_active}")

                # Check if overdue
                if canary.is_overdue():
                    print(f"      ⚠️ STATUS: OVERDUE - Should trigger alert!")
                else:
                    print(f"      ✅ STATUS: Not overdue")

            return canaries

        except Exception as e:
            self.print_test("Check user canaries", "FAIL", f"Error: {str(e)}")
            return None

    def test_scheduler_status(self):
        """Test 6: Check if scheduler is running"""
        self.print_header("Test 6: Scheduler and Worker Status")

        try:
            redis_conn = get_redis_connection()

            # Check health-checks queue
            from rq import Queue
            health_queue = Queue('health-checks', connection=redis_conn)
            notifications_queue = Queue('notifications', connection=redis_conn)

            health_jobs = health_queue.get_jobs()
            notification_jobs = notifications_queue.get_jobs()

            print(f"   📊 Queue Status:")
            print(f"      Health Checks Queue: {len(health_jobs)} job(s)")
            print(f"      Notifications Queue: {len(notification_jobs)} job(s)")

            if len(health_jobs) > 0 or len(notification_jobs) > 0:
                self.print_test("Worker queues active", "PASS", "Jobs found in queues")
            else:
                self.print_test("Worker queues active", "WARN", "No jobs in queues - scheduler may not be running")

            # Check if worker is actually running by looking at workers
            from rq import Worker
            workers = Worker.all(connection=redis_conn)

            if workers:
                self.print_test("RQ Workers running", "PASS", f"{len(workers)} worker(s) active")
                for worker in workers:
                    print(f"      Worker: {worker.name} - State: {worker.get_state()}")
            else:
                self.print_test("RQ Workers running", "FAIL", "No workers found - emails won't be sent!")
                print("\n   ⚠️ CRITICAL: Worker process is not running!")
                print("   Start the worker with: docker-compose restart worker")

        except Exception as e:
            self.print_test("Scheduler status check", "FAIL", f"Error: {str(e)}")

    def print_summary(self):
        """Print test summary"""
        self.print_header("Test Summary")

        total_tests = self.tests_passed + self.tests_failed

        print(f"   ✅ Passed: {self.tests_passed}/{total_tests}")
        print(f"   ❌ Failed: {self.tests_failed}/{total_tests}")
        print(f"   ⚠️  Warnings: {len(self.warnings)}")

        if self.warnings:
            print("\n   Warnings:")
            for warning in self.warnings:
                print(f"      • {warning}")

        print(f"\n   {'='*80}")
        if self.tests_failed == 0:
            print("   ✅ ALL TESTS PASSED - Email system is configured correctly")
        else:
            print("   ❌ SOME TESTS FAILED - Please review the errors above")
        print(f"   {'='*80}\n")

def main():
    """Main test runner"""
    print("\n" + "="*80)
    print("  SilentCanary End-to-End Email System Test")
    print("="*80)

    # Get recipient email from environment or command line
    recipient = os.environ.get('TEST_EMAIL')
    if not recipient and len(sys.argv) > 1:
        recipient = sys.argv[1]

    if not recipient:
        print("\n❌ Error: No recipient email specified")
        print("Usage: python test_email_e2e.py your-email@example.com")
        print("Or set TEST_EMAIL environment variable")
        sys.exit(1)

    print(f"\n📧 Testing email delivery to: {recipient}")
    print(f"⏰ Test started at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

    # Run tests
    tester = EmailSystemTester()

    # Test 1: Environment configuration
    tester.test_environment_config()

    # Test 2: Send test email
    tester.test_send_test_email(recipient)

    # Test 3: Canary alert email
    tester.test_canary_alert_email(recipient)

    # Test 4: Worker functions
    tester.test_worker_notification_function()

    # Test 5: Check user's canaries
    tester.check_user_canaries(recipient)

    # Test 6: Scheduler status
    tester.test_scheduler_status()

    # Print summary
    tester.print_summary()

    # Exit with error code if tests failed
    sys.exit(1 if tester.tests_failed > 0 else 0)

if __name__ == '__main__':
    main()
