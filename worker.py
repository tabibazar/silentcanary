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
from models import Canary, User
import requests
from flask_mail import Mail, Message
from flask import Flask
from dotenv import load_dotenv

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
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'auth@avriz.com')

mail = Mail(app)

def send_notifications(canary_id):
    """Send notifications for a failed canary"""
    with app.app_context():
        try:
            # Get canary and user data
            canary = Canary.get_by_id(canary_id)
            if not canary:
                print(f"❌ Canary {canary_id} not found")
                return False
            
            user = User.get_by_id(canary.user_id)
            
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
            if canary.alert_type in ['email', 'both']:
                recipient = canary.alert_email or (user.email if user else None)
                if recipient:
                    msg = Message(
                        subject=subject,
                        recipients=[recipient],
                        html=html_message
                    )
                    mail.send(msg)
                    print(f"📧 Email notification sent to {recipient}")
                else:
                    print("❌ No email recipient available")
            
            # Send Slack notification
            if canary.alert_type in ['slack', 'both'] and canary.slack_webhook:
                payload = {"text": slack_message}
                response = requests.post(canary.slack_webhook, json=payload, timeout=10)
                if response.status_code == 200:
                    print(f"💬 Slack notification sent for canary: {canary.name}")
                else:
                    print(f"❌ Slack notification failed: {response.status_code}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error sending notifications for canary {canary_id}: {e}")
            return False

def check_canary_health():
    """Check all active canaries for health and enqueue notifications for failed ones"""
    print(f"🔍 Checking canary health at {datetime.now(timezone.utc)}")
    
    try:
        # Get Redis connection for queuing notifications
        redis_conn = get_redis_connection()
        notification_queue = Queue('notifications', connection=redis_conn)
        
        # Get all active canaries
        active_canaries = Canary.get_active_canaries()
        print(f"📊 Checking {len(active_canaries)} active canaries")
        
        failed_count = 0
        for canary in active_canaries:
            if canary.status != 'failed' and canary.is_overdue():
                print(f"⚠️ Canary '{canary.name}' is overdue - marking as failed")
                
                # Update canary status
                canary.status = 'failed'
                canary.save()
                
                # Enqueue notification job
                notification_queue.enqueue(
                    send_notifications,
                    canary.canary_id,
                    job_timeout=300,  # 5 minutes timeout
                    retry=3
                )
                
                failed_count += 1
        
        if failed_count > 0:
            print(f"📧 Enqueued notifications for {failed_count} failed canaries")
        else:
            print("✅ All canaries are healthy")
        
        return failed_count
        
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