#!/usr/bin/env python3
"""
Test script to debug notification issues
"""
from flask import Flask
from flask_mail import Mail, Message
from models import Canary, User
from dotenv import load_dotenv
import os
import sys

# Load environment variables
load_dotenv()

def test_email_only():
    """Test email functionality directly"""
    print("=== TESTING EMAIL DIRECTLY ===")
    
    # Create test Flask app
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test'
    app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = 'apikey'
    app.config['MAIL_PASSWORD'] = os.environ.get('SENDGRID_API_KEY')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'auth@avriz.com')
    
    print(f"SendGrid API Key: {'*' * 60}{os.environ.get('SENDGRID_API_KEY', '')[-10:] if os.environ.get('SENDGRID_API_KEY') else 'NOT SET'}")
    print(f"Mail sender: {app.config['MAIL_DEFAULT_SENDER']}")
    
    with app.app_context():
        mail = Mail(app)
        
        try:
            msg = Message(
                subject='SilentCanary Debug Test',
                recipients=['reza@tabibazar.com'],
                html='<p>This is a debug test from SilentCanary notification system.</p>'
            )
            mail.send(msg)
            print("✅ Direct email test: SUCCESS")
            return True
        except Exception as e:
            print(f"❌ Direct email test FAILED: {e}")
            return False

def test_notification_function():
    """Test the actual send_notifications function"""
    print("\n=== TESTING NOTIFICATION FUNCTION ===")
    
    # We need to import from the main app to get the proper Flask context
    try:
        from app import app, send_notifications
        
        # Get the overdue canary
        from models import get_dynamodb_resource
        dynamodb = get_dynamodb_resource()
        canaries_table = dynamodb.Table('SilentCanary_Canaries')
        response = canaries_table.scan()
        canaries = response.get('Items', [])
        
        # Find the overdue canary
        target_canary = None
        for canary_data in canaries:
            if canary_data['name'] == 'prod-backups-job':
                target_canary = canary_data
                break
        
        if not target_canary:
            print("❌ Could not find prod-backups-job canary")
            return
        
        # Convert to Canary object
        canary = Canary(
            canary_id=target_canary['canary_id'],
            name=target_canary['name'],
            user_id=target_canary['user_id'],
            alert_type=target_canary.get('alert_type', 'email'),
            alert_email=target_canary.get('alert_email'),
            slack_webhook=target_canary.get('slack_webhook'),
            interval_minutes=target_canary.get('interval_minutes', 60),
            grace_minutes=target_canary.get('grace_minutes', 5)
        )
        
        print(f"Testing with canary: {canary.name}")
        print(f"Alert type: {canary.alert_type}")
        print(f"Alert email: {canary.alert_email}")
        print(f"User ID: {canary.user_id}")
        
        # Get user
        user = User.get_by_id(canary.user_id)
        print(f"User email: {user.email if user else 'No user found'}")
        
        # Test within Flask context
        with app.app_context():
            print("Calling send_notifications...")
            send_notifications(canary)
            print("send_notifications completed")
            
    except Exception as e:
        print(f"❌ Notification function test FAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    print("SilentCanary Notification Debug Test")
    print("=" * 40)
    
    # Test email directly first
    email_works = test_email_only()
    
    if email_works:
        # Test the actual notification function
        test_notification_function()
    else:
        print("❌ Skipping notification function test due to email failure")