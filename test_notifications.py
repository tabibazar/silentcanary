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
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@silentcanary.com')
    
    print(f"SendGrid API Key: {'✅ Set' if os.environ.get('SENDGRID_API_KEY') else '❌ NOT SET'}")
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

def test_cancellation_email():
    """Test the cancellation email template"""
    print("\n=== TESTING CANCELLATION EMAIL TEMPLATE ===")

    try:
        from app import app, send_templated_email

        # Test within Flask context
        with app.app_context():
            print("Sending test cancellation email...")
            send_templated_email(
                recipients='reza@tabibazar.com',
                subject='TEST: Your SilentCanary subscription has been canceled',
                template_name='subscription_canceled',
                user_name='reza',
                plan_name='Growth',
                access_end_date='October 15, 2025',
                subscription_id='sub_test_orphaned_subscription'
            )
            print("✅ Cancellation email sent successfully")

    except Exception as e:
        print(f"❌ Cancellation email test FAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    print("SilentCanary Notification Debug Test")
    print("=" * 40)

    # Test email directly first
    email_works = test_email_only()

    if email_works:
        # Test the cancellation email template
        test_cancellation_email()
    else:
        print("❌ Skipping template email test due to email failure")