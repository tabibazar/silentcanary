#!/usr/bin/env python3
"""
SendGrid diagnostic script for SilentCanary
"""

import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_sendgrid_api():
    """Check SendGrid API connectivity and permissions."""
    api_key = os.environ.get('SENDGRID_API_KEY')
    
    if not api_key:
        print("❌ SENDGRID_API_KEY not found in environment")
        return False
    
    if not api_key.startswith('SG.'):
        print("❌ SENDGRID_API_KEY doesn't appear to be valid (should start with 'SG.')")
        return False
    
    print("✅ API Key format looks correct")
    
    # Test API connectivity
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    # Check API key permissions
    print("\n=== Testing SendGrid API Connectivity ===")
    try:
        response = requests.get('https://api.sendgrid.com/v3/user/profile', headers=headers)
        if response.status_code == 200:
            print("✅ API key is valid and has access")
            profile = response.json()
            print(f"   Account: {profile.get('username', 'Unknown')}")
        elif response.status_code == 401:
            print("❌ API key is invalid or doesn't have permissions")
            print("   Please check your API key in SendGrid dashboard")
            return False
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")
            print(f"   Response: {response.text}")
    except Exception as e:
        print(f"❌ Error connecting to SendGrid API: {e}")
        return False
    
    # Check verified senders
    print("\n=== Checking Verified Senders ===")
    try:
        response = requests.get('https://api.sendgrid.com/v3/verified_senders', headers=headers)
        if response.status_code == 200:
            senders = response.json()
            verified_senders = senders.get('results', [])
            
            sender_email = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@silentcanary.com')
            print(f"Looking for sender: {sender_email}")
            
            if not verified_senders:
                print("❌ No verified senders found!")
                print("   You need to verify a sender email in SendGrid:")
                print("   1. Go to https://app.sendgrid.com/settings/sender_auth")
                print("   2. Click 'Verify a Single Sender'")
                print(f"   3. Add and verify: {sender_email}")
                return False
            
            sender_found = False
            for sender in verified_senders:
                email = sender.get('from_email', '')
                verified = sender.get('verified', False)
                print(f"   {email}: {'✅ Verified' if verified else '❌ Not verified'}")
                
                if email == sender_email and verified:
                    sender_found = True
            
            if not sender_found:
                print(f"❌ Sender email {sender_email} is not verified!")
                print("   Please verify this email in SendGrid dashboard")
                return False
            else:
                print(f"✅ Sender email {sender_email} is verified")
                
        else:
            print(f"⚠️  Could not check verified senders: {response.status_code}")
            print("   This might be due to API key permissions")
    
    except Exception as e:
        print(f"❌ Error checking verified senders: {e}")
    
    # Check sending quota
    print("\n=== Checking Sending Quota ===")
    try:
        response = requests.get('https://api.sendgrid.com/v3/user/credits', headers=headers)
        if response.status_code == 200:
            credits = response.json()
            print(f"✅ Remaining credits: {credits.get('remain', 'Unknown')}")
            print(f"   Total credits: {credits.get('total', 'Unknown')}")
        else:
            print(f"⚠️  Could not check credits: {response.status_code}")
    except Exception as e:
        print(f"❌ Error checking credits: {e}")
    
    return True

def test_smtp_connection():
    """Test SMTP connection to SendGrid."""
    print("\n=== Testing SMTP Connection ===")
    
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Connect to SMTP server
        server = smtplib.SMTP('smtp.sendgrid.net', 587)
        server.starttls()
        
        api_key = os.environ.get('SENDGRID_API_KEY')
        server.login('apikey', api_key)
        
        print("✅ SMTP connection successful")
        server.quit()
        return True
        
    except Exception as e:
        print(f"❌ SMTP connection failed: {e}")
        return False

if __name__ == '__main__':
    print("🔍 SendGrid Diagnostic Tool for SilentCanary\n")
    
    api_ok = check_sendgrid_api()
    smtp_ok = test_smtp_connection()
    
    print("\n" + "="*50)
    if api_ok and smtp_ok:
        print("✅ SendGrid configuration appears to be working!")
        print("   If you're still not receiving emails:")
        print("   1. Check your spam/junk folder")
        print("   2. Try sending to a different email address")
        print("   3. Check SendGrid Activity Feed for delivery status")
    else:
        print("❌ SendGrid configuration has issues")
        print("   Please fix the issues above before trying to send emails")