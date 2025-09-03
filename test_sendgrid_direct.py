#!/usr/bin/env python3
"""
Direct SendGrid email test using the Web API instead of SMTP
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

def test_sendgrid_api():
    """Test SendGrid using the Web API directly."""
    api_key = os.environ.get('SENDGRID_API_KEY')
    sender_email = os.environ.get('MAIL_DEFAULT_SENDER', 'auth@avriz.com')
    
    if not api_key:
        print("❌ SENDGRID_API_KEY not found in environment")
        return False
    
    print("Testing SendGrid Web API with configured key")
    print(f"Sender email: {sender_email}")
    
    # Get test email
    test_email = input("Enter your email to send a test: ").strip()
    if not test_email or '@' not in test_email:
        print("Invalid email address")
        return False
    
    # SendGrid Web API payload
    payload = {
        "personalizations": [
            {
                "to": [{"email": test_email}],
                "subject": "SilentCanary SendGrid Test"
            }
        ],
        "from": {"email": sender_email},
        "content": [
            {
                "type": "text/html",
                "value": """
                <h2>SilentCanary SendGrid Test</h2>
                <p>This email was sent using the SendGrid Web API.</p>
                <p>If you received this, your SendGrid configuration is working!</p>
                <p><strong>Configuration:</strong></p>
                <ul>
                    <li>API Key: Working</li>
                    <li>Sender: {}</li>
                </ul>
                """.format(sender_email)
            }
        ]
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers=headers
        )
        
        if response.status_code == 202:
            print("✅ Email sent successfully!")
            print("Check your inbox (and spam folder) for the test email.")
            return True
        else:
            print(f"❌ Failed to send email: {response.status_code}")
            print(f"Response: {response.text}")
            
            if response.status_code == 401:
                print("API key is invalid or expired")
            elif response.status_code == 403:
                print("API key doesn't have permission to send emails")
            elif response.status_code == 400:
                print("Bad request - check sender email is verified")
            
            return False
            
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False

if __name__ == '__main__':
    print("🧪 SendGrid Web API Direct Test\n")
    test_sendgrid_api()