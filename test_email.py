#!/usr/bin/env python3
"""
Email testing script for SilentCanary
Use this to test your SendGrid configuration.
"""

from app import app, send_email
import os

def test_email_config():
    """Test the email configuration and send a test email."""
    with app.app_context():
        print("=== SendGrid Configuration Test ===")
        print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
        print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
        print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
        print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
        print(f"MAIL_PASSWORD: {'[CONFIGURED]' if app.config['MAIL_PASSWORD'] else '[NOT SET]'}")
        print(f"MAIL_DEFAULT_SENDER: {app.config['MAIL_DEFAULT_SENDER']}")
        print()
        
        # Check if API key is properly loaded
        api_key = os.environ.get('SENDGRID_API_KEY')
        if not api_key:
            print("❌ SENDGRID_API_KEY not found in environment variables")
            return False
        elif not api_key.startswith('SG.'):
            print("❌ SENDGRID_API_KEY doesn't look like a valid SendGrid API key")
            print("   API keys should start with 'SG.'")
            return False
        else:
            print("✅ SENDGRID_API_KEY found and appears valid")
        
        print()
        
        # Get test email address
        test_email = input("Enter your email address to send a test email (or 'skip' to skip): ").strip()
        
        if test_email.lower() == 'skip':
            print("Skipping email test.")
            return True
            
        if not test_email or '@' not in test_email:
            print("Invalid email address.")
            return False
        
        # Send test email
        print(f"Sending test email to {test_email}...")
        
        html_content = f"""
        <h2>SilentCanary Email Test</h2>
        <p>This is a test email from your SilentCanary application.</p>
        <p>If you received this email, your SendGrid configuration is working correctly!</p>
        <p><strong>Configuration Details:</strong></p>
        <ul>
            <li>SMTP Server: {app.config['MAIL_SERVER']}</li>
            <li>Port: {app.config['MAIL_PORT']}</li>
            <li>TLS: {app.config['MAIL_USE_TLS']}</li>
            <li>Sender: {app.config['MAIL_DEFAULT_SENDER']}</li>
        </ul>
        """
        
        success = send_email(test_email, "SilentCanary Email Test", html_content)
        
        if success:
            print("✅ Test email sent successfully!")
            print("Check your inbox (and spam folder) for the test email.")
        else:
            print("❌ Failed to send test email. Check the error messages above.")
        
        return success

if __name__ == '__main__':
    test_email_config()