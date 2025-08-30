#!/usr/bin/env python3
"""
Flask email test for SilentCanary
"""

from app import app, send_email

def test_flask_email():
    """Test sending email through Flask-Mail with SendGrid."""
    with app.app_context():
        print("=== Flask Email Test ===")
        
        test_email = input("Enter your email address to test: ").strip()
        if not test_email or '@' not in test_email:
            print("Invalid email address.")
            return
        
        print("Sending test email...")
        
        html_content = """
        <h2>SilentCanary Flask Email Test</h2>
        <p>This email was sent using Flask-Mail with SendGrid SMTP.</p>
        <p>If you received this, your email configuration is working!</p>
        """
        
        result = send_email(test_email, "SilentCanary Flask Email Test", html_content)
        
        if result:
            print("✅ Email sent successfully!")
        else:
            print("❌ Email sending failed!")

if __name__ == '__main__':
    test_flask_email()