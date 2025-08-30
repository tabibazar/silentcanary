#!/usr/bin/env python3
"""
Gmail setup helper for SilentCanary
This script helps you configure Gmail SMTP for email delivery.
"""

import os
from dotenv import load_dotenv

def setup_gmail():
    """Interactive Gmail setup."""
    print("🔧 Gmail SMTP Setup for SilentCanary\n")
    
    print("To use Gmail for sending emails, you need:")
    print("1. A Gmail account")
    print("2. Two-factor authentication enabled")
    print("3. An App Password generated for SilentCanary")
    print()
    
    print("📋 Setup Steps:")
    print("1. Go to https://myaccount.google.com/security")
    print("2. Enable 2-Factor Authentication if not already enabled")
    print("3. Go to 'App passwords' section")
    print("4. Generate a new app password for 'Mail'")
    print("5. Copy the 16-character password (format: xxxx xxxx xxxx xxxx)")
    print()
    
    # Get user input
    gmail_address = input("Enter your Gmail address: ").strip()
    if not gmail_address or '@gmail.com' not in gmail_address:
        print("❌ Please enter a valid Gmail address (must end with @gmail.com)")
        return False
    
    print(f"\n✅ Gmail address: {gmail_address}")
    print("\nNow you need to generate an App Password:")
    print("1. Visit: https://myaccount.google.com/apppasswords")
    print("2. Select 'Mail' as the app")
    print("3. Copy the generated 16-character password")
    print()
    
    app_password = input("Enter your Gmail App Password (16 characters): ").strip().replace(" ", "")
    if len(app_password) != 16:
        print("❌ App password should be exactly 16 characters")
        print("   Format should be like: abcdabcdabcdabcd")
        return False
    
    print(f"\n✅ App password configured: {'*' * 12}{app_password[-4:]}")
    
    # Update .env file
    env_file = '.env'
    if not os.path.exists(env_file):
        print(f"❌ {env_file} not found. Please create it first.")
        return False
    
    # Read current .env
    with open(env_file, 'r') as f:
        lines = f.readlines()
    
    # Update Gmail settings
    updated_lines = []
    gmail_username_set = False
    gmail_password_set = False
    
    for line in lines:
        if line.startswith('GMAIL_USERNAME='):
            updated_lines.append(f'GMAIL_USERNAME={gmail_address}\n')
            gmail_username_set = True
        elif line.startswith('GMAIL_APP_PASSWORD='):
            updated_lines.append(f'GMAIL_APP_PASSWORD={app_password}\n')
            gmail_password_set = True
        else:
            updated_lines.append(line)
    
    # Add missing lines if needed
    if not gmail_username_set:
        updated_lines.append(f'GMAIL_USERNAME={gmail_address}\n')
    if not gmail_password_set:
        updated_lines.append(f'GMAIL_APP_PASSWORD={app_password}\n')
    
    # Write updated .env
    with open(env_file, 'w') as f:
        f.writelines(updated_lines)
    
    print(f"\n✅ Updated {env_file} with Gmail configuration")
    
    return True

def test_gmail_config():
    """Test Gmail configuration."""
    load_dotenv()
    
    print("\n🔍 Testing Gmail Configuration...")
    
    gmail_user = os.environ.get('GMAIL_USERNAME')
    gmail_pass = os.environ.get('GMAIL_APP_PASSWORD')
    
    print(f"Gmail Username: {gmail_user}")
    print(f"Gmail Password: {'✅ Configured' if gmail_pass else '❌ Missing'}")
    
    if not gmail_user or not gmail_pass:
        print("\n❌ Gmail configuration incomplete")
        return False
    
    # Test SMTP connection
    print("\n🔌 Testing SMTP connection...")
    try:
        import smtplib
        from email.mime.text import MIMEText
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_pass)
        server.quit()
        
        print("✅ Gmail SMTP connection successful!")
        return True
        
    except Exception as e:
        print(f"❌ Gmail SMTP connection failed: {e}")
        print("\nCommon issues:")
        print("- Make sure 2FA is enabled on your Google account")
        print("- Use an App Password, not your regular Gmail password")
        print("- Check that 'Less secure app access' is not blocking the connection")
        return False

if __name__ == '__main__':
    if setup_gmail():
        test_gmail_config()
        print("\n🎉 Gmail setup complete!")
        print("You can now test email sending with: python3 test_flask_email.py")
    else:
        print("\n❌ Gmail setup failed. Please try again.")