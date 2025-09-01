#!/usr/bin/env python3
"""
SilentCanary API Key Generator

This script helps generate API keys for CI/CD integration.
Run this script with your user ID to generate the properly formatted API key.
"""

import base64
import sys

def generate_api_key(user_id):
    """Generate a properly formatted API key for the given user ID"""
    if not user_id:
        print("Error: User ID is required")
        return None
    
    # Create the secret using first 8 characters of user_id
    secret = f"secret_{user_id[:8]}"
    
    # Combine user_id and secret
    credentials = f"{user_id}:{secret}"
    
    # Encode to base64
    api_key = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    
    return api_key

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_api_key.py <user_id>")
        print("\nExample:")
        print("  python generate_api_key.py abc123def456")
        print("\nTo find your user ID:")
        print("  1. Log into SilentCanary")
        print("  2. Check browser developer tools → Network tab")
        print("  3. Look for API calls containing your user_id")
        sys.exit(1)
    
    user_id = sys.argv[1].strip()
    
    if not user_id:
        print("Error: User ID cannot be empty")
        sys.exit(1)
    
    api_key = generate_api_key(user_id)
    
    if api_key:
        print("\n" + "="*60)
        print("🔑 SilentCanary API Key Generated")
        print("="*60)
        print(f"User ID: {user_id}")
        print(f"API Key: {api_key}")
        print("\n📋 Add to your CI/CD secrets as:")
        print(f"SILENTCANARY_API_KEY={api_key}")
        print("\n🧪 Test with curl:")
        print(f'curl -H "X-API-Key: {api_key}" \\')
        print('     -H "Content-Type: application/json" \\')
        print('     -d \'{"service_name": "test", "environment": "dev", "deployment_id": "test-123"}\' \\')
        print('     https://silentcanary.com/api/v1/deployment/webhook')
        print("\n⚠️  Keep this API key secure and never commit it to version control!")
        print("="*60)

if __name__ == "__main__":
    main()