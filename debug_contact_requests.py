#!/usr/bin/env python3
"""
Debug script to check contact requests in database
"""
import os
from dotenv import load_dotenv
from models import get_dynamodb_resource, ContactRequest

# Load environment variables
load_dotenv()

def debug_contact_requests():
    """Debug contact requests storage and retrieval"""
    print("=== DEBUGGING CONTACT REQUESTS ===")

    try:
        # Check what's in the APIUsage table
        api_usage_table = get_dynamodb_resource().Table('SilentCanary_APIUsage')

        print("1. Scanning for contact_request records...")
        response = api_usage_table.scan(
            FilterExpression='api_type = :api_type',
            ExpressionAttributeValues={':api_type': 'contact_request'}
        )

        items = response.get('Items', [])
        print(f"Found {len(items)} contact request records")

        if items:
            print("\n2. Sample contact request data:")
            for i, item in enumerate(items[:3]):  # Show first 3
                print(f"   Record {i+1}:")
                print(f"     log_id: {item.get('log_id')}")
                print(f"     user_id (email): {item.get('user_id')}")
                print(f"     endpoint (name): {item.get('endpoint')}")
                print(f"     feature_used (subject): {item.get('feature_used')}")
                print(f"     model (category): {item.get('model')}")
                print(f"     success: {item.get('success')}")
                print(f"     timestamp: {item.get('timestamp')}")
                print(f"     error_message (message): {item.get('error_message', '')[:100]}...")
                print()

        print("3. Testing ContactRequest.get_all() method...")
        contact_requests = ContactRequest.get_all(limit=200)
        print(f"ContactRequest.get_all() returned {len(contact_requests)} requests")

        if contact_requests:
            print("\n4. Sample parsed contact request:")
            req = contact_requests[0]
            print(f"   Request ID: {req.request_id}")
            print(f"   Name: {req.name}")
            print(f"   Email: {req.email}")
            print(f"   Subject: {req.subject}")
            print(f"   Category: {req.category}")
            print(f"   Status: {req.status}")
            print(f"   Message: {req.message[:100] if req.message else 'None'}...")

        print("\n5. Testing ContactRequest.get_stats() method...")
        stats = ContactRequest.get_stats()
        print(f"Stats: {stats}")

    except Exception as e:
        print(f"❌ Error debugging contact requests: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    debug_contact_requests()