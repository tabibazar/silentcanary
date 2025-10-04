#!/usr/bin/env python3
"""
Test Email Infrastructure - Phase 1 Extended
"""
from flask import Flask
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_email_templates():
    """Test all email templates render correctly"""
    print("📧 Testing email template infrastructure...")

    try:
        from app import app, send_templated_email

        with app.app_context():
            test_data = {
                'name': 'Test User',
                'email': 'test-e2e@tabibazar.com',
                'form_subject': 'E2E Test Contact',
                'message': 'This is a comprehensive end-to-end test of the contact system.',
                'timestamp': '2025-09-30 01:00:00 UTC',
                'username': 'testuser',
                'verification_link': 'https://silentcanary.com/verify/test123',
                'user_name': 'Test User',
                'plan_name': 'Startup',
                'subscription_id': 'sub_test123',
                'next_billing_date': 'October 30, 2025',
                'access_end_date': 'October 30, 2025',
                'amount': '$7.00'
            }

            templates_to_test = [
                {
                    'name': 'Contact Form Notification',
                    'template': 'contact_form',
                    'recipients': 'reza@tabibazar.com',
                    'subject': '[E2E Test] Contact Form Submission',
                    'data': test_data
                },
                {
                    'name': 'Contact Confirmation',
                    'template': 'contact_confirmation',
                    'recipients': 'test-e2e@tabibazar.com',
                    'subject': '[E2E Test] Contact Confirmation',
                    'data': test_data
                }
            ]

            results = []
            for template_test in templates_to_test:
                try:
                    print(f"  📤 Testing {template_test['name']}...")
                    send_templated_email(
                        recipients=template_test['recipients'],
                        subject=template_test['subject'],
                        template_name=template_test['template'],
                        **template_test['data']
                    )
                    print(f"  ✅ {template_test['name']} sent successfully")
                    results.append(True)
                except Exception as e:
                    print(f"  ❌ {template_test['name']} failed: {e}")
                    results.append(False)

            return all(results)

    except Exception as e:
        print(f"❌ Email template testing failed: {e}")
        return False

def test_database_contact_storage():
    """Test contact request storage in database"""
    print("💾 Testing contact request database storage...")

    try:
        from models import ContactRequest

        # Create a test contact request
        test_contact = ContactRequest(
            name="E2E Test User",
            email="test-e2e-db@tabibazar.com",
            subject="E2E Database Test",
            category="technical",
            message="Testing database storage functionality for contact requests during end-to-end testing.",
            status="new"
        )

        # Save to database
        if test_contact.save():
            print("✅ Contact request saved to database")

            # Verify it can be retrieved
            retrieved = ContactRequest.get_by_id(test_contact.request_id)
            if retrieved and retrieved.email == test_contact.email:
                print("✅ Contact request retrieved successfully")
                return True
            else:
                print("❌ Contact request retrieval failed")
                return False
        else:
            print("❌ Contact request save failed")
            return False

    except Exception as e:
        print(f"❌ Database contact storage test failed: {e}")
        return False

def test_admin_contact_view():
    """Test admin contact request viewing"""
    print("👨‍💼 Testing admin contact request functionality...")

    try:
        from models import ContactRequest

        # Get all contact requests
        contact_requests = ContactRequest.get_all(limit=10)
        print(f"📊 Found {len(contact_requests)} contact requests in database")

        if len(contact_requests) > 0:
            print("✅ Contact requests retrievable for admin panel")

            # Test stats
            stats = ContactRequest.get_stats()
            print(f"📈 Contact stats: {stats}")
            print("✅ Contact statistics working")
            return True
        else:
            print("⚠️  No contact requests found (this is expected if none submitted)")
            return True

    except Exception as e:
        print(f"❌ Admin contact view test failed: {e}")
        return False

def run_email_infrastructure_tests():
    """Run email infrastructure tests"""
    print("📧 TESTING EMAIL INFRASTRUCTURE")
    print("=" * 50)

    test_results = []

    test_results.append(("Email Templates", test_email_templates()))
    test_results.append(("Database Storage", test_database_contact_storage()))
    test_results.append(("Admin Contact View", test_admin_contact_view()))

    # Summary
    print("\n" + "=" * 50)
    print("📊 EMAIL INFRASTRUCTURE RESULTS:")
    print("=" * 50)

    passed = 0
    total = len(test_results)

    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1

    print("=" * 50)
    print(f"📈 Overall: {passed}/{total} tests passed ({(passed/total)*100:.1f}%)")

    return passed == total

if __name__ == '__main__':
    run_email_infrastructure_tests()