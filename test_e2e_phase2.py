#!/usr/bin/env python3
"""
End-to-End Testing - Phase 2: Subscription & Billing
"""
import requests
import json
import time
from datetime import datetime

BASE_URL = "https://silentcanary.com"

def test_pricing_page_plans():
    """Test 2.1: Pricing page shows all plans correctly"""
    print("💰 Testing pricing page plan display...")
    try:
        response = requests.get(f"{BASE_URL}/pricing", timeout=10)
        if response.status_code == 200:
            content = response.text

            # Check for plan names
            plans_found = []
            expected_plans = ['Solo', 'Startup', 'Growth', 'Enterprise']

            for plan in expected_plans:
                if plan in content:
                    plans_found.append(plan)
                    print(f"  ✅ {plan} plan displayed")
                else:
                    print(f"  ❌ {plan} plan missing")

            print(f"📊 Plans displayed: {len(plans_found)}/{len(expected_plans)}")
            return len(plans_found) == len(expected_plans)
        else:
            print(f"❌ Pricing page returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Pricing page test failed: {e}")
        return False

def test_subscription_upgrade_flow():
    """Test 2.2: Subscription upgrade flow accessibility"""
    print("⬆️ Testing subscription upgrade flow...")

    upgrade_paths = [
        '/upgrade_plan/startup',
        '/upgrade_plan/growth',
        '/upgrade_plan/enterprise'
    ]

    session = requests.Session()
    success_count = 0

    for path in upgrade_paths:
        try:
            # These should redirect to login for non-authenticated users
            response = session.get(f"{BASE_URL}{path}", timeout=10, allow_redirects=False)
            if response.status_code in [302, 401]:  # Redirect to login or unauthorized
                print(f"  ✅ {path} properly requires authentication")
                success_count += 1
            else:
                print(f"  ❌ {path} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {path} failed: {e}")

    print(f"📊 Upgrade paths: {success_count}/{len(upgrade_paths)} properly secured")
    return success_count == len(upgrade_paths)

def test_account_management_page():
    """Test 2.3: Account management page accessibility"""
    print("⚙️ Testing account management page...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/account", timeout=10, allow_redirects=False)

        # Should redirect to login for non-authenticated users
        if response.status_code in [302, 401]:
            print("✅ Account page properly requires authentication")
            return True
        else:
            print(f"❌ Account page returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Account page test failed: {e}")
        return False

def test_stripe_webhook_endpoint():
    """Test 2.4: Stripe webhook endpoint accessibility"""
    print("🎣 Testing Stripe webhook endpoint...")
    try:
        # This should accept POST but reject GET without proper signature
        response = requests.get(f"{BASE_URL}/webhook/stripe", timeout=10)

        # Webhook should return method not allowed for GET or require proper Stripe signature
        if response.status_code in [405, 400, 401]:
            print("✅ Stripe webhook endpoint properly secured")
            return True
        else:
            print(f"❌ Stripe webhook returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Stripe webhook test failed: {e}")
        return False

def test_billing_frequency_endpoints():
    """Test 2.5: Billing frequency change endpoints"""
    print("📅 Testing billing frequency endpoints...")

    frequency_paths = [
        '/change_billing_frequency/monthly',
        '/change_billing_frequency/annual'
    ]

    session = requests.Session()
    success_count = 0

    for path in frequency_paths:
        try:
            response = session.get(f"{BASE_URL}{path}", timeout=10, allow_redirects=False)
            if response.status_code in [302, 401]:  # Should require authentication
                print(f"  ✅ {path} properly requires authentication")
                success_count += 1
            else:
                print(f"  ❌ {path} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {path} failed: {e}")

    print(f"📊 Billing frequency endpoints: {success_count}/{len(frequency_paths)} properly secured")
    return success_count == len(frequency_paths)

def test_subscription_cancellation_endpoint():
    """Test 2.6: Subscription cancellation endpoint"""
    print("❌ Testing subscription cancellation endpoint...")
    try:
        session = requests.Session()
        # Should only accept POST and require authentication
        response = session.get(f"{BASE_URL}/cancel_subscription", timeout=10, allow_redirects=False)

        if response.status_code in [405, 302, 401]:  # Method not allowed or auth required
            print("✅ Cancellation endpoint properly secured")
            return True
        else:
            print(f"❌ Cancellation endpoint returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cancellation endpoint test failed: {e}")
        return False

def test_resubscribe_endpoint():
    """Test 2.7: Resubscribe endpoint"""
    print("🔄 Testing resubscribe endpoint...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/resubscribe", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401]:  # Should require authentication
            print("✅ Resubscribe endpoint properly requires authentication")
            return True
        else:
            print(f"❌ Resubscribe endpoint returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Resubscribe endpoint test failed: {e}")
        return False

def test_checkout_success_page():
    """Test 2.8: Checkout success page"""
    print("🎉 Testing checkout success page...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/checkout/success", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401]:  # Should require authentication or redirect
            print("✅ Checkout success page properly secured")
            return True
        else:
            print(f"❌ Checkout success page returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Checkout success page test failed: {e}")
        return False

def test_subscription_email_templates():
    """Test 2.9: Subscription-related email templates"""
    print("📧 Testing subscription email templates...")

    try:
        from app import app, send_templated_email

        with app.app_context():
            test_templates = [
                {
                    'name': 'Subscription Created',
                    'template': 'subscription_created',
                    'data': {
                        'user_name': 'Test User',
                        'plan_name': 'Startup',
                        'subscription_id': 'sub_test_e2e_123',
                        'next_billing_date': 'October 30, 2025'
                    }
                },
                {
                    'name': 'Payment Success',
                    'template': 'payment_success',
                    'data': {
                        'user_name': 'Test User',
                        'plan_name': 'Startup',
                        'amount': '$7.00',
                        'next_billing_date': 'November 30, 2025'
                    }
                },
                {
                    'name': 'Subscription Canceled',
                    'template': 'subscription_canceled',
                    'data': {
                        'user_name': 'Test User',
                        'plan_name': 'Startup',
                        'subscription_id': 'sub_test_e2e_123',
                        'access_end_date': 'November 30, 2025'
                    }
                }
            ]

            results = []
            for template_test in test_templates:
                try:
                    print(f"  📤 Testing {template_test['name']} email...")
                    send_templated_email(
                        recipients='test-billing@tabibazar.com',
                        subject=f'[E2E Test] {template_test["name"]}',
                        template_name=template_test['template'],
                        **template_test['data']
                    )
                    print(f"  ✅ {template_test['name']} email sent successfully")
                    results.append(True)
                except Exception as e:
                    print(f"  ❌ {template_test['name']} email failed: {e}")
                    results.append(False)

            return all(results)

    except Exception as e:
        print(f"❌ Subscription email template testing failed: {e}")
        return False

def run_phase2_tests():
    """Run all Phase 2 tests"""
    print("💳 STARTING PHASE 2: Subscription & Billing Testing")
    print("=" * 60)

    test_results = []

    # Subscription and billing tests
    test_results.append(("Pricing Page Plans", test_pricing_page_plans()))
    test_results.append(("Upgrade Flow Security", test_subscription_upgrade_flow()))
    test_results.append(("Account Management", test_account_management_page()))
    test_results.append(("Stripe Webhook", test_stripe_webhook_endpoint()))
    test_results.append(("Billing Frequency", test_billing_frequency_endpoints()))
    test_results.append(("Cancellation Endpoint", test_subscription_cancellation_endpoint()))
    test_results.append(("Resubscribe Endpoint", test_resubscribe_endpoint()))
    test_results.append(("Checkout Success", test_checkout_success_page()))
    test_results.append(("Subscription Emails", test_subscription_email_templates()))

    # Summary
    print("\n" + "=" * 60)
    print("📊 PHASE 2 TEST RESULTS:")
    print("=" * 60)

    passed = 0
    total = len(test_results)

    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:25} {status}")
        if result:
            passed += 1

    print("=" * 60)
    print(f"📈 Overall: {passed}/{total} tests passed ({(passed/total)*100:.1f}%)")

    if passed == total:
        print("🎉 Phase 2 COMPLETE - All subscription & billing tests passed!")
        return True
    else:
        print(f"⚠️  Phase 2 PARTIAL - {total-passed} tests failed")
        return False

if __name__ == '__main__':
    run_phase2_tests()