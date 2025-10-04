#!/usr/bin/env python3
"""
End-to-End Testing - Phase 3: Core Canary Features
"""
import requests
import json
import time
import uuid
from datetime import datetime

BASE_URL = "https://silentcanary.com"

def test_canary_creation_endpoint():
    """Test 3.1: Canary creation endpoint security"""
    print("🐦 Testing canary creation endpoint...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/create_canary", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401]:  # Should require authentication
            print("✅ Canary creation properly requires authentication")
            return True
        else:
            print(f"❌ Canary creation returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Canary creation test failed: {e}")
        return False

def test_dashboard_endpoint():
    """Test 3.2: Dashboard endpoint security"""
    print("📊 Testing dashboard endpoint...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/dashboard", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401]:  # Should require authentication
            print("✅ Dashboard properly requires authentication")
            return True
        else:
            print(f"❌ Dashboard returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Dashboard test failed: {e}")
        return False

def test_settings_endpoint():
    """Test 3.3: Settings endpoint security"""
    print("⚙️ Testing settings endpoint...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/settings", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401]:  # Should require authentication
            print("✅ Settings properly requires authentication")
            return True
        else:
            print(f"❌ Settings returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Settings test failed: {e}")
        return False

def test_canary_checkin_endpoints():
    """Test 3.4: Canary check-in endpoints with test tokens"""
    print("📡 Testing canary check-in endpoints...")

    # Test with fake tokens (should return 404)
    test_tokens = [
        'test-token-1',
        'test-token-2',
        'invalid-uuid-token'
    ]

    success_count = 0
    for token in test_tokens:
        try:
            # Test GET check-in
            response = requests.get(f"{BASE_URL}/checkin/{token}", timeout=10)
            if response.status_code == 404:
                print(f"  ✅ GET /checkin/{token} properly returns 404 for invalid token")
                success_count += 1
            else:
                print(f"  ❌ GET /checkin/{token} returned unexpected {response.status_code}")

            # Test POST check-in
            response = requests.post(f"{BASE_URL}/checkin/{token}",
                                   json={"message": "test"}, timeout=10)
            if response.status_code == 404:
                print(f"  ✅ POST /checkin/{token} properly returns 404 for invalid token")
                success_count += 1
            else:
                print(f"  ❌ POST /checkin/{token} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ Check-in test for {token} failed: {e}")

    total_tests = len(test_tokens) * 2  # GET and POST for each token
    print(f"📊 Check-in endpoints: {success_count}/{total_tests} properly secured")
    return success_count == total_tests

def test_canary_management_endpoints():
    """Test 3.5: Canary management endpoints security"""
    print("🔧 Testing canary management endpoints...")

    # Test with fake canary IDs (should require authentication)
    test_canary_id = str(uuid.uuid4())
    management_endpoints = [
        f'/edit_canary/{test_canary_id}',
        f'/delete_canary/{test_canary_id}',
        f'/canary_logs/{test_canary_id}',
        f'/canary_analytics/{test_canary_id}',
        f'/export_canary_data/{test_canary_id}/csv',
        f'/canary_diagnostics/{test_canary_id}'
    ]

    session = requests.Session()
    success_count = 0

    for endpoint in management_endpoints:
        try:
            response = session.get(f"{BASE_URL}{endpoint}", timeout=10, allow_redirects=False)
            if response.status_code in [302, 401]:  # Should require authentication
                print(f"  ✅ {endpoint} properly requires authentication")
                success_count += 1
            else:
                print(f"  ❌ {endpoint} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {endpoint} failed: {e}")

    print(f"📊 Management endpoints: {success_count}/{len(management_endpoints)} properly secured")
    return success_count == len(management_endpoints)

def test_smart_alert_endpoints():
    """Test 3.6: Smart Alert endpoints security"""
    print("🧠 Testing Smart Alert endpoints...")

    test_canary_id = str(uuid.uuid4())
    smart_alert_endpoints = [
        f'/smart_alert/{test_canary_id}',
        f'/enable_smart_alert/{test_canary_id}',
        f'/disable_smart_alert/{test_canary_id}',
        f'/smart_alert_progress/{test_canary_id}',
        f'/smart_alert_insights/{test_canary_id}',
        f'/smart_alert_timeline/{test_canary_id}',
        f'/smart_alert_logic/{test_canary_id}'
    ]

    session = requests.Session()
    success_count = 0

    for endpoint in smart_alert_endpoints:
        try:
            response = session.get(f"{BASE_URL}{endpoint}", timeout=10, allow_redirects=False)
            if response.status_code in [302, 401]:  # Should require authentication
                print(f"  ✅ {endpoint} properly requires authentication")
                success_count += 1
            else:
                print(f"  ❌ {endpoint} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {endpoint} failed: {e}")

    print(f"📊 Smart Alert endpoints: {success_count}/{len(smart_alert_endpoints)} properly secured")
    return success_count == len(smart_alert_endpoints)

def test_api_endpoints():
    """Test 3.7: API endpoints security"""
    print("🔌 Testing API endpoints...")

    api_endpoints = [
        '/api/canaries/status',
        '/api/v1/deployment/webhook',
        '/api/v1/canary/template',
        f'/api/v1/canary/{uuid.uuid4()}/deployment'
    ]

    session = requests.Session()
    success_count = 0

    for endpoint in api_endpoints:
        try:
            response = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            # API endpoints should return 401 for unauthorized or proper API responses
            if response.status_code in [401, 403, 405, 422]:  # Various expected auth/method errors
                print(f"  ✅ {endpoint} properly secured")
                success_count += 1
            elif response.status_code == 200:
                print(f"  ✅ {endpoint} accessible (public API)")
                success_count += 1
            else:
                print(f"  ❌ {endpoint} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {endpoint} failed: {e}")

    print(f"📊 API endpoints: {success_count}/{len(api_endpoints)} properly configured")
    return success_count == len(api_endpoints)

def test_email_verification_endpoints():
    """Test 3.8: Email verification endpoints"""
    print("✉️ Testing email verification endpoints...")

    test_verification_id = str(uuid.uuid4())
    verification_endpoints = [
        f'/verify-email/{test_verification_id}',
        '/verify-email-code',
        '/resend-verification'
    ]

    session = requests.Session()
    success_count = 0

    for endpoint in verification_endpoints:
        try:
            if endpoint == '/verify-email-code' or endpoint == '/resend-verification':
                # These are POST endpoints
                response = session.post(f"{BASE_URL}{endpoint}", timeout=10)
            else:
                response = session.get(f"{BASE_URL}{endpoint}", timeout=10)

            # Should handle gracefully (404 for invalid IDs, 401 for auth required, etc.)
            if response.status_code in [200, 302, 400, 401, 404, 405]:
                print(f"  ✅ {endpoint} handled gracefully")
                success_count += 1
            else:
                print(f"  ❌ {endpoint} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {endpoint} failed: {e}")

    print(f"📊 Verification endpoints: {success_count}/{len(verification_endpoints)} working")
    return success_count == len(verification_endpoints)

def test_canary_email_templates():
    """Test 3.9: Canary-related email templates"""
    print("📧 Testing canary email templates...")

    try:
        from app import app, send_templated_email

        with app.app_context():
            test_templates = [
                {
                    'name': 'Canary Alert',
                    'template': 'canary_alert',
                    'data': {
                        'canary_name': 'E2E Test Canary',
                        'last_checkin': '2025-09-30 00:30:00 UTC',
                        'canary_url': 'https://silentcanary.com/dashboard',
                        'custom_message': 'This is a test alert for end-to-end testing'
                    }
                },
                {
                    'name': 'Canary Verification',
                    'template': 'canary_verification',
                    'data': {
                        'canary_name': 'E2E Test Canary',
                        'verification_link': 'https://silentcanary.com/verify-email/test123',
                        'username': 'testuser'
                    }
                }
            ]

            results = []
            for template_test in test_templates:
                try:
                    print(f"  📤 Testing {template_test['name']} email...")
                    send_templated_email(
                        recipients='test-canary@tabibazar.com',
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
        print(f"❌ Canary email template testing failed: {e}")
        return False

def run_phase3_tests():
    """Run all Phase 3 tests"""
    print("🐦 STARTING PHASE 3: Core Canary Features Testing")
    print("=" * 60)

    test_results = []

    # Core canary feature tests
    test_results.append(("Canary Creation", test_canary_creation_endpoint()))
    test_results.append(("Dashboard Security", test_dashboard_endpoint()))
    test_results.append(("Settings Security", test_settings_endpoint()))
    test_results.append(("Check-in Endpoints", test_canary_checkin_endpoints()))
    test_results.append(("Management Endpoints", test_canary_management_endpoints()))
    test_results.append(("Smart Alert Endpoints", test_smart_alert_endpoints()))
    test_results.append(("API Endpoints", test_api_endpoints()))
    test_results.append(("Email Verification", test_email_verification_endpoints()))
    test_results.append(("Canary Emails", test_canary_email_templates()))

    # Summary
    print("\n" + "=" * 60)
    print("📊 PHASE 3 TEST RESULTS:")
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
        print("🎉 Phase 3 COMPLETE - All core canary feature tests passed!")
        return True
    else:
        print(f"⚠️  Phase 3 PARTIAL - {total-passed} tests failed")
        return False

if __name__ == '__main__':
    run_phase3_tests()