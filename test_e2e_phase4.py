#!/usr/bin/env python3
"""
End-to-End Testing - Phase 4: Advanced Features
"""
import requests
import json
import time
import uuid
from datetime import datetime

BASE_URL = "https://silentcanary.com"

def test_admin_panel_access():
    """Test 4.1: Admin panel access control"""
    print("👨‍💼 Testing admin panel access...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/admin", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401, 403]:  # Should require admin authentication
            print("✅ Admin panel properly requires admin authentication")
            return True
        else:
            print(f"❌ Admin panel returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Admin panel test failed: {e}")
        return False

def test_admin_contact_requests():
    """Test 4.2: Admin contact requests functionality"""
    print("📞 Testing admin contact requests...")
    try:
        session = requests.Session()
        response = session.get(f"{BASE_URL}/admin/contact-requests", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401, 403]:  # Should require admin authentication
            print("✅ Admin contact requests properly secured")
            return True
        else:
            print(f"❌ Admin contact requests returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Admin contact requests test failed: {e}")
        return False

def test_admin_user_management():
    """Test 4.3: Admin user management endpoints"""
    print("👥 Testing admin user management...")

    test_user_id = str(uuid.uuid4())
    admin_endpoints = [
        f'/admin/delete_user/{test_user_id}',
        f'/admin/update_email/{test_user_id}'
    ]

    session = requests.Session()
    success_count = 0

    for endpoint in admin_endpoints:
        try:
            response = session.post(f"{BASE_URL}{endpoint}", timeout=10, allow_redirects=False)
            if response.status_code in [302, 401, 403]:  # Should require admin authentication
                print(f"  ✅ {endpoint} properly requires admin authentication")
                success_count += 1
            else:
                print(f"  ❌ {endpoint} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {endpoint} failed: {e}")

    print(f"📊 Admin user management: {success_count}/{len(admin_endpoints)} properly secured")
    return success_count == len(admin_endpoints)

def test_api_key_management():
    """Test 4.4: API key management endpoints"""
    print("🔑 Testing API key management...")

    api_key_endpoints = [
        '/api_key_logs',
        '/api_usage_summary',
        '/api_usage_logs',
        f'/api_key_usage/{uuid.uuid4()}'
    ]

    session = requests.Session()
    success_count = 0

    for endpoint in api_key_endpoints:
        try:
            response = session.get(f"{BASE_URL}{endpoint}", timeout=10, allow_redirects=False)
            if response.status_code in [302, 401]:  # Should require authentication
                print(f"  ✅ {endpoint} properly requires authentication")
                success_count += 1
            else:
                print(f"  ❌ {endpoint} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {endpoint} failed: {e}")

    print(f"📊 API key management: {success_count}/{len(api_key_endpoints)} properly secured")
    return success_count == len(api_key_endpoints)

def test_anthropic_validation():
    """Test 4.5: Anthropic API key validation endpoint"""
    print("🧠 Testing Anthropic API key validation...")
    try:
        session = requests.Session()
        response = session.post(f"{BASE_URL}/validate_anthropic_key", timeout=10, allow_redirects=False)

        if response.status_code in [302, 401, 422]:  # Should require auth or return validation error
            print("✅ Anthropic key validation properly secured")
            return True
        else:
            print(f"❌ Anthropic validation returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Anthropic validation test failed: {e}")
        return False

def test_ai_chat_endpoint():
    """Test 4.6: AI chat endpoint security"""
    print("💬 Testing AI chat endpoint...")
    try:
        test_canary_id = str(uuid.uuid4())
        session = requests.Session()
        response = session.post(f"{BASE_URL}/ai_chat/{test_canary_id}",
                              json={"message": "test"}, timeout=10, allow_redirects=False)

        if response.status_code in [302, 401]:  # Should require authentication
            print("✅ AI chat endpoint properly requires authentication")
            return True
        else:
            print(f"❌ AI chat endpoint returned unexpected {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ AI chat endpoint test failed: {e}")
        return False

def test_smart_alert_management():
    """Test 4.7: Smart Alert management endpoints"""
    print("🤖 Testing Smart Alert management...")

    test_canary_id = str(uuid.uuid4())
    smart_alert_endpoints = [
        f'/relearn_patterns/{test_canary_id}',
        f'/delete_pattern_data/{test_canary_id}'
    ]

    session = requests.Session()
    success_count = 0

    for endpoint in smart_alert_endpoints:
        try:
            response = session.post(f"{BASE_URL}{endpoint}", timeout=10, allow_redirects=False)
            if response.status_code in [302, 401]:  # Should require authentication
                print(f"  ✅ {endpoint} properly requires authentication")
                success_count += 1
            else:
                print(f"  ❌ {endpoint} returned unexpected {response.status_code}")
        except Exception as e:
            print(f"  ❌ {endpoint} failed: {e}")

    print(f"📊 Smart Alert management: {success_count}/{len(smart_alert_endpoints)} properly secured")
    return success_count == len(smart_alert_endpoints)

def test_resource_pages():
    """Test 4.8: Resource documentation pages"""
    print("📚 Testing resource pages...")

    resource_pages = [
        '/resources/smart-alerts',
        '/resources/integrations',
        '/resources/api',
        '/resources/examples'
    ]

    success_count = 0
    for page in resource_pages:
        try:
            response = requests.get(f"{BASE_URL}{page}", timeout=10)
            if response.status_code == 200:
                print(f"  ✅ {page} accessible")
                success_count += 1
            else:
                print(f"  ❌ {page} returned {response.status_code}")
        except Exception as e:
            print(f"  ❌ {page} failed: {e}")

    print(f"📊 Resource pages: {success_count}/{len(resource_pages)} accessible")
    return success_count == len(resource_pages)

def test_legal_pages():
    """Test 4.9: Legal and policy pages"""
    print("⚖️ Testing legal pages...")

    legal_pages = [
        '/terms-of-service',
        '/privacy-policy',
        '/cookie-policy',
        '/sla',
        '/status'
    ]

    success_count = 0
    for page in legal_pages:
        try:
            response = requests.get(f"{BASE_URL}{page}", timeout=10)
            if response.status_code == 200:
                print(f"  ✅ {page} accessible")
                success_count += 1
            else:
                print(f"  ❌ {page} returned {response.status_code}")
        except Exception as e:
            print(f"  ❌ {page} failed: {e}")

    print(f"📊 Legal pages: {success_count}/{len(legal_pages)} accessible")
    return success_count == len(legal_pages)

def test_csrf_token_endpoint():
    """Test 4.10: CSRF token endpoint"""
    print("🛡️ Testing CSRF token endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/csrf-token", timeout=10)
        if response.status_code == 200:
            try:
                data = response.json()
                if 'csrf_token' in data:
                    print("✅ CSRF token endpoint working correctly")
                    return True
                else:
                    print("❌ CSRF token not in response")
                    return False
            except json.JSONDecodeError:
                print("❌ CSRF token response not valid JSON")
                return False
        else:
            print(f"❌ CSRF token endpoint returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ CSRF token test failed: {e}")
        return False

def test_comprehensive_email_system():
    """Test 4.11: Comprehensive email system test"""
    print("📧 Testing comprehensive email system...")

    try:
        from app import app, send_templated_email

        with app.app_context():
            # Test all remaining email templates
            remaining_templates = [
                {
                    'name': 'Welcome Verify',
                    'template': 'welcome_verify',
                    'data': {
                        'username': 'testuser',
                        'verification_link': 'https://silentcanary.com/verify-email/test123'
                    }
                },
                {
                    'name': 'Email Verification',
                    'template': 'email_verification',
                    'data': {
                        'username': 'testuser',
                        'verification_link': 'https://silentcanary.com/verify-email/test123'
                    }
                },
                {
                    'name': 'Password Reset',
                    'template': 'password_reset',
                    'data': {
                        'username': 'testuser',
                        'reset_link': 'https://silentcanary.com/reset_password/test123'
                    }
                },
                {
                    'name': 'Payment Failed',
                    'template': 'payment_failed',
                    'data': {
                        'user_name': 'Test User',
                        'plan_name': 'Startup',
                        'amount': '$7.00',
                        'next_attempt': 'October 5, 2025'
                    }
                }
            ]

            results = []
            for template_test in remaining_templates:
                try:
                    print(f"  📤 Testing {template_test['name']} email...")
                    send_templated_email(
                        recipients='test-advanced@tabibazar.com',
                        subject=f'[E2E Advanced] {template_test["name"]}',
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
        print(f"❌ Comprehensive email system test failed: {e}")
        return False

def run_phase4_tests():
    """Run all Phase 4 tests"""
    print("🚀 STARTING PHASE 4: Advanced Features Testing")
    print("=" * 60)

    test_results = []

    # Advanced feature tests
    test_results.append(("Admin Panel Access", test_admin_panel_access()))
    test_results.append(("Admin Contact Requests", test_admin_contact_requests()))
    test_results.append(("Admin User Management", test_admin_user_management()))
    test_results.append(("API Key Management", test_api_key_management()))
    test_results.append(("Anthropic Validation", test_anthropic_validation()))
    test_results.append(("AI Chat Endpoint", test_ai_chat_endpoint()))
    test_results.append(("Smart Alert Management", test_smart_alert_management()))
    test_results.append(("Resource Pages", test_resource_pages()))
    test_results.append(("Legal Pages", test_legal_pages()))
    test_results.append(("CSRF Token", test_csrf_token_endpoint()))
    test_results.append(("Email System", test_comprehensive_email_system()))

    # Summary
    print("\n" + "=" * 60)
    print("📊 PHASE 4 TEST RESULTS:")
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
        print("🎉 Phase 4 COMPLETE - All advanced feature tests passed!")
        return True
    else:
        print(f"⚠️  Phase 4 PARTIAL - {total-passed} tests failed")
        return False

if __name__ == '__main__':
    run_phase4_tests()