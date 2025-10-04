#!/usr/bin/env python3
"""
End-to-End Testing - Phase 1: Core Platform Infrastructure
"""
import requests
import json
import time
from datetime import datetime

# Production URL
BASE_URL = "https://silentcanary.com"

def test_homepage():
    """Test 1.1: Homepage accessibility"""
    print("🏠 Testing homepage accessibility...")
    try:
        response = requests.get(BASE_URL, timeout=10)
        if response.status_code == 200:
            print("✅ Homepage accessible")
            return True
        else:
            print(f"❌ Homepage returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Homepage test failed: {e}")
        return False

def test_contact_form():
    """Test 1.2: Contact form submission"""
    print("📧 Testing contact form submission...")

    # Get contact page first to extract CSRF token
    try:
        session = requests.Session()
        contact_page = session.get(f"{BASE_URL}/contact", timeout=10)

        if contact_page.status_code != 200:
            print(f"❌ Contact page not accessible: {contact_page.status_code}")
            return False

        print("✅ Contact page accessible")

        # For now, we'll just verify the page loads
        # Actual form submission would require reCAPTCHA token
        print("📝 Contact form loaded successfully (reCAPTCHA required for submission)")
        return True

    except Exception as e:
        print(f"❌ Contact form test failed: {e}")
        return False

def test_registration_page():
    """Test 1.3: Registration page accessibility"""
    print("📝 Testing registration page...")
    try:
        response = requests.get(f"{BASE_URL}/register", timeout=10)
        if response.status_code == 200:
            print("✅ Registration page accessible")
            return True
        else:
            print(f"❌ Registration page returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Registration page test failed: {e}")
        return False

def test_login_page():
    """Test 1.4: Login page accessibility"""
    print("🔐 Testing login page...")
    try:
        response = requests.get(f"{BASE_URL}/login", timeout=10)
        if response.status_code == 200:
            print("✅ Login page accessible")
            return True
        else:
            print(f"❌ Login page returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Login page test failed: {e}")
        return False

def test_pricing_page():
    """Test 1.5: Pricing page accessibility"""
    print("💰 Testing pricing page...")
    try:
        response = requests.get(f"{BASE_URL}/pricing", timeout=10)
        if response.status_code == 200:
            print("✅ Pricing page accessible")
            return True
        else:
            print(f"❌ Pricing page returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Pricing page test failed: {e}")
        return False

def test_help_pages():
    """Test 1.6: Help documentation accessibility"""
    print("📚 Testing help pages...")
    help_pages = [
        '/help',
        '/help/getting-started',
        '/help/examples',
        '/help/api',
        '/help/troubleshooting'
    ]

    success_count = 0
    for page in help_pages:
        try:
            response = requests.get(f"{BASE_URL}{page}", timeout=10)
            if response.status_code == 200:
                print(f"✅ {page} accessible")
                success_count += 1
            else:
                print(f"❌ {page} returned {response.status_code}")
        except Exception as e:
            print(f"❌ {page} failed: {e}")

    print(f"📊 Help pages: {success_count}/{len(help_pages)} accessible")
    return success_count == len(help_pages)

def test_api_health():
    """Test 1.7: API health endpoint"""
    print("🏥 Testing API health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        if response.status_code == 200:
            print("✅ Health endpoint responsive")
            return True
        else:
            print(f"❌ Health endpoint returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health endpoint test failed: {e}")
        return False

def run_phase1_tests():
    """Run all Phase 1 tests"""
    print("🎯 STARTING PHASE 1: Core Platform Infrastructure Testing")
    print("=" * 60)

    test_results = []

    # Core page accessibility tests
    test_results.append(("Homepage", test_homepage()))
    test_results.append(("Registration Page", test_registration_page()))
    test_results.append(("Login Page", test_login_page()))
    test_results.append(("Contact Form", test_contact_form()))
    test_results.append(("Pricing Page", test_pricing_page()))
    test_results.append(("Help Pages", test_help_pages()))
    test_results.append(("API Health", test_api_health()))

    # Summary
    print("\n" + "=" * 60)
    print("📊 PHASE 1 TEST RESULTS:")
    print("=" * 60)

    passed = 0
    total = len(test_results)

    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1

    print("=" * 60)
    print(f"📈 Overall: {passed}/{total} tests passed ({(passed/total)*100:.1f}%)")

    if passed == total:
        print("🎉 Phase 1 COMPLETE - All core infrastructure tests passed!")
        return True
    else:
        print(f"⚠️  Phase 1 PARTIAL - {total-passed} tests failed")
        return False

if __name__ == '__main__':
    run_phase1_tests()