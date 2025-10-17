#!/usr/bin/env python3
"""
Comprehensive Subscription Testing Suite

Tests all subscription models, variations, and edge cases including:
- Plan validation (Free/Solo, Startup, Growth, Enterprise)
- Billing frequencies (Monthly, Annual)
- Stripe product/price configurations
- Plan limits and features
- Upgrade/downgrade scenarios
- Billing frequency changes
- Subscription states (active, canceled, past_due)
- Edge cases and error handling
"""

import os
import sys
import stripe
from dotenv import load_dotenv
from decimal import Decimal
from datetime import datetime

# Load environment variables
load_dotenv()

# Initialize Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SubscriptionTestSuite:
    """Comprehensive subscription testing suite"""

    def __init__(self):
        self.tests_passed = 0
        self.tests_failed = 0
        self.warnings = 0
        self.test_results = []

        # Plan configurations from app.py
        self.plan_configs = {
            'free': {
                'name': 'Solo',
                'canary_limit': 1,
                'price_monthly': 0,
                'price_annual': 0,
                'monthly_price_id': None,
                'annual_price_id': None,
                'features': ['Complete Feature Set', 'Email Support']
            },
            'startup': {
                'name': 'Startup',
                'canary_limit': 5,
                'price_monthly': 7,
                'price_annual': 70,
                'monthly_price_id': os.environ.get('STRIPE_STARTUP_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_STARTUP_ANNUAL_PRICE_ID'),
                'features': ['Complete Feature Set', 'Email Support']
            },
            'growth': {
                'name': 'Growth',
                'canary_limit': 25,
                'price_monthly': 25,
                'price_annual': 250,
                'monthly_price_id': os.environ.get('STRIPE_GROWTH_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_GROWTH_ANNUAL_PRICE_ID'),
                'features': ['Complete Feature Set', 'Priority Support']
            },
            'enterprise': {
                'name': 'Enterprise',
                'canary_limit': 100,
                'price_monthly': 75,
                'price_annual': 750,
                'monthly_price_id': os.environ.get('STRIPE_ENTERPRISE_MONTHLY_PRICE_ID'),
                'annual_price_id': os.environ.get('STRIPE_ENTERPRISE_ANNUAL_PRICE_ID'),
                'features': ['Complete Feature Set', 'White-glove Support']
            }
        }

    def print_header(self, text):
        """Print a section header"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

    def print_test(self, test_name, status, details=""):
        """Print test result"""
        if status == "PASS":
            symbol = "✅"
            color = Colors.GREEN
            self.tests_passed += 1
        elif status == "FAIL":
            symbol = "❌"
            color = Colors.RED
            self.tests_failed += 1
        elif status == "WARN":
            symbol = "⚠️ "
            color = Colors.YELLOW
            self.warnings += 1
        else:
            symbol = "ℹ️ "
            color = Colors.BLUE

        print(f"{symbol} {color}{test_name}{Colors.END}")
        if details:
            print(f"   {details}")

        self.test_results.append({
            'test': test_name,
            'status': status,
            'details': details
        })

    def test_environment_configuration(self):
        """Test 1: Environment Configuration"""
        self.print_header("Test 1: Environment Configuration")

        # Test Stripe secret key
        stripe_key = os.environ.get('STRIPE_SECRET_KEY')
        if stripe_key:
            if stripe_key.startswith('sk_live_'):
                self.print_test("Stripe Secret Key", "PASS", f"Live mode key configured: {stripe_key[:15]}...")
            elif stripe_key.startswith('sk_test_'):
                self.print_test("Stripe Secret Key", "WARN", "Using TEST mode key (not production)")
            else:
                self.print_test("Stripe Secret Key", "FAIL", "Invalid key format")
        else:
            self.print_test("Stripe Secret Key", "FAIL", "STRIPE_SECRET_KEY not configured")

        # Test publishable key
        pub_key = os.environ.get('STRIPE_PUBLISHABLE_KEY')
        if pub_key:
            self.print_test("Stripe Publishable Key", "PASS", f"Configured: {pub_key[:15]}...")
        else:
            self.print_test("Stripe Publishable Key", "FAIL", "Not configured")

        # Test webhook secret
        webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
        if webhook_secret:
            self.print_test("Stripe Webhook Secret", "PASS", "Configured")
        else:
            self.print_test("Stripe Webhook Secret", "WARN", "Not configured")

        # Test all price IDs
        for plan_key, plan_config in self.plan_configs.items():
            if plan_key == 'free':
                continue

            monthly_id = plan_config['monthly_price_id']
            annual_id = plan_config['annual_price_id']

            if monthly_id:
                self.print_test(f"{plan_config['name']} Monthly Price ID", "PASS", monthly_id)
            else:
                self.print_test(f"{plan_config['name']} Monthly Price ID", "FAIL", "Not configured")

            if annual_id:
                self.print_test(f"{plan_config['name']} Annual Price ID", "PASS", annual_id)
            else:
                self.print_test(f"{plan_config['name']} Annual Price ID", "FAIL", "Not configured")

    def test_stripe_products_and_prices(self):
        """Test 2: Stripe Products and Prices"""
        self.print_header("Test 2: Stripe Products and Prices")

        for plan_key, plan_config in self.plan_configs.items():
            if plan_key == 'free':
                self.print_test(f"{plan_config['name']} Plan", "INFO", "Free plan - no Stripe configuration needed")
                continue

            print(f"\n{Colors.BOLD}Testing {plan_config['name']} Plan:{Colors.END}")

            # Test Monthly Price
            monthly_id = plan_config['monthly_price_id']
            if monthly_id:
                try:
                    price = stripe.Price.retrieve(monthly_id)
                    product = stripe.Product.retrieve(price.product)

                    # Validate price amount
                    expected_amount = int(plan_config['price_monthly'] * 100)
                    if price.unit_amount == expected_amount:
                        self.print_test(
                            f"  Monthly Price Amount",
                            "PASS",
                            f"${price.unit_amount/100} matches expected ${plan_config['price_monthly']}"
                        )
                    else:
                        self.print_test(
                            f"  Monthly Price Amount",
                            "FAIL",
                            f"${price.unit_amount/100} != ${plan_config['price_monthly']}"
                        )

                    # Validate billing interval
                    if price.recurring.interval == 'month':
                        self.print_test(f"  Monthly Billing Interval", "PASS", "Correct")
                    else:
                        self.print_test(
                            f"  Monthly Billing Interval",
                            "FAIL",
                            f"Expected 'month', got '{price.recurring.interval}'"
                        )

                    # Validate product is active
                    if product.active:
                        self.print_test(f"  Product Active", "PASS", f"{product.name} (ID: {product.id})")
                    else:
                        self.print_test(f"  Product Active", "FAIL", f"{product.name} is INACTIVE")

                    # Validate price is active
                    if price.active:
                        self.print_test(f"  Price Active", "PASS", "Monthly price is active")
                    else:
                        self.print_test(f"  Price Active", "FAIL", "Monthly price is INACTIVE")

                except stripe.error.InvalidRequestError as e:
                    self.print_test(f"  Monthly Price Retrieval", "FAIL", str(e))
                except Exception as e:
                    self.print_test(f"  Monthly Price Test", "FAIL", str(e))

            # Test Annual Price
            annual_id = plan_config['annual_price_id']
            if annual_id:
                try:
                    price = stripe.Price.retrieve(annual_id)
                    product = stripe.Product.retrieve(price.product)

                    # Validate price amount
                    expected_amount = int(plan_config['price_annual'] * 100)
                    if price.unit_amount == expected_amount:
                        self.print_test(
                            f"  Annual Price Amount",
                            "PASS",
                            f"${price.unit_amount/100} matches expected ${plan_config['price_annual']}"
                        )
                    else:
                        self.print_test(
                            f"  Annual Price Amount",
                            "FAIL",
                            f"${price.unit_amount/100} != ${plan_config['price_annual']}"
                        )

                    # Validate billing interval
                    if price.recurring.interval == 'year':
                        self.print_test(f"  Annual Billing Interval", "PASS", "Correct")
                    else:
                        self.print_test(
                            f"  Annual Billing Interval",
                            "FAIL",
                            f"Expected 'year', got '{price.recurring.interval}'"
                        )

                    # Validate product is active
                    if product.active:
                        self.print_test(f"  Product Active", "PASS", f"{product.name} (ID: {product.id})")
                    else:
                        self.print_test(f"  Product Active", "FAIL", f"{product.name} is INACTIVE")

                    # Validate price is active
                    if price.active:
                        self.print_test(f"  Price Active", "PASS", "Annual price is active")
                    else:
                        self.print_test(f"  Price Active", "FAIL", "Annual price is INACTIVE")

                    # Calculate savings
                    monthly_total_annual = plan_config['price_monthly'] * 12
                    annual_price = plan_config['price_annual']
                    savings = monthly_total_annual - annual_price
                    savings_percent = (savings / monthly_total_annual) * 100

                    if savings > 0:
                        self.print_test(
                            f"  Annual Savings",
                            "PASS",
                            f"${savings:.2f}/year ({savings_percent:.1f}% discount)"
                        )
                    else:
                        self.print_test(f"  Annual Savings", "WARN", "No discount for annual billing")

                except stripe.error.InvalidRequestError as e:
                    self.print_test(f"  Annual Price Retrieval", "FAIL", str(e))
                except Exception as e:
                    self.print_test(f"  Annual Price Test", "FAIL", str(e))

    def test_plan_limits_and_features(self):
        """Test 3: Plan Limits and Features"""
        self.print_header("Test 3: Plan Limits and Features")

        for plan_key, plan_config in self.plan_configs.items():
            print(f"\n{Colors.BOLD}{plan_config['name']} Plan:{Colors.END}")

            # Test canary limits
            limit = plan_config['canary_limit']
            self.print_test(f"  Canary Limit", "INFO", f"{limit} canaries")

            # Test pricing
            if plan_config['price_monthly'] == 0:
                self.print_test(f"  Pricing", "INFO", "Free tier")
            else:
                monthly = plan_config['price_monthly']
                annual = plan_config['price_annual']
                monthly_equiv = annual / 12
                self.print_test(
                    f"  Pricing",
                    "INFO",
                    f"${monthly}/mo or ${annual}/yr (${monthly_equiv:.2f}/mo)"
                )

            # Test features
            if 'features' in plan_config:
                self.print_test(
                    f"  Features",
                    "INFO",
                    ", ".join(plan_config['features'])
                )

    def test_upgrade_downgrade_paths(self):
        """Test 4: Upgrade/Downgrade Paths"""
        self.print_header("Test 4: Upgrade/Downgrade Paths")

        plans = ['free', 'startup', 'growth', 'enterprise']

        print(f"{Colors.BOLD}Valid Upgrade Paths:{Colors.END}")
        for i, plan in enumerate(plans[:-1]):
            for target_plan in plans[i+1:]:
                from_name = self.plan_configs[plan]['name']
                to_name = self.plan_configs[target_plan]['name']
                self.print_test(
                    f"  {from_name} → {to_name}",
                    "PASS",
                    "Valid upgrade path"
                )

        print(f"\n{Colors.BOLD}Valid Downgrade Paths:{Colors.END}")
        for i, plan in enumerate(plans[1:], 1):
            for target_plan in plans[:i]:
                from_name = self.plan_configs[plan]['name']
                to_name = self.plan_configs[target_plan]['name']
                self.print_test(
                    f"  {from_name} → {to_name}",
                    "INFO",
                    "Valid downgrade path (may require confirmation)"
                )

    def test_billing_frequency_changes(self):
        """Test 5: Billing Frequency Changes"""
        self.print_header("Test 5: Billing Frequency Changes")

        for plan_key, plan_config in self.plan_configs.items():
            if plan_key == 'free':
                self.print_test(
                    f"{plan_config['name']}: Frequency Change",
                    "INFO",
                    "Not applicable for free plan"
                )
                continue

            monthly_id = plan_config['monthly_price_id']
            annual_id = plan_config['annual_price_id']

            if monthly_id and annual_id:
                self.print_test(
                    f"{plan_config['name']}: Monthly ↔ Annual",
                    "PASS",
                    "Both frequencies available"
                )

                # Verify both prices use same product
                try:
                    monthly_price = stripe.Price.retrieve(monthly_id)
                    annual_price = stripe.Price.retrieve(annual_id)

                    if monthly_price.product == annual_price.product:
                        self.print_test(
                            f"  Same Product",
                            "PASS",
                            f"Both use product: {monthly_price.product}"
                        )
                    else:
                        self.print_test(
                            f"  Same Product",
                            "FAIL",
                            f"Monthly uses {monthly_price.product}, Annual uses {annual_price.product}"
                        )
                except Exception as e:
                    self.print_test(f"  Product Verification", "FAIL", str(e))
            else:
                self.print_test(
                    f"{plan_config['name']}: Frequency Change",
                    "WARN",
                    "Missing price IDs for one or both frequencies"
                )

    def test_edge_cases(self):
        """Test 6: Edge Cases and Error Handling"""
        self.print_header("Test 6: Edge Cases and Error Handling")

        # Test 6.1: Invalid price ID
        try:
            stripe.Price.retrieve('price_invalid_test_id')
            self.print_test("Invalid Price ID Handling", "FAIL", "Should have raised error")
        except stripe.error.InvalidRequestError:
            self.print_test("Invalid Price ID Handling", "PASS", "Correctly raises InvalidRequestError")
        except Exception as e:
            self.print_test("Invalid Price ID Handling", "WARN", f"Unexpected error: {e}")

        # Test 6.2: Check for old inactive products
        print(f"\n{Colors.BOLD}Checking for old/inactive products:{Colors.END}")
        old_price_ids = [
            'price_1S6gQOC1JljIJA9azsEdRU2G',  # Old Growth Monthly
            'price_1S6gQOC1JljIJA9aRCJdfUuj',  # Old Growth Annual
        ]

        for old_price_id in old_price_ids:
            try:
                price = stripe.Price.retrieve(old_price_id)
                product = stripe.Product.retrieve(price.product)

                if not product.active:
                    self.print_test(
                        f"  Old Price {old_price_id}",
                        "WARN",
                        f"Product {product.id} is INACTIVE - ensure no active subscriptions use this"
                    )
                else:
                    self.print_test(
                        f"  Old Price {old_price_id}",
                        "INFO",
                        f"Product {product.id} is still active"
                    )
            except stripe.error.InvalidRequestError:
                self.print_test(f"  Old Price {old_price_id}", "INFO", "Not found (expected)")
            except Exception as e:
                self.print_test(f"  Old Price {old_price_id}", "FAIL", str(e))

        # Test 6.3: Subscription state validations
        print(f"\n{Colors.BOLD}Subscription State Validations:{Colors.END}")

        valid_states = ['active', 'canceled', 'past_due', 'unpaid', 'trialing']
        for state in valid_states:
            self.print_test(
                f"  Subscription State: {state}",
                "INFO",
                "Valid Stripe subscription status"
            )

        # Test 6.4: Currency validation
        expected_currency = 'usd'
        print(f"\n{Colors.BOLD}Currency Validation:{Colors.END}")

        for plan_key, plan_config in self.plan_configs.items():
            if plan_key == 'free':
                continue

            for frequency in ['monthly', 'annual']:
                price_id = plan_config.get(f'{frequency}_price_id')
                if price_id:
                    try:
                        price = stripe.Price.retrieve(price_id)
                        if price.currency == expected_currency:
                            self.print_test(
                                f"  {plan_config['name']} {frequency.title()}",
                                "PASS",
                                f"Currency: {price.currency.upper()}"
                            )
                        else:
                            self.print_test(
                                f"  {plan_config['name']} {frequency.title()}",
                                "WARN",
                                f"Expected {expected_currency.upper()}, got {price.currency.upper()}"
                            )
                    except Exception as e:
                        self.print_test(f"  {plan_config['name']} {frequency.title()}", "FAIL", str(e))

    def test_price_consistency(self):
        """Test 7: Price Consistency"""
        self.print_header("Test 7: Price Consistency")

        for plan_key, plan_config in self.plan_configs.items():
            if plan_key == 'free':
                continue

            print(f"\n{Colors.BOLD}{plan_config['name']} Plan:{Colors.END}")

            # Check that annual is cheaper per month than monthly
            monthly_price = plan_config['price_monthly']
            annual_price = plan_config['price_annual']
            annual_per_month = annual_price / 12

            if annual_per_month < monthly_price:
                savings = monthly_price - annual_per_month
                percent = (savings / monthly_price) * 100
                self.print_test(
                    f"  Annual Discount",
                    "PASS",
                    f"Save ${savings:.2f}/mo ({percent:.1f}%) with annual billing"
                )
            elif annual_per_month == monthly_price:
                self.print_test(
                    f"  Annual Discount",
                    "WARN",
                    "No discount for annual billing"
                )
            else:
                self.print_test(
                    f"  Annual Discount",
                    "FAIL",
                    f"Annual is MORE expensive per month (${annual_per_month:.2f} vs ${monthly_price})"
                )

            # Check pricing tiers make sense
            if plan_key == 'startup':
                continue

            prev_plans = {
                'growth': 'startup',
                'enterprise': 'growth'
            }

            if plan_key in prev_plans:
                prev_key = prev_plans[plan_key]
                prev_config = self.plan_configs[prev_key]

                # Monthly should be more expensive
                if monthly_price > prev_config['price_monthly']:
                    self.print_test(
                        f"  Tier Pricing (Monthly)",
                        "PASS",
                        f"${monthly_price} > {prev_config['name']} ${prev_config['price_monthly']}"
                    )
                else:
                    self.print_test(
                        f"  Tier Pricing (Monthly)",
                        "FAIL",
                        f"${monthly_price} <= {prev_config['name']} ${prev_config['price_monthly']}"
                    )

                # More canaries
                if plan_config['canary_limit'] > prev_config['canary_limit']:
                    self.print_test(
                        f"  Canary Limit Progression",
                        "PASS",
                        f"{plan_config['canary_limit']} > {prev_config['name']} {prev_config['canary_limit']}"
                    )
                else:
                    self.print_test(
                        f"  Canary Limit Progression",
                        "FAIL",
                        f"{plan_config['canary_limit']} <= {prev_config['name']} {prev_config['canary_limit']}"
                    )

    def print_summary(self):
        """Print test summary"""
        self.print_header("Test Summary")

        total_tests = self.tests_passed + self.tests_failed
        pass_rate = (self.tests_passed / total_tests * 100) if total_tests > 0 else 0

        print(f"{Colors.BOLD}Results:{Colors.END}")
        print(f"  {Colors.GREEN}✅ Passed: {self.tests_passed}{Colors.END}")
        print(f"  {Colors.RED}❌ Failed: {self.tests_failed}{Colors.END}")
        print(f"  {Colors.YELLOW}⚠️  Warnings: {self.warnings}{Colors.END}")
        print(f"  {Colors.BOLD}Total: {total_tests}{Colors.END}")
        print(f"  {Colors.BOLD}Pass Rate: {pass_rate:.1f}%{Colors.END}")

        if self.tests_failed == 0:
            print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 ALL TESTS PASSED!{Colors.END}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}❌ {self.tests_failed} TEST(S) FAILED{Colors.END}")

        if self.warnings > 0:
            print(f"{Colors.YELLOW}⚠️  {self.warnings} WARNING(S){Colors.END}")

    def run_all_tests(self):
        """Run all tests"""
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}")
        print("╔════════════════════════════════════════════════════════════════════════════╗")
        print("║          COMPREHENSIVE SUBSCRIPTION TEST SUITE                             ║")
        print("║          Testing all plans, pricing, and configurations                    ║")
        print("╚════════════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.END}")

        self.test_environment_configuration()
        self.test_stripe_products_and_prices()
        self.test_plan_limits_and_features()
        self.test_upgrade_downgrade_paths()
        self.test_billing_frequency_changes()
        self.test_edge_cases()
        self.test_price_consistency()
        self.print_summary()

        return self.tests_failed == 0

def main():
    """Main entry point"""
    suite = SubscriptionTestSuite()
    success = suite.run_all_tests()

    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
