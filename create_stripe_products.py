#!/usr/bin/env python3
"""
Create Stripe products and prices for SilentCanary subscription plans
Based on the pricing page structure
"""

import stripe
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set your Stripe secret key
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

if not stripe.api_key:
    print("❌ STRIPE_SECRET_KEY not found in environment variables")
    print("Please set your Stripe secret key in .env file")
    exit(1)

print(f"🔐 Using Stripe API key: {stripe.api_key[:12]}...")

def create_stripe_products():
    """Create all SilentCanary products and prices in Stripe"""

    products_to_create = [
        {
            'name': 'SilentCanary Solo',
            'description': 'Perfect for personal projects and testing. Get started with 1 canary and access to all features.',
            'features': [
                '1 Canary',
                'Complete Feature Set',
                'Email Alerts',
                'Web Dashboard',
                'API Access',
                'Smart Alerts (AI)',
                'Advanced Analytics',
                'Custom Webhooks',
                'Email Support'
            ],
            'prices': []  # Free plan - no prices needed
        },
        {
            'name': 'SilentCanary Startup',
            'description': 'Ideal for small teams and growing projects. Monitor up to 5 critical processes.',
            'features': [
                '5 Canaries',
                'Complete Feature Set',
                'Email Alerts',
                'Web Dashboard',
                'API Access',
                'Smart Alerts (AI)',
                'Advanced Analytics',
                'Custom Webhooks',
                'Email Support'
            ],
            'prices': [
                {'amount': 700, 'interval': 'month', 'nickname': 'Startup Monthly'},
                {'amount': 7000, 'interval': 'year', 'nickname': 'Startup Annual'}
            ]
        },
        {
            'name': 'SilentCanary Growth',
            'description': 'Most popular plan for established teams. Scale your monitoring with 25 canaries.',
            'features': [
                '25 Canaries',
                'Complete Feature Set',
                'Email Alerts',
                'Web Dashboard',
                'API Access',
                'Smart Alerts (AI)',
                'Advanced Analytics',
                'Custom Webhooks',
                'Priority Support'
            ],
            'prices': [
                {'amount': 2500, 'interval': 'month', 'nickname': 'Growth Monthly'},
                {'amount': 25000, 'interval': 'year', 'nickname': 'Growth Annual'}
            ]
        },
        {
            'name': 'SilentCanary Enterprise',
            'description': 'For large organizations with extensive monitoring needs. Monitor up to 100 critical processes.',
            'features': [
                '100 Canaries',
                'Complete Feature Set',
                'Email Alerts',
                'Web Dashboard',
                'API Access',
                'Smart Alerts (AI)',
                'Advanced Analytics',
                'Custom Webhooks',
                'White-glove Support'
            ],
            'prices': [
                {'amount': 7500, 'interval': 'month', 'nickname': 'Enterprise Monthly'},
                {'amount': 75000, 'interval': 'year', 'nickname': 'Enterprise Annual'}
            ]
        }
    ]

    created_products = []

    for product_data in products_to_create:
        try:
            print(f"\n📦 Creating product: {product_data['name']}")

            # Create the product
            product = stripe.Product.create(
                name=product_data['name'],
                description=product_data['description'],
                metadata={
                    'features': ', '.join(product_data['features']),
                    'canary_limit': product_data['features'][0].split()[0],  # Extract number of canaries
                    'support_level': [f for f in product_data['features'] if 'Support' in f][0] if any('Support' in f for f in product_data['features']) else 'Email Support'
                }
            )

            print(f"✅ Product created: {product.id}")

            # Create prices for this product
            prices = []
            for price_data in product_data['prices']:
                print(f"   💰 Creating price: {price_data['nickname']} - ${price_data['amount']/100:.2f}/{price_data['interval']}")

                price = stripe.Price.create(
                    product=product.id,
                    unit_amount=price_data['amount'],
                    currency='usd',
                    recurring={'interval': price_data['interval']},
                    nickname=price_data['nickname'],
                    metadata={
                        'plan_type': product_data['name'].split()[-1].lower(),  # solo, startup, growth, enterprise
                        'billing_period': price_data['interval']
                    }
                )

                prices.append(price)
                print(f"   ✅ Price created: {price.id}")

            created_products.append({
                'product': product,
                'prices': prices
            })

        except stripe.error.StripeError as e:
            print(f"❌ Error creating {product_data['name']}: {e}")
            continue

    return created_products

def display_summary(created_products):
    """Display a summary of created products and prices"""
    print("\n" + "="*60)
    print("🎉 STRIPE PRODUCTS CREATED SUCCESSFULLY!")
    print("="*60)

    for item in created_products:
        product = item['product']
        prices = item['prices']

        print(f"\n📦 {product.name}")
        print(f"   ID: {product.id}")
        print(f"   Description: {product.description}")

        if prices:
            print("   💰 Prices:")
            for price in prices:
                amount = price.unit_amount / 100
                interval = price.recurring['interval']
                print(f"      • {price.nickname}: ${amount:.2f}/{interval} (ID: {price.id})")
        else:
            print("   💰 Free plan - no prices")

    print(f"\n🔗 View all products at: https://dashboard.stripe.com/products")
    print(f"🔗 View all prices at: https://dashboard.stripe.com/prices")

def update_env_file(created_products):
    """Generate environment variables for the created price IDs"""
    print("\n" + "="*60)
    print("📋 ENVIRONMENT VARIABLES FOR YOUR .ENV FILE")
    print("="*60)

    env_vars = {}

    for item in created_products:
        product = item['product']
        prices = item['prices']

        plan_name = product.name.split()[-1].upper()  # SOLO, STARTUP, GROWTH, ENTERPRISE

        for price in prices:
            interval = price.recurring['interval'].upper()  # MONTH, YEAR
            if interval == 'YEAR':
                interval = 'ANNUAL'
            elif interval == 'MONTH':
                interval = 'MONTHLY'

            var_name = f"STRIPE_{plan_name}_{interval}_PRICE_ID"
            env_vars[var_name] = price.id

    print("\n# Add these to your .env file:")
    for var_name, price_id in env_vars.items():
        print(f"{var_name}={price_id}")

    return env_vars

if __name__ == '__main__':
    try:
        print("🚀 Starting Stripe product creation for SilentCanary...")
        print("="*60)

        # Create products and prices
        created_products = create_stripe_products()

        if created_products:
            # Display summary
            display_summary(created_products)

            # Generate environment variables
            env_vars = update_env_file(created_products)

            print(f"\n✅ Successfully created {len(created_products)} products with their prices!")
            print("🎯 Next steps:")
            print("   1. Copy the environment variables to your .env file")
            print("   2. Update your GitHub Secrets if using automated deployment")
            print("   3. Test the subscription flow in your application")

        else:
            print("❌ No products were created successfully")

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()