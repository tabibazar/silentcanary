#!/usr/bin/env python3
"""
Migrate existing Stripe subscriptions from old inactive products to new active products.

This script handles the migration of subscriptions that are using old, inactive
Stripe products to the new active products with correct price IDs.

Usage:
    python migrate_stripe_subscriptions.py [--dry-run] [--user-email EMAIL]
"""

import os
import sys
import argparse
import stripe
from dotenv import load_dotenv
from models import Subscription, User

# Load environment variables
load_dotenv()

# Initialize Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# Old product IDs that are inactive
OLD_PRODUCTS = {
    'prod_T2ly1pEt5GqdP8': 'growth',  # Old Growth product
    # Add other old products here as discovered
}

# Price ID mapping: old_price_id -> new_price_id
PRICE_MIGRATION_MAP = {
    # Old Growth prices -> New Growth prices
    'price_1S6gQOC1JljIJA9azsEdRU2G': os.environ.get('STRIPE_GROWTH_MONTHLY_PRICE_ID'),  # Monthly
    'price_1S6gQOC1JljIJA9aRCJdfUuj': os.environ.get('STRIPE_GROWTH_ANNUAL_PRICE_ID'),   # Annual
    # Add other migrations as needed
}

def check_subscription_needs_migration(stripe_subscription):
    """Check if a subscription needs to be migrated."""
    try:
        if not stripe_subscription.items or not stripe_subscription.items.data:
            return False, None, None

        current_price = stripe_subscription.items.data[0].price
        current_price_id = current_price.id
        current_product_id = current_price.product

        # Check if product is inactive
        product = stripe.Product.retrieve(current_product_id)

        if not product.active:
            return True, current_price_id, current_product_id

        # Check if this is an old price ID we want to migrate
        if current_price_id in PRICE_MIGRATION_MAP:
            return True, current_price_id, current_product_id

        return False, None, None
    except Exception as e:
        print(f"   ⚠️  Error checking subscription: {e}")
        return False, None, None

def migrate_subscription(subscription_obj, dry_run=False):
    """
    Migrate a subscription from old product to new product.

    Args:
        subscription_obj: Subscription model object from database
        dry_run: If True, only show what would be done without making changes

    Returns:
        bool: True if migration successful or not needed, False on error
    """
    try:
        stripe_sub_id = subscription_obj.stripe_subscription_id
        if not stripe_sub_id:
            print(f"   ⚠️  No Stripe subscription ID found")
            return False

        # Get subscription from Stripe
        stripe_subscription = stripe.Subscription.retrieve(stripe_sub_id)

        # Check if migration is needed
        needs_migration, old_price_id, old_product_id = check_subscription_needs_migration(stripe_subscription)

        if not needs_migration:
            print(f"   ✅ Subscription already on active product - no migration needed")
            return True

        # Get new price ID
        new_price_id = PRICE_MIGRATION_MAP.get(old_price_id)
        if not new_price_id:
            print(f"   ❌ No migration mapping found for price: {old_price_id}")
            print(f"      Please add mapping to PRICE_MIGRATION_MAP")
            return False

        print(f"   📋 Migration plan:")
        print(f"      From price: {old_price_id}")
        print(f"      To price:   {new_price_id}")
        print(f"      Old product: {old_product_id}")

        # Verify new price is active
        new_price = stripe.Price.retrieve(new_price_id)
        new_product = stripe.Product.retrieve(new_price.product)

        print(f"      New product: {new_product.id} ({new_product.name})")
        print(f"      New product active: {new_product.active}")

        if not new_product.active:
            print(f"   ❌ New product is not active! Cannot migrate.")
            return False

        if dry_run:
            print(f"   🔍 DRY RUN - Would migrate subscription")
            return True

        # Perform the migration
        print(f"   🔄 Migrating subscription...")

        # Get the subscription item ID
        subscription_item_id = stripe_subscription.items.data[0].id

        # Update the subscription to use the new price
        updated_subscription = stripe.Subscription.modify(
            stripe_sub_id,
            items=[{
                'id': subscription_item_id,
                'price': new_price_id,
            }],
            proration_behavior='none'  # Don't charge/credit for the switch
        )

        print(f"   ✅ Subscription migrated successfully!")
        print(f"      New subscription status: {updated_subscription.status}")

        return True

    except stripe.error.InvalidRequestError as e:
        print(f"   ❌ Stripe error: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Migration error: {e}")
        import traceback
        traceback.print_exc()
        return False

def migrate_user_subscription(user_email, dry_run=False):
    """Migrate a specific user's subscription."""
    print(f"\n{'='*70}")
    print(f"Migrating subscription for user: {user_email}")
    print(f"{'='*70}")

    # Get user
    user = User.get_by_email(user_email)
    if not user:
        print(f"❌ User not found: {user_email}")
        return False

    print(f"✅ User found: {user.username} ({user.email})")

    # Get subscription
    subscription = Subscription.get_by_user_id(user.user_id)
    if not subscription:
        print(f"⚠️  No subscription found for user")
        return False

    print(f"📋 Current subscription:")
    print(f"   Plan: {subscription.plan_name}")
    print(f"   Status: {subscription.status}")
    print(f"   Stripe ID: {subscription.stripe_subscription_id}")

    # Migrate
    success = migrate_subscription(subscription, dry_run=dry_run)

    if success:
        print(f"\n✅ Migration completed for {user_email}")
    else:
        print(f"\n❌ Migration failed for {user_email}")

    return success

def migrate_all_subscriptions(dry_run=False):
    """Migrate all subscriptions that need it."""
    print(f"\n{'='*70}")
    print(f"Migrating ALL subscriptions")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"{'='*70}\n")

    # Get all subscriptions from Stripe
    try:
        subscriptions = stripe.Subscription.list(limit=100)
        total = len(subscriptions.data)
        migrated = 0
        skipped = 0
        failed = 0

        print(f"Found {total} subscriptions to check\n")

        for idx, stripe_sub in enumerate(subscriptions.data, 1):
            print(f"\n[{idx}/{total}] Checking subscription: {stripe_sub.id}")

            # Get customer email
            customer = stripe.Customer.retrieve(stripe_sub.customer)
            customer_email = customer.email or 'No email'
            print(f"   Customer: {customer_email}")

            # Check if needs migration
            needs_migration, old_price_id, old_product_id = check_subscription_needs_migration(stripe_sub)

            if not needs_migration:
                print(f"   ✅ Subscription OK - no migration needed")
                skipped += 1
                continue

            # Find user in database
            user = User.get_by_email(customer_email)
            if not user:
                print(f"   ⚠️  User not found in database, skipping")
                skipped += 1
                continue

            subscription_obj = Subscription.get_by_user_id(user.user_id)
            if not subscription_obj:
                print(f"   ⚠️  Subscription not found in database, skipping")
                skipped += 1
                continue

            # Migrate
            success = migrate_subscription(subscription_obj, dry_run=dry_run)
            if success:
                migrated += 1
            else:
                failed += 1

        # Summary
        print(f"\n{'='*70}")
        print(f"Migration Summary:")
        print(f"  Total checked: {total}")
        print(f"  Migrated: {migrated}")
        print(f"  Skipped: {skipped}")
        print(f"  Failed: {failed}")
        print(f"{'='*70}\n")

        return failed == 0

    except Exception as e:
        print(f"❌ Error listing subscriptions: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Migrate Stripe subscriptions from old inactive products to new products'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--user-email',
        type=str,
        help='Migrate only this specific user (email address)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Migrate all subscriptions'
    )

    args = parser.parse_args()

    if not stripe.api_key:
        print("❌ STRIPE_SECRET_KEY not configured")
        return 1

    print(f"🔐 Stripe API key configured: {stripe.api_key[:15]}...")

    if args.dry_run:
        print(f"🔍 DRY RUN MODE - No changes will be made")

    if args.user_email:
        success = migrate_user_subscription(args.user_email, dry_run=args.dry_run)
        return 0 if success else 1
    elif args.all:
        success = migrate_all_subscriptions(dry_run=args.dry_run)
        return 0 if success else 1
    else:
        print("❌ Please specify --user-email or --all")
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())
