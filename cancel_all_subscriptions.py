#!/usr/bin/env python3
"""
Cancel All Active Subscriptions Script
"""
import os
import sys
sys.path.append('.')

from app import app
import stripe
from models import subscriptions_table, users_table
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

def get_all_active_subscriptions():
    """Get all active subscriptions from DynamoDB"""
    print("🔍 Scanning for active subscriptions in database...")

    try:
        response = subscriptions_table.scan(
            FilterExpression="subscription_status = :status",
            ExpressionAttributeValues={':status': 'active'}
        )

        active_subs = response.get('Items', [])
        print(f"📊 Found {len(active_subs)} active subscriptions in database")

        # Also check for subscriptions with other active statuses
        other_statuses = ['trialing', 'past_due', 'unpaid']
        for status in other_statuses:
            response = subscriptions_table.scan(
                FilterExpression="subscription_status = :status",
                ExpressionAttributeValues={':status': status}
            )
            other_subs = response.get('Items', [])
            if other_subs:
                print(f"📊 Found {len(other_subs)} subscriptions with status '{status}'")
                active_subs.extend(other_subs)

        return active_subs

    except Exception as e:
        print(f"❌ Error scanning subscriptions: {e}")
        return []

def get_stripe_active_subscriptions():
    """Get all active subscriptions directly from Stripe"""
    print("🔍 Fetching active subscriptions from Stripe...")

    try:
        # Get all active subscriptions from Stripe
        subscriptions = stripe.Subscription.list(
            status='active',
            limit=100  # Adjust if you have more than 100
        )

        stripe_subs = subscriptions.data
        print(f"📊 Found {len(stripe_subs)} active subscriptions in Stripe")

        # Also check other statuses
        other_statuses = ['trialing', 'past_due', 'unpaid']
        for status in other_statuses:
            subs = stripe.Subscription.list(status=status, limit=100)
            if subs.data:
                print(f"📊 Found {len(subs.data)} subscriptions with status '{status}' in Stripe")
                stripe_subs.extend(subs.data)

        return stripe_subs

    except Exception as e:
        print(f"❌ Error fetching Stripe subscriptions: {e}")
        return []

def cancel_subscription(subscription_id, user_email=None):
    """Cancel a single subscription"""
    try:
        print(f"🗑️ Canceling subscription {subscription_id}...")

        # Cancel in Stripe
        canceled_sub = stripe.Subscription.delete(subscription_id)
        print(f"✅ Canceled subscription {subscription_id} in Stripe")

        # Update in database
        try:
            subscriptions_table.update_item(
                Key={'subscription_id': subscription_id},
                UpdateExpression="SET subscription_status = :status, canceled_at = :canceled_at",
                ExpressionAttributeValues={
                    ':status': 'canceled',
                    ':canceled_at': datetime.utcnow().isoformat()
                }
            )
            print(f"✅ Updated subscription {subscription_id} status in database")
        except ClientError as db_error:
            print(f"⚠️ Could not update database for {subscription_id}: {db_error}")

        return True

    except stripe.error.InvalidRequestError as e:
        if "No such subscription" in str(e):
            print(f"⚠️ Subscription {subscription_id} already canceled or doesn't exist")
            return False
        else:
            print(f"❌ Stripe error canceling {subscription_id}: {e}")
            return False
    except Exception as e:
        print(f"❌ Error canceling subscription {subscription_id}: {e}")
        return False

def main():
    """Main function to cancel all active subscriptions"""
    print("🚨 STARTING MASS SUBSCRIPTION CANCELLATION")
    print("=" * 60)

    with app.app_context():
        # Get subscriptions from both sources
        db_subscriptions = get_all_active_subscriptions()
        stripe_subscriptions = get_stripe_active_subscriptions()

        # Create a set of all unique subscription IDs
        all_subscription_ids = set()

        # Add database subscription IDs
        for sub in db_subscriptions:
            all_subscription_ids.add(sub['subscription_id'])

        # Add Stripe subscription IDs
        for sub in stripe_subscriptions:
            all_subscription_ids.add(sub.id)

        print(f"\n📊 Total unique subscriptions to cancel: {len(all_subscription_ids)}")

        if len(all_subscription_ids) == 0:
            print("✅ No active subscriptions found!")
            return

        # Confirm cancellation
        print("\n🚨 WARNING: This will cancel ALL active subscriptions!")
        print("Subscription IDs to be canceled:")
        for sub_id in sorted(all_subscription_ids):
            print(f"  - {sub_id}")

        confirm = input("\nType 'CANCEL ALL' to proceed: ")
        if confirm != 'CANCEL ALL':
            print("❌ Cancellation aborted")
            return

        # Cancel each subscription
        print(f"\n🗑️ Canceling {len(all_subscription_ids)} subscriptions...")
        canceled_count = 0
        failed_count = 0

        for sub_id in all_subscription_ids:
            if cancel_subscription(sub_id):
                canceled_count += 1
            else:
                failed_count += 1

        print("\n" + "=" * 60)
        print("📊 CANCELLATION SUMMARY:")
        print(f"✅ Successfully canceled: {canceled_count}")
        print(f"❌ Failed to cancel: {failed_count}")
        print(f"📈 Total processed: {len(all_subscription_ids)}")
        print("=" * 60)

if __name__ == '__main__':
    main()