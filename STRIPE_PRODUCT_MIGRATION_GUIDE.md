# Stripe Product Migration Guide

## Problem

Users with subscriptions on old, inactive Stripe products receive the following error when trying to change billing frequency:

```
Billing frequency change failed: Request req_P7qgnw0PixRHC7: Price `price_1S6gQOC1JljIJA9aRCJdfUuj`
is not available to be purchased because its product is not active.. Please contact support.
```

## Root Cause

### Old vs New Products

**OLD Products** (INACTIVE):
- Product ID: `prod_T2ly1pEt5GqdP8` (SilentCanary Growth)
- Status: **Inactive**
- Price IDs:
  - Monthly: `price_1S6gQOC1JljIJA9azsEdRU2G` ($25/month)
  - Annual: `price_1S6gQOC1JljIJA9aRCJdfUuj` ($250/year) ← **This is the error price**

**NEW Products** (ACTIVE):
- Startup: `prod_TCToYgu9HSZKGf` (Active)
  - Monthly: `price_1SG4r8C1JljIJA9anjSJ1Gzc` ($7/month)
  - Annual: `price_1SG4r9C1JljIJA9af57SQY96` ($70/year)

- Growth: `prod_TCTolhPSXJaD8z` (Active)
  - Monthly: `price_1SG4r9C1JljIJA9aH1QXAUyV` ($25/month)
  - Annual: `price_1SG4r9C1JljIJA9aALoMud9w` ($250/year)

- Enterprise: `prod_TCToJSs4jwOWsO` (Active)
  - Monthly: `price_1SG4rAC1JljIJA9aqNNZMsLs` ($75/month)
  - Annual: `price_1SG4rAC1JljIJA9aO8IOFYU9` ($750/year)

### Why It Happens

When a user tries to:
1. **Change billing frequency** (monthly ↔ annual)
2. **Upgrade/downgrade plans**
3. **Reactivate a canceled subscription**

Stripe validates that the product associated with the price is **active**. If the product is inactive, Stripe rejects the request.

### Additional Issue: Canceled Subscriptions

For user `reza@tabibazar.com`:
- Subscription status: **CANCELED**
- Still using old price: `price_1S6gQOC1JljIJA9aRCJdfUuj`
- Trying to change billing frequency on a canceled subscription doesn't make sense

## Solutions

### Solution 1: Prevent Billing Changes on Canceled Subscriptions ✅

**Status: IMPLEMENTED**

Added validation in `app.py:3210-3214` to prevent billing frequency changes on canceled subscriptions:

```python
# Check if subscription is canceled
if subscription.status == 'canceled':
    flash('Your subscription has been canceled. Please resubscribe to change your plan or billing frequency.', 'error')
    return redirect(url_for('account_management'))
```

Users with canceled subscriptions should use the **Resubscribe** button instead, which will create a new subscription with the NEW active price IDs.

### Solution 2: Migrate Existing Active Subscriptions

For users with **active** subscriptions still on old products, use the migration script:

#### Dry Run (Test Mode)

Test migration for a specific user:
```bash
python3 migrate_stripe_subscriptions.py --user-email user@example.com --dry-run
```

Test migration for all users:
```bash
python3 migrate_stripe_subscriptions.py --all --dry-run
```

#### Live Migration

Migrate a specific user:
```bash
python3 migrate_stripe_subscriptions.py --user-email user@example.com
```

Migrate all users:
```bash
python3 migrate_stripe_subscriptions.py --all
```

### Solution 3: Reactivate Old Products (Not Recommended)

You could reactivate the old products in Stripe Dashboard, but this is **not recommended** because:
- You want to standardize on the new product structure
- Old products may have incorrect configurations
- Creates confusion with duplicate products

## User Instructions

### For Canceled Subscriptions

If you have a canceled subscription and want to change your plan or billing:

1. Log in to https://silentcanary.com
2. Go to **Account Management**
3. Click the **Resubscribe** button
4. Select your desired plan and billing frequency
5. Complete payment

The resubscribe flow will automatically use the NEW active products.

### For Active Subscriptions

If you have an active subscription on an old product:

1. **Option A**: Wait for automatic migration (when admin runs migration script)
2. **Option B**: Cancel and resubscribe
   - Cancel your current subscription
   - Wait for it to end (or ends immediately based on settings)
   - Resubscribe to the same or different plan

## Verification

### Check if a User Needs Migration

```python
python3 -c "
import stripe
import os
from dotenv import load_dotenv
from models import Subscription, User

load_dotenv()
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

user = User.get_by_email('user@example.com')
subscription = Subscription.get_by_user_id(user.user_id)

stripe_sub = stripe.Subscription.retrieve(
    subscription.stripe_subscription_id,
    expand=['items.data.price.product']
)

price = stripe_sub['items']['data'][0]['price']
product = price['product']

print(f'User: {user.email}')
print(f'Status: {subscription.status}')
print(f'Price: {price[\"id\"]}')
print(f'Product: {product[\"id\"] if isinstance(product, dict) else product}')
print(f'Product Active: {product[\"active\"] if isinstance(product, dict) else \"Unknown\"}')

if isinstance(product, dict) and not product['active']:
    print('❌ NEEDS MIGRATION')
else:
    print('✅ OK')
"
```

### Verify Migration Completed

After migration, verify the user is on a new active product:

```bash
python3 migrate_stripe_subscriptions.py --user-email user@example.com --dry-run
```

Should show: "Subscription already on active product - no migration needed"

## Testing

### Test Case 1: Canceled Subscription

1. User: `reza@tabibazar.com`
2. Status: Canceled
3. Try to change billing frequency
4. **Expected**: Error message: "Your subscription has been canceled. Please resubscribe..."

### Test Case 2: Active Subscription on Old Product

1. Create or identify user with active subscription on old product
2. Run migration script:
   ```bash
   python3 migrate_stripe_subscriptions.py --user-email user@example.com --dry-run
   ```
3. Verify migration plan is shown
4. Run without `--dry-run` to execute
5. Verify subscription now uses new price ID

### Test Case 3: Resubscribe Flow

1. User with canceled subscription clicks "Resubscribe"
2. Should redirect to upgrade flow with new price IDs
3. Complete payment in Stripe Checkout
4. Verify new subscription uses new active product

## Code Changes

### Files Modified

1. **app.py** (line 3210-3214)
   - Added validation to prevent billing changes on canceled subscriptions

### Files Created

1. **migrate_stripe_subscriptions.py**
   - Script to migrate subscriptions from old to new products
   - Supports dry-run mode
   - Can target specific users or migrate all

2. **STRIPE_PRODUCT_MIGRATION_GUIDE.md** (this file)
   - Documentation of the issue and solutions

## Deployment

### Step 1: Deploy Code Changes

```bash
git add app.py migrate_stripe_subscriptions.py STRIPE_PRODUCT_MIGRATION_GUIDE.md
git commit -m "Fix billing frequency change error for canceled subscriptions"
git push origin main
```

### Step 2: Run Migration for Active Subscriptions

After deployment, run the migration script on production:

```bash
# SSH to production server
ssh ubuntu@35.182.6.75

# Navigate to app directory
cd /opt/silentcanary

# Run migration in dry-run mode first
docker exec silentcanary-app python3 migrate_stripe_subscriptions.py --all --dry-run

# If everything looks good, run live migration
docker exec silentcanary-app python3 migrate_stripe_subscriptions.py --all
```

### Step 3: Monitor Results

Check application logs for any errors:
```bash
docker logs silentcanary-app | grep -i "billing\|stripe"
```

## Prevention

To prevent this issue in the future:

1. **Never deactivate products** that have active subscriptions
2. **Before deactivating**, migrate all subscriptions to new products
3. **Test in Stripe test mode** before making changes in live mode
4. **Use environment variables** for all price IDs (already implemented)
5. **Version your products** clearly (e.g., "SilentCanary Growth V2")

## Support

If users continue to experience issues:

1. Check their subscription status in Stripe Dashboard
2. Verify the product/price IDs they're using
3. Run diagnostic:
   ```bash
   python3 migrate_stripe_subscriptions.py --user-email user@example.com --dry-run
   ```
4. If needed, manually migrate in Stripe Dashboard:
   - Go to the subscription
   - Click "Update subscription"
   - Change the price to the new price ID
   - Apply changes

## References

- Stripe Product Dashboard: https://dashboard.stripe.com/products
- Stripe Subscription API: https://stripe.com/docs/api/subscriptions
- STRIPE_PRODUCTS_SUMMARY.md: Lists all current products and price IDs
