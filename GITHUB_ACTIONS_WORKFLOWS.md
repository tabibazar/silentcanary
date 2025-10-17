# GitHub Actions Workflows

This document describes the automated workflows configured for the SilentCanary project.

## Workflows

### 1. Subscription Tests (`test-subscriptions.yml`)

**Purpose**: Comprehensive testing of all subscription models, pricing, and Stripe configurations.

**Triggers**:
- Push to `main` branch
- Pull requests to `main` branch
- Manual trigger (`workflow_dispatch`)
- Scheduled daily at 6 AM UTC

**What it tests**:
- ✅ Environment configuration (Stripe keys, price IDs)
- ✅ Stripe products and prices (all tiers, both frequencies)
- ✅ Plan limits and features
- ✅ Upgrade/downgrade paths
- ✅ Billing frequency changes
- ✅ Edge cases and error handling
- ✅ Price consistency

**Duration**: ~10-15 seconds

**Status Badge**:
```markdown
![Subscription Tests](https://github.com/tabibazar/silentcanary/actions/workflows/test-subscriptions.yml/badge.svg)
```

**Manual Trigger**:
```bash
gh workflow run test-subscriptions.yml
```

**View Results**:
```bash
# List recent runs
gh run list --workflow=test-subscriptions.yml --limit 5

# Watch live
gh run watch

# View details
gh run view <run-id>
```

---

### 2. Deploy to EC2 (`deploy.yml`)

**Purpose**: Automated deployment to production EC2 server with pre-deployment testing.

**Triggers**:
- Push to `main` branch
- Manual trigger (`workflow_dispatch`)

**Workflow Steps**:

#### Step 1: Test Job
Before deploying, runs comprehensive subscription tests to ensure:
- All Stripe configurations are valid
- All products and prices are active
- No pricing inconsistencies
- All upgrade/downgrade paths work

**If tests fail**: Deployment is blocked ❌

#### Step 2: Deploy Job (only runs if tests pass)
1. Connects to EC2 server via SSH
2. Pulls latest code from GitHub
3. Updates environment variables:
   - AWS credentials
   - reCAPTCHA keys
   - Stripe credentials (secret key, publishable key, webhook secret)
   - All Stripe price IDs (6 total)
4. Rebuilds Docker containers
5. Restarts services
6. Runs health check

**Duration**: ~5-10 minutes (depending on Docker build)

**Environment**: Production (live Stripe keys, live database)

**Manual Trigger**:
```bash
gh workflow run deploy.yml
```

---

## Workflow Dependencies

```
deploy.yml
├─ test job (runs first)
│  └─ test_subscriptions_comprehensive.py
│     └─ Validates all Stripe configurations
│
└─ deploy job (runs only if test passes)
   └─ Deploys to EC2
```

The `deploy` job **depends on** the `test` job via `needs: test`. This ensures:
- ✅ Tests always run before deployment
- ✅ Deployment is blocked if tests fail
- ✅ Production stays stable

---

## Required GitHub Secrets

All workflows require these secrets to be configured:

### Stripe Secrets
```
STRIPE_SECRET_KEY                    # sk_live_...
STRIPE_PUBLISHABLE_KEY               # pk_live_...
STRIPE_WEBHOOK_SECRET                # whsec_...
STRIPE_STARTUP_MONTHLY_PRICE_ID      # price_1SG4r8...
STRIPE_STARTUP_ANNUAL_PRICE_ID       # price_1SG4r9...
STRIPE_GROWTH_MONTHLY_PRICE_ID       # price_1SG4r9...
STRIPE_GROWTH_ANNUAL_PRICE_ID        # price_1SG4r9...
STRIPE_ENTERPRISE_MONTHLY_PRICE_ID   # price_1SG4rA...
STRIPE_ENTERPRISE_ANNUAL_PRICE_ID    # price_1SG4rA...
```

### AWS Secrets
```
AWS_ACCESS_KEY_ID                    # For DynamoDB access
AWS_SECRET_ACCESS_KEY                # For DynamoDB access
```

### reCAPTCHA Secrets
```
RECAPTCHA_SITE_KEY                   # Public site key
RECAPTCHA_SECRET_KEY                 # Secret key
```

### Deployment Secrets
```
EC2_SSH_KEY                          # SSH private key for EC2 access
```

### Setup Secrets

Use the `setup-github-secrets.sh` script to configure all secrets at once:

```bash
./setup-github-secrets.sh
```

Or manually set secrets:
```bash
gh secret set STRIPE_SECRET_KEY < <(echo "sk_live_...")
gh secret set STRIPE_PUBLISHABLE_KEY < <(echo "pk_live_...")
# ... etc
```

---

## Monitoring Workflows

### Check Status

```bash
# List all recent runs
gh run list --limit 10

# List runs for specific workflow
gh run list --workflow=deploy.yml --limit 5
gh run list --workflow=test-subscriptions.yml --limit 5

# Watch current run
gh run watch

# View specific run
gh run view <run-id>

# View logs
gh run view <run-id> --log
```

### View in Browser

```bash
# Open Actions tab
gh workflow view deploy.yml --web
gh workflow view test-subscriptions.yml --web

# Open specific run
gh run view <run-id> --web
```

---

## Test Failures

### What Happens When Tests Fail?

1. **In `test-subscriptions.yml`**:
   - Workflow fails ❌
   - No deployment occurs
   - GitHub sends notification
   - Logs show which test(s) failed

2. **In `deploy.yml` test job**:
   - Test job fails ❌
   - Deploy job is **skipped** (never runs)
   - Production remains unchanged
   - Logs show failure reason

### Common Test Failures

| Failure | Cause | Fix |
|---------|-------|-----|
| STRIPE_SECRET_KEY not configured | GitHub secret missing | Run `setup-github-secrets.sh` |
| Price ID mismatch | Price amount doesn't match expected | Update price or expected value |
| Product inactive | Old product still referenced | Run migration script |
| Authentication error | Invalid Stripe key | Verify key is correct |

### Debugging Failed Tests

```bash
# View failed run
gh run view <run-id> --log

# Look for specific errors
gh run view <run-id> --log | grep "❌"

# Download logs for offline analysis
gh run view <run-id> --log > test-failure.log
```

---

## Scheduled Tests

The `test-subscriptions.yml` workflow runs automatically **daily at 6 AM UTC**.

**Why?**
- Detects Stripe configuration drift
- Catches deactivated products
- Validates price changes
- Ensures production readiness

**Disable scheduled tests**:
```yaml
# Comment out in .github/workflows/test-subscriptions.yml
# schedule:
#   - cron: '0 6 * * *'
```

---

## Workflow Best Practices

### Before Pushing to Main

1. **Run tests locally**:
   ```bash
   python3 test_subscriptions_comprehensive.py
   ```

2. **Verify all 62 tests pass**

3. **Check for warnings** (old products, etc.)

### After Push

1. **Monitor the workflow**:
   ```bash
   gh run watch
   ```

2. **Verify tests pass**

3. **Wait for deployment to complete**

4. **Check production**:
   ```bash
   curl https://silentcanary.com/health
   ```

### Emergency Rollback

If deployment fails or causes issues:

```bash
# SSH to server
ssh ubuntu@35.182.6.75

# Check logs
docker logs silentcanary-app

# Rollback to previous version
cd /opt/silentcanary
git log --oneline -10
git checkout <previous-commit>
docker-compose restart
```

---

## Workflow Artifacts

Test results are uploaded as artifacts and retained for 30 days:

**Download artifacts**:
```bash
# List available artifacts
gh run view <run-id> --json artifacts

# Download
gh run download <run-id>
```

**Artifacts include**:
- `SUBSCRIPTION_TEST_REPORT.md` - Detailed test report

---

## Adding New Tests

To add tests to the subscription test suite:

1. Edit `test_subscriptions_comprehensive.py`
2. Add new test method:
   ```python
   def test_new_feature(self):
       """Test description"""
       self.print_header("Test N: New Feature")
       # Test logic
       self.print_test("Test name", "PASS", "Details")
   ```
3. Call from `run_all_tests()`:
   ```python
   self.test_new_feature()
   ```
4. Commit and push - tests run automatically

---

## Continuous Integration Benefits

✅ **Automated Testing**: Every push runs full test suite
✅ **Pre-Deployment Validation**: Deployment blocked if tests fail
✅ **Daily Health Checks**: Scheduled tests catch drift
✅ **Audit Trail**: All runs logged with timestamps
✅ **Fast Feedback**: Results in ~10 seconds
✅ **Zero Downtime**: Tests don't affect production
✅ **Comprehensive Coverage**: 62 tests across 7 categories

---

## Support

For issues with workflows:

1. Check workflow logs: `gh run view <run-id> --log`
2. Review test output for specific failures
3. Verify GitHub secrets are set correctly: `gh secret list`
4. Check this documentation for troubleshooting steps

---

**Last Updated**: 2025-01-16
**Workflows Version**: 1.0
