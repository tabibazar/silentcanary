# 🚀 GitHub Actions Setup Guide

## Overview

This guide sets up automated deployment using GitHub Actions instead of manual deployment. Every push to main will automatically deploy to your EC2 instance.

## Benefits of GitHub Actions Deployment

- ✅ **Automated deployment** on every push to main
- ✅ **Consistent environment** - same deployment process every time
- ✅ **Rollback capability** - easy to revert to previous versions
- ✅ **Secure secrets management** - API keys stored safely
- ✅ **Build optimization** - cached Docker layers
- ✅ **Health checks** - automatic verification after deployment

---

## Setup Instructions

### 1. Add SSH Key to GitHub Secrets

Your EC2 private key needs to be added as a GitHub secret:

1. **Copy your EC2 private key**:
   ```bash
   cat ~/.ssh/your-ec2-key.pem
   ```

2. **Go to GitHub Repository Settings**:
   - Navigate to your repository on GitHub
   - Click "Settings" → "Secrets and variables" → "Actions"
   - Click "New repository secret"

3. **Add the secret**:
   - Name: `EC2_SSH_KEY`
   - Value: Paste your entire private key (including `-----BEGIN ... END-----`)

### 2. Configure Repository Secrets

Add these secrets in GitHub repository settings:

| Secret Name | Description | Example Value |
|-------------|-------------|---------------|
| `EC2_SSH_KEY` | Your EC2 private key | `-----BEGIN RSA PRIVATE KEY-----...` |

### 3. Update Workflow Variables (Optional)

If your EC2 details change, update these in `.github/workflows/deploy.yml`:

```yaml
env:
  EC2_HOST: 15.223.77.246  # Your EC2 IP
  EC2_USER: ubuntu         # EC2 username
  APP_DIR: /opt/silentcanary  # App directory on EC2
```

---

## How It Works

### Automatic Deployment Trigger

1. **Push to main branch** → GitHub Actions starts
2. **Checkout code** → Gets latest version
3. **SSH to EC2** → Connects to your server
4. **Pull latest code** → Updates app on server
5. **Fix environment** → Ensures Redis uses Docker network
6. **Rebuild containers** → Builds and starts fresh containers
7. **Health check** → Verifies deployment success
8. **Notify results** → Shows success/failure

### Manual Deployment

You can also trigger deployment manually:

1. Go to your repository on GitHub
2. Click "Actions" tab
3. Select "Deploy SilentCanary to EC2"
4. Click "Run workflow" → "Run workflow"

---

## Deployment Process

The workflow performs these steps:

```bash
# 1. Connect to EC2
ssh ubuntu@15.223.77.246

# 2. Update code
cd /opt/silentcanary
git pull origin main

# 3. Fix Redis configuration
echo "REDIS_HOST=redis" >> .env
echo "REDIS_ENDPOINT=" >> .env

# 4. Rebuild and restart
docker-compose down
docker system prune -f
docker-compose up -d --build

# 5. Health check
curl http://localhost/health
```

---

## Monitoring Deployments

### View Deployment Status

1. **GitHub Actions tab** - See all deployment runs
2. **Real-time logs** - Watch deployment progress
3. **Health checks** - Automatic verification
4. **Failure notifications** - Get alerted if deployment fails

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| SSH connection fails | Check `EC2_SSH_KEY` secret is correct |
| Health check fails | Check app logs: `docker-compose logs` |
| Build fails | Check Docker build errors in logs |
| Port conflicts | Run fix script: `./fix-port-conflicts.sh` |

---

## Advanced Features

### Rollback Strategy

If a deployment fails:

1. **Manual rollback**:
   ```bash
   ssh ubuntu@15.223.77.246
   cd /opt/silentcanary
   git reset --hard HEAD~1  # Go back one commit
   docker-compose up -d --build
   ```

2. **Automatic rollback** (can be added to workflow):
   - Health check fails → automatically rollback
   - Slack/email notifications on failure

### Environment-Specific Deployments

You can extend this for staging/production:

```yaml
# Add environment matrix
strategy:
  matrix:
    environment: [staging, production]
    include:
      - environment: staging
        ec2_host: staging-ip
      - environment: production
        ec2_host: 15.223.77.246
```

---

## Security Considerations

- ✅ **SSH keys** stored as encrypted secrets
- ✅ **No credentials** in workflow files
- ✅ **Secure deployment** using SSH
- ✅ **Health checks** prevent broken deployments
- ✅ **Audit trail** of all deployments

---

## Next Steps

1. **Test the workflow** - Push a small change to main
2. **Monitor deployment** - Watch GitHub Actions tab
3. **Verify site works** - Check https://silentcanary.com
4. **Set up notifications** - Get alerts on failures
5. **Add staging environment** - For safer deployments

---

*With GitHub Actions, you now have professional-grade CI/CD for SilentCanary! 🎉*