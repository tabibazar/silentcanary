# HTTPS Setup Instructions

## Current Status
- ✅ Deployment workflow is working successfully
- ✅ Website is accessible at http://silentcanary.com
- ⏳ **Let's Encrypt rate limit hit** - need to wait until rate limit resets

## Rate Limit Reset Time
- **UTC**: 2024-10-24 03:54:50 UTC
- **EST (EDT)**: 2024-10-23 11:54:50 PM EDT (Tonight)
- **Approximately**: 2 hours from now (as of 9:40 PM EDT)

## What Happened
We attempted to obtain SSL certificates too many times in a short period, hitting Let's Encrypt's rate limit:
- Error: "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s"
- This is a safety measure by Let's Encrypt to prevent abuse

## Steps to Enable HTTPS (After Rate Limit Resets)

### Option 1: Run the GitHub Actions Workflow
```bash
gh workflow run setup-https.yml
```

Then monitor:
```bash
gh run watch $(gh run list --workflow=setup-https.yml --limit 1 --json databaseId -q '.[0].databaseId')
```

### Option 2: SSH Directly to Server (Recommended)
```bash
ssh -i ~/.ssh/silentcanary.pem ubuntu@35.182.6.75
cd /opt/silentcanary
git pull origin main
chmod +x setup-https.sh
./setup-https.sh
```

## What the Script Does
1. Creates certbot directories
2. Updates nginx configuration to support ACME challenges
3. Obtains SSL certificate from Let's Encrypt for:
   - silentcanary.com
   - www.silentcanary.com
4. Creates HTTPS nginx configuration with:
   - SSL certificate paths
   - HTTP to HTTPS redirect
   - Strong SSL settings (TLSv1.2, TLSv1.3)
   - HSTS header
5. Restarts nginx with new configuration
6. Starts certbot auto-renewal service

## Expected Result
After successful setup:
- https://silentcanary.com will be accessible
- https://www.silentcanary.com will be accessible
- http://silentcanary.com will redirect to HTTPS
- SSL certificates will auto-renew every 12 hours via the certbot container

## Verification
Test HTTPS access:
```bash
curl -I https://silentcanary.com
```

Check certificate:
```bash
echo | openssl s_client -servername silentcanary.com -connect silentcanary.com:443 2>/dev/null | openssl x509 -noout -dates
```

## Troubleshooting
If the setup fails:
1. Check certbot logs on the server:
   ```bash
   ssh -i ~/.ssh/silentcanary.pem ubuntu@35.182.6.75
   sudo cat /var/log/letsencrypt/letsencrypt.log
   ```

2. Check nginx logs:
   ```bash
   ssh -i ~/.ssh/silentcanary.pem ubuntu@35.182.6.75
   docker logs silentcanary-nginx
   ```

3. Verify DNS is pointing to the server:
   ```bash
   nslookup silentcanary.com
   ```

4. If still having issues, wait another hour and try again (rate limits can be conservative)

## Files Modified
- `setup-https.sh` - HTTPS setup script
- `.github/workflows/setup-https.yml` - GitHub Actions workflow
- `nginx.conf` - Has ACME challenge location configured
- `docker-compose.yml` - Includes certbot service

## Important Notes
- Do NOT run the setup script multiple times in rapid succession - this will trigger the rate limit again
- The certbot container will handle certificate renewals automatically
- Certificates are valid for 90 days and auto-renew at 60 days
