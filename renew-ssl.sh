#!/bin/bash

# SSL Certificate Renewal Script for SilentCanary

echo "🔄 Starting SSL certificate renewal check..."

# Check if certificates need renewal (30 days before expiry)
if sudo certbot renew --dry-run; then
    echo "🔍 Checking if renewal is needed..."

    # Actually renew certificates
    sudo certbot renew --quiet

    # Check if renewal happened
    if [ $? -eq 0 ]; then
        echo "🔄 Certificates renewed, updating Docker containers..."

        # Copy renewed certificates
        sudo cp /etc/letsencrypt/live/silentcanary.com/fullchain.pem /opt/silentcanary/ssl/silentcanary.com.crt
        sudo cp /etc/letsencrypt/live/silentcanary.com/privkey.pem /opt/silentcanary/ssl/silentcanary.com.key
        sudo chown -R ubuntu:ubuntu /opt/silentcanary/ssl

        # Restart nginx container to load new certificates
        cd /opt/silentcanary
        docker-compose restart nginx

        echo "✅ SSL certificates renewed and nginx restarted"
    else
        echo "ℹ️ No renewal needed, certificates are still valid"
    fi
else
    echo "❌ Certificate renewal check failed"
    exit 1
fi