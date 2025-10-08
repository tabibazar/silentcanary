#!/bin/bash

# Manual SSL Setup Script for SilentCanary

echo "🔒 Manual SSL certificate setup for SilentCanary"
echo "================================================"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run this script with sudo"
    exit 1
fi

# Install certbot if not present
if ! command -v certbot &> /dev/null; then
    echo "📦 Installing certbot..."
    apt-get update
    apt-get install -y certbot
fi

# Stop any service using port 80
echo "🛑 Stopping services on port 80..."
systemctl stop nginx 2>/dev/null || true
systemctl stop apache2 2>/dev/null || true
fuser -k 80/tcp 2>/dev/null || true

# Stop Docker nginx container
echo "🛑 Stopping Docker nginx container..."
cd /opt/silentcanary
docker-compose stop nginx 2>/dev/null || true

# Wait a moment for ports to be free
sleep 5

# Try to get certificate for main domain only first
echo "🔐 Requesting SSL certificate for silentcanary.com..."
if certbot certonly --standalone \
    --preferred-challenges http \
    --email admin@silentcanary.com \
    --agree-tos \
    --no-eff-email \
    -d silentcanary.com \
    --force-renewal; then

    echo "✅ Certificate obtained successfully!"

    # Copy certificates to Docker volume
    echo "📋 Copying certificates to Docker volume..."
    mkdir -p /opt/silentcanary/ssl
    cp /etc/letsencrypt/live/silentcanary.com/fullchain.pem /opt/silentcanary/ssl/silentcanary.com.crt
    cp /etc/letsencrypt/live/silentcanary.com/privkey.pem /opt/silentcanary/ssl/silentcanary.com.key
    chown -R ubuntu:ubuntu /opt/silentcanary/ssl

    # Switch to SSL nginx config
    echo "⚙️ Switching to SSL nginx configuration..."
    if [ -f "/opt/silentcanary/nginx-ssl.conf" ]; then
        cp /opt/silentcanary/nginx-ssl.conf /opt/silentcanary/nginx.conf

        # Update docker-compose to use SSL config
        sed -i 's|./nginx-simple.conf|./nginx.conf|g' /opt/silentcanary/docker-compose.yml
    fi

    # Start containers with SSL
    echo "🚀 Starting containers with SSL..."
    docker-compose up -d

    echo "✅ SSL setup completed!"
    echo "🌐 Your site should now be available at:"
    echo "   - https://silentcanary.com"
    echo "   - http://silentcanary.com (redirects to HTTPS)"

else
    echo "❌ Certificate generation failed!"
    echo "💡 Please check:"
    echo "   1. Domain silentcanary.com points to this server"
    echo "   2. Port 80 is accessible from the internet"
    echo "   3. No firewall blocking connections"

    # Restart containers without SSL
    echo "🔄 Restarting containers without SSL..."
    docker-compose up -d
    exit 1
fi