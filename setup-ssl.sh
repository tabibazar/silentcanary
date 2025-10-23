#!/bin/bash
set -e

echo "🔐 SSL Certificate Setup Script for SilentCanary"
echo "================================================"
echo ""

# Configuration
DOMAIN="silentcanary.com"
WWW_DOMAIN="www.silentcanary.com"
EMAIL="reza@tabibazar.com"

echo "📁 Step 1: Creating certbot directories..."
mkdir -p certbot/conf certbot/www

echo ""
echo "📝 Step 2: Using temporary nginx config (HTTP only)..."
cp nginx.conf nginx.conf.backup
cp nginx.conf.temp nginx.conf

echo ""
echo "🔄 Step 3: Restarting nginx with HTTP-only config..."
docker-compose up -d nginx

echo ""
echo "⏳ Step 4: Waiting 5 seconds for nginx to start..."
sleep 5

echo ""
echo "🔐 Step 5: Obtaining SSL certificate from Let's Encrypt..."
docker-compose run --rm certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  --email "$EMAIL" \
  --agree-tos \
  --no-eff-email \
  -d "$DOMAIN" \
  -d "$WWW_DOMAIN"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ SSL certificate obtained successfully!"

    echo ""
    echo "📝 Step 6: Restoring nginx config with HTTPS..."
    cp nginx.conf.backup nginx.conf

    echo ""
    echo "🔄 Step 7: Restarting nginx with SSL configuration..."
    docker-compose restart nginx

    echo ""
    echo "⏳ Step 8: Waiting 5 seconds..."
    sleep 5

    echo ""
    echo "🔄 Step 9: Starting certbot auto-renewal service..."
    docker-compose up -d certbot

    echo ""
    echo "📊 Step 10: Checking service status..."
    docker-compose ps

    echo ""
    echo "🧪 Step 11: Testing HTTPS..."
    curl -I https://localhost --insecure || echo "Local HTTPS test incomplete"

    echo ""
    echo "✅ SSL setup complete! Your site should now be accessible at https://$DOMAIN"
    echo ""
    echo "📝 Note: Certificates will auto-renew via the certbot container"
else
    echo ""
    echo "❌ Failed to obtain SSL certificate"
    echo "Restoring original nginx config..."
    cp nginx.conf.backup nginx.conf
    docker-compose restart nginx
    exit 1
fi
