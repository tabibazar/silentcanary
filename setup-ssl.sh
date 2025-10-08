#!/bin/bash

# SSL Certificate Setup Script for SilentCanary

set -e

DOMAIN="silentcanary.com"
EMAIL="admin@silentcanary.com"
APP_DIR="/opt/silentcanary"

echo "🔒 Setting up SSL certificates for $DOMAIN..."

# Stop nginx if running
docker-compose -f $APP_DIR/docker-compose.yml stop nginx 2>/dev/null || true

# Create temporary nginx config for Let's Encrypt challenge
cat > /tmp/nginx-ssl-setup.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    server {
        listen 80;
        server_name silentcanary.com www.silentcanary.com;

        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        location / {
            return 200 'SSL setup in progress';
            add_header Content-Type text/plain;
        }
    }
}
EOF

# Create certbot directory
sudo mkdir -p /var/www/certbot
sudo chown -R silentcanary:silentcanary /var/www/certbot

# Start temporary nginx
docker run -d \
    --name nginx-ssl-setup \
    -p 80:80 \
    -v /tmp/nginx-ssl-setup.conf:/etc/nginx/nginx.conf:ro \
    -v /var/www/certbot:/var/www/certbot:ro \
    nginx:alpine

# Wait for nginx to start
sleep 5

# Obtain SSL certificate
echo "📜 Obtaining SSL certificate from Let's Encrypt..."
sudo certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email $EMAIL \
    --agree-tos \
    --no-eff-email \
    -d $DOMAIN \
    -d www.$DOMAIN

# Stop temporary nginx
docker stop nginx-ssl-setup
docker rm nginx-ssl-setup

# Copy certificates to app directory
echo "📋 Copying certificates..."
sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $APP_DIR/ssl/$DOMAIN.crt
sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $APP_DIR/ssl/$DOMAIN.key
sudo chown silentcanary:silentcanary $APP_DIR/ssl/*

# Set up auto-renewal
echo "🔄 Setting up certificate auto-renewal..."
cat > /tmp/renew-ssl.sh << 'EOF'
#!/bin/bash
/usr/bin/certbot renew --quiet --webroot --webroot-path=/var/www/certbot
if [ $? -eq 0 ]; then
    cp /etc/letsencrypt/live/silentcanary.com/fullchain.pem /opt/silentcanary/ssl/silentcanary.com.crt
    cp /etc/letsencrypt/live/silentcanary.com/privkey.pem /opt/silentcanary/ssl/silentcanary.com.key
    chown silentcanary:silentcanary /opt/silentcanary/ssl/*
    docker-compose -f /opt/silentcanary/docker-compose.yml restart nginx
fi
EOF

sudo mv /tmp/renew-ssl.sh /opt/silentcanary/renew-ssl.sh
sudo chmod +x /opt/silentcanary/renew-ssl.sh

# Add to crontab
(crontab -l 2>/dev/null; echo "0 12 * * * /opt/silentcanary/renew-ssl.sh") | crontab -

echo "✅ SSL certificates set up successfully!"
echo "Certificates saved to: $APP_DIR/ssl/"
echo "Auto-renewal configured to run daily at noon"