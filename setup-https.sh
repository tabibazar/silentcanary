#!/bin/bash
set -e

echo "🔐 Setting up HTTPS for silentcanary.com"
echo "=========================================="
echo ""

DOMAIN="silentcanary.com"
WWW_DOMAIN="www.silentcanary.com"
EMAIL="reza@tabibazar.com"

# Step 1: Create directories
echo "📁 Creating certbot directories..."
mkdir -p certbot/conf certbot/www
echo "✅ Directories created"
echo ""

# Step 2: Deploy current config (with ACME challenge support)
echo "🔄 Updating nginx configuration..."
docker-compose up -d nginx
sleep 5
echo "✅ Nginx updated"
echo ""

# Step 3: Obtain certificate
echo "🔐 Obtaining SSL certificate from Let's Encrypt..."
docker-compose run --rm certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  --email "$EMAIL" \
  --agree-tos \
  --no-eff-email \
  -d "$DOMAIN" \
  -d "$WWW_DOMAIN"

if [ $? -ne 0 ]; then
    echo "❌ Failed to obtain certificate"
    exit 1
fi

echo "✅ Certificate obtained successfully!"
echo ""

# Step 4: Create HTTPS nginx configuration
echo "📝 Creating HTTPS nginx configuration..."
cat > nginx.conf.https << 'NGINX_EOF'
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 20M;

    upstream app {
        server app:8000;
    }

    # HTTP server - redirect to HTTPS
    server {
        listen 80;
        server_name silentcanary.com www.silentcanary.com;

        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }

        location / {
            return 301 https://$host$request_uri;
        }
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name silentcanary.com www.silentcanary.com;

        ssl_certificate /etc/letsencrypt/live/silentcanary.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/silentcanary.com/privkey.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        location /health {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
        }

        location / {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_read_timeout 60s;
            proxy_connect_timeout 60s;
        }
    }
}
NGINX_EOF

echo "✅ HTTPS configuration created"
echo ""

# Step 5: Apply HTTPS configuration
echo "🔄 Applying HTTPS configuration..."
cp nginx.conf nginx.conf.http.backup
cp nginx.conf.https nginx.conf
docker-compose restart nginx
sleep 5
echo "✅ HTTPS configuration applied"
echo ""

# Step 6: Start certbot renewal service
echo "🔄 Starting certificate auto-renewal service..."
docker-compose up -d certbot
echo "✅ Auto-renewal service started"
echo ""

# Step 7: Test
echo "🧪 Testing HTTPS..."
curl -I https://localhost --insecure 2>&1 | head -5 || echo "Local test could not complete"
echo ""

echo "✅ HTTPS setup complete!"
echo ""
echo "Your site should now be accessible at:"
echo "  • https://silentcanary.com"
echo "  • https://www.silentcanary.com"
echo ""
echo "Certificates will auto-renew via the certbot container."
