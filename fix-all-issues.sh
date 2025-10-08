#!/bin/bash

# Fix all identified container issues

echo "🔧 Fixing all container issues..."

# Fix 1: Update docker-compose to use simple nginx
echo "1️⃣ Updating nginx configuration..."
curl -sSL https://raw.githubusercontent.com/tabibazar/silentcanary/main/docker-compose.yml -o docker-compose.yml
curl -sSL https://raw.githubusercontent.com/tabibazar/silentcanary/main/nginx-simple.conf -o nginx-simple.conf

# Fix 2: Remove ports section for HTTPS temporarily
echo "2️⃣ Updating nginx to HTTP only..."
sed -i 's/- "443:443"/# - "443:443"/' docker-compose.yml

# Fix 3: Check Redis connection in worker.py
echo "3️⃣ Checking Redis configuration..."
grep -n "localhost:6379" worker.py || echo "Redis config looks correct"

# Fix 4: Stop and restart all services
echo "4️⃣ Restarting all services..."
docker-compose down
docker-compose up -d

echo "5️⃣ Waiting for services to start..."
sleep 10

echo "6️⃣ Checking service status..."
docker-compose ps

echo "7️⃣ Testing application..."
curl -f http://localhost/health && echo "✅ Health check passed!" || echo "❌ Health check failed"

echo "8️⃣ Testing external access..."
curl -f http://$(curl -s ifconfig.me)/health && echo "✅ External access works!" || echo "❌ External access failed"

echo "✅ Fix script completed!"