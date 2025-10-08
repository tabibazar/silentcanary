#!/bin/bash

# Fix port conflicts for SilentCanary deployment

echo "🔧 Fixing port conflicts..."

# Stop any existing Redis service
echo "🛑 Stopping system Redis service..."
sudo systemctl stop redis-server 2>/dev/null || echo "Redis service not running"
sudo systemctl disable redis-server 2>/dev/null || echo "Redis service not enabled"

# Stop any existing nginx
echo "🛑 Stopping system Nginx service..."
sudo systemctl stop nginx 2>/dev/null || echo "Nginx service not running"
sudo systemctl disable nginx 2>/dev/null || echo "Nginx service not enabled"

# Clean up any Docker containers using these ports
echo "🧹 Cleaning up Docker containers..."
docker stop silentcanary-redis silentcanary-nginx silentcanary-app silentcanary-worker silentcanary-scheduler 2>/dev/null || true
docker rm silentcanary-redis silentcanary-nginx silentcanary-app silentcanary-worker silentcanary-scheduler 2>/dev/null || true

# Check what's using port 6379
echo "🔍 Checking what's using port 6379..."
sudo lsof -i :6379 || echo "Port 6379 is free"

# Check what's using port 80
echo "🔍 Checking what's using port 80..."
sudo lsof -i :80 || echo "Port 80 is free"

# Check what's using port 443
echo "🔍 Checking what's using port 443..."
sudo lsof -i :443 || echo "Port 443 is free"

echo "✅ Port conflict fixes completed!"
echo "Now you can run: docker-compose up -d"