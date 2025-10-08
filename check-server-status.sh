#!/bin/bash

# Check SilentCanary server status and fix issues

SERVER_IP="15.223.77.246"

echo "🔍 Checking SilentCanary server status..."
echo "Server IP: $SERVER_IP"
echo "Domain: silentcanary.com"
echo "=================================="

# Test direct IP access
echo "📡 Testing direct IP access..."
curl -s -o /dev/null -w "HTTP Status: %{http_code}\nResponse Time: %{time_total}s\n" http://$SERVER_IP/ || echo "Failed to connect to IP"

# Test domain access
echo "📡 Testing domain access..."
curl -s -o /dev/null -w "HTTP Status: %{http_code}\nResponse Time: %{time_total}s\n" http://silentcanary.com/ || echo "Failed to connect to domain"

# Check DNS resolution
echo "🔍 DNS Resolution:"
nslookup silentcanary.com

# Check if ports are open
echo "🔍 Checking open ports on server..."
echo "Port 80 (HTTP):"
nc -zv $SERVER_IP 80 2>&1 || echo "Port 80 not accessible"

echo "Port 443 (HTTPS):"
nc -zv $SERVER_IP 443 2>&1 || echo "Port 443 not accessible"

echo "Port 22 (SSH):"
nc -zv $SERVER_IP 22 2>&1 || echo "Port 22 not accessible"

echo "=================================="
echo "💡 If you see 503 errors, the application containers may not be running"
echo "💡 SSH to the server and run: docker-compose ps"
echo "💡 If containers are down, run: docker-compose up -d"