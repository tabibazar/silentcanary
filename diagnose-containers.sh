#!/bin/bash

# Diagnose container restart issues

echo "🔍 Diagnosing container restart issues..."

echo "📋 1. Check nginx logs:"
docker-compose logs nginx --tail=20

echo ""
echo "📋 2. Check worker logs:"
docker-compose logs worker --tail=20

echo ""
echo "📋 3. Check scheduler logs:"
docker-compose logs scheduler --tail=20

echo ""
echo "📋 4. Check SSL certificate directory:"
ls -la ssl/ 2>/dev/null || echo "SSL directory not found"

echo ""
echo "📋 5. Check nginx config file:"
ls -la nginx.conf

echo ""
echo "📋 6. Test app container directly:"
docker-compose exec app curl -f http://localhost:8000/health || echo "App health check failed"

echo ""
echo "📋 7. Check environment file:"
ls -la .env

echo ""
echo "🔧 Quick fixes to try:"
echo "1. Create SSL directory: mkdir -p ssl"
echo "2. Temporarily disable SSL in nginx"
echo "3. Check .env file has all required variables"
echo "4. Restart specific services: docker-compose restart nginx"