#!/bin/bash

# Quick Setup Script for SilentCanary on EC2
# Run this script on a fresh Ubuntu 22.04 ARM64 instance

set -e

echo "🚀 SilentCanary Quick Setup Starting..."

# Check if running on ARM64
if [ "$(uname -m)" != "aarch64" ]; then
    echo "⚠️  Warning: This script is optimized for ARM64 (Graviton) instances"
fi

# Update system
echo "📦 Updating system..."
sudo apt-get update -y

# Install Docker
echo "🐳 Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
echo "🐳 Installing Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install other essentials
echo "📦 Installing essentials..."
sudo apt-get install -y git curl htop nginx certbot python3-certbot-nginx

# Create app directory
echo "📁 Creating application directory..."
sudo mkdir -p /opt/silentcanary
sudo chown $USER:$USER /opt/silentcanary

# Clone repository (you'll need to do this manually)
echo "📥 Ready to clone repository..."
echo "Next steps:"
echo "1. cd /opt/silentcanary"
echo "2. git clone https://github.com/tabibazar/silentcanary.git ."
echo "3. cp .env.template .env"
echo "4. nano .env  # Configure your environment"
echo "5. ./setup-ssl.sh  # Setup SSL certificates"
echo "6. docker-compose up -d  # Start services"

echo "✅ Quick setup completed!"
echo "💡 You may need to log out and back in for Docker permissions to take effect"