#!/bin/bash

# Complete SilentCanary Deployment Script for EC2
# This script does everything needed to deploy SilentCanary

set -e

echo "🚀 SilentCanary Complete Deployment Starting..."
echo "Server: $(hostname -I | awk '{print $1}')"
echo "Time: $(date)"
echo "============================================"

# Update system
echo "📦 Step 1: Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install Docker
echo "🐳 Step 2: Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    echo "✅ Docker installed successfully"
else
    echo "✅ Docker already installed"
fi

# Install Docker Compose
echo "🐳 Step 3: Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo "✅ Docker Compose installed successfully"
else
    echo "✅ Docker Compose already installed"
fi

# Install essential packages
echo "📦 Step 4: Installing essential packages..."
sudo apt-get install -y \
    git \
    curl \
    htop \
    nginx \
    certbot \
    python3-certbot-nginx \
    unzip \
    jq \
    python3-pip

# Install AWS CLI (ARM64 compatible)
echo "☁️ Installing AWS CLI..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
if [ -f "awscliv2.zip" ]; then
    unzip -q awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
    echo "✅ AWS CLI installed successfully"
else
    echo "⚠️ Official installer failed, using system package..."
    sudo apt-get install -y python3-boto3
fi

# Clone repository
echo "📥 Step 5: Cloning SilentCanary repository..."
if [ ! -d "silentcanary" ]; then
    git clone https://github.com/tabibazar/silentcanary.git
    echo "✅ Repository cloned successfully"
else
    echo "✅ Repository already exists, pulling latest changes..."
    cd silentcanary && git pull && cd ..
fi

cd silentcanary

# Make scripts executable
chmod +x *.sh

# Create environment file from template
echo "⚙️ Step 6: Setting up environment configuration..."
if [ ! -f ".env" ]; then
    cp .env.template .env
    echo "✅ Environment file created from template"
else
    echo "✅ Environment file already exists"
fi

# Create necessary directories
echo "📁 Step 7: Creating application directories..."
sudo mkdir -p /opt/silentcanary/logs
sudo mkdir -p /opt/silentcanary/ssl
sudo mkdir -p /var/www/certbot
sudo chown -R $USER:$USER /opt/silentcanary

# Copy application to /opt
echo "📋 Step 8: Setting up application in /opt/silentcanary..."
sudo cp -r . /opt/silentcanary/
sudo chown -R $USER:$USER /opt/silentcanary

# Setup systemd service
echo "🔧 Step 9: Setting up systemd service..."
if [ -f "systemd/silentcanary.service" ]; then
    sudo cp systemd/silentcanary.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable silentcanary
    echo "✅ Systemd service configured"
fi

# Check if running in new shell session for Docker permissions
echo "🔍 Step 10: Checking Docker permissions..."
if groups $USER | grep &>/dev/null '\bdocker\b'; then
    echo "✅ User already in docker group"
else
    echo "⚠️  User added to docker group. You may need to log out and back in."
fi

echo ""
echo "============================================"
echo "🎉 DEPLOYMENT COMPLETED SUCCESSFULLY!"
echo "============================================"
echo ""
echo "📋 NEXT STEPS:"
echo "1. Configure environment variables:"
echo "   cd /opt/silentcanary"
echo "   nano .env"
echo ""
echo "2. Start the application:"
echo "   docker-compose up -d"
echo ""
echo "3. Check status:"
echo "   docker-compose ps"
echo ""
echo "4. View logs:"
echo "   docker-compose logs -f"
echo ""
echo "5. Setup SSL (optional):"
echo "   ./setup-ssl.sh"
echo ""
echo "🌐 Your server IP: $(curl -s ifconfig.me || echo 'Unable to detect')"
echo ""
echo "⚠️  IMPORTANT: Configure the .env file before starting services!"
echo "============================================"