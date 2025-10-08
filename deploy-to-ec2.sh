#!/bin/bash

# SilentCanary EC2 Graviton Deployment Script
# This script sets up the application on a single AWS Graviton instance

set -e

# Configuration
APP_DIR="/opt/silentcanary"
APP_USER="silentcanary"
PYTHON_VERSION="3.9"

echo "🚀 Starting SilentCanary deployment on EC2 Graviton instance..."

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required packages
echo "📦 Installing required packages..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    redis-server \
    supervisor \
    git \
    curl \
    unzip \
    htop \
    certbot \
    python3-certbot-nginx

# Create application user
echo "👤 Creating application user..."
if ! id "$APP_USER" &>/dev/null; then
    sudo useradd -m -s /bin/bash $APP_USER
    sudo usermod -aG sudo $APP_USER
fi

# Create application directory
echo "📁 Setting up application directory..."
sudo mkdir -p $APP_DIR
sudo chown $APP_USER:$APP_USER $APP_DIR

# Clone or copy application code
echo "📥 Setting up application code..."
sudo -u $APP_USER git clone https://github.com/tabibazar/silentcanary.git $APP_DIR/app || \
    (cd $APP_DIR/app && sudo -u $APP_USER git pull)

# Set up Python virtual environment
echo "🐍 Setting up Python virtual environment..."
sudo -u $APP_USER python3 -m venv $APP_DIR/venv
sudo -u $APP_USER $APP_DIR/venv/bin/pip install --upgrade pip

# Install Python dependencies
echo "📦 Installing Python dependencies..."
sudo -u $APP_USER $APP_DIR/venv/bin/pip install -r $APP_DIR/app/requirements.txt

# Install additional production packages
sudo -u $APP_USER $APP_DIR/venv/bin/pip install gunicorn gevent

echo "✅ SilentCanary deployment setup completed!"
echo "Next steps:"
echo "1. Configure environment variables"
echo "2. Set up SSL certificates"
echo "3. Start services"