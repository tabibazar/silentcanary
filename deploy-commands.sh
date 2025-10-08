#!/bin/bash

# Complete deployment commands for SilentCanary on EC2
# Copy and paste these commands one by one on your EC2 instance

echo "🚀 Starting SilentCanary deployment on 15.223.77.246..."

# Update system and install Docker
sudo apt-get update -y
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install essentials
sudo apt-get install -y git curl htop nginx certbot python3-certbot-nginx

# Clone repository
git clone https://github.com/tabibazar/silentcanary.git
cd silentcanary

# Make scripts executable
chmod +x *.sh

echo "✅ Basic setup complete!"
echo "Next: Configure .env file and start services"