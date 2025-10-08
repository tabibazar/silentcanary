#!/bin/bash

# Environment Setup Script for SilentCanary EC2 Deployment

set -e

APP_DIR="/opt/silentcanary"

echo "🔧 Setting up SilentCanary environment..."

# Create environment file template
cat > $APP_DIR/.env.template << 'EOF'
# Flask Configuration
FLASK_ENV=production
FLASK_APP=app.py
SECRET_KEY=your_secret_key_here

# Database Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=ca-central-1

# Stripe Configuration
STRIPE_PUBLISHABLE_KEY=pk_live_your_stripe_publishable_key
STRIPE_SECRET_KEY=sk_live_your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# SendGrid Configuration
SENDGRID_API_KEY=SG.your_sendgrid_api_key
FROM_EMAIL=noreply@silentcanary.com

# reCAPTCHA Configuration
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key

# Redis Configuration
REDIS_URL=redis://redis:6379/0

# Application URLs
BASE_URL=https://silentcanary.com

# Subscription Plan Pricing (Stripe Price IDs)
STRIPE_STARTUP_MONTHLY_PRICE_ID=price_startup_monthly
STRIPE_STARTUP_ANNUAL_PRICE_ID=price_startup_annual
STRIPE_GROWTH_MONTHLY_PRICE_ID=price_growth_monthly
STRIPE_GROWTH_ANNUAL_PRICE_ID=price_growth_annual
STRIPE_ENTERPRISE_MONTHLY_PRICE_ID=price_enterprise_monthly
STRIPE_ENTERPRISE_ANNUAL_PRICE_ID=price_enterprise_annual

# Anthropic AI Configuration
ANTHROPIC_API_KEY=your_anthropic_api_key
EOF

echo "📝 Created environment template at $APP_DIR/.env.template"
echo "Please copy this to .env and fill in your actual values:"
echo "cp $APP_DIR/.env.template $APP_DIR/.env"
echo "nano $APP_DIR/.env"

# Set up SSL certificate directories
sudo mkdir -p $APP_DIR/ssl
sudo chown silentcanary:silentcanary $APP_DIR/ssl

# Set up log directories
sudo mkdir -p $APP_DIR/logs
sudo chown silentcanary:silentcanary $APP_DIR/logs

# Install Docker Compose
echo "🐳 Installing Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Docker
echo "🐳 Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker silentcanary

# Copy systemd service
echo "🔧 Setting up systemd service..."
sudo cp $APP_DIR/app/systemd/silentcanary.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable silentcanary

echo "✅ Environment setup completed!"
echo ""
echo "Next steps:"
echo "1. Configure .env file with your credentials"
echo "2. Set up SSL certificates: ./setup-ssl.sh"
echo "3. Start the application: sudo systemctl start silentcanary"
echo "4. Check status: sudo systemctl status silentcanary"