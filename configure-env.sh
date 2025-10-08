#!/bin/bash

# Environment Configuration Script for SilentCanary

echo "🔧 Configuring SilentCanary environment..."

# Check if .env.template exists
if [ ! -f ".env.template" ]; then
    echo "❌ .env.template not found. Creating one..."

    cat > .env.template << 'EOF'
# SilentCanary Environment Configuration Template
FLASK_ENV=production
FLASK_APP=app.py
SECRET_KEY=your_super_secret_key_here

# AWS Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=ca-central-1

# Stripe Configuration
STRIPE_PUBLISHABLE_KEY=pk_live_your_publishable_key
STRIPE_SECRET_KEY=sk_live_your_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# SendGrid Configuration
SENDGRID_API_KEY=SG.your_sendgrid_key
FROM_EMAIL=noreply@silentcanary.com

# reCAPTCHA Configuration
RECAPTCHA_SITE_KEY=your_site_key
RECAPTCHA_SECRET_KEY=your_secret_key

# Redis Configuration
REDIS_URL=redis://redis:6379/0

# Application Configuration
BASE_URL=https://silentcanary.com
ANTHROPIC_API_KEY=your_anthropic_key
EOF
fi

# Copy template to .env if it doesn't exist
if [ ! -f ".env" ]; then
    cp .env.template .env
    echo "✅ Created .env from template"
else
    echo "✅ .env already exists"
fi

# Generate a secure secret key
echo "🔑 Generating secure secret key..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sed -i "s/your_super_secret_key_here/$SECRET_KEY/" .env

echo "✅ Environment configuration completed!"
echo ""
echo "📝 Next steps:"
echo "1. Edit .env file: nano .env"
echo "2. Add your API keys:"
echo "   - AWS credentials"
echo "   - Stripe keys"
echo "   - SendGrid API key"
echo "   - reCAPTCHA keys"
echo "3. Start services: docker-compose up -d"