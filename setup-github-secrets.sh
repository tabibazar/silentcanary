#!/bin/bash

# Script to set up GitHub secrets from .env file
# This script uses the GitHub CLI (gh) to add secrets to your repository

set -e

echo "🔐 Setting up GitHub Secrets for SilentCanary deployment"
echo "========================================================="
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed"
    echo ""
    echo "Install it with:"
    echo "  macOS: brew install gh"
    echo "  Linux: https://github.com/cli/cli/blob/trunk/docs/install_linux.md"
    echo ""
    exit 1
fi

# Check if gh is authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ GitHub CLI is not authenticated"
    echo ""
    echo "Please authenticate with:"
    echo "  gh auth login"
    echo ""
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found in current directory"
    exit 1
fi

echo "✅ GitHub CLI is authenticated"
echo "✅ .env file found"
echo ""

# Load .env file
source .env

echo "📋 The following secrets will be configured:"
echo ""
echo "AWS Credentials:"
echo "  - AWS_ACCESS_KEY_ID"
echo "  - AWS_SECRET_ACCESS_KEY"
echo ""
echo "reCAPTCHA Credentials:"
echo "  - RECAPTCHA_SITE_KEY"
echo "  - RECAPTCHA_SECRET_KEY"
echo ""
echo "Stripe Credentials:"
echo "  - STRIPE_SECRET_KEY"
echo "  - STRIPE_PUBLISHABLE_KEY"
echo "  - STRIPE_WEBHOOK_SECRET"
echo ""
echo "Stripe Price IDs:"
echo "  - STRIPE_STARTUP_MONTHLY_PRICE_ID"
echo "  - STRIPE_STARTUP_ANNUAL_PRICE_ID"
echo "  - STRIPE_GROWTH_MONTHLY_PRICE_ID"
echo "  - STRIPE_GROWTH_ANNUAL_PRICE_ID"
echo "  - STRIPE_ENTERPRISE_MONTHLY_PRICE_ID"
echo "  - STRIPE_ENTERPRISE_ANNUAL_PRICE_ID"
echo ""
echo "SSH Key:"
echo "  - EC2_SSH_KEY (you'll need to provide this)"
echo ""

read -p "Continue? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "🔧 Setting GitHub secrets..."
echo ""

# Function to set a secret
set_secret() {
    local secret_name=$1
    local secret_value=$2

    if [ -z "$secret_value" ]; then
        echo "⚠️  Skipping $secret_name (not set in .env)"
        return
    fi

    echo "Setting $secret_name..."
    echo "$secret_value" | gh secret set "$secret_name"

    if [ $? -eq 0 ]; then
        echo "✅ $secret_name set successfully"
    else
        echo "❌ Failed to set $secret_name"
    fi
}

# Set AWS credentials
set_secret "AWS_ACCESS_KEY_ID" "$AWS_ACCESS_KEY_ID"
set_secret "AWS_SECRET_ACCESS_KEY" "$AWS_SECRET_ACCESS_KEY"

# Set reCAPTCHA credentials
set_secret "RECAPTCHA_SITE_KEY" "$RECAPTCHA_SITE_KEY"
set_secret "RECAPTCHA_SECRET_KEY" "$RECAPTCHA_SECRET_KEY"

# Set Stripe credentials
set_secret "STRIPE_SECRET_KEY" "$STRIPE_SECRET_KEY"
set_secret "STRIPE_PUBLISHABLE_KEY" "$STRIPE_PUBLISHABLE_KEY"
set_secret "STRIPE_WEBHOOK_SECRET" "$STRIPE_WEBHOOK_SECRET"

# Set Stripe price IDs
set_secret "STRIPE_STARTUP_MONTHLY_PRICE_ID" "$STRIPE_STARTUP_MONTHLY_PRICE_ID"
set_secret "STRIPE_STARTUP_ANNUAL_PRICE_ID" "$STRIPE_STARTUP_ANNUAL_PRICE_ID"
set_secret "STRIPE_GROWTH_MONTHLY_PRICE_ID" "$STRIPE_GROWTH_MONTHLY_PRICE_ID"
set_secret "STRIPE_GROWTH_ANNUAL_PRICE_ID" "$STRIPE_GROWTH_ANNUAL_PRICE_ID"
set_secret "STRIPE_ENTERPRISE_MONTHLY_PRICE_ID" "$STRIPE_ENTERPRISE_MONTHLY_PRICE_ID"
set_secret "STRIPE_ENTERPRISE_ANNUAL_PRICE_ID" "$STRIPE_ENTERPRISE_ANNUAL_PRICE_ID"

echo ""
echo "🔑 Setting up EC2_SSH_KEY..."
echo ""
echo "You need to provide your EC2 SSH private key for deployment."
echo "This is typically located at ~/.ssh/id_rsa or ~/.ssh/id_ed25519"
echo ""

# Common SSH key locations
SSH_KEY_PATHS=(
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/id_ed25519"
    "$HOME/.ssh/silentcanary"
    "$HOME/.ssh/ec2-key.pem"
)

SSH_KEY_FOUND=""
for key_path in "${SSH_KEY_PATHS[@]}"; do
    if [ -f "$key_path" ]; then
        echo "Found SSH key at: $key_path"
        read -p "Use this key? (y/n) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            SSH_KEY_FOUND="$key_path"
            break
        fi
    fi
done

if [ -z "$SSH_KEY_FOUND" ]; then
    read -p "Enter the path to your EC2 SSH private key: " SSH_KEY_PATH
    if [ ! -f "$SSH_KEY_PATH" ]; then
        echo "❌ SSH key file not found at: $SSH_KEY_PATH"
        echo "⚠️  You'll need to set EC2_SSH_KEY manually with:"
        echo "    gh secret set EC2_SSH_KEY < /path/to/your/key"
    else
        SSH_KEY_FOUND="$SSH_KEY_PATH"
    fi
fi

if [ -n "$SSH_KEY_FOUND" ]; then
    echo "Setting EC2_SSH_KEY..."
    gh secret set EC2_SSH_KEY < "$SSH_KEY_FOUND"
    if [ $? -eq 0 ]; then
        echo "✅ EC2_SSH_KEY set successfully"
    else
        echo "❌ Failed to set EC2_SSH_KEY"
    fi
fi

echo ""
echo "========================================================="
echo "🎉 GitHub secrets configuration complete!"
echo ""
echo "You can verify the secrets with:"
echo "  gh secret list"
echo ""
echo "To trigger a deployment, you can:"
echo "1. Push changes to main branch (automatic deployment)"
echo "2. Manually trigger deployment:"
echo "   gh workflow run deploy.yml"
echo ""
echo "To check deployment status:"
echo "  gh run list --workflow=deploy.yml"
echo ""
