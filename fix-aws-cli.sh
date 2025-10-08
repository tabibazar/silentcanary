#!/bin/bash

# Fix AWS CLI installation on ARM64

echo "🔧 Installing AWS CLI for ARM64..."

# Method 1: Try official AWS installer
echo "📥 Trying official AWS CLI installer..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
if [ -f "awscliv2.zip" ]; then
    sudo apt-get install -y unzip
    unzip -q awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
    echo "✅ AWS CLI installed via official installer"
else
    echo "📦 Official installer failed, trying pipx..."
    # Method 2: Use pipx (safer than pip)
    sudo apt-get update
    sudo apt-get install -y pipx
    pipx install awscli
    pipx ensurepath

    # Add to current session PATH
    export PATH="$HOME/.local/bin:$PATH"
    echo "✅ AWS CLI installed via pipx"
fi

# Test installation
echo "🧪 Testing AWS CLI installation..."
if command -v aws &> /dev/null; then
    aws --version
    echo "✅ AWS CLI is working!"
else
    echo "❌ AWS CLI installation failed"
    echo "You can install manually with: sudo apt-get install -y awscli"
fi