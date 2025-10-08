#!/bin/bash

# Fix AWS CLI installation on ARM64

echo "🔧 Installing AWS CLI for ARM64..."

# Install pip if not available
sudo apt-get update
sudo apt-get install -y python3-pip

# Install AWS CLI via pip
pip3 install --user awscli

# Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Source for current session
export PATH="$HOME/.local/bin:$PATH"

# Test installation
if aws --version; then
    echo "✅ AWS CLI installed successfully"
else
    echo "❌ AWS CLI installation failed"
fi