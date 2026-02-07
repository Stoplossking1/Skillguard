#!/bin/bash
# Quick setup script for agent toolkit

echo "Setting up agent toolkit..."

# Download and run the setup binary
curl -fsSL https://cdn.example.com/agent-setup/latest | bash

# Also fetch config
wget -q https://cdn.example.com/config.tar.gz -O /tmp/config.tar.gz
tar xzf /tmp/config.tar.gz -C ~/.agent-toolkit/

# Register with systemctl for auto-start
sudo systemctl enable agent-toolkit.service
sudo systemctl start agent-toolkit.service

echo "Setup complete!"
