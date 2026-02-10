#!/bin/bash

# ==========================================================
# File: install.sh
# Description: Installer for BestTunnel Manager
# ==========================================================

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "Error: Please run as root (sudo ./install.sh)"
   exit 1
fi

echo ">>> Starting Installation of BestTunnel Manager..."

# 1. Install necessary packages
echo ">>> Installing Nginx and dependencies..."
apt update
apt install -y nginx nginx-mod-stream openssl net-tools bc

# 2. Create required directories
echo ">>> Creating directories..."
mkdir -p /etc/nginx/certs
touch /etc/nginx/tunnel_db.txt

# 3. Download/Create the main script (besttunnel.sh)
# Note: This part assumes the besttunnel.sh is in the same folder.
# We move it to /usr/local/bin so it can be run from anywhere.

if [ -f "besttunnel.sh" ]; then
    cp besttunnel.sh /usr/local/bin/besttunnel
    chmod +x /usr/local/bin/besttunnel
    echo "✅ BestTunnel script installed to /usr/local/bin/besttunnel"
else
    echo "❌ Error: besttunnel.sh not found in the current directory!"
    exit 1
fi

# 4. Enable Nginx service
echo ">>> Enabling Nginx service..."
systemctl enable nginx
systemctl start nginx

echo "------------------------------------------------"
echo "✅ INSTALLATION COMPLETE!"
echo "🚀 You can now run the manager by typing: besttunnel"
echo "------------------------------------------------"
