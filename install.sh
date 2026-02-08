#!/bin/bash

# BestTunnel Quick Installer
REPO_URL="https://raw.githubusercontent.com/alirezalaleh2005/BestTunnel/main/besttunnel.sh"
INSTALL_PATH="/usr/local/bin/besttunnel"

echo "Installing BestTunnel Pro..."

# دانلود اسکریپت اصلی
curl -sL $REPO_URL -o $INSTALL_PATH

# اجازه دسترسی اجرا
chmod +x $INSTALL_PATH

echo -e "\nInstallation Complete!"
echo -e "You can now run the panel by typing: sudo besttunnel"
