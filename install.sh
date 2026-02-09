#!/bin/bash

# --- Colors ---
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Installing BestTunnel Ultimate Edition...${NC}"

# ۱. نصب پیش‌نیازها
echo -e "Installing dependencies..."
apt-get update -y && apt-get install -y curl iproute2 iptables dnsutils ifstat > /dev/null 2>&1

# ۲. دانلود اسکریپت اصلی از گیت‌هاب شما
# نکته: در لینک زیر به جای USERNAME و REPO، نام کاربری و نام مخزن خود را قرار دهید
REPO_URL="https://raw.githubusercontent.com/alirezalaleh2005/BestTunnel/main/besttunnel.sh"
DEST="/usr/local/bin/besttunnel"

curl -Ls $REPO_URL -o $DEST

if [ $? -eq 0 ]; then
    chmod +x $DEST
    # ایجاد میانبر برای اجرای راحت با تایپ کلمه besttunnel
    ln -s /usr/local/bin/besttunnel /usr/bin/besttunnel 2>/dev/null
    
    echo -e "${GREEN}Installation Complete!${NC}"
    echo -e "You can now run the script by typing: ${BLUE}besttunnel${NC}"
else
    echo -e "${RED}Error: Failed to download the script. Please check your internet connection.${NC}"
    exit 1
fi
