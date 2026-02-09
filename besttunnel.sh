#!/bin/bash

# ==========================================================
# Project: BestTunnel Pro (Multi-Port & Range Support)
# Developer: alirezalaleh2005
# ==========================================================

INTERFACE_NAME="besttunnel"
LOCAL_IP=$(hostname -I | awk '{print $1}')

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

show_logo() {
    clear
    echo -e "${CYAN}"
    echo "  ____  _____ ____ _____ _____ _   _ _   _ _   _ _____ _     "
    echo " | __ )| ____/ ___|_   _|_   _| | | | \ | | \ | | ____| |    "
    echo " |  _ \|  _| \___ \ | |   | | | | | |  \| |  \| |  _| | |    "
    echo " | |_) | |___ ___) || |   | | | |_| | |\  | |\  | |___| |___ "
    echo " |____/|_____|____/ |_|   |_|  \___/|_| \_|_| \_|_____|_____|"
    echo -e "             ${YELLOW}Multi-Port & Range Routing System${NC}"
    echo "------------------------------------------------------------"
}

# --- Intelligent Setup ---
setup_tunnel() {
    echo -e "${YELLOW}Tunnel Configuration...${NC}"
    echo "1) IRAN Server"
    echo "2) FOREIGN Server"
    read -p "Select role [1/2]: " ROLE
    read -p "Enter REMOTE Public IP: " REMOTE_IP

    if [ "$ROLE" == "1" ]; then
        L_TUN="10.0.0.1"; R_TUN="10.0.0.2"
    else
        L_TUN="10.0.0.2"; R_TUN="10.0.0.1"
    fi

    modprobe ip_gre
    ip link del "$INTERFACE_NAME" 2>/dev/null
    ip tunnel add "$INTERFACE_NAME" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set "$INTERFACE_NAME" up
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    if [ "$ROLE" == "2" ]; then
        iptables -t nat -A POSTROUTING -s 10.0.0.0/30 -o eth0 -j MASQUERADE
    fi
    echo -e "${GREEN}Tunnel Setup Completed.${NC}"
}

# --- Multi-Port & Range Routing ---
apply_advanced_routing() {
    echo -e "${PURPLE}Advanced Port Routing (Multi-Port Support)${NC}"
    echo -e "${CYAN}Examples: 443 | 80,443,8080 | 10000-20000${NC}"
    read -p "Enter ports/range: " USER_PORTS

    if [ -n "$USER_PORTS" ]; then
        # بهینه‌سازی MTU برای ضد فیلتر
        ip link set dev "$INTERFACE_NAME" mtu 1280
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200

        # ایجاد جدول روتینگ
        if ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then
            echo "100 tunnel" >> /etc/iproute2/rt_tables
        fi
        
        # پاکسازی رول‌های قدیمی برای جلوگیری از تداخل
        ip rule del fwmark 1 table tunnel 2>/dev/null
        iptables -t mangle -F PREROUTING

        # اعمال روتینگ پورت‌ها (پشتیبانی از کاما و خط تیره)
        iptables -t mangle -A PREROUTING -p tcp -m multiport --dports "$USER_PORTS" -j MARK --set-mark 1
        iptables -t mangle -A PREROUTING -p udp -m multiport --dports "$USER_PORTS" -j MARK --set-mark 1
        
        ip route replace default via 10.0.0.2 dev $INTERFACE_NAME table tunnel
        ip rule add fwmark 1 table tunnel
        iptables -t nat -A POSTROUTING -o $INTERFACE_NAME -j MASQUERADE
        
        echo -e "${GREEN}Successfully routed ports: $USER_PORTS${NC}"
    else
        echo -e "${RED}No ports entered!${NC}"
    fi
}

# --- Menu Logic ---
if [[ $EUID -ne 0 ]]; then echo -e "${RED}Run as root!${NC}"; exit 1; fi

while true; do
    show_logo
    ip link show "$INTERFACE_NAME" > /dev/null 2>&1 && status="${GREEN}ONLINE${NC}" || status="${RED}OFFLINE${NC}"
    echo -e "STATUS: $status | LOCAL IP: $LOCAL_IP"
    echo "------------------------------------------------------------"
    echo -e "1) 🛠️ Setup Tunnel (Iran/Foreign)"
    echo -e "2) 🛡️ Multi-Port Routing (Single, List, or Range)"
    echo -e "3) 🚀 Speed Boost (BBR)"
    echo -e "4) 📡 Ping Test"
    echo -e "5) 🧨 Reset All"
    echo -e "0) Exit"
    echo "------------------------------------------------------------"
    read -p "Select: " OPT

    case $OPT in
        1) setup_tunnel ;;
        2) apply_advanced_routing ;;
        3) 
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
            sysctl -p
            echo -e "${GREEN}BBR Activated.${NC}" ;;
        4) ping -c 4 10.0.0.2 ;;
        5) 
            ip link del "$INTERFACE_NAME" 2>/dev/null
            iptables -F && iptables -t nat -F && iptables -t mangle -F
            ip rule del fwmark 1 table tunnel 2>/dev/null
            echo "Reset Done." ;;
        0) exit 0 ;;
    esac
    read -p "Press Enter..."
done
