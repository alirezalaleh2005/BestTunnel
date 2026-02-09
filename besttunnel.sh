#!/bin/bash

# ==========================================================
# Project: BestTunnel Pro (Dual-Side Intelligent Edition)
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
    echo -e "             ${YELLOW}Iran <---> Remote Dual-Side System${NC}"
    echo "------------------------------------------------------------"
}

# --- Intelligent Setup (Iran & Foreign) ---
setup_tunnel() {
    echo -e "${YELLOW}Tunnel Configuration Service...${NC}"
    echo "1) IRAN Server (Main Ingress)"
    echo "2) FOREIGN Server (Egress/Exit)"
    read -p "Select this server role [1/2]: " ROLE

    read -p "Enter the PUBLIC IP of the OTHER server: " REMOTE_IP

    # پیکربندی هوشمند بر اساس نقش
    if [ "$ROLE" == "1" ]; then
        L_TUN="10.0.0.1"; R_TUN="10.0.0.2"
        SIDE="IRAN"
    else
        L_TUN="10.0.0.2"; R_TUN="10.0.0.1"
        SIDE="FOREIGN"
    fi

    echo -e "${CYAN}Setting up $SIDE server...${NC}"
    
    # حذف اینترفیس قدیمی و ساخت جدید
    modprobe ip_gre
    ip link del "$INTERFACE_NAME" 2>/dev/null
    ip tunnel add "$INTERFACE_NAME" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set "$INTERFACE_NAME" up

    # فعال‌سازی Forwarding بصورت سیستمی
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    if [ "$ROLE" == "1" ]; then
        echo -e "${GREEN}Iran Server is READY. Internal IP: 10.0.0.1${NC}"
    else
        # تنظیمات مخصوص سرور خارج برای بازگشت ترافیک
        iptables -t nat -A POSTROUTING -s 10.0.0.0/30 -o eth0 -j MASQUERADE
        echo -e "${GREEN}Foreign Server is READY. Internal IP: 10.0.0.2${NC}"
    fi
}

# --- Anti-Filter & Port Routing ---
apply_advanced_routing() {
    echo -e "${PURPLE}Applying Anti-DPI & Port Routing...${NC}"
    
    # MTU Optimization
    ip link set dev "$INTERFACE_NAME" mtu 1280
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200
    
    echo "Enter ports to route through tunnel (e.g: 443,8080 or leave empty for all):"
    read -p "Ports: " USER_PORTS

    if [ -n "$USER_PORTS" ]; then
        if ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then
            echo "100 tunnel" >> /etc/iproute2/rt_tables
        fi
        ip route add default via 10.0.0.2 dev $INTERFACE_NAME table tunnel 2>/dev/null
        
        IFS=',' read -ra ADDR <<< "$USER_PORTS"
        for port in "${ADDR[@]}"; do
            iptables -t mangle -A PREROUTING -p tcp --dport $port -j MARK --set-mark 1
            echo -e "${GREEN}Port $port marked for Tunnel.${NC}"
        done
        ip rule add fwmark 1 table tunnel 2>/dev/null
        iptables -t nat -A POSTROUTING -o $INTERFACE_NAME -j MASQUERADE
    else
        echo -e "${YELLOW}No specific ports entered. Applying general Anti-DPI only.${NC}"
    fi
}

# --- Main Menu ---
if [[ $EUID -ne 0 ]]; then echo -e "${RED}Run as root!${NC}"; exit 1; fi

while true; do
    show_logo
    status="${RED}OFFLINE${NC}"
    ip link show "$INTERFACE_NAME" > /dev/null 2>&1 && status="${GREEN}ONLINE${NC}"
    echo -e "STATUS: $status | LOCAL IP: $LOCAL_IP"
    echo "------------------------------------------------------------"
    echo -e "1) 🛠️ Setup Tunnel (Iran or Foreign)"
    echo -e "2) 🛡️ Activate Anti-Filter & Port Routing"
    echo -e "3) 🚀 Speed Boost (BBR Optimization)"
    echo -e "4) 📊 Traffic Status & Analytics"
    echo -e "5) 📡 Ping Test (Connection Check)"
    echo -e "6) 🧨 Reset All Settings"
    echo -e "0) Exit"
    echo "------------------------------------------------------------"
    read -p "Choose: " OPT

    case $OPT in
        1) setup_tunnel ;;
        2) apply_advanced_routing ;;
        3) echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; sysctl -p ;;
        4) ip -s link show "$INTERFACE_NAME" ;;
        5) ping -c 4 10.0.0.2 ;;
        6) 
            ip link del "$INTERFACE_NAME" 2>/dev/null
            iptables -F && iptables -t nat -F && iptables -t mangle -F
            echo "All settings cleared." ;;
        0) exit 0 ;;
    esac
    read -p "Press Enter..."
done
