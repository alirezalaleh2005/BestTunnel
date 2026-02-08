#!/bin/bash

# ==========================================================
# Project: BestTunnel Pro (Ironclad Edition)
# Description: High-Performance GRE Tunnel with Anti-DPI
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

# --- Header / Logo ---
show_logo() {
    clear
    echo -e "${CYAN}"
    echo "  ____  _____ ____ _____ _____ _   _ _   _ _   _ _____ _     "
    echo " | __ )| ____/ ___|_   _|_   _| | | | \ | | \ | | ____| |    "
    echo " |  _ \|  _| \___ \ | |   | | | | | |  \| |  \| |  _| | |    "
    echo " | |_) | |___ ___) || |   | | | |_| | |\  | |\  | |___| |___ "
    echo " |____/|_____|____/ |_|   |_|  \___/|_| \_|_| \_|_____|_____|"
    echo -e "             ${YELLOW}Heavy Filtering Defense System${NC}"
    echo "------------------------------------------------------------"
}

# --- 1. GRE Core ---
setup_gre() {
    read -p "Enter Remote Server Public IP: " REMOTE_IP
    read -p "Is this Server 1 (Iran) or 2 (Foreign)? [1/2]: " ROLE
    
    L_TUN="10.0.0.1"; R_TUN="10.0.0.2"
    [[ "$ROLE" == "2" ]] && { L_TUN="10.0.0.2"; R_TUN="10.0.0.1"; }

    echo -e "${YELLOW}Creating GRE Tunnel...${NC}"
    modprobe ip_gre
    ip link del "$INTERFACE_NAME" 2>/dev/null
    ip tunnel add "$INTERFACE_NAME" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set "$INTERFACE_NAME" up
    echo -e "${GREEN}GRE Interface Created Successfully.${NC}"
}

# --- 2. Ultra Anti-Filter Shield ---
apply_anti_filter() {
    echo -e "${PURPLE}Applying Anti-DPI & Stealth Shields...${NC}"
    # Optimized MTU for Iran Infrastructure
    ip link set dev "$INTERFACE_NAME" mtu 1280
    # TCPMSS Clamping to prevent packet drops
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200
    # ICMP Stealth
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
    echo -e "${GREEN}Shields are UP! (MTU 1280 / MSS 1200)${NC}"
}

# --- 3. Hyper Speed (BBR) ---
enable_bbr() {
    echo -e "${CYAN}Activating BBR Speed Engine...${NC}"
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
    fi
    echo -e "${GREEN}BBR is active. Speed optimized.${NC}"
}

# --- 4. Persistence ---
enable_persistence() {
    echo -e "${YELLOW}Setting up Auto-Start Service...${NC}"
    SCRIPT_PATH=$(readlink -f "$0")
    cat <<EOF > /etc/systemd/system/besttunnel.service
[Unit]
Description=BestTunnel Persistence Service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/bash $SCRIPT_PATH 1
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable besttunnel.service > /dev/null 2>&1
    echo -e "${GREEN}Persistence enabled for reboots.${NC}"
}

# --- 5. Traffic Analytics ---
show_analytics() {
    echo -e "${YELLOW}--- Traffic Analytics ---${NC}"
    if ip link show "$INTERFACE_NAME" > /dev/null 2>&1; then
        RX=$(ip -s link show "$INTERFACE_NAME" | grep -A 1 "RX" | tail -n 1 | awk '{print $1}')
        TX=$(ip -s link show "$INTERFACE_NAME" | grep -A 1 "TX" | tail -n 1 | awk '{print $1}')
        echo -e "Download: $(($RX/1024/1024)) MB"
        echo -e "Upload: $(($TX/1024/1024)) MB"
    else
        echo -e "${RED}Tunnel is Offline.${NC}"
    fi
}

# --- Main Logic ---
if [[ $EUID -ne 0 ]]; then echo -e "${RED}Please run as root!${NC}"; exit 1; fi

while true; do
    show_logo
    status="${RED}OFFLINE${NC}"
    ip link show "$INTERFACE_NAME" > /dev/null 2>&1 && status="${GREEN}ONLINE${NC}"
    echo -e "STATUS: $status | LOCAL IP: $LOCAL_IP"
    echo "------------------------------------------------------------"
    echo -e "1) ${GREEN}[CORE]${NC} Setup GRE Tunnel"
    echo -e "2) ${PURPLE}[SHIELD]${NC} Activate Anti-Filter (DPI Bypass)"
    echo -e "3) ${CYAN}[SPEED]${NC} Boost Speed (BBR/Forwarding)"
    echo -e "4) ${YELLOW}[STABLE]${NC} Enable Auto-Start (Persistence)"
    echo -e "5) ${CYAN}[REPORT]${NC} Traffic Analytics & Stats"
    echo -e "6) ${GREEN}[TEST]${NC} Ping Test"
    echo -e "0) ${RED}[EXIT]${NC}"
    echo "------------------------------------------------------------"
    read -p "Choose an option: " OPT

    case $OPT in
        1) setup_gre ;;
        2) apply_anti_filter ;;
        3) enable_bbr; sysctl -w net.ipv4.ip_forward=1 ;;
        4) enable_persistence ;;
        5) show_analytics ;;
        6) ping -c 4 10.0.0.2 ;;
        0) exit 0 ;;
        *) echo "Invalid option." ;;
    esac
    read -p "Press Enter to return..."
done
