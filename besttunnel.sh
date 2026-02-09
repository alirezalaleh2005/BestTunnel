#!/bin/bash

# ==========================================================
# Project: BestTunnel Pro (Ultra Port-Routing Edition)
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

# --- Logo ---
show_logo() {
    clear
    echo -e "${CYAN}"
    echo "  ____  _____ ____ _____ _____ _   _ _   _ _   _ _____ _     "
    echo " | __ )| ____/ ___|_   _|_   _| | | | \ | | \ | | ____| |    "
    echo " |  _ \|  _| \___ \ | |   | | | | | |  \| |  \| |  _| | |    "
    echo " | |_) | |___ ___) || |   | | | |_| | |\  | |\  | |___| |___ "
    echo " |____/|_____|____/ |_|   |_|  \___/|_| \_|_| \_|_____|_____|"
    echo -e "             ${YELLOW}Advanced Multi-Port Tunneling System${NC}"
    echo "------------------------------------------------------------"
}

# --- 1. Setup GRE Core ---
setup_gre() {
    echo -e "${YELLOW}Setting up GRE Tunnel...${NC}"
    read -p "Enter Remote Server Public IP: " REMOTE_IP
    read -p "Is this Server 1 (Iran) or 2 (Foreign)? [1/2]: " ROLE
    
    L_TUN="10.0.0.1"; R_TUN="10.0.0.2"
    [[ "$ROLE" == "2" ]] && { L_TUN="10.0.0.2"; R_TUN="10.0.0.1"; }

    modprobe ip_gre
    ip link del "$INTERFACE_NAME" 2>/dev/null
    ip tunnel add "$INTERFACE_NAME" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set "$INTERFACE_NAME" up
    
    # Enable IP Forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
    echo -e "${GREEN}GRE Interface Established ($L_TUN -> $R_TUN).${NC}"
}

# --- 2. Anti-DPI & MTU Shield ---
apply_shields() {
    echo -e "${PURPLE}Applying Anti-Filter & MTU Optimization...${NC}"
    # تنظیم MTU بهینه برای عبور از فیلترینگ هوشمند ایران
    ip link set dev "$INTERFACE_NAME" mtu 1280
    # کلمپ کردن MSS برای جلوگیری از دراپ شدن بسته‌های TCP
    iptables -t mangle -F FORWARD
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200
    echo -e "${GREEN}Anti-DPI Shield Active (MTU 1280).${NC}"
}

# --- 3. Port Specific Routing (NEW) ---
route_ports() {
    echo -e "${CYAN}--- Port Specific Routing ---${NC}"
    echo "Enter the ports you want to send through tunnel (comma separated, e.g: 80,443,2082)"
    read -p "Ports: " USER_PORTS
    
    # ایجاد جدول مسیریابی مخصوص تانل
    if ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then
        echo "100 tunnel" >> /etc/iproute2/rt_tables
    fi

    # پاکسازی قوانین قدیمی
    ip rule del fwmark 1 table tunnel 2>/dev/null
    ip route flush table tunnel 2>/dev/null
    
    # هدایت ترافیک جدول به سمت آی‌پی تانل (سرور مقابل)
    ip route add default via 10.0.0.2 dev $INTERFACE_NAME table tunnel

    # تبدیل کاما به پورت‌های جداگانه و اعمال در iptables
    IFS=',' read -ra ADDR <<< "$USER_PORTS"
    for port in "${ADDR[@]}"; do
        iptables -t mangle -A PREROUTING -p tcp --dport $port -j MARK --set-mark 1
        iptables -t mangle -A PREROUTING -p udp --dport $port -j MARK --set-mark 1
        echo -e "${GREEN}Port $port is now marked for Tunnel.${NC}"
    done

    # فعال سازی قانون مسیریابی برای مارک 1
    ip rule add fwmark 1 table tunnel
    
    # NAT برای خروج ترافیک از تانل
    iptables -t nat -A POSTROUTING -o $INTERFACE_NAME -j MASQUERADE
    
    echo -e "${YELLOW}Routing applied successfully!${NC}"
}

# --- 4. BBR Speed Boost ---
enable_bbr() {
    echo -e "${CYAN}Optimizing Network Speed (BBR)...${NC}"
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
    fi
    echo -e "${GREEN}BBR Speed Boost is now Active.${NC}"
}

# --- 5. Reset & Clear ---
reset_all() {
    echo -e "${RED}Clearing all tunnel rules and interfaces...${NC}"
    ip link del "$INTERFACE_NAME" 2>/dev/null
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    ip rule del fwmark 1 table tunnel 2>/dev/null
    echo -e "${GREEN}System Reset Done.${NC}"
}

# --- Main Menu ---
if [[ $EUID -ne 0 ]]; then echo -e "${RED}Run as root!${NC}"; exit 1; fi

while true; do
    show_logo
    status="${RED}OFFLINE${NC}"
    ip link show "$INTERFACE_NAME" > /dev/null 2>&1 && status="${GREEN}ONLINE${NC}"
    echo -e "STATUS: $status | LOCAL IP: $LOCAL_IP"
    echo "------------------------------------------------------------"
    echo -e "1) ${GREEN}[CORE]${NC} Setup GRE Tunnel"
    echo -e "2) ${PURPLE}[SHIELD]${NC} Activate Anti-Filter (MTU/MSS)"
    echo -e "3) ${YELLOW}[ROUTE]${NC} Pass Specific Ports through Tunnel"
    echo -e "4) ${CYAN}[SPEED]${NC} Enable BBR Speed Engine"
    echo -e "5) ${GREEN}[TEST]${NC} Ping Test (10.0.0.2)"
    echo -e "6) ${RED}[RESET]${NC} Clear Everything"
    echo -e "0) Exit"
    echo "------------------------------------------------------------"
    read -p "Select Option: " OPT

    case $OPT in
        1) setup_gre ;;
        2) apply_shields ;;
        3) route_ports ;;
        4) enable_bbr ;;
        5) ping -c 4 10.0.0.2 ;;
        6) reset_all ;;
        0) exit 0 ;;
        *) echo "Invalid choice." ;;
    esac
    read -p "Press Enter to continue..."
done
