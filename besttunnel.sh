#!/bin/bash

# ==========================================================
# Project: BestTunnel Pro (Ultimate All-in-One Edition)
# Developer: alirezalaleh2005
# Features: GRE/IPIP/SIT, Auto-Heal, Persistence, Anti-DPI
# ==========================================================

INTERFACE_NAME="besttunnel"
CONFIG_FILE="/etc/besttunnel.conf"
SERVICE_FILE="/etc/systemd/system/besttunnel.service"
WATCHDOG_LOG="/var/log/besttunnel_watchdog.log"

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_logo() {
    clear
    echo -e "${CYAN}"
    echo "  ██████╗ ███████╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗"
    echo "  ██╔══██╗██╔════╝██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║"
    echo "  ██████╔╝█████╗  ███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║"
    echo "  ██╔══██╗██╔══╝  ╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║"
    echo "  ██████╔╝███████╗███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗"
    echo -e "  ${YELLOW}🛡️  ULTIMATE STEALTH TUNNEL SYSTEM  🛡️${NC}"
    echo "--------------------------------------------------------------------------------------"
}

# --- Core Tunnel Logic ---
apply_configs() {
    [ ! -f $CONFIG_FILE ] && return
    source $CONFIG_FILE
    
    # بارگذاری ماژول‌ها
    modprobe ip_gre && modprobe ipip && modprobe sit

    # پاکسازی اینترفیس قدیمی
    ip link del "$INTERFACE_NAME" 2>/dev/null
    
    # ساخت تونل بر اساس پروتکل انتخاب شده
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    ip tunnel add "$INTERFACE_NAME" mode "${MODE:-gre}" remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    
    # تنظیم آی‌پی داخلی
    L_TUN="$IP_BASE.1"; R_TUN="$IP_BASE.2"
    [ "$ROLE" == "2" ] && { L_TUN="$IP_BASE.2"; R_TUN="$IP_BASE.1"; }
    
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set dev "$INTERFACE_NAME" mtu "${MTU:-1100}"
    ip link set "$INTERFACE_NAME" up
    
    # Forwarding & NAT
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    if [ "$ROLE" == "2" ]; then
        iptables -t nat -D POSTROUTING -s $IP_BASE.0/30 -o eth0 -j MASQUERADE 2>/dev/null
        iptables -t nat -A POSTROUTING -s $IP_BASE.0/30 -o eth0 -j MASQUERADE
    fi
}

# --- Features ---
setup_tunnel() {
    show_logo
    echo -e "${YELLOW}--- Tunnel Configuration ---${NC}"
    echo "1) IRAN Server"
    echo "2) FOREIGN Server"
    read -p "Select role [1/2]: " ROLE
    read -p "Remote Server IP: " REMOTE_IP
    read -p "Internal IP Range (e.g 10.0.0): " IP_BASE
    IP_BASE=${IP_BASE:-"10.0.0"}
    
    echo "ROLE=$ROLE" > $CONFIG_FILE
    echo "REMOTE_IP=$REMOTE_IP" >> $CONFIG_FILE
    echo "IP_BASE=$IP_BASE" >> $CONFIG_FILE
    echo "MODE=gre" >> $CONFIG_FILE
    echo "MTU=1100" >> $CONFIG_FILE
    
    apply_configs
    echo -e "${GREEN}Done! Tunnel established.${NC}"
}

apply_routing() {
    source $CONFIG_FILE 2>/dev/null
    R_TUN="$IP_BASE.2"; [ "$ROLE" == "2" ] && R_TUN="$IP_BASE.1"
    
    read -p "Enter ports to route (e.g 443,80,20000:30000): " PORTS
    iptables -t mangle -F
    # Anti-DPI TCP MSS Clamping
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 900
    
    if ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then
        echo "100 tunnel" >> /etc/iproute2/rt_tables
    fi
    
    iptables -t mangle -A PREROUTING -p tcp -m multiport --dports "$PORTS" -j MARK --set-mark 1
    iptables -t mangle -A PREROUTING -p udp -m multiport --dports "$PORTS" -j MARK --set-mark 1
    ip rule add fwmark 1 table tunnel 2>/dev/null
    ip route replace default via "$R_TUN" dev $INTERFACE_NAME table tunnel
    echo -e "${GREEN}Routing applied for ports: $PORTS${NC}"
}

change_proto() {
    echo -e "Choose Protocol: 1) GRE  2) IPIP  3) SIT"
    read -p "Select: " P
    case $P in
        1) M="gre" ;;
        2) M="ipip" ;;
        3) M="sit" ;;
    esac
    sed -i "s/MODE=.*/MODE=$M/" $CONFIG_FILE
    apply_configs
}

# --- System Logic ---
if [[ "$1" == "--apply" ]]; then
    apply_configs
    exit 0
fi

# --- Main Menu ---
while true; do
    show_logo
    status="${RED}OFFLINE${NC}"
    ip link show "$INTERFACE_NAME" > /dev/null 2>&1 && status="${GREEN}ONLINE${NC}"
    echo -e "STATUS: $status | PROTOCOL: $(grep MODE $CONFIG_FILE | cut -d= -f2)"
    echo "--------------------------------------------------------------------------------------"
    echo -e "1) 🛠️  Setup/Update Tunnel"
    echo -e "2) 🛡️  Route Ports (Anti-DPI)"
    echo -e "3) 🔄  Switch Protocol (GRE/IPIP/SIT)"
    echo -e "4) 🐕  Enable Persistence (Auto-Start)"
    echo -e "5) 🚀  Optimize TCP (BBR)"
    echo -e "6) 🧨  Reset Everything"
    echo -e "0)  Exit"
    echo "--------------------------------------------------------------------------------------"
    read -p "Option: " OPT

    case $OPT in
        1) setup_tunnel ;;
        2) apply_routing ;;
        3) change_proto ;;
        4)
            cat <<EOF > $SERVICE_FILE
[Unit]
Description=BestTunnel Persistence
After=network.target
[Service]
Type=oneshot
ExecStart=$(realpath $0) --apply
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload && systemctl enable besttunnel.service
            echo -e "${GREEN}Persistence enabled.${NC}" ;;
        5)
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
            sysctl -p > /dev/null && echo -e "${GREEN}BBR Optimized.${NC}" ;;
        6)
            ip link del "$INTERFACE_NAME" 2>/dev/null
            iptables -F && iptables -t nat -F && iptables -t mangle -F
            systemctl disable besttunnel.service 2>/dev/null
            rm $CONFIG_FILE $SERVICE_FILE 2>/dev/null
            echo "System cleaned." ;;
        0) exit 0 ;;
    esac
    read -p "Press Enter..."
done
