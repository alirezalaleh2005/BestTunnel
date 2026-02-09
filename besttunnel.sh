#!/bin/bash

# ==============================================================================
# Project: BestTunnel Ultimate Edition (Rathole Support)
# Version: 8.5
# Developer: alirezalaleh2005
# Features: GRE/IPIP/SIT, Rathole, Auto-Fix, Speedtest, BBR
# ==============================================================================

# --- Global Variables ---
INTERFACE_NAME="besttunnel"
CONFIG_FILE="/etc/besttunnel.conf"
RATHOLE_CONFIG="/etc/rathole.toml"
RATHOLE_SERVICE="/etc/systemd/system/rathole.service"
RATHOLE_BIN="/usr/local/bin/rathole"

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# --- Check Root ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Run as root!${NC}"
   exit 1
fi

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ██████╗ ███████╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗"
    echo "  ██╔══██╗██╔════╝██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝"
    echo "  ██████╔╝█████╗  ███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  "
    echo "  ██╔══██╗██╔══╝  ╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  "
    echo "  ██████╔╝███████╗███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗"
    echo -e "  ${YELLOW}🛡️  BESTTUNNEL PRO v8.5 (RATHOLE EDITION)  🛡️${NC}"
    echo "--------------------------------------------------------------------------------------"
}

# --- Rathole Logic ---
install_rathole() {
    echo -e "${YELLOW}>>> Installing/Updating Rathole...${NC}"
    apt-get update -qq && apt-get install -y unzip wget > /dev/null 2>&1
    
    # Download Rathole (Linux x86_64)
    wget -O rathole.zip https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip > /dev/null 2>&1
    unzip -o rathole.zip -d /usr/local/bin/ > /dev/null 2>&1
    chmod +x $RATHOLE_BIN
    rm rathole.zip
    
    echo -e "${GREEN}✔ Rathole installed successfully.${NC}"
}

setup_rathole() {
    install_rathole
    
    echo -e "${CYAN}--- Rathole Configuration ---${NC}"
    echo -e "${MAGENTA}Architecture:${NC} Iran = Server (Listener) | Foreign = Client (Sender)"
    echo "1) IRAN Server (Accepts connections)"
    echo "2) FOREIGN Server (Connects to Iran)"
    read -p "Select Role: " R_ROLE

    if [ "$R_ROLE" == "1" ]; then
        # --- IRAN CONFIG (SERVER) ---
        read -p "Enter Control Port (Default 2333): " C_PORT
        C_PORT=${C_PORT:-"2333"}
        read -p "Enter Token (Password): " TOKEN
        
        # Open Firewall
        iptables -A INPUT -p tcp --dport $C_PORT -j ACCEPT
        
        cat > $RATHOLE_CONFIG <<EOF
[server]
bind_addr = "0.0.0.0:$C_PORT"
default_token = "$TOKEN"
EOF
        echo -e "${GREEN}✔ Configured as Rathole SERVER (IRAN).${NC}"

    elif [ "$R_ROLE" == "2" ]; then
        # --- FOREIGN CONFIG (CLIENT) ---
        read -p "Enter IRAN IP: " IR_IP
        read -p "Enter Control Port (Default 2333): " C_PORT
        C_PORT=${C_PORT:-"2333"}
        read -p "Enter Token (Password): " TOKEN
        
        echo -e "${YELLOW}--- Service Mapping ---${NC}"
        read -p "Local Port to Forward (e.g. V2Ray Port 443): " LOCAL_PORT
        read -p "Remote Port on Iran (e.g. 443): " REMOTE_PORT
        
        cat > $RATHOLE_CONFIG <<EOF
[client]
remote_addr = "$IR_IP:$C_PORT"
token = "$TOKEN"

[services.service1]
type = "tcp"
local_addr = "127.0.0.1:$LOCAL_PORT"
bind_addr = "0.0.0.0:$REMOTE_PORT"
EOF
        echo -e "${GREEN}✔ Configured as Rathole CLIENT (FOREIGN).${NC}"
    else
        echo -e "${RED}Invalid Option.${NC}"; return
    fi

    # Create Systemd Service
    cat > $RATHOLE_SERVICE <<EOF
[Unit]
Description=Rathole Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=$RATHOLE_BIN -c $RATHOLE_CONFIG
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable rathole > /dev/null 2>&1
    systemctl restart rathole
    
    echo -e "${GREEN}✔ Rathole Service Started!${NC}"
    systemctl status rathole --no-pager | grep "Active:"
}

# --- Standard Tunnel Logic (GRE/IPIP) ---
apply_configs() {
    if [ ! -f $CONFIG_FILE ]; then return; fi
    source $CONFIG_FILE
    
    ip link del "$INTERFACE_NAME" 2>/dev/null
    modprobe ip_gre && modprobe ipip && modprobe sit
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    case $MODE in
        "sit") ip tunnel add "$INTERFACE_NAME" mode sit remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
        "ipip") ip tunnel add "$INTERFACE_NAME" mode ipip remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
        *) ip tunnel add "$INTERFACE_NAME" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
    esac
    
    L_TUN="$IP_BASE.1"; R_TUN="$IP_BASE.2"
    [ "$ROLE" == "2" ] && { L_TUN="$IP_BASE.2"; R_TUN="$IP_BASE.1"; }
    
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set dev "$INTERFACE_NAME" mtu 1050 up
    fix_connection
    
    if [ "$ROLE" == "2" ]; then
        iptables -t nat -A POSTROUTING -s "$IP_BASE.0/30" -o $(ip route show default | awk '/default/ {print $5}') -j MASQUERADE
    fi
}

fix_connection() {
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    iptables -t mangle -F
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000
    if ip link show "$INTERFACE_NAME" > /dev/null 2>&1; then
        ip link set dev "$INTERFACE_NAME" mtu 1050
    fi
}

run_speedtest() {
    source $CONFIG_FILE 2>/dev/null
    if [ -z "$IP_BASE" ]; then echo -e "${RED}Setup tunnel first!${NC}"; return; fi
    apt-get install -y iperf3 > /dev/null 2>&1
    TARGET_IP="$IP_BASE.2"; [ "$ROLE" == "2" ] && TARGET_IP="$IP_BASE.1"
    iperf3 -s -1 > /dev/null 2>&1 &
    sleep 2
    iperf3 -c "$TARGET_IP" -t 10
}

setup_routing() {
    echo -e "${CYAN}Routing specific ports through GRE/IPIP tunnel...${NC}"
    read -p "Enter Ports (e.g. 443,80): " PORTS
    source $CONFIG_FILE
    R_TUN="$IP_BASE.2"; [ "$ROLE" == "2" ] && R_TUN="$IP_BASE.1"
    
    if ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then echo "100 tunnel" >> /etc/iproute2/rt_tables; fi
    iptables -t mangle -A PREROUTING -p tcp -m multiport --dports "$PORTS" -j MARK --set-mark 1
    iptables -t mangle -A PREROUTING -p udp -m multiport --dports "$PORTS" -j MARK --set-mark 1
    ip rule add fwmark 1 table tunnel
    ip route replace default via "$R_TUN" dev "$INTERFACE_NAME" table tunnel
    echo -e "${GREEN}Routing applied.${NC}"
}

optimize_bbr() {
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    echo -e "${GREEN}BBR Enabled.${NC}"
}

uninstall_all() {
    echo -e "${RED}Uninstalling Everything (Tunnel + Rathole)...${NC}"
    # Remove Tunnel
    ip link del "$INTERFACE_NAME" 2>/dev/null
    rm -f "$CONFIG_FILE"
    iptables -F && iptables -t nat -F && iptables -t mangle -F
    
    # Remove Rathole
    systemctl stop rathole 2>/dev/null
    systemctl disable rathole 2>/dev/null
    rm -f "$RATHOLE_SERVICE" "$RATHOLE_CONFIG" "$RATHOLE_BIN"
    systemctl daemon-reload
    
    echo -e "${GREEN}✔ System Cleaned.${NC}"
}

# --- Menu ---
while true; do
    show_banner
    # Status Check
    TUN_STAT="${RED}OFF${NC}"; [ -f $CONFIG_FILE ] && TUN_STAT="${GREEN}ON${NC}"
    RAT_STAT="${RED}OFF${NC}"; systemctl is-active --quiet rathole && RAT_STAT="${GREEN}ON${NC}"
    
    echo -e " TUNNEL: $TUN_STAT  |  RATHOLE: $RAT_STAT"
    echo "--------------------------------------------------------------------------------------"
    echo -e " 1) 🛠️   Setup GRE/IPIP Tunnel (Layer 3)"
    echo -e " 2) 🐀   Setup RATHOLE Tunnel (Layer 4 - High Performance)"
    echo -e " 3) ⚡   Internal Speedtest"
    echo -e " 4) 🔧   Fix Connection (MTU/MSS)"
    echo -e " 5) 🛣️   Port Routing (For GRE/IPIP)"
    echo -e " 6) 🚀   Optimize BBR"
    echo -e " 7) 🧨   UNINSTALL EVERYTHING"
    echo -e " 0)      Exit"
    echo "--------------------------------------------------------------------------------------"
    read -p " Select option: " OPT

    case $OPT in
        1)
            read -p "Role (1:IR, 2:FR): " ROLE
            read -p "Remote IP: " REMOTE_IP
            read -p "IP Base (10.0.0): " IP_BASE
            IP_BASE=${IP_BASE:-"10.0.0"}
            echo -e "ROLE=$ROLE\nREMOTE_IP=$REMOTE_IP\nIP_BASE=$IP_BASE\nMODE=gre" > $CONFIG_FILE
            apply_configs ;;
        2) setup_rathole ;;
        3) run_speedtest ;;
        4) fix_connection; echo -e "${GREEN}Fixed.${NC}" ;;
        5) setup_routing ;;
        6) optimize_bbr ;;
        7) uninstall_all ;;
        0) exit 0 ;;
    esac
    read -p "Press Enter..."
done
