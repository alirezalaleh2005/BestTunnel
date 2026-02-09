#!/bin/bash

# ==========================================================
# Project: BestTunnel Ultimate Edition
# Developer: alirezalaleh2005
# Features: GRE/IPIP/SIT, Internal Speedtest, BBR, Anti-DPI
# Language: English
# ==========================================================

INTERFACE_NAME="besttunnel"
CONFIG_FILE="/etc/besttunnel.conf"

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ██████╗ ███████╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗"
    echo "  ██╔══██╗██╔════╝██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝"
    echo "  ██████╔╝█████╗  ███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  "
    echo "  ██╔══██╗██╔══╝  ╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  "
    echo "  ██████╔╝███████╗███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗"
    echo -e "  ${YELLOW}🛡️  INTERNAL SPEED-SYNC TUNNEL PRO v5.0  🛡️${NC}"
    echo "--------------------------------------------------------------------------------------"
}

# --- Core Logic ---
apply_configs() {
    if [ ! -f $CONFIG_FILE ]; then return; fi
    source $CONFIG_FILE
    
    # Clean old interface
    ip link del "$INTERFACE_NAME" 2>/dev/null
    modprobe ip_gre && modprobe ipip && modprobe sit

    LOCAL_IP=$(hostname -I | awk '{print $1}')
    ip tunnel add "$INTERFACE_NAME" mode "${MODE:-gre}" remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    
    L_TUN="$IP_BASE.1"; R_TUN="$IP_BASE.2"
    [ "$ROLE" == "2" ] && { L_TUN="$IP_BASE.2"; R_TUN="$IP_BASE.1"; }
    
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set dev "$INTERFACE_NAME" mtu 1100 up
    
    # Forwarding & MSS Clamping (Anti-DPI)
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 900
    
    if [ "$ROLE" == "2" ]; then
        iptables -t nat -A POSTROUTING -s $IP_BASE.0/30 -o eth0 -j MASQUERADE 2>/dev/null
    fi
}

# --- Speedtest Function ---
run_internal_speedtest() {
    source $CONFIG_FILE 2>/dev/null
    if [ -z "$IP_BASE" ]; then echo -e "${RED}Error: Please setup the tunnel first.${NC}"; return; fi

    echo -e "${YELLOW}Installing iperf3 and preparing...${NC}"
    apt-get update -qq && apt-get install -y iperf3 > /dev/null 2>&1
    
    TARGET_IP="$IP_BASE.2"; [ "$ROLE" == "2" ] && TARGET_IP="$IP_BASE.1"

    echo -e "${CYAN}>>> Starting Internal Speedtest to $TARGET_IP...${NC}"
    echo -e "${YELLOW}Note: For accurate results, run this option on BOTH servers simultaneously.${NC}"
    
    # Run server in background
    iperf3 -s -1 > /dev/null 2>&1 &
    sleep 2
    
    # Run client test
    iperf3 -c "$TARGET_IP" -t 10
}

# --- Menu ---
while true; do
    show_banner
    status="${RED}OFFLINE${NC}"
    current_mode="NONE"
    if ip link show "$INTERFACE_NAME" > /dev/null 2>&1; then 
        status="${GREEN}ONLINE${NC}"
        current_mode=$(grep MODE $CONFIG_FILE | cut -d= -f2 | tr '[:lower:]' '[:upper:]')
    fi
    
    echo -e "STATUS: $status | PROTOCOL: ${YELLOW}$current_mode${NC}"
    echo "--------------------------------------------------------------------------------------"
    echo -e "1) 🛠️  Setup/Update Tunnel"
    echo -e "2) ⚡  Internal Speedtest (iperf3)"
    echo -e "3) 🔄  Switch Protocol (GRE/IPIP/SIT)"
    echo -e "4) 🛡️  Port Routing"
    echo -e "5) 🚀  Optimize Speed (BBR)"
    echo -e "6) 🧨  Reset All Settings"
    echo -e "0)  Exit"
    echo "--------------------------------------------------------------------------------------"
    read -p "Choose an option: " OPT

    case $OPT in
        1)
            echo -e "${CYAN}Initial Setup:${NC}"
            read -p "Server Role (1 for IRAN / 2 for FOREIGN): " ROLE
            read -p "Remote Server IP: " REMOTE_IP
            read -p "Tunnel IP Base (e.g. 10.0.0): " IP_BASE
            IP_BASE=${IP_BASE:-"10.0.0"}
            
            echo -e "ROLE=$ROLE\nREMOTE_IP=$REMOTE_IP\nIP_BASE=$IP_BASE\nMODE=gre" > $CONFIG_FILE
            apply_configs
            echo -e "${GREEN}Tunnel setup successfully.${NC}" ;;
            
        2) run_internal_speedtest ;;
        
        3)
            echo -e "1) GRE (Default/Fast)\n2) IPIP (Lightweight)\n3) SIT (Best for heavy censorship)"
            read -p "Select protocol: " P
            case $P in
                1) M="gre" ;;
                2) M="ipip" ;;
                3) M="sit" ;;
                *) M="gre" ;;
            esac
            sed -i "s/MODE=.*/MODE=$M/" $CONFIG_FILE
            apply_configs
            echo -e "${GREEN}Protocol changed to $M.${NC}" ;;
            
        4)
            read -p "Enter ports to route (e.g. 443,80,20000:30000): " PORTS
            source $CONFIG_FILE
            R_TUN="$IP_BASE.2"; [ "$ROLE" == "2" ] && R_TUN="$IP_BASE.1"
            if ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then echo "100 tunnel" >> /etc/iproute2/rt_tables; fi
            iptables -t mangle -F
            iptables -t mangle -A PREROUTING -p tcp -m multiport --dports "$PORTS" -j MARK --set-mark 1
            iptables -t mangle -A PREROUTING -p udp -m multiport --dports "$PORTS" -j MARK --set-mark 1
            ip rule add fwmark 1 table tunnel 2>/dev/null
            ip route replace default via "$R_TUN" dev $INTERFACE_NAME table tunnel
            echo -e "${GREEN}Routing applied for ports: $PORTS${NC}" ;;
            
        5)
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
            sysctl -p
            echo -e "${GREEN}BBR Optimization enabled.${NC}" ;;
            
        6)
            ip link del "$INTERFACE_NAME" 2>/dev/null
            rm $CONFIG_FILE 2>/dev/null
            iptables -F && iptables -t nat -F && iptables -t mangle -F
            echo -e "${RED}All settings have been cleared.${NC}" ;;
            
        0) exit 0 ;;
    esac
    read -p "Press Enter to continue..."
done
