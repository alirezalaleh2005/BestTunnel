#!/bin/bash

# ==============================================================================
# Project: BestTunnel Ultimate Edition (Full Feature)
# Version: 8.0 Stable
# Developer: alirezalaleh2005
# Description: Advanced Tunneling (GRE/IPIP/SIT) with Auto-Fix, Speedtest & Routing
# ==============================================================================

# --- Global Variables ---
INTERFACE_NAME="besttunnel"
CONFIG_FILE="/etc/besttunnel.conf"
RT_TABLE_FILE="/etc/iproute2/rt_tables"

# --- Colors for UI ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# --- Check Root Permissions ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root!${NC}"
   exit 1
fi

# --- UI Banner ---
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "  ██████╗ ███████╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗"
    echo "  ██╔══██╗██╔════╝██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝"
    echo "  ██████╔╝█████╗  ███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  "
    echo "  ██╔══██╗██╔══╝  ╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  "
    echo "  ██████╔╝███████╗███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗"
    echo -e "  ${YELLOW}🛡️  BESTTUNNEL ULTIMATE EDITION v8.0 (FULL)  🛡️${NC}"
    echo "--------------------------------------------------------------------------------------"
}

# --- 1. Connection Fixer (MTU/MSS/Forwarding) ---
# This function solves the "Ping but no internet" issue
fix_connection() {
    echo -e "${YELLOW}>>> Applying Connection & Stability Fixes...${NC}"
    
    # Enable IP Forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    echo -e "${GREEN}✔ IPv4 Forwarding Enabled${NC}"
    
    # MSS Clamping (Crucial for passing firewalls)
    iptables -t mangle -F
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    echo -e "${GREEN}✔ MSS Clamping Applied (Size: 1000)${NC}"
    
    # Set Interface MTU
    if ip link show "$INTERFACE_NAME" > /dev/null 2>&1; then
        ip link set dev "$INTERFACE_NAME" mtu 1050
        echo -e "${GREEN}✔ Tunnel MTU set to 1050${NC}"
    else
        echo -e "${RED}✘ Interface not found (Tunnel not setup yet).${NC}"
    fi

    # Allow GRE/IPIP protocols in Input
    iptables -A INPUT -p gre -j ACCEPT 2>/dev/null
    iptables -A INPUT -p ipencap -j ACCEPT 2>/dev/null
}

# --- 2. Apply/Setup Configurations ---
apply_configs() {
    if [ ! -f $CONFIG_FILE ]; then 
        echo -e "${RED}Error: Config file not found.${NC}"
        return
    fi
    source $CONFIG_FILE
    
    echo -e "${CYAN}>>> Setting up Tunnel ($MODE)...${NC}"

    # Remove existing interface
    ip link del "$INTERFACE_NAME" 2>/dev/null
    
    # Load Kernel Modules
    modprobe ip_gre
    modprobe ipip
    modprobe sit

    # Detect Local IP
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    # Create Tunnel Interface
    if [ "$MODE" == "sit" ]; then
        ip tunnel add "$INTERFACE_NAME" mode sit remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    elif [ "$MODE" == "ipip" ]; then
        ip tunnel add "$INTERFACE_NAME" mode ipip remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    else
        # Default GRE
        ip tunnel add "$INTERFACE_NAME" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255
    fi
    
    # Assign IPs
    L_TUN="$IP_BASE.1"
    R_TUN="$IP_BASE.2"
    if [ "$ROLE" == "2" ]; then
        L_TUN="$IP_BASE.2"
        R_TUN="$IP_BASE.1"
    fi
    
    ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
    ip link set dev "$INTERFACE_NAME" up
    
    # Apply Fixes Immediately
    fix_connection
    
    # NAT Masquerade (Only for Foreign Server)
    if [ "$ROLE" == "2" ]; then
        echo -e "${YELLOW}>>> Applying NAT (Masquerade) for Foreign Server...${NC}"
        iptables -t nat -A POSTROUTING -s "$IP_BASE.0/30" -o $(ip route show default | awk '/default/ {print $5}') -j MASQUERADE
    fi
    
    echo -e "${GREEN}✔ Tunnel Established Successfully!${NC}"
}

# --- 3. Port Routing (Anti-DPI / Game Routing) ---
setup_routing() {
    source $CONFIG_FILE 2>/dev/null
    if [ -z "$IP_BASE" ]; then echo -e "${RED}Setup tunnel first!${NC}"; return; fi
    
    R_TUN="$IP_BASE.2"
    [ "$ROLE" == "2" ] && R_TUN="$IP_BASE.1"

    echo -e "${CYAN}--- Advanced Port Routing ---${NC}"
    read -p "Enter Ports to Route (e.g. 443,80,2083 or ranges 20000:30000): " PORTS
    
    # Ensure routing table exists
    if ! grep -q "100 tunnel" "$RT_TABLE_FILE"; then
        echo "100 tunnel" >> "$RT_TABLE_FILE"
    fi
    
    # Clean previous mangle rules
    # Note: We don't flush all mangles here to keep MSS clamping
    iptables -t mangle -D PREROUTING -p tcp -m multiport --dports "$PORTS" -j MARK --set-mark 1 2>/dev/null
    iptables -t mangle -D PREROUTING -p udp -m multiport --dports "$PORTS" -j MARK --set-mark 1 2>/dev/null

    # Add new rules
    iptables -t mangle -A PREROUTING -p tcp -m multiport --dports "$PORTS" -j MARK --set-mark 1
    iptables -t mangle -A PREROUTING -p udp -m multiport --dports "$PORTS" -j MARK --set-mark 1
    
    # IP Rules
    ip rule del fwmark 1 table tunnel 2>/dev/null
    ip rule add fwmark 1 table tunnel
    
    # IP Route
    ip route replace default via "$R_TUN" dev "$INTERFACE_NAME" table tunnel
    
    echo -e "${GREEN}✔ Traffic for ports [$PORTS] is now routed through the tunnel.${NC}"
}

# --- 4. Internal Speedtest (iperf3) ---
run_speedtest() {
    source $CONFIG_FILE 2>/dev/null
    if [ -z "$IP_BASE" ]; then echo -e "${RED}Error: Setup tunnel first.${NC}"; return; fi

    echo -e "${YELLOW}>>> Checking for iperf3...${NC}"
    if ! command -v iperf3 &> /dev/null; then
        apt-get update -qq && apt-get install -y iperf3
    fi
    
    TARGET_IP="$IP_BASE.2"
    [ "$ROLE" == "2" ] && TARGET_IP="$IP_BASE.1"

    echo -e "${MAGENTA}-----------------------------------------------------${NC}"
    echo -e "${MAGENTA} INTERNAL SPEEDTEST (Bandwidth between servers)      ${NC}"
    echo -e "${MAGENTA}-----------------------------------------------------${NC}"
    echo -e "${CYAN}1. Starting Background Server (Listener)...${NC}"
    # Kill existing iperf3 instances to prevent conflict
    pkill iperf3
    iperf3 -s -1 > /dev/null 2>&1 &
    sleep 2
    
    echo -e "${CYAN}2. Connecting to Remote Server ($TARGET_IP)...${NC}"
    echo -e "${YELLOW}NOTE: Please run this option on BOTH servers at the same time!${NC}"
    
    iperf3 -c "$TARGET_IP" -t 10 -P 4
    
    echo -e "${MAGENTA}-----------------------------------------------------${NC}"
}

# --- 5. BBR Optimization ---
optimize_bbr() {
    echo -e "${YELLOW}>>> Enabling TCP BBR Congestion Control...${NC}"
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}✔ BBR Enabled!${NC}"
    else
        echo -e "${GREEN}✔ BBR is already enabled.${NC}"
    fi
}

# --- 6. Uninstall / Reset ---
uninstall() {
    echo -e "${RED}!!! WARNING !!!${NC}"
    echo -e "This will remove the tunnel, delete configs, and flush firewall rules."
    read -p "Are you sure you want to proceed? (y/N): " CONFIRM
    if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
        echo -e "${YELLOW}Cleaning up...${NC}"
        
        # Delete Interface
        ip link del "$INTERFACE_NAME" 2>/dev/null
        
        # Remove Config
        rm -f "$CONFIG_FILE"
        
        # Flush Tables
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        
        # Remove Routing Rule
        ip rule del fwmark 1 table tunnel 2>/dev/null
        
        echo -e "${GREEN}✔ BestTunnel has been completely removed.${NC}"
    else
        echo -e "${CYAN}Operation cancelled.${NC}"
    fi
}

# --- Main Menu Loop ---
while true; do
    show_banner
    
    # Status Check
    STATUS="${RED}OFFLINE${NC}"
    PROTOCOL="NONE"
    
    if ip link show "$INTERFACE_NAME" > /dev/null 2>&1; then 
        STATUS="${GREEN}ONLINE${NC}"
        if [ -f $CONFIG_FILE ]; then
            PROTOCOL=$(grep MODE $CONFIG_FILE | cut -d= -f2 | tr '[:lower:]' '[:upper:]')
        fi
    fi
    
    echo -e " STATUS: $STATUS   |   PROTOCOL: ${YELLOW}$PROTOCOL${NC}"
    echo "--------------------------------------------------------------------------------------"
    echo -e " 1) 🛠️   Setup / Update Tunnel (Interactive)"
    echo -e " 2) ⚡   Internal Speedtest (iperf3)"
    echo -e " 3) 🔧   FORCE FIX CONNECTION (Solve Ping/Traffic Issues)"
    echo -e " 4) 🔄   Switch Protocol (GRE / IPIP / SIT)"
    echo -e " 5) 🛣️   Port Routing (Send specific ports through tunnel)"
    echo -e " 6) 🚀   Enable BBR Optimization"
    echo -e " 7) 🧨   UNINSTALL / RESET ALL"
    echo -e " 0)      Exit"
    echo "--------------------------------------------------------------------------------------"
    read -p " Select an option [0-7]: " OPTION

    case $OPTION in
        1)
            echo -e "${CYAN}--- Configuration Setup ---${NC}"
            echo "1) IRAN Server"
            echo "2) FOREIGN Server"
            read -p "Select Role: " R_INPUT
            
            read -p "Enter Remote Server IP: " REMOTE_IP
            read -p "Enter Tunnel IP Base (Default 10.0.0): " IP_BASE_INPUT
            IP_BASE=${IP_BASE_INPUT:-"10.0.0"}
            
            # Default to GRE initially
            echo -e "ROLE=$R_INPUT\nREMOTE_IP=$REMOTE_IP\nIP_BASE=$IP_BASE\nMODE=gre" > $CONFIG_FILE
            apply_configs
            read -p "Press Enter to continue..." ;;
            
        2) 
            run_speedtest
            read -p "Press Enter to continue..." ;;
            
        3) 
            fix_connection
            echo -e "${GREEN}Fixes applied. Try checking your connection now.${NC}"
            read -p "Press Enter to continue..." ;;
            
        4)
            if [ ! -f $CONFIG_FILE ]; then echo -e "${RED}Setup tunnel first!${NC}"; else
                echo -e "Current Protocol: $PROTOCOL"
                echo "1) GRE (Standard)"
                echo "2) IPIP (Low Overhead)"
                echo "3) SIT (IPv6 Encapsulation - Good for filtering)"
                read -p "Select New Protocol: " P_SEL
                case $P_SEL in
                    1) NEW_MODE="gre" ;;
                    2) NEW_MODE="ipip" ;;
                    3) NEW_MODE="sit" ;;
                    *) NEW_MODE="gre" ;;
                esac
                sed -i "s/MODE=.*/MODE=$NEW_MODE/" $CONFIG_FILE
                apply_configs
            fi
            read -p "Press Enter to continue..." ;;
            
        5)
            setup_routing
            read -p "Press Enter to continue..." ;;
            
        6)
            optimize_bbr
            read -p "Press Enter to continue..." ;;
            
        7)
            uninstall
            read -p "Press Enter to continue..." ;;
            
        0)
            echo -e "${CYAN}Exiting... Have a great day!${NC}"
            exit 0 ;;
        *)
            echo -e "${RED}Invalid Option.${NC}"
            sleep 1 ;;
    esac
done
