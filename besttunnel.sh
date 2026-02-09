#!/bin/bash
# ==============================================================================
# Project: BestTunnel - Layer 3 Only (GRE/IPIP/SIT)
# Version: 8.6 (Edited per user request)
# Developer: alirezalaleh2005 → Optimized & Cleaned
# Features: IP validation, ping test, tunnel mode selection, bandwidth test (no iperf), BBR
# ==============================================================================

set -euo pipefail

# --- Global ---
INTERFACE_NAME="besttunnel"
CONFIG_FILE="/etc/besttunnel.conf"

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Error: Run as root!${NC}" >&2
  exit 1
fi

# --- Utilities ---
is_valid_ip() {
  [[ $1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && \
  IFS='.' read -r a b c d <<< "$1" && \
  [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]]
}

show_banner() {
  clear
  echo -e "${CYAN}"
  cat << "EOF"
  ██████╗ ███████╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗
  ██╔══██╗██╔════╝██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝
  ██████╔╝█████╗  ███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  
  ██╔══██╗██╔══╝  ╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  
  ██████╔╝███████╗███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗
EOF
  echo -e "${YELLOW}🛡️  BESTTUNNEL L3 ONLY v8.6 (Rathole REMOVED)  🛡️${NC}"
  echo "--------------------------------------------------------------------------------------"
}

apply_configs() {
  if [[ ! -f "$CONFIG_FILE" ]]; then return; fi
  source "$CONFIG_FILE"

  ip link delete "$INTERFACE_NAME" 2>/dev/null || true
  modprobe ip_gre ipip sit 2>/dev/null

  local LOCAL_IP=$(hostname -I | awk '{print $1}')
  if [[ -z "$LOCAL_IP" ]]; then
    echo -e "${RED}Failed to detect local IP.${NC}"
    return 1
  fi

  case "$MODE" in
    "sit")  ip tunnel add "$INTERFACE_NAME" mode sit remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
    "ipip") ip tunnel add "$INTERFACE_NAME" mode ipip remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
    *)      ip tunnel add "$INTERFACE_NAME" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
  esac

  local L_TUN="$IP_BASE.1" R_TUN="$IP_BASE.2"
  [[ "$ROLE" == "2" ]] && { L_TUN="$IP_BASE.2"; R_TUN="$IP_BASE.1"; }

  ip addr add "$L_TUN/30" dev "$INTERFACE_NAME"
  ip link set dev "$INTERFACE_NAME" mtu 1050 up

  # Fix MTU/MSS
  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  iptables -t mangle -F
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000

  if [[ "$ROLE" == "2" ]]; then
    local OUT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    iptables -t nat -A POSTROUTING -s "$IP_BASE.0/30" -o "$OUT_IFACE" -j MASQUERADE
  fi

  echo -e "${GREEN}✔ Tunnel '$INTERFACE_NAME' is UP.${NC}"
}

run_bandwidth_test() {
  echo -e "${CYAN}🚀 Starting bandwidth test (using public server)...${NC}"
  local TEST_URL="http://speedtest.tele2.net/10MB.zip"
  local TEMP_FILE="/tmp/besttunnel_speed.tmp"

  rm -f "$TEMP_FILE"
  local START=$(date +%s.%N)

  if wget -O "$TEMP_FILE" --quiet --timeout=30 "$TEST_URL"; then
    local END=$(date +%s.%N)
    local SIZE=$(stat -c%s "$TEMP_FILE")
    local ELAPSED=$(echo "$END - $START" | bc -l)
    local SPEED=$(echo "scale=2; ($SIZE * 8) / (1024*1024*$ELAPSED)" | bc -l)

    echo -e "${GREEN}✔ Download completed!${NC}"
    echo -e "   Size: $(($SIZE / 1024 / 1024)) MB"
    echo -e "   Time: $(printf "%.2f" $ELAPSED) sec"
    echo -e "   Speed: ${GREEN}$(printf "%.2f" $SPEED) Mbps${NC}"
  else
    echo -e "${RED}❌ Failed to download test file. Check internet or firewall.${NC}"
  fi
  rm -f "$TEMP_FILE"
}

fix_connection() {
  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  iptables -t mangle -F
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000
  ip link set dev "$INTERFACE_NAME" mtu 1050 2>/dev/null || true
  echo -e "${GREEN}✔ Connection fixed (MTU/MSS adjusted).${NC}"
}

setup_routing() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}Setup tunnel first!${NC}"
    return 1
  fi
  source "$CONFIG_FILE"

  read -p "Enter ports to route (e.g., 443,80): " PORTS
  [[ -z "$PORTS" ]] && { echo -e "${RED}No ports given.${NC}"; return 1; }

  local R_TUN="$IP_BASE.2"
  [[ "$ROLE" == "2" ]] && R_TUN="$IP_BASE.1"

  if ! grep -q "^100[[:space:]]\+tunnel" /etc/iproute2/rt_tables 2>/dev/null; then
    echo "100 tunnel" >> /etc/iproute2/rt_tables
  fi

  iptables -t mangle -A PREROUTING -p tcp -m multiport --dports "$PORTS" -j MARK --set-mark 1
  iptables -t mangle -A PREROUTING -p udp -m multiport --dports "$PORTS" -j MARK --set-mark 1
  ip rule add fwmark 1 table tunnel 2>/dev/null || true
  ip route replace default via "$R_TUN" dev "$INTERFACE_NAME" table tunnel

  echo -e "${GREEN}✔ Port routing applied for: $PORTS${NC}"
}

optimize_bbr() {
  if grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf 2>/dev/null; then
    echo -e "${YELLOW}BBR already enabled.${NC}"
    return
  fi
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p > /dev/null
  echo -e "${GREEN}✔ BBR congestion control enabled.${NC}"
}

uninstall_all() {
  echo -e "${RED}Uninstalling tunnel...${NC}"
  ip link delete "$INTERFACE_NAME" 2>/dev/null || true
  rm -f "$CONFIG_FILE"
  iptables -F
  iptables -t nat -F
  iptables -t mangle -F
  echo -e "${GREEN}✔ Tunnel removed completely.${NC}"
}

# --- Main Loop ---
while true; do
  show_banner

  TUN_STAT="${RED}OFF${NC}"
  [[ -f "$CONFIG_FILE" ]] && TUN_STAT="${GREEN}ON${NC}"

  echo -e " TUNNEL: $TUN_STAT"
  echo "--------------------------------------------------------------------------------------"
  echo -e " 1) 🛠️   Setup GRE/IPIP/SIT Tunnel"
  echo -e " 2) ⚡   Bandwidth Test (No iperf needed)"
  echo -e " 3) 🔧   Fix Connection (MTU/MSS)"
  echo -e " 4) 🛣️   Port Routing"
  echo -e " 5) 🚀   Enable BBR Optimization"
  echo -e " 6) 🧨   UNINSTALL TUNNEL"
  echo -e " 0)      Exit"
  echo "--------------------------------------------------------------------------------------"

  read -rp "Select option: " OPT

  case "$OPT" in
    1)
      read -p "Role (1=Iran, 2=Foreign): " ROLE
      [[ "$ROLE" != "1" && "$ROLE" != "2" ]] && { echo -e "${RED}Invalid role.${NC}"; continue; }

      read -p "Remote IP: " REMOTE_IP
      if ! is_valid_ip "$REMOTE_IP"; then
        echo -e "${RED}Invalid IP format.${NC}"
        continue
      fi
      if ! timeout 3 ping -c 1 -W 2 "$REMOTE_IP" > /dev/null 2>&1; then
        echo -e "${RED}Remote IP not reachable (ping failed).${NC}"
        continue
      fi

      read -p "IP Base (e.g., 10.0.0): " IP_BASE
      IP_BASE=${IP_BASE:-"10.0.0"}
      if ! [[ $IP_BASE =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${RED}Invalid IP base (use format like 10.0.0).${NC}"
        continue
      fi

      echo -e "${CYAN}Select Tunnel Mode:${NC}"
      echo "1) GRE  (Recommended)"
      echo "2) IPIP"
      echo "3) SIT  (IPv6 over IPv4)"
      read -p "Choice (1/2/3): " MODE_SEL
      case "$MODE_SEL" in
        1) MODE="gre" ;;
        2) MODE="ipip" ;;
        3) MODE="sit" ;;
        *) MODE="gre" ;;
      esac

      cat > "$CONFIG_FILE" <<EOF
ROLE=$ROLE
REMOTE_IP=$REMOTE_IP
IP_BASE=$IP_BASE
MODE=$MODE
EOF

      apply_configs
      ;;

    2) run_bandwidth_test ;;
    3) fix_connection ;;
    4) setup_routing ;;
    5) optimize_bbr ;;
    6) uninstall_all ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}" ;;
  esac

  read -rp "Press Enter to continue..."
done
