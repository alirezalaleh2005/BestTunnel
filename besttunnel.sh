#!/bin/bash
# ==============================================================================
# Project: BestTunnel - Smart Layer 3 Only (No Rathole)
# Version: 8.6 (Tunnel Speedtest + Auto-Probe + Anti-Filter)
# Developer: alirezalaleh2005 → Fully Edited per User Request
# Features: Auto protocol selection, internal tunnel speedtest, ping validation, Iran-optimized
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
  echo -e "${YELLOW}🛡️  BESTTUNNEL SMART v8.6 (Internal Speedtest)  🛡️${NC}"
  echo "--------------------------------------------------------------------------------------"
}

# --- SMART PROTOCOL SELECTION ---
auto_select_protocol() {
  local protocols=("gre" "ipip" "sit")
  local best_proto=""
  local best_time=999999
  local temp_iface="best_probe"

  echo -e "${CYAN}🔍 Testing tunnel protocols for best performance...${NC}"

  for proto in "${protocols[@]}"; do
    echo -e "   Trying ${YELLOW}$proto${NC}..."

    ip link delete "$temp_iface" 2>/dev/null || true

    case "$proto" in
      "sit")  ip tunnel add "$temp_iface" mode sit remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
      "ipip") ip tunnel add "$temp_iface" mode ipip remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
      *)      ip tunnel add "$temp_iface" mode gre remote "$REMOTE_IP" local "$LOCAL_IP" ttl 255 ;;
    esac

    local l_tun="$IP_BASE.1" r_tun="$IP_BASE.2"
    [[ "$ROLE" == "2" ]] && { l_tun="$IP_BASE.2"; r_tun="$IP_BASE.1"; }

    ip addr add "$l_tun/30" dev "$temp_iface"
    ip link set dev "$temp_iface" mtu 1300 up

    if timeout 4 ping -c 2 -W 1 "$r_tun" > /dev/null 2>&1; then
      local start=$(date +%s%3N)
      timeout 3 ping -c 3 -W 1 "$r_tun" > /dev/null 2>&1
      local end=$(date +%s%3N)
      local latency=$((end - start))

      echo -e "   ${GREEN}✔ $proto works (latency: ${latency}ms)${NC}"
      if (( latency < best_time )); then
        best_time=$latency
        best_proto=$proto
      fi
    else
      echo -e "   ${RED}✘ $proto failed${NC}"
    fi

    ip link delete "$temp_iface" 2>/dev/null || true
    sleep 1
  done

  if [[ -n "$best_proto" ]]; then
    echo -e "${GREEN}✅ Best protocol selected: $best_proto${NC}"
    MODE="$best_proto"
  else
    echo -e "${RED}❌ All protocols failed. Check firewall or network.${NC}"
    exit 1
  fi
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
  ip link set dev "$INTERFACE_NAME" mtu 1300 up

  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  iptables -t mangle -F
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200

  if [[ "$ROLE" == "2" ]]; then
    local OUT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    iptables -t nat -A POSTROUTING -s "$IP_BASE.0/30" -o "$OUT_IFACE" -j MASQUERADE
  fi

  echo -e "${GREEN}✔ Tunnel '$INTERFACE_NAME' is UP with mode: $MODE${NC}"
}

# --- INTERNAL TUNNEL SPEEDTEST (BETWEEN SERVERS) ---
run_tunnel_speedtest() {
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}❌ Tunnel not configured. Run option 1 first.${NC}"
    return 1
  fi

  source "$CONFIG_FILE"

  local LOCAL_TUN_IP="$IP_BASE.1"
  local REMOTE_TUN_IP="$IP_BASE.2"
  [[ "$ROLE" == "2" ]] && { LOCAL_TUN_IP="$IP_BASE.2"; REMOTE_TUN_IP="$IP_BASE.1"; }

  local TEST_FILE="/tmp/besttunnel_test_$$"
  local PORT=8080
  local SIZE_MB=10
  local SIZE_BYTES=$((SIZE_MB * 1024 * 1024))

  if [[ "$ROLE" == "1" ]]; then
    # === Iran Side: Serve file ===
    echo -e "${CYAN}📡 Iran side: Serving test file on $LOCAL_TUN_IP:$PORT ...${NC}"

    dd if=/dev/zero of="$TEST_FILE" bs=1M count=$SIZE_MB 2>/dev/null

    if ! command -v python3 >/dev/null; then
      echo -e "${RED}❌ Python3 not found. Install it first: apt install python3${NC}"
      rm -f "$TEST_FILE"
      return 1
    fi

    python3 -m http.server $PORT --bind "$LOCAL_TUN_IP" > /dev/null 2>&1 &
    local SERVER_PID=$!

    sleep 2

    if ! kill -0 $SERVER_PID 2>/dev/null; then
      echo -e "${RED}❌ Failed to start HTTP server.${NC}"
      rm -f "$TEST_FILE"
      return 1
    fi

    echo -e "${GREEN}✔ Server running. Wait for foreign side to connect...${NC}"
    echo -e "${YELLOW}💡 On foreign server, run the speed test again.${NC}"

    sleep 60
    kill $SERVER_PID 2>/dev/null
    rm -f "$TEST_FILE"
    echo -e "${GREEN}✔ Test server stopped.${NC}"

  else
    # === Foreign Side: Download from Iran ===
    echo -e "${CYAN}📥 Foreign side: Downloading from $REMOTE_TUN_IP:$PORT ...${NC}"

    if ! command -v wget >/dev/null; then
      echo -e "${RED}❌ wget not found. Install it first: apt install wget${NC}"
      return 1
    fi

    local TEMP_DL="/tmp/besttunnel_dl_$$"
    local START=$(date +%s.%N)

    if wget -O "$TEMP_DL" --quiet --timeout=30 "http://$REMOTE_TUN_IP:$PORT/$(basename "$TEST_FILE")" 2>/dev/null; then
      local END=$(date +%s.%N)
      local DL_SIZE=$(stat -c%s "$TEMP_DL")
      local ELAPSED=$(echo "$END - $START" | bc -l)
      local SPEED_Mbps=$(echo "scale=2; ($DL_SIZE * 8) / (1024*1024*$ELAPSED)" | bc -l)

      echo -e "${GREEN}✔ Download completed!${NC}"
      echo -e "   Size: $(($DL_SIZE / 1024 / 1024)) MB"
      echo -e "   Speed: ${GREEN}$(printf "%.2f" $SPEED_Mbps) Mbps${NC}"
    else
      echo -e "${RED}❌ Failed to download from $REMOTE_TUN_IP:$PORT${NC}"
      echo -e "${YELLOW}💡 Make sure Iran side is running the test server.${NC}"
    fi

    rm -f "$TEMP_DL"
  fi
}

fix_connection() {
  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  iptables -t mangle -F
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200
  ip link set dev "$INTERFACE_NAME" mtu 1300 2>/dev/null || true
  echo -e "${GREEN}✔ Connection fixed (MTU/MSS adjusted for Iran).${NC}"
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

# --- Main Menu ---
while true; do
  show_banner

  TUN_STAT="${RED}OFF${NC}"
  [[ -f "$CONFIG_FILE" ]] && TUN_STAT="${GREEN}ON${NC}"

  echo -e " TUNNEL: $TUN_STAT"
  echo "--------------------------------------------------------------------------------------"
  echo -e " 1) 🛠️   Setup Smart Tunnel (Auto Protocol)"
  echo -e " 2) ⚡   Tunnel Speedtest (Between Servers)"
  echo -e " 3) 🔧   Fix Connection (MTU/MSS for Iran)"
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

      LOCAL_IP=$(hostname -I | awk '{print $1}')
      if [[ -z "$LOCAL_IP" ]]; then
        echo -e "${RED}Cannot detect local IP.${NC}"
        continue
      fi

      auto_select_protocol

      cat > "$CONFIG_FILE" <<EOF
ROLE=$ROLE
REMOTE_IP=$REMOTE_IP
IP_BASE=$IP_BASE
MODE=$MODE
EOF

      apply_configs
      ;;

    2) run_tunnel_speedtest ;;
    3) fix_connection ;;
    4) setup_routing ;;
    5) optimize_bbr ;;
    6) uninstall_all ;;
    0) exit 0 ;;
    *) echo -e "${RED}Invalid option.${NC}" ;;
  esac

  read -rp "Press Enter to continue..."
done
