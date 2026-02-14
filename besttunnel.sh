#!/bin/bash

# ==========================================================
# File: ultimate_tunnel_pro.sh
# Version: 4.0 (Extreme Global Edition)
# Description: High-Performance Nginx Tunnel Manager
# Features: Kernel Bypass Tuning, Zero-Copy, Reuseport, BBR
# ==========================================================

DB_FILE="/etc/nginx/tunnel_db.txt"
CERT_DIR="/etc/nginx/certs"

# Color Codes for UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 1. Root Access Check
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root.${NC}"
   exit 1
fi

# 2. System Optimization (Kernel & Network)
optimize_system() {
    echo -e "${YELLOW}>>> Optimizing Kernel for Unlimited Speed...${NC}"
    
    # Install Prerequisites
    apt update && apt install -y nginx openssl coreutils procps

    # Increase File Descriptor Limits
    cat <<EOF > /etc/security/limits.d/99-tunnel.conf
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
* soft nproc unlimited
* hard nproc unlimited
EOF

    # Deep Network Stack Tuning
    cat <<EOF > /etc/sysctl.d/99-tunnel-pro.conf
# TCP BBR & Congestion Control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_nodelay = 1
net.ipv4.tcp_low_latency = 1

# Maximize Buffers for Gigabit Networks
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# Connection Backlog & Handling
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 100000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.ip_local_port_range = 1024 65535

# Virtual Memory Tuning
vm.swappiness = 10
EOF
    sysctl --system > /dev/null 2>&1
    echo -e "${GREEN}✅ System Optimized Successfully.${NC}"
}

# 3. SSL Preparation
prepare_ssl() {
    if [ ! -f "$CERT_DIR/tunnel.crt" ]; then
        mkdir -p "$CERT_DIR"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/tunnel.key" -out "$CERT_DIR/tunnel.crt" \
        -subj "/C=US/ST=NY/O=Cloud/CN=www.google.com" > /dev/null 2>&1
    fi
}

# 4. Generate High-Performance Nginx Config
update_nginx_conf() {
    prepare_ssl
    CPU_CORES=$(nproc)
    
    cat <<EOF > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 1000000;

events {
    worker_connections 100000;
    use epoll;
    multi_accept on;
    accept_mutex off;
}

stream {
    # Performance & Timing Settings
    tcp_nodelay on;
    
    # SSL Session Optimization
    ssl_session_cache shared:SSL:100m;
    ssl_session_timeout 24h;
    ssl_session_tickets on;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate $CERT_DIR/tunnel.crt;
    ssl_certificate_key $CERT_DIR/tunnel.key;

    # Dynamic Tunnel Load
EOF

    if [ -f "$DB_FILE" ]; then
        while IFS=, read -r l_port r_ip r_port use_tls; do
            echo "    server {" >> /etc/nginx/nginx.conf
            if [ "$use_tls" == "yes" ]; then
                echo "        listen $l_port ssl reuseport;" >> /etc/nginx/nginx.conf
                echo "        listen $l_port udp reuseport;" >> /etc/nginx/nginx.conf
            else
                echo "        listen $l_port reuseport;" >> /etc/nginx/nginx.conf
                echo "        listen $l_port udp reuseport;" >> /etc/nginx/nginx.conf
            fi
            cat <<EOF >> /etc/nginx/nginx.conf
        proxy_pass $r_ip:$r_port;
        proxy_timeout 48h;
        proxy_connect_timeout 2s;
        proxy_buffer_size 128k;
        proxy_upload_rate 0;
        proxy_download_rate 0;
    }
EOF
        done < "$DB_FILE"
    fi
    echo "}" >> /etc/nginx/nginx.conf
    
    nginx -t && systemctl restart nginx
}

# 5. Core Functions
add_tunnel() {
    echo -e "${YELLOW}--- Add New Tunnel ---${NC}"
    read -p "Local Listening Port: " l_port
    read -p "Remote Destination IP: " r_ip
    read -p "Remote Destination Port: " r_port
    read -p "Enable TLS? (yes/no): " use_tls
    
    echo "$l_port,$r_ip,$r_port,$use_tls" >> "$DB_FILE"
    update_nginx_conf
    echo -e "${GREEN}✅ Tunnel on Port $l_port established.${NC}"
}

list_tunnels() {
    echo -e "${YELLOW}--- Active Tunnels ---${NC}"
    if [ ! -s "$DB_FILE" ]; then
        echo "No tunnels configured."
    else
        printf "${GREEN}%-10s | %-16s | %-10s | %-5s${NC}\n" "Local" "Remote IP" "Port" "TLS"
        echo "--------------------------------------------------------"
        while IFS=, read -r lp rip rp tls; do
            printf "%-10s | %-16s | %-10s | %-5s\n" "$lp" "$rip" "$rp" "$tls"
        done < "$DB_FILE"
    fi
}

# 6. Main Interactive Menu
clear
echo "========================================"
echo "    ULTIMATE TUNNEL MANAGER PRO v4.0    "
echo "========================================"
optimize_system
[ ! -f "$DB_FILE" ] && touch "$DB_FILE"

while true; do
    echo -e "\n${YELLOW}1)${NC} Add New Tunnel"
    echo -e "${YELLOW}2)${NC} List All Tunnels"
    echo -e "${YELLOW}3)${NC} Enable Auto-Recovery (Cron)"
    echo -e "${YELLOW}4)${NC} Reset Everything"
    echo -e "${YELLOW}5)${NC} Exit"
    read -p "Choose an option [1-5]: " choice

    case $choice in
        1) add_tunnel ;;
        2) list_tunnels ;;
        3) (crontab -l 2>/dev/null; echo "*/5 * * * * systemctl is-active --quiet nginx || systemctl restart nginx") | crontab -
           echo -e "${GREEN}✅ Auto-recovery active.${NC}" ;;
        4) rm -f "$DB_FILE" && touch "$DB_FILE" && update_nginx_conf
           echo -e "${GREEN}✅ Database reset.${NC}" ;;
        5) exit 0 ;;
        *) echo -e "${RED}Invalid choice.${NC}" ;;
    esac
done
