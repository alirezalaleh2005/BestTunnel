#!/bin/bash

# ==========================================================
# File: besttunnel.sh
# Version: 0.9 (Ultimate Hybrid & Multi-Port)
# Description: Professional Nginx Tunnel Manager with BBR & TLS
# ==========================================================

DB_FILE="/etc/nginx/tunnel_db.txt"
CERT_DIR="/etc/nginx/certs"

# Check for root access
if [[ $EUID -ne 0 ]]; then
   echo "Error: Please run as root (sudo ./besttunnel.sh)"
   exit 1
fi

# Optimization: Enable BBR
enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p > /dev/null 2>&1
        echo ">>> BBR Speed Optimization Enabled."
    fi
}

# Ensure SSL certificate exists for TLS tunnels
prepare_ssl() {
    if [ ! -f "$CERT_DIR/tunnel.crt" ]; then
        mkdir -p "$CERT_DIR"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/tunnel.key" -out "$CERT_DIR/tunnel.crt" \
        -subj "/C=US/ST=NY/L=NY/O=IT/CN=www.google.com" > /dev/null 2>&1
    fi
}

# Core function: Update Nginx Configuration
update_nginx_conf() {
    prepare_ssl
    cat <<EOF > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
}

stream {
    # SSL Settings for Secure Tunnels
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate $CERT_DIR/tunnel.crt;
    ssl_certificate_key $CERT_DIR/tunnel.key;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1h;

    # Load all tunnels from Database
    if [ -f "$DB_FILE" ]; then
        while IFS=, read -r l_port r_ip r_port use_tls; do
            echo "    server {" >> /etc/nginx/nginx.conf
            if [ "$use_tls" == "yes" ]; then
                echo "        listen $l_port ssl;" >> /etc/nginx/nginx.conf
                echo "        listen $l_port udp;" >> /etc/nginx/nginx.conf
            else
                echo "        listen $l_port;" >> /etc/nginx/nginx.conf
                echo "        listen $l_port udp;" >> /etc/nginx/nginx.conf
            fi
            echo "        proxy_pass $r_ip:$r_port;" >> /etc/nginx/nginx.conf
            echo "        proxy_timeout 24h;" >> /etc/nginx/nginx.conf
            echo "        proxy_connect_timeout 2s;" >> /etc/nginx/nginx.conf
            echo "        tcp_nodelay on;" >> /etc/nginx/nginx.conf
            echo "    }" >> /etc/nginx/nginx.conf
        done < "$DB_FILE"
    fi
}
EOF
    nginx -t && systemctl restart nginx
}

# Function to add a new tunnel
add_tunnel() {
    echo "------------------------------------"
    read -p "Local Port (e.g. 443): " l_port
    read -p "Remote Destination IP: " r_ip
    read -p "Remote Destination Port: " r_port
    read -p "Enable TLS Encryption? (yes/no): " use_tls
    
    # Save to database
    echo "$l_port,$r_ip,$r_port,$use_tls" >> "$DB_FILE"
    update_nginx_conf
    echo "------------------------------------"
    echo "✅ Success! Tunnel on Port $l_port is active."
}

# Function to show current status
show_status() {
    echo ">>> ACTIVE TUNNELS (Local Port | Remote IP | Remote Port | TLS):"
    if [ ! -s "$DB_FILE" ]; then
        echo "No tunnels configured."
    else
        column -s, -t < "$DB_FILE"
    fi
    echo "------------------------------------"
    echo ">>> NETWORK TRAFFIC (eth0):"
    ip -s link show eth0 | grep -A 1 "RX" | grep "bytes" || echo "Check interface name."
}

# Main Menu
clear
echo "===================================="
echo "    ULTIMATE NGINX TUNNEL MANAGER   "
echo "===================================="
enable_bbr
echo "1) Add New Tunnel (Hybrid TLS/Plain)"
echo "2) List Active Tunnels & Traffic"
echo "3) Enable Auto-Recovery (Cron)"
echo "4) Delete All Tunnels & Reset"
echo "5) Exit"
echo "------------------------------------"
read -p "Select option [1-5]: " choice

case $choice in
    1) add_tunnel ;;
    2) show_status ;;
    3) (crontab -l 2>/dev/null; echo "*/5 * * * * systemctl is-active --quiet nginx || systemctl restart nginx") | crontab -
       echo "✅ Auto-recovery enabled (checks every 5 mins)." ;;
    4) rm -f "$DB_FILE" && touch "$DB_FILE" && update_nginx_conf
       echo "✅ All tunnels deleted and Nginx reset." ;;
    5) exit 0 ;;
    *) echo "Invalid choice." ;;
esac
