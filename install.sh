#!/bin/bash

# ==========================================================
# Project: BestTunnel Manager
# URL: https://github.com/alirezalaleh2005/BestTunnel
# ==========================================================

# Colors for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Please run as root (sudo).${NC}"
   exit 1
fi

echo -e "${GREEN}>>> Initializing BestTunnel Installation...${NC}"

# 1. Update and install Nginx + dependencies
apt update
apt install -y nginx openssl net-tools bc libnginx-mod-stream

# 2. Setup Directories and Database
mkdir -p /etc/nginx/certs
touch /etc/nginx/tunnel_db.txt

# 3. Create the executable binary in /usr/local/bin
echo -e "${GREEN}>>> Creating management command 'besttunnel'...${NC}"

cat <<'EOF' > /usr/local/bin/besttunnel
#!/bin/bash
DB_FILE="/etc/nginx/tunnel_db.txt"
CERT_DIR="/etc/nginx/certs"

prepare_ssl() {
    if [ ! -f "$CERT_DIR/tunnel.crt" ]; then
        mkdir -p "$CERT_DIR"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/tunnel.key" -out "$CERT_DIR/tunnel.crt" \
        -subj "/C=US/ST=NY/L=NY/O=IT/CN=www.google.com" > /dev/null 2>&1
    fi
}

update_nginx_conf() {
    prepare_ssl
    cat <<EON > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
include /etc/nginx/modules-enabled/*.conf;
events { worker_connections 4096; }
stream {
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate $CERT_DIR/tunnel.crt;
    ssl_certificate_key $CERT_DIR/tunnel.key;
EON
    if [ -f "$DB_FILE" ]; then
        while IFS=, read -r l_port r_ip r_port use_tls; do
            echo "    server {" >> /etc/nginx/nginx.conf
            [[ "$use_tls" == "yes" ]] && ssl_tag="ssl" || ssl_tag=""
            echo "        listen $l_port $ssl_tag; listen $l_port udp;" >> /etc/nginx/nginx.conf
            echo "        proxy_pass $r_ip:$r_port; proxy_timeout 24h; proxy_connect_timeout 2s;" >> /etc/nginx/nginx.conf
            echo "    }" >> /etc/nginx/nginx.conf
        done < "$DB_FILE"
    fi
    echo "}" >> /etc/nginx/nginx.conf
    nginx -t && systemctl restart nginx
}

# Simple Menu Logic
clear
echo "BestTunnel Manager v7.5"
echo "1) Add Tunnel"
echo "2) List Tunnels"
echo "3) Reset All"
echo "4) Exit"
read -p "Choice: " c
case $c in
    1) read -p "Local Port: " lp; read -p "Remote IP: " rip; read -p "Remote Port: " rp; read -p "TLS (yes/no): " tls
       echo "$lp,$rip,$rp,$tls" >> "$DB_FILE"; update_nginx_conf ;;
    2) column -s, -t < "$DB_FILE" ;;
    3) rm -f "$DB_FILE" && touch "$DB_FILE" && update_nginx_conf ;;
    4) exit 0 ;;
esac
EOF

chmod +x /usr/local/bin/besttunnel

echo -e "------------------------------------------------"
echo -e "${GREEN}✅ INSTALLATION SUCCESSFUL!${NC}"
echo -e "Run the manager by typing: ${GREEN}besttunnel${NC}"
echo -e "------------------------------------------------"
