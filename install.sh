
#!/bin/bash

# ==========================================================
# File: install.sh (All-in-One Version)
# ==========================================================

if [[ $EUID -ne 0 ]]; then
   echo "Error: Please run as root."
   exit 1
fi

echo ">>> Updating and installing dependencies..."
apt update
# نصب خودکار nginx (در نسخه‌های جدید ماژول stream به صورت پیش‌فرض همراه nginx نصب می‌شود)
apt install -y nginx openssl net-tools bc

# حل مشکل ماژول Stream در برخی نسخه‌های اوبونتو/دبیان
if [ ! -d "/etc/nginx/modules-enabled" ]; then
    apt install -y libnginx-mod-stream
fi

echo ">>> Creating directories..."
mkdir -p /etc/nginx/certs
touch /etc/nginx/tunnel_db.txt

echo ">>> Generating the main script: /usr/local/bin/besttunnel"

# ساخت مستقیم اسکریپت اصلی در مسیر اجرایی سیستم
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
            if [ "$use_tls" == "yes" ]; then
                echo "        listen $l_port ssl; listen $l_port udp;" >> /etc/nginx/nginx.conf
            else
                echo "        listen $l_port; listen $l_port udp;" >> /etc/nginx/nginx.conf
            fi
            echo "        proxy_pass $r_ip:$r_port; proxy_timeout 24h;" >> /etc/nginx/nginx.conf
            echo "    }" >> /etc/nginx/nginx.conf
        done < "$DB_FILE"
    fi
    echo "}" >> /etc/nginx/nginx.conf
    nginx -t && systemctl restart nginx
}

# --- Menu Logic ---
echo "1) Add Tunnel  2) List  3) Recovery  4) Reset  5) Exit"
read -p "Choice: " c
case $c in
    1) read -p "Local Port: " lp; read -p "Remote IP: " rip; read -p "Remote Port: " rp; read -p "TLS (yes/no): " tls
       echo "$lp,$rip,$rp,$tls" >> "$DB_FILE"; update_nginx_conf ;;
    2) column -s, -t < "$DB_FILE" ;;
    3) (crontab -l 2>/dev/null; echo "*/5 * * * * systemctl is-active --quiet nginx || systemctl restart nginx") | crontab - ;;
    4) rm -f "$DB_FILE" && touch "$DB_FILE" && update_nginx_conf ;;
    5) exit 0 ;;
esac
EOF

chmod +x /usr/local/bin/besttunnel

echo "------------------------------------------------"
echo "✅ SUCCESS! Now just type: besttunnel"
echo "------------------------------------------------"
