#!/bin/bash

# ==========================================================
# Project: BestTunnel Ultimate Edition
# Developer: alirezalaleh2005
# Features: GRE/IPIP/SIT, Internal Speedtest, BBR, Anti-DPI
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
    if [ -z "$IP_BASE" ]; then echo -e "${RED}خطا: ابتدا تانل را راه‌اندازی کنید.${NC}"; return; fi

    echo -e "${YELLOW}در حال نصب و آماده‌سازی iperf3...${NC}"
    apt-get update -qq && apt-get install -y iperf3 > /dev/null 2>&1
    
    TARGET_IP="$IP_BASE.2"; [ "$ROLE" == "2" ] && TARGET_IP="$IP_BASE.1"

    echo -e "${CYAN}>>> شروع تست سرعت داخلی به سمت $TARGET_IP...${NC}"
    echo -e "${YELLOW}نکته: برای نتیجه دقیق، این گزینه را همزمان روی هر دو سرور اجرا کنید.${NC}"
    
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
    
    echo -e "وضعیت اتصال: $status | پروتکل فعال: ${YELLOW}$current_mode${NC}"
    echo "--------------------------------------------------------------------------------------"
    echo -e "1) 🛠️  راه‌اندازی تانل (Setup/Update)"
    echo -e "2) ⚡  تست سرعت داخلی (Internal Speedtest)"
    echo -e "3) 🔄  تغییر پروتکل (GRE / IPIP / SIT)"
    echo -e "4) 🛡️  مسیریابی پورت‌ها (Routing)"
    echo -e "5) 🚀  بهینه‌سازی سرعت (BBR)"
    echo -e "6) 🧨  حذف کامل تنظیمات (Reset)"
    echo -e "0)  خروج"
    echo "--------------------------------------------------------------------------------------"
    read -p "یک گزینه را انتخاب کنید: " OPT

    case $OPT in
        1)
            echo -e "${CYAN}تنظیمات اولیه:${NC}"
            read -p "نقش سرور (1 برای ایران / 2 برای خارج): " ROLE
            read -p "آی‌پی سرور مقابل: " REMOTE_IP
            read -p "رنج آی‌پی تانل (مثلاً 10.0.0): " IP_BASE
            IP_BASE=${IP_BASE:-"10.0.0"}
            
            echo -e "ROLE=$ROLE\nREMOTE_IP=$REMOTE_IP\nIP_BASE=$IP_BASE\nMODE=gre" > $CONFIG_FILE
            apply_configs
            echo -e "${GREEN}تانل با موفقیت راه‌اندازی شد.${NC}" ;;
            
        2) run_internal_speedtest ;;
        
        3)
            echo -e "1) GRE (پیش‌فرض/سریع)\n2) IPIP (سبک)\n3) SIT (عبور از فیلترینگ شدید)"
            read -p "پروتکل را انتخاب کنید: " P
            case $P in
                1) M="gre" ;;
                2) M="ipip" ;;
                3) M="sit" ;;
                *) M="gre" ;;
            esac
            sed -i "s/MODE=.*/MODE=$M/" $CONFIG_FILE
            apply_configs
            echo -e "${GREEN}پروتکل به $M تغییر یافت.${NC}" ;;
            
        4)
            read -p "پورت‌های مورد نظر را وارد کنید (مثلاً 443,80,20000:30000): " PORTS
            source $CONFIG_FILE
            R_TUN="$IP_BASE.2"; [ "$ROLE" == "2" ] && R_TUN="$IP_BASE.1"
            if ! grep -q "100 tunnel" /etc/iproute2/rt_tables; then echo "100 tunnel" >> /etc/iproute2/rt_tables; fi
            iptables -t mangle -F
            iptables -t mangle -A PREROUTING -p tcp -m multiport --dports "$PORTS" -j MARK --set-mark 1
            iptables -t mangle -A PREROUTING -p udp -m multiport --dports "$PORTS" -j MARK --set-mark 1
            ip rule add fwmark 1 table tunnel 2>/dev/null
            ip route replace default via "$R_TUN" dev $INTERFACE_NAME table tunnel
            echo -e "${GREEN}مسیریابی برای پورت‌های $PORTS اعمال شد.${NC}" ;;
            
        5)
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
            sysctl -p
            echo -e "${GREEN}بهینه‌ساز BBR فعال شد.${NC}" ;;
            
        6)
            ip link del "$INTERFACE_NAME" 2>/dev/null
            rm $CONFIG_FILE 2>/dev/null
            iptables -F && iptables -t nat -F && iptables -t mangle -F
            echo -e "${RED}تمام تنظیمات پاکسازی شد.${NC}" ;;
            
        0) exit 0 ;;
    esac
    read -p "برای بازگشت اینتر بزنید..."
done
