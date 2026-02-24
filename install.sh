#!/bin/bash
#=================================================
# Paqet-X Client Manager v3.0 (90-Day Offline Trial)
# Developed for Best AI / IliyaDev
#=================================================

# Colors
readonly RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m' BLUE='\033[0;34m' MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m' NC='\033[0m'

# Config Paths
readonly LICENSE_DIR="/etc/paqet-x"
readonly TRIAL_FILE="$LICENSE_DIR/.trial_data"
readonly LICENSE_FILE="$LICENSE_DIR/.license_key"
readonly FLAG_FILE="$LICENSE_DIR/.trial_used_flag"

# ⚙️ تنظیمات تست رایگان
# 90 Days = 90 * 24 * 60 * 60 = 7,776,000 Seconds
readonly TRIAL_DURATION_SECONDS=7776000 
readonly SECRET_SALT="BestAI-Secure-Salt-90Days-2024"

# ═══════════════════════════════════════
#  Helper Functions
# ═══════════════════════════════════════
print_step()    { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }
print_info()    { echo -e "${CYAN}[i]${NC} $1"; }

check_root() { 
    if [[ $EUID -ne 0 ]]; then 
        print_error "Please run as root (sudo ./install)"; 
        exit 1; 
    fi 
}

# Get Unique Hardware Fingerprint (MAC + Machine ID)
get_fingerprint() {
    local interface=$(ip route | grep default | awk '{print $5}' | head -1)
    local mac=""
    if [ -n "$interface" ] && [ -f "/sys/class/net/$interface/address" ]; then
        mac=$(cat "/sys/class/net/$interface/address" | tr -d ':' | tr '[:upper:]' '[:lower:]')
    else
        # Fallback to first available interface
        mac=$(ls /sys/class/net/ | grep -v lo | head -1 | xargs -I {} cat /sys/class/net/{}/address 2>/dev/null | tr -d ':' | tr '[:upper:]' '[:lower:]')
    fi
    
    local mid=$(cat /etc/machine-id 2>/dev/null | head -c 16)
    
    if [ -z "$mac" ] || [ -z "$mid" ]; then
        echo "unknown-host-$(hostname | tr -d ' ')"
    else
        echo "${mid}-${mac}"
    fi
}

# Generate SHA256 Signature
generate_signature() {
    local data="$1"
    echo -n "${data}${SECRET_SALT}" | sha256sum | cut -d' ' -f1
}

# ═══════════════════════════════════════
#  Core Logic: 90-Day Trial System
# ═══════════════════════════════════════

activate_90day_trial() {
    local fp=$(get_fingerprint)
    local start_time=$(date +%s)
    local expiry_time=$((start_time + TRIAL_DURATION_SECONDS))
    
    # Content: fingerprint|start|expiry
    local content="${fp}|${start_time}|${expiry_time}"
    local signature=$(generate_signature "$content")
    
    # Ensure directory exists
    mkdir -p "$LICENSE_DIR"
    
    # Write secure file
    echo "${content}|${signature}" > "$TRIAL_FILE"
    chmod 600 "$TRIAL_FILE"
    chown root:root "$TRIAL_FILE"
    
    # Create immutable flag to prevent re-trial after expiration
    touch "$FLAG_FILE"
    chmod 444 "$FLAG_FILE" # Read-only
    
    local expiry_date=$(date -d "@$expiry_time" '+%Y-%m-%d %H:%M:%S')
    
    print_success "90-Day Free Trial Activated Automatically!"
    print_info "Start Date: $(date '+%Y-%m-%d %H:%M:%S')"
    print_info "Expiry Date: ${expiry_date}"
    print_warning "Do not delete files in $LICENSE_DIR or trial will be lost."
}

check_trial_status() {
    # 1. Check if trial was ever used (Flag check)
    if [ -f "$FLAG_FILE" ] && [ ! -f "$TRIAL_FILE" ]; then
        # Flag exists but data file is missing -> Means expired and cleaned, or tampered
        # If flag is read-only, they can't easily remove it without root effort
        print_error "Free Trial has already been used on this server."
        return 1
    fi

    # 2. Check if trial file exists
    if [ ! -f "$TRIAL_FILE" ]; then
        return 2 # No trial found (needs activation)
    fi

    # 3. Validate Integrity & Time
    local line=$(cat "$TRIAL_FILE")
    local stored_fp=$(echo "$line" | cut -d'|' -f1)
    local stored_start=$(echo "$line" | cut -d'|' -f2)
    local stored_expiry=$(echo "$line" | cut -d'|' -f3)
    local stored_sig=$(echo "$line" | cut -d'|' -f4)

    # Verify Signature (Anti-Tamper)
    local current_content="${stored_fp}|${stored_start}|${stored_expiry}"
    local expected_sig=$(generate_signature "$current_content")
    
    if [ "$stored_sig" != "$expected_sig" ]; then
        print_error "Security Alert: Trial file tampered! Access denied."
        rm -f "$TRIAL_FILE"
        return 1
    fi

    # Verify Hardware (Anti-Copy)
    local current_fp=$(get_fingerprint)
    if [ "$stored_fp" != "$current_fp" ]; then
        print_error "Hardware Mismatch: Trial cannot be transferred to another server."
        return 1
    fi

    # Verify Time
    local now=$(date +%s)
    if [ "$now" -gt "$stored_expiry" ]; then
        print_error "90-Day Free Trial Has Expired."
        print_info "Please purchase a full license to continue."
        rm -f "$TRIAL_FILE" # Clean up expired file
        return 1
    fi

    # Success
    local remaining_days=$(( (stored_expiry - now) / 86400 ))
    local remaining_hours=$(( ((stored_expiry - now) % 86400) / 3600 ))
    print_success "Trial Active: ${remaining_days} days and ${remaining_hours} hours remaining."
    return 0
}

# Main Access Validator
validate_access() {
    # Priority 1: Full License Key (If user bought it)
    if [ -f "$LICENSE_FILE" ]; then
        local key=$(cat "$LICENSE_FILE")
        if [ -n "$key" ]; then
            print_success "Full License Detected. Trial restrictions bypassed."
            return 0
        fi
    fi

    # Priority 2: Check Existing Trial
    check_trial_status
    local status=$?

    if [ $status -eq 0 ]; then
        return 0 # Valid trial
    elif [ $status -eq 1 ]; then
        return 1 # Invalid/Expired/Tampered
    elif [ $status -eq 2 ]; then
        # No trial found, activate automatically
        print_info "No license found. Initializing 90-Day Auto-Trial..."
        activate_90day_trial
        
        # Re-check immediately after activation
        if check_trial_status; then
            return 0
        else
            return 1
        fi
    fi
    
    return 1
}

# ═══════════════════════════════════════
#  Installation & Configuration Logic
# ═══════════════════════════════════════

configure_server() {
    clear
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║           PAQET-X Server Configuration                       ║${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # CRITICAL CHECK BEFORE CONFIGURATION
    if ! validate_access; then
        echo ""
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ACCESS DENIED                                               ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "Reason: Trial expired or invalid."
        echo "Solution: Contact admin for a full license key."
        echo ""
        exit 1
    fi

    echo -e "${GREEN}Access Granted. Proceeding with configuration...${NC}"
    sleep 2
    
    # ... (Here you would put your actual server configuration logic) ...
    # Example placeholder:
    read -p "Enter Server Port (default 8888): " port
    port=${port:-8888}
    print_step "Configuring server on port $port..."
    print_success "Configuration Complete!"
}

show_menu() {
    while true; do
        clear
        echo -e "${WHITE}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${WHITE}║  Paqet-X Manager (90-Day Trial Edition)                      ║${NC}"
        echo -e "${WHITE}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}1.${NC} 🚀 Configure / Run Server"
        echo -e "${CYAN}2.${NC} 🔑 Enter Full License Key"
        echo -e "${CYAN}3.${NC} ℹ️  Check Trial Status"
        echo -e "${CYAN}4.${NC} ❌ Exit"
        echo ""
        read -p "Select an option [1-4]: " choice

        case $choice in
            1) configure_server ;;
            2)
                read -p "Enter your License Key: " lkey
                if [ -n "$lkey" ]; then
                    echo "$lkey" > "$LICENSE_FILE"
                    chmod 600 "$LICENSE_FILE"
                    print_success "License key saved successfully."
                    read -p "Press Enter to continue..."
                else
                    print_error "Key cannot be empty."
                fi
                ;;
            3)
                validate_access
                read -p "Press Enter to continue..."
                ;;
            4) exit 0 ;;
            *) print_error "Invalid option." ; sleep 1 ;;
        esac
    done
}

# Start
check_root
show_menu
