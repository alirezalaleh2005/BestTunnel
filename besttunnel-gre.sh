#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# === Global Config ===
readonly PROJECT_NAME="besttunnel-gre"
readonly BACKUP_DIR="/root/${PROJECT_NAME}-backup"
readonly LOG_DIR="/var/log"
declare -a LOG_LINES=()
readonly LOG_MIN=3
readonly LOG_MAX=10

# === Banner ===
banner() {
cat <<EOF
╔═════════════════════════════════════════════════════╗
║                                                     ║
║   ██████╗███████╗████████╗██╗   ██╗███████╗██████╗  ║
║   ██╔══██╗██╔════╝╚══██╔══╝██║   ██║██╔════╝██╔══██╗║
║   ██████╔╝█████╗     ██║   ██║   ██║█████╗  ██████╔╝║
║   ██╔══██╗██╔══╝     ██║   ██║   ██║██╔══╝  ██╔══██╗║
║   ██║  ██║███████╗   ██║   ╚██████╔╝███████╗██║  ██║║
║   ╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝║
║                                                     ║
║                BESTTUNNEL-GRE v1.0                  ║
║                                                     ║
╚═════════════════════════════════════════════════════╝
EOF
}

# === Utilities ===
trim() { sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$1"; }
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }
valid_octet() { local o="$1"; [[ "$o" =~ ^[0-9]+$ ]] && ((o >= 0 && o <= 255)); }
valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  valid_octet "$a" && valid_octet "$b" && valid_octet "$c" && valid_octet "$d"
}
valid_port() { local p="$1"; is_int "$p" && ((p >= 1 && p <= 65535)); }
valid_gre_base() { local ip="$1"; valid_ipv4 "$ip" && [[ "$ip" =~ \.0$ ]]; }
ipv4_set_last_octet() { local ip="$1" last="$2"; IFS='.' read -r a b c _ <<<"$ip"; echo "${a}.${b}.${c}.${last}"; }

add_log() {
  local msg="$1" ts="$(date +"%H:%M:%S")"
  LOG_LINES+=("[$ts] $msg")
  if (( ${#LOG_LINES[@]} > LOG_MAX )); then
    LOG_LINES=("${LOG_LINES[@]: -$LOG_MAX}")
  fi
}

render() {
  clear; banner; echo
  local shown=${#LOG_LINES[@]}
  local height=$((shown < LOG_MIN ? LOG_MIN : (shown > LOG_MAX ? LOG_MAX : shown)))
  echo "┌───────────────────────────── ACTION LOG ─────────────────────────────┐"
  local start=$(( ${#LOG_LINES[@]} > height ? ${#LOG_LINES[@]} - height : 0 ))
  for ((i=start; i<${#LOG_LINES[@]}; i++)); do
    printf "│ %-68s │\n" "${LOG_LINES[i]}"
  done
  for ((i=0; i<height - (${#LOG_LINES[@]} - start); i++)); do
    printf "│ %-68s │\n" ""
  done
  echo "└──────────────────────────────────────────────────────────────────────┘"
  echo
}

pause_enter() { read -r -p "Press ENTER to return..." _; }

die_soft() { add_log "ERROR: $1"; render; pause_enter; }

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Re-running with sudo..."
    exec sudo -E bash "$0" "$@"
  fi
}

ask_until_valid() {
  local prompt="$1" validator="$2" __var="$3"
  local ans=""
  while true; do
    render
    read -r -e -p "$prompt " ans
    ans="$(trim "$ans")"
    if [[ -z "$ans" ]]; then
      add_log "Empty input. Please try again."
      continue
    fi
    if "$validator" "$ans"; then
      printf -v "$__var" '%s' "$ans"
      add_log "OK: $prompt $ans"
      return 0
    else
      add_log "Invalid: $prompt $ans"
      add_log "Please enter a valid value."
    fi
  done
}

ask_ports() {
  local raw=""
  while true; do
    render
    read -r -e -p "ForWard PORT (80 | 80,2053 | 2050-2060): " raw
    raw="$(trim "${raw// /}")"
    [[ -n "$raw" ]] || { add_log "Empty ports."; continue; }
    local -a ports=() ok=1
    if [[ "$raw" =~ ^[0-9]+$ ]]; then
      valid_port "$raw" && ports+=("$raw") || ok=0
    elif [[ "$raw" =~ ^[0-9]+-[0-9]+$ ]]; then
      local s="${raw%-*}" e="${raw#*-}"
      if valid_port "$s" && valid_port "$e" && ((s <= e)); then
        for ((p=s; p<=e; p++)); do ports+=("$p"); done
      else
        ok=0
      fi
    elif [[ "$raw" =~ ^[0-9]+(,[0-9]+)+$ ]]; then
      IFS=',' read -r -a parts <<<"$raw"
      for part in "${parts[@]}"; do
        valid_port "$part" && ports+=("$part") || { ok=0; break; }
      done
    else
      ok=0
    fi
    if ((ok == 0)); then
      add_log "Invalid ports: $raw"
      add_log "Examples: 80 | 80,2053 | 2050-2060"
      continue
    fi
    mapfile -t PORT_LIST < <(printf "%s\n" "${ports[@]}" | awk '!seen[$0]++' | sort -n)
    add_log "Ports accepted: ${PORT_LIST[*]}"
    return 0
  done
}

# === Package & System ===
ensure_packages() {
  add_log "Checking required packages: iproute2, socat"
  render
  local missing=()
  command -v ip >/dev/null || missing+=("iproute2")
  command -v socat >/dev/null || missing+=("socat")
  if (( ${#missing[@]} == 0 )); then
    add_log "All required packages are installed."
    return 0
  fi
  add_log "Installing: ${missing[*]}"
  apt-get update -y >/dev/null
  apt-get install -y "${missing[@]}" >/dev/null && add_log "Installed successfully." || return 1
}

systemd_reload() { systemctl daemon-reload >/dev/null; }
unit_exists() { [[ -f "/etc/systemd/system/$1" ]]; }
enable_now() { systemctl enable --now "$1" >/dev/null; }
stop_disable() { systemctl stop "$1" >/dev/null; systemctl disable "$1" >/dev/null; }

# === Service Creation ===
make_gre_service() {
  local id="$1" local_ip="$2" remote_ip="$3" local_gre_ip="$4" key="$5" mtu="${6:-}"
  local unit="gre${id}.service" path="/etc/systemd/system/$unit"
  [[ -f "$path" ]] && { add_log "Service exists: $unit"; return 2; }
  add_log "Creating: $path"
  local mtu_line=""
  [[ -n "$mtu" ]] && mtu_line="ExecStart=/sbin/ip link set gre${id} mtu ${mtu}"
  cat >"$path" <<EOF
[Unit]
Description=GRE Tunnel to (${remote_ip})
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "/sbin/ip tunnel del gre${id} 2>/dev/null || true"
ExecStart=/sbin/ip tunnel add gre${id} mode gre local ${local_ip} remote ${remote_ip} key ${key} nopmtudisc
ExecStart=/sbin/ip addr add ${local_gre_ip}/30 dev gre${id}
${mtu_line}
ExecStart=/sbin/ip link set gre${id} up
ExecStop=/sbin/ip link set gre${id} down
ExecStop=/sbin/ip tunnel del gre${id}
[Install]
WantedBy=multi-user.target
EOF
  add_log "GRE service created: $unit"
}

make_fw_service() {
  local id="$1" port="$2" target_ip="$3"
  local unit="fw-gre${id}-${port}.service" path="/etc/systemd/system/$unit"
  [[ -f "$path" ]] && { add_log "Forwarder exists: $unit"; return; }
  add_log "Creating forwarder: $unit"
  cat >"$path" <<EOF
[Unit]
Description=forward gre${id} ${port}
After=network-online.target gre${id}.service
Wants=network-online.target
[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:${port},reuseaddr,fork TCP4:${target_ip}:${port}
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  add_log "Forwarder created: $unit"
}

# === Setup Functions ===
iran_setup() {
  local ID IRANIP KHAREJIP GREBASE MTU_VALUE=""
  local -a PORT_LIST=()
  ask_until_valid "GRE Number:" is_int ID
  ask_until_valid "IRAN IP:" valid_ipv4 IRANIP
  ask_until_valid "KHAREJ IP:" valid_ipv4 KHAREJIP
  ask_until_valid "GRE IP RANGE (e.g., 10.80.70.0):" valid_gre_base GREBASE
  ask_ports
  read -r -p "Set custom MTU? (y/n): " use_mtu
  [[ "${use_mtu,,}" == "y" ]] && ask_until_valid "MTU (576-1600):" valid_mtu MTU_VALUE

  local key=$((ID * 100))
  local local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"
  local peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"
  add_log "KEY=$key | IRAN=$local_gre_ip | KHAREJ=$peer_gre_ip"

  ensure_packages || { die_soft "Package install failed."; return; }
  make_gre_service "$ID" "$IRANIP" "$KHAREJIP" "$local_gre_ip" "$key" "$MTU_VALUE"
  [[ $? -eq 2 ]] && return
  for p in "${PORT_LIST[@]}"; do make_fw_service "$ID" "$p" "$peer_gre_ip"; done
  systemd_reload
  enable_now "gre${ID}.service"
  for p in "${PORT_LIST[@]}"; do enable_now "fw-gre${ID}-${p}.service"; done
  render
  echo "GRE IPs:"
  echo "  IRAN  : $local_gre_ip"
  echo "  KHAREJ: $peer_gre_ip"
  pause_enter
}

kharej_setup() {
  local ID KHAREJIP IRANIP GREBASE MTU_VALUE=""
  ask_until_valid "GRE Number (same as Iran):" is_int ID
  ask_until_valid "KHAREJ IP:" valid_ipv4 KHAREJIP
  ask_until_valid "IRAN IP:" valid_ipv4 IRANIP
  ask_until_valid "GRE IP RANGE (same as Iran):" valid_gre_base GREBASE
  read -r -p "Set custom MTU? (y/n): " use_mtu
  [[ "${use_mtu,,}" == "y" ]] && ask_until_valid "MTU (576-1600):" valid_mtu MTU_VALUE

  local key=$((ID * 100))
  local local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"
  local peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"
  add_log "KEY=$key | KHAREJ=$local_gre_ip | IRAN=$peer_gre_ip"

  ensure_packages || { die_soft "Package install failed."; return; }
  make_gre_service "$ID" "$KHAREJIP" "$IRANIP" "$local_gre_ip" "$key" "$MTU_VALUE"
  [[ $? -eq 2 ]] && return
  systemd_reload
  enable_now "gre${ID}.service"
  render
  echo "GRE IPs:"
  echo "  KHAREJ: $local_gre_ip"
  echo "  IRAN  : $peer_gre_ip"
  pause_enter
}

# === Helper Queries ===
get_gre_ids() {
  {
    systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}'
    find /etc/systemd/system -maxdepth 1 -name 'gre*.service' 2>/dev/null
  } | grep -oE '^gre([0-9]+)\.service$' | cut -d'g' -f2 | cut -d'.' -f1 | sort -nu
}

get_fw_units_for_id() {
  find /etc/systemd/system -maxdepth 1 -name "fw-gre${1}-*.service" 2>/dev/null | sort -V
}

get_all_fw_units() {
  find /etc/systemd/system -maxdepth 1 -name "fw-gre*-*.service" 2>/dev/null | sort -V
}

# === Menus ===
MENU_SELECTED=-1
menu_select_index() {
  local title="$1" prompt="$2"; shift 2
  local -a items=("$@")
  local choice=""
  while true; do
    render
    echo "$title"; echo
    if (( ${#items[@]} == 0 )); then
      echo "No service found."; pause_enter; MENU_SELECTED=-1; return 1
    fi
    for i in "${!items[@]}"; do
      printf "%d) %s\n" $((i+1)) "${items[i]}"
    done
    echo "0) Back"
    read -r -e -p "$prompt " choice
    choice="$(trim "$choice")"
    if [[ "$choice" == "0" ]]; then MENU_SELECTED=-1; return 1; fi
    if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#items[@]})); then
      MENU_SELECTED=$((choice - 1)); return 0
    fi
    add_log "Invalid selection: $choice"
  done
}

service_action_menu() {
  local unit="$1" action=""
  while true; do
    render
    echo "Selected: $unit"; echo
    echo "1) Enable & Start"
    echo "2) Restart"
    echo "3) Stop & Disable"
    echo "4) Status"
    echo "0) Back"
    read -r -e -p "Select action: " action
    case "$(trim "$action")" in
      1) systemctl enable "$unit" >/dev/null; systemctl start "$unit" >/dev/null; add_log "Started: $unit" ;;
      2) systemctl restart "$unit" >/dev/null; add_log "Restarted: $unit" ;;
      3) systemctl stop "$unit" >/dev/null; systemctl disable "$unit" >/dev/null; add_log "Stopped & Disabled: $unit" ;;
      4) render; systemctl --no-pager status "$unit" | head -16; pause_enter ;;
      0) return ;;
      *) add_log "Invalid action: $action" ;;
    esac
  done
}

services_management() {
  local sel=""
  while true; do
    render
    echo "Services Management"; echo
    echo "1) GRE"
    echo "2) Forwarder"
    echo "0) Back"
    read -r -e -p "Select: " sel
    case "$(trim "$sel")" in
      1)
        mapfile -t GRE_IDS < <(get_gre_ids)
        local -a GRE_LABELS=(); for id in "${GRE_IDS[@]}"; do GRE_LABELS+=("GRE$id"); done
        menu_select_index "GRE Services" "Select GRE:" "${GRE_LABELS[@]}" && service_action_menu "gre${GRE_IDS[MENU_SELECTED]}.service"
        ;;
      2)
        mapfile -t FW_UNITS < <(get_all_fw_units)
        local -a FW_LABELS=()
        for u in "${FW_UNITS[@]}"; do
          [[ "$u" =~ ^fw-gre([0-9]+)-([0-9]+)\.service$ ]] && FW_LABELS+=("GRE${BASH_REMATCH[1]}:${BASH_REMATCH[2]}")
        done
        menu_select_index "Forwarder Services" "Select Forwarder:" "${FW_LABELS[@]}" && service_action_menu "${FW_UNITS[MENU_SELECTED]}"
        ;;
      0) return ;;
      *) add_log "Invalid selection: $sel" ;;
    esac
  done
}

# === Uninstall & Automation ===
automation_script_path() { echo "/usr/local/bin/${PROJECT_NAME}-recreate${1}.sh"; }
automation_log_path() { echo "${LOG_DIR}/${PROJECT_NAME}${1}.log"; }

uninstall_clean() {
  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=(); for id in "${GRE_IDS[@]}"; do GRE_LABELS+=("GRE$id"); done
  menu_select_index "Uninstall & Clean" "Select GRE:" "${GRE_LABELS[@]}" || return
  local id="${GRE_IDS[MENU_SELECTED]}"
  render
  echo "Uninstall & Clean"; echo
  echo "Target: GRE$id"
  echo "This will remove:"
  echo "  - /etc/systemd/system/gre${id}.service"
  echo "  - /etc/systemd/system/fw-gre${id}-*.service"
  echo "  - cron + $(automation_script_path "$id")"
  echo "  - $(automation_log_path "$id")"
  echo "  - $BACKUP_DIR/gre${id}.service (and fw backups)"
  echo; read -r -p "Type YES to confirm: " confirm
  [[ "$(trim "$confirm")" != "YES" ]] && { add_log "Cancelled."; return; }

  systemctl stop "gre${id}.service" >/dev/null 2>&1 || true
  systemctl disable "gre${id}.service" >/dev/null 2>&1 || true
  for u in $(get_fw_units_for_id "$id"); do
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
  done
  rm -f "/etc/systemd/system/gre${id}.service" "/etc/systemd/system/fw-gre${id}"-* 2>/dev/null
  systemctl daemon-reload; systemctl reset-failed

  # Remove automation
  crontab -l 2>/dev/null | grep -vF "$(automation_script_path "$id")" | crontab -
  rm -f "$(automation_script_path "$id})" "$(automation_log_path "$id})"
  rm -f "$BACKUP_DIR/gre${id}.service" "$BACKUP_DIR/fw-gre${id}"-* 2>/dev/null

  add_log "Uninstall completed for GRE$id"
  render; pause_enter
}

# === Add Port & MTU ===
add_tunnel_port() {
  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=(); for id in "${GRE_IDS[@]}"; do GRE_LABELS+=("GRE$id"); done
  menu_select_index "Add Tunnel Port" "Select GRE:" "${GRE_LABELS[@]}" || return
  local id="${GRE_IDS[MENU_SELECTED]}"
  ask_ports
  local cidr=$(ip -4 addr show dev "gre$id" 2>/dev/null | awk '/inet /{print $2}' | head -n1)
  [[ -n "$cidr" ]] || { die_soft "gre$id not UP."; return; }
  [[ "${cidr#*/}" == "30" ]] || { die_soft "Mask must be /30."; return; }
  local ip="${cidr%/*}" base_last=$(( $(IFS='.'; echo "$ip" | awk '{print $4}') & 252 ))
  local target_ip="$(IFS='.'; echo "$ip" | awk -v bl="$base_last" '{print $1"."$2"."$3"."(bl+2)}')"
  for p in "${PORT_LIST[@]}"; do make_fw_service "$id" "$p" "$target_ip"; done
  systemd_reload
  for p in "${PORT_LIST[@]}"; do enable_now "fw-gre${id}-${p}.service"; done
  render
  echo "Added ports to GRE$id → $target_ip"
  pause_enter
}

change_mtu() {
  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=(); for id in "${GRE_IDS[@]}"; do GRE_LABELS+=("GRE$id"); done
  menu_select_index "Change MTU" "Select GRE:" "${GRE_LABELS[@]}" || return
  local id="${GRE_IDS[MENU_SELECTED]}" mtu=""
  ask_until_valid "New MTU (576-1600):" valid_mtu mtu
  ip link set "gre$id" mtu "$mtu" >/dev/null 2>&1 || true
  for file in "/etc/systemd/system/gre${id}.service" "$BACKUP_DIR/gre${id}.service"; do
    [[ -f "$file" ]] || continue
    if grep -qE "^ExecStart=/sbin/ip link set gre${id} mtu [0-9]+$" "$file"; then
      sed -i "s|^ExecStart=/sbin/ip link set gre${id} mtu [0-9]*$|ExecStart=/sbin/ip link set gre${id} mtu ${mtu}|" "$file"
    elif grep -qE "^ExecStart=/sbin/ip link set gre${id} up$" "$file"; then
      sed -i "s|^ExecStart=/sbin/ip link set gre${id} up$|ExecStart=/sbin/ip link set gre${id} mtu ${mtu}\nExecStart=/sbin/ip link set gre${id} up|" "$file"
    else
      echo -e "\nExecStart=/sbin/ip link set gre${id} mtu ${mtu}" >> "$file"
    fi
  done
  systemd_reload
  systemctl restart "gre${id}.service" >/dev/null 2>&1 || true
  add_log "MTU changed to $mtu for GRE$id"
  render; pause_enter
}

# === Automation (Regenerate / Rebuild) ===
select_and_set_timezone() {
  local tz_map=(
    "Europe/Berlin" "Europe/Istanbul" "Europe/Paris" "Europe/Amsterdam"
    "Europe/Helsinki" "Europe/London" "Europe/Stockholm" "Europe/Moscow"
    "America/New_York" "America/Toronto" "Etc/UTC"
  )
  local tz_names=(
    "Germany" "Turkey" "France" "Netherlands"
    "Finland" "England" "Sweden" "Russia"
    "USA" "Canada" "UTC"
  )
  while true; do
    render
    echo "Select server timezone (for cron sync):"; echo
    for i in "${!tz_map[@]}"; do
      echo "$((i+1))) ${tz_names[i]} (${tz_map[i]})"
    done
    echo "0) Skip"
    read -r -p "Select: " choice
    case "$choice" in
      ''|0) add_log "Timezone skipped."; return 0 ;;
      *[!0-9]*) continue ;;
      *) if ((choice >= 1 && choice <= ${#tz_map[@]})); then
           timedatectl set-timezone "${tz_map[choice-1]}" >/dev/null
           timedatectl set-ntp true >/dev/null
           add_log "Timezone set to ${tz_map[choice-1]}"
           return 0
         fi ;;
    esac
  done
}

recreate_automation_common() {
  local rebuild_mode="$1"
  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=(); for id in "${GRE_IDS[@]}"; do GRE_LABELS+=("GRE$id"); done
  menu_select_index "Automation" "Select GRE:" "${GRE_LABELS[@]}" || return
  local id="${GRE_IDS[MENU_SELECTED]}"

  local side=""
  while true; do
    render; echo "Select Side"; echo "1) IRAN"; echo "2) KHAREJ"
    read -r -p "Select: " s
    [[ "$s" == "1" ]] && { side="IRAN"; break; }
    [[ "$s" == "2" ]] && { side="KHAREJ"; break; }
    add_log "Invalid side"
  done

  select_and_set_timezone || { die_soft "Timezone setup failed."; return; }

  local mode="" val=""
  while true; do
    render; echo "Time Mode"; echo "1) Hourly (1-12)"; echo "2) Minute (15-45)"
    read -r -p "Select: " mode
    [[ "$mode" == "1" || "$mode" == "2" ]] && break
    add_log "Invalid mode"
  done
  while true; do
    read -r -p "Interval value: " val
    if [[ "$mode" == "1" && "$val" =~ ^([1-9]|1[0-2])$ ]]; then break; fi
    if [[ "$mode" == "2" && "$val" =~ ^(1[5-9]|[2-3][0-9]|4[0-5])$ ]]; then break; fi
    add_log "Invalid value"
  done

  local script="$(automation_script_path "$id")"
  if [[ "$rebuild_mode" == "rebuild" ]]; then
    cat > "$script" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ID="${id}"
SIDE="${side}"
UNIT="/etc/systemd/system/gre\${ID}.service"
LOG_FILE="$(automation_log_path "\${ID}")"
BACKUP_DIR="${BACKUP_DIR}"
TZ="Europe/Berlin"
mkdir -p "\$LOG_FILE" >/dev/null 2>&1 || true
log() { echo "[\$(TZ="\$TZ" date '+%Y-%m-%d %H:%M %Z')] \$1" >> "\$LOG_FILE"; }
list_fw() { find /etc/systemd/system -maxdepth 1 -name "fw-gre\${ID}-*.service" 2>/dev/null; }
[[ -f "\$UNIT" ]] || { log "ERROR: unit not found"; exit 1; }
mkdir -p "\$BACKUP_DIR"
[[ -f "\$BACKUP_DIR/gre\${ID}.service" ]] || cp "\$UNIT" "\$BACKUP_DIR/gre\${ID}.service"
if [[ "\$SIDE" == "IRAN" ]]; then
  while IFS= read -r fw; do [[ -f "\$fw" ]] && cp "\$fw" "\$BACKUP_DIR/"; done < <(list_fw)
fi
systemctl stop "gre\${ID}.service" >/dev/null 2>&1 || true
ip link set "gre\${ID}" down 2>/dev/null || true
ip tunnel del "gre\${ID}" 2>/dev/null || true
rm -f "\$UNIT"
if [[ "\$SIDE" == "IRAN" ]]; then rm -f /etc/systemd/system/fw-gre\${ID}-*.service; fi
cp "\$BACKUP_DIR/gre\${ID}.service" "\$UNIT"
if [[ "\$SIDE" == "IRAN" ]]; then
  for f in "\$BACKUP_DIR"/fw-gre\${ID}-*.service; do [[ -f "\$f" ]] && cp "\$f" /etc/systemd/system/; done
fi
systemctl daemon-reload
systemctl enable --now "gre\${ID}.service"
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
if [[ "\$SIDE" == "IRAN" ]]; then
  for u in /etc/systemd/system/fw-gre\${ID}-*.service; do [[ -f "\$u" ]] && systemctl enable --now "\$(basename "\$u")"; done
fi
log "Rebuilt from backup | SIDE=\$SIDE"
EOF
  else
    cat > "$script" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ID="${id}"
SIDE="${side}"
UNIT="/etc/systemd/system/gre\${ID}.service"
LOG_FILE="$(automation_log_path "\${ID}")"
TZ="Europe/Berlin"
log() { echo "[\$(TZ="\$TZ" date '+%Y-%m-%d %H:%M %Z')] \$1" >> "\$LOG_FILE"; }
[[ -f "\$UNIT" ]] || { log "ERROR: unit not found"; exit 1; }
old_ip=\$(grep -oP 'ip addr add \\K([0-9.]+)' "\$UNIT" | head -n1)
[[ -n "\$old_ip" ]] || { log "ERROR: old IP not found"; exit 1; }
IFS='.' read -r b1 oldblock b3 b4 <<< "\$old_ip"
oldblock=\$((10#\$oldblock))
if (( oldblock > 230 )); then oldblock=4; fi
DAY=\$((10#\$(TZ="\$TZ" date +%d)))
HOUR=\$((10#\$(TZ="\$TZ" date +%H)))
AMPM=\$(TZ="\$TZ" date +%p)
datetimecountnumber=\$((DAY + HOUR))
if (( DAY <= 15 )); then
  if [[ "\$AMPM" == "AM" ]]; then newblock=\$((datetimecountnumber + oldblock + 7))
  else newblock=\$((datetimecountnumber + oldblock - 13)); fi
else
  if [[ "\$AMPM" == "AM" ]]; then newblock=\$((datetimecountnumber + oldblock + 3))
  else newblock=\$((datetimecountnumber + oldblock - 5)); fi
fi
(( newblock > 245 )) && newblock=245
(( newblock < 0 )) && newblock=0
new_ip="\${b1}.\${newblock}.\${datetimecountnumber}.\${b4}"
sed -i.bak -E "s/ip addr add [0-9.]+\\/30/ip addr add \${new_ip}\\/30/" "\$UNIT"
if [[ "\$SIDE" == "IRAN" ]]; then
  for fw in /etc/systemd/system/fw-gre\${ID}-*.service; do
    [[ -f "\$fw" ]] && sed -i.bak -E "s/TCP:[0-9.]+:/TCP:\${new_ip}:/" "\$fw"
  done
fi
systemctl stop "gre\${ID}.service" >/dev/null 2>&1 || true
ip link set "gre\${ID}" down 2>/dev/null || true
ip tunnel del "gre\${ID}" 2>/dev/null || true
systemctl daemon-reload
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
systemctl enable --now "gre\${ID}.service"
if [[ "\$SIDE" == "IRAN" ]]; then
  for u in /etc/systemd/system/fw-gre\${ID}-*.service; do
    [[ -f "\$u" ]] && systemctl restart "\$(basename "\$u")"
  done
fi
log "Regenerated | OLD=\$old_ip | NEW=\$new_ip"
EOF
  fi
  chmod +x "$script"
  local cron_line
  if [[ "$mode" == "1" ]]; then cron_line="0 */${val} * * * $script"
  else cron_line="*/${val} * * * * $script"; fi
  (crontab -l 2>/dev/null | grep -vF "$script" || true; echo "$cron_line") | crontab -
  add_log "Automation created for GRE$id"
  add_log "Script: $script"
  add_log "Cron: $cron_line"
  pause_enter
}

# === Main Menu ===
main_menu() {
  local choice=""
  while true; do
    render
    echo "1 > IRAN SETUP"
    echo "2 > KHAREJ SETUP"
    echo "3 > Services Management"
    echo "4 > Uninstall & Clean"
    echo "5 > Add Tunnel Port"
    echo "6 > Rebuild Automation (from backup)"
    echo "7 > Regenerate Automation (dynamic IP)"
    echo "8 > Change MTU"
    echo "0 > Exit"
    read -r -e -p "Select option: " choice
    case "$(trim "$choice")" in
      1) iran_setup ;;
      2) kharej_setup ;;
      3) services_management ;;
      4) uninstall_clean ;;
      5) add_tunnel_port ;;
      6) recreate_automation_common "rebuild" ;;
      7) recreate_automation_common "regenerate" ;;
      8) change_mtu ;;
      0) add_log "Bye!"; render; exit 0 ;;
      *) add_log "Invalid option: $choice" ;;
    esac
  done
}

# === Bootstrap ===
ensure_root "$@"
mkdir -p "$BACKUP_DIR" "$LOG_DIR" 2>/dev/null || true
add_log "${PROJECT_NAME} installer started."
main_menu
