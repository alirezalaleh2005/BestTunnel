#!/usr/bin/env bash
# ==============================================================================
# Installer for BestTunnel-GRE
# Downloads from: https://github.com/alirezalaleh2005/BestTunnel/
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
  error "This installer must be run as root."
  exit 1
fi

# --- Configuration ---
INSTALL_DIR="/opt/besttunnel-gre"
SCRIPT_NAME="besttunnel-gre.sh"
SCRIPT_URL="https://raw.githubusercontent.com/alirezalaleh2005/BestTunnel/main/besttunnel-gre.sh"
DEST_SCRIPT="$INSTALL_DIR/$SCRIPT_NAME"
SYMLINK="/usr/local/bin/besttunnel-gre"

# --- Create directory ---
log "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# --- Download script ---
log "Downloading from GitHub..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$SCRIPT_URL" -o "$DEST_SCRIPT"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$DEST_SCRIPT" "$SCRIPT_URL"
else
  error "Neither curl nor wget is installed. Please install one and try again."
  exit 1
fi

# --- Verify download ---
if [[ ! -s "$DEST_SCRIPT" ]]; then
  error "Download failed or file is empty. Check your internet or GitHub URL."
  exit 1
fi

# --- Set permissions ---
chmod +x "$DEST_SCRIPT"
success "Script downloaded and made executable."

# --- Create symlink ---
if [[ -e "$SYMLINK" ]]; then
  rm -f "$SYMLINK"
fi
ln -sf "$DEST_SCRIPT" "$SYMLINK"
success "Created symlink: $SYMLINK"

# --- Final message ---
echo
success "✅ BestTunnel-GRE installed successfully!"
echo
echo "📌 To run:"
echo "   besttunnel-gre"
echo
echo "📁 Installed at:"
echo "   $DEST_SCRIPT"
echo
echo "🌐 Source: https://github.com/alirezalaleh2005/BestTunnel/"
