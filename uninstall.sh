#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Riva uninstaller
# ---------------------------------------------------------------------------

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}${BOLD}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}${BOLD}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}${BOLD}[warn]${NC}  $*"; }

echo ""
echo -e "${BOLD}Riva Uninstaller${NC}"
echo ""

# Stop the web dashboard if running
RIVA_CONFIG="$HOME/.config/riva"
PID_FILE="$RIVA_CONFIG/web.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        info "Stopping web dashboard (PID $PID)..."
        kill "$PID" 2>/dev/null || true
        sleep 1
        ok "Dashboard stopped"
    fi
    rm -f "$PID_FILE"
fi

# Uninstall the Python package
info "Uninstalling riva package..."
python3 -m pip uninstall -y riva 2>/dev/null || \
    python3 -m pip uninstall -y riva 2>/dev/null || \
    warn "Package not found (may already be uninstalled)"

ok "Package removed"

# Ask about config cleanup
echo ""
read -rp "Remove Riva config directory ($RIVA_CONFIG)? [y/N] " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    rm -rf "$RIVA_CONFIG"
    ok "Config directory removed"
else
    info "Config directory kept at $RIVA_CONFIG"
fi

echo ""
ok "Riva has been uninstalled."
echo ""
