#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Riva installer — works on macOS, Linux, and WSL2
# ---------------------------------------------------------------------------

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}${BOLD}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}${BOLD}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}${BOLD}[warn]${NC}  $*"; }
err()   { echo -e "${RED}${BOLD}[error]${NC} $*"; }

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

detect_os() {
    case "$(uname -s)" in
        Darwin) OS="macos" ;;
        Linux)  OS="linux" ;;
        *)      err "Unsupported OS: $(uname -s). Use macOS, Linux, or WSL2."; exit 1 ;;
    esac
    info "Detected OS: $OS"
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

check_python() {
    local py=""
    for candidate in python3 python; do
        if command -v "$candidate" &>/dev/null; then
            py="$candidate"
            break
        fi
    done

    if [ -z "$py" ]; then
        err "Python 3.11+ is required but not found."
        err "Install it from https://www.python.org/downloads/ or via your package manager."
        exit 1
    fi

    local version
    version=$("$py" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 11 ]; }; then
        err "Python >= 3.11 required (found $version)"
        exit 1
    fi

    ok "Python $version ($py)"
    PYTHON="$py"
}

check_pip() {
    if $PYTHON -m pip --version &>/dev/null; then
        ok "pip available"
    else
        warn "pip not found — attempting to install via ensurepip"
        $PYTHON -m ensurepip --upgrade || {
            err "Could not install pip. Please install it manually."
            exit 1
        }
    fi
}

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install_riva() {
    info "Installing Riva..."

    if [ "${INSTALL_FROM_SOURCE:-0}" = "1" ]; then
        info "Installing from source (editable mode)..."
        $PYTHON -m pip install -e ".[test]"
    else
        info "Installing from PyPI..."
        $PYTHON -m pip install riva
    fi

    # Verify the command is available
    if command -v riva &>/dev/null; then
        ok "riva CLI installed: $(command -v riva)"
    else
        # pip may install to a directory not on PATH
        local user_bin
        user_bin=$($PYTHON -c 'import sysconfig; print(sysconfig.get_path("scripts"))')
        warn "riva not found on PATH"
        warn "You may need to add $user_bin to your PATH:"
        echo ""
        echo "  export PATH=\"$user_bin:\$PATH\""
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------

verify_install() {
    echo ""
    info "Verifying installation..."

    if command -v riva &>/dev/null; then
        ok "riva is available"
        echo ""
        riva --help
    else
        warn "riva command not found on PATH — see above for PATH instructions"
    fi
}

print_summary() {
    echo ""
    echo -e "${BOLD}============================================${NC}"
    echo -e "${BOLD}  Riva installed successfully!${NC}"
    echo -e "${BOLD}============================================${NC}"
    echo ""
    echo "  Quick start:"
    echo ""
    echo "    riva scan            # One-shot agent scan"
    echo "    riva watch           # Live TUI dashboard"
    echo "    riva web start       # Start web dashboard"
    echo "    riva stats           # Token usage statistics"
    echo "    riva audit           # Security audit"
    echo ""
    echo "  Useful flags:"
    echo ""
    echo "    riva scan --json     # JSON output"
    echo "    riva web start -f    # Foreground mode"
    echo "    riva --help          # Full help"
    echo ""
    echo -e "  Docs: ${CYAN}https://github.com/sarkar-ai-taken/riva${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BOLD}Riva Installer${NC}"
    echo ""

    detect_os
    check_python
    check_pip
    install_riva
    verify_install
    print_summary
}

main "$@"
