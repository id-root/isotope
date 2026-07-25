#!/usr/bin/env bash
# ==============================================================================
#  ISOTOPE — Automated Installer & Setup Script (Linux / macOS)
#  v4.0.0 — Post-Quantum Secure Messaging over Tor
# ==============================================================================
set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# ── Helpers ────────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}══ $* ${NC}"; }
divider() { echo -e "${DIM}────────────────────────────────────────────────────${NC}"; }

banner() {
cat << 'EOF'

  ██╗███████╗ ██████╗ ████████╗ ██████╗ ██████╗ ███████╗
  ██║██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
  ██║███████╗██║   ██║   ██║   ██║   ██║██████╔╝█████╗
  ██║╚════██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══╝
  ██║███████║╚██████╔╝   ██║   ╚██████╔╝██║     ███████╗
  ╚═╝╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚══════╝

       Post-Quantum Secure Messaging over Tor — v4.0.0
       Automated Installer for Linux / macOS
EOF
echo ""
}

# ── Detect OS ──────────────────────────────────────────────────────────────────
detect_os() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    case "$OS" in
        Linux*)  OS_TYPE="linux" ;;
        Darwin*) OS_TYPE="macos" ;;
        *)       error "Unsupported OS: $OS. Use install.ps1 on Windows." ;;
    esac
    info "Detected: ${BOLD}${OS_TYPE}/${ARCH}${NC}"
}

# ── Check for root (warn but don't block) ──────────────────────────────────────
check_root() {
    if [[ "$EUID" -eq 0 ]]; then
        warn "Running as root. Tor and Rust install will proceed, but identity files will be owned by root."
    fi
}

# ── Install system dependencies ────────────────────────────────────────────────
install_dependencies() {
    step "Installing System Dependencies"

    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v apt-get &>/dev/null; then
            info "Detected apt (Debian/Ubuntu)"
            sudo apt-get update -qq
            sudo apt-get install -y \
                tor \
                curl \
                git \
                build-essential \
                pkg-config \
                libssl-dev \
                libasound2-dev \
                cmake \
                clang \
                llvm \
                2>/dev/null
            success "apt dependencies installed."

        elif command -v dnf &>/dev/null; then
            info "Detected dnf (Fedora/RHEL)"
            sudo dnf install -y \
                tor \
                curl \
                git \
                gcc \
                gcc-c++ \
                make \
                openssl-devel \
                alsa-lib-devel \
                cmake \
                clang \
                llvm \
                2>/dev/null
            success "dnf dependencies installed."

        elif command -v pacman &>/dev/null; then
            info "Detected pacman (Arch Linux)"
            sudo pacman -Sy --noconfirm \
                tor \
                curl \
                git \
                base-devel \
                openssl \
                alsa-lib \
                cmake \
                clang \
                llvm \
                2>/dev/null
            success "pacman dependencies installed."

        else
            warn "Unknown package manager. Please manually install: tor, curl, git, build-essential, libssl-dev, libasound2-dev, cmake, clang"
        fi

    elif [[ "$OS_TYPE" == "macos" ]]; then
        if ! command -v brew &>/dev/null; then
            info "Homebrew not found. Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        info "Installing macOS dependencies via Homebrew..."
        brew install tor curl git cmake pkg-config 2>/dev/null || true
        success "Homebrew dependencies installed."
    fi
}

# ── Install Rust ───────────────────────────────────────────────────────────────
install_rust() {
    step "Checking Rust Toolchain"
    if command -v cargo &>/dev/null; then
        RUST_VER="$(cargo --version)"
        success "Rust already installed: ${RUST_VER}"
        info "Updating Rust to latest stable..."
        rustup update stable 2>/dev/null || true
    else
        info "Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        # Source the cargo env for the current session
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
        success "Rust installed: $(cargo --version)"
    fi
}

# ── Build ISOTOPE ──────────────────────────────────────────────────────────────
build_isotope() {
    step "Building ISOTOPE (Release Mode)"
    info "This may take a few minutes on first build (compiling cryptographic dependencies)..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ ! -f "$SCRIPT_DIR/Cargo.toml" ]]; then
        error "Cargo.toml not found. Run this script from the isotope project root directory."
    fi

    cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

    BINARY="$SCRIPT_DIR/target/release/isotope"
    if [[ ! -f "$BINARY" ]]; then
        error "Build succeeded but binary not found at: $BINARY"
    fi
    success "Build complete: ${BOLD}$BINARY${NC}"
}

# ── Install binary to PATH ─────────────────────────────────────────────────────
install_binary() {
    step "Installing Binary to PATH"
    BINARY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/target/release/isotope"

    INSTALL_DIR="/usr/local/bin"
    if [[ ! -w "$INSTALL_DIR" ]]; then
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        # Ensure ~/.local/bin is on PATH in profile
        PROFILE_FILE="$HOME/.bashrc"
        [[ -f "$HOME/.zshrc" ]] && PROFILE_FILE="$HOME/.zshrc"
        if ! grep -q "$HOME/.local/bin" "$PROFILE_FILE" 2>/dev/null; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$PROFILE_FILE"
            info "Added ~/.local/bin to PATH in $PROFILE_FILE"
            warn "Run: source $PROFILE_FILE  (or open a new terminal) to use 'isotope' globally."
        fi
    fi

    cp "$BINARY" "$INSTALL_DIR/isotope"
    chmod +x "$INSTALL_DIR/isotope"
    success "Installed to: ${BOLD}$INSTALL_DIR/isotope${NC}"
}

# ── Configure Tor ──────────────────────────────────────────────────────────────
configure_tor() {
    step "Configuring Tor Service"

    if [[ "$OS_TYPE" == "linux" ]]; then

        # ── Strategy 1: systemctl with a proper tor unit file ──────────────────
        # Check the unit FILE (not just running units) so freshly installed packages work.
        if command -v systemctl &>/dev/null && systemctl list-unit-files tor.service &>/dev/null 2>&1; then
            info "Found tor.service unit. Enabling and starting via systemctl..."
            sudo systemctl enable tor --now
            sleep 2
            if systemctl is-active --quiet tor; then
                success "Tor system service is active on port 9050."
                _verify_tor_port
                return
            else
                warn "systemctl start tor failed. Falling back to user-space Tor."
            fi
        fi

        # ── Strategy 2: write a clean user-space torrc and run with -f ─────────
        # We CANNOT rely on CLI flags alone because tor always loads /etc/tor/torrc
        # first and that may have a DataDirectory pointing to a root-owned path.
        # Using  tor -f <our_file>  completely replaces the config and avoids the
        # permission error: "Directory /var/lib/tor/... cannot be read"
        if command -v tor &>/dev/null; then
            TOR_CONF_DIR="$HOME/.config/isotope"
            TOR_DATA_DIR="$TOR_CONF_DIR/tor_data"
            TOR_PID_FILE="$TOR_CONF_DIR/tor.pid"
            TOR_LOG_FILE="$TOR_CONF_DIR/tor.log"
            TOR_RC_FILE="$TOR_CONF_DIR/torrc"

            mkdir -p "$TOR_DATA_DIR"

            # Write a fully self-contained torrc (no system torrc is read)
            cat > "$TOR_RC_FILE" << TORRC_EOF
SocksPort 9050
RunAsDaemon 1
DataDirectory ${TOR_DATA_DIR}
PidFile ${TOR_PID_FILE}
Log notice file ${TOR_LOG_FILE}
TORRC_EOF

            # Kill any stale user-level tor daemon from a prior run
            if [[ -f "$TOR_PID_FILE" ]]; then
                OLD_PID="$(cat "$TOR_PID_FILE" 2>/dev/null || true)"
                if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
                    info "Stopping previous Tor instance (PID $OLD_PID)..."
                    kill "$OLD_PID" 2>/dev/null || true
                    sleep 1
                fi
            fi

            info "Starting Tor with user-space config: $TOR_RC_FILE"
            tor -f "$TOR_RC_FILE"
            sleep 4  # give Tor time to bind the SOCKS port

            NEW_PID="$(cat "$TOR_PID_FILE" 2>/dev/null || echo 'unknown')"
            success "Tor started (PID: $NEW_PID)"
            info  "  Config : $TOR_RC_FILE"
            info  "  Data   : $TOR_DATA_DIR"
            info  "  Log    : $TOR_LOG_FILE"
        else
            warn "Tor binary not found. Install tor first, then re-run this script."
        fi

    elif [[ "$OS_TYPE" == "macos" ]]; then
        if brew services list 2>/dev/null | grep -q "^tor"; then
            info "Starting Tor via Homebrew services..."
            brew services start tor 2>/dev/null
        else
            warn "tor not in Homebrew services. Starting manually..."
            TOR_CONF_DIR="$HOME/.config/isotope"
            TOR_DATA_DIR="$TOR_CONF_DIR/tor_data"
            TOR_RC_FILE="$TOR_CONF_DIR/torrc"
            mkdir -p "$TOR_DATA_DIR"
            cat > "$TOR_RC_FILE" << TORRC_EOF
SocksPort 9050
RunAsDaemon 1
DataDirectory ${TOR_DATA_DIR}
PidFile ${TOR_CONF_DIR}/tor.pid
Log notice file ${TOR_CONF_DIR}/tor.log
TORRC_EOF
            tor -f "$TOR_RC_FILE"
        fi
        sleep 3
        success "Tor started on macOS."
    fi

    _verify_tor_port
}

# ── Internal: verify Tor SOCKS port is accepting connections ──────────────────
_verify_tor_port() {
    if command -v nc &>/dev/null; then
        if nc -z 127.0.0.1 9050 2>/dev/null; then
            success "Tor SOCKS5 proxy confirmed on 127.0.0.1:9050 ✓"
        else
            warn "Tor SOCKS port 9050 not yet reachable. Tor may still be bootstrapping."
            warn "Check the log: $HOME/.config/isotope/tor.log"
        fi
    fi
}

# ── Interactive Identity Setup ─────────────────────────────────────────────────
setup_identity() {
    step "Identity Setup"
    divider

    echo -e "${YELLOW}ISOTOPE uses a ${BOLD}Dual-Slot Identity${NC}${YELLOW} system:"
    echo -e "  • ${BOLD}REAL password${NC}  → Your actual operational profile"
    echo -e "  • ${BOLD}DURESS password${NC} → A decoy profile (safe to reveal under coercion)"
    echo -e "  ${DIM}Both slots are mathematically indistinguishable from the outside.${NC}"
    divider

    read -rp "$(echo -e "${CYAN}?${NC} Create a new identity now? [Y/n]: ")" CREATE_ID
    CREATE_ID="${CREATE_ID:-Y}"

    if [[ "$CREATE_ID" =~ ^[Yy]$ ]]; then
        read -rp "$(echo -e "${CYAN}?${NC} Identity filename [isotope.id]: ")" ID_FILE
        ID_FILE="${ID_FILE:-isotope.id}"

        if [[ -f "$ID_FILE" ]]; then
            read -rp "$(echo -e "${YELLOW}!${NC} '$ID_FILE' already exists. Overwrite? [y/N]: ")" OVERWRITE
            if [[ ! "$OVERWRITE" =~ ^[Yy]$ ]]; then
                warn "Skipping identity creation. Using existing: $ID_FILE"
                return
            fi
        fi

        # The identity is created interactively when isotope first runs
        # We just validate the binary works here
        BINARY_PATH="$(command -v isotope 2>/dev/null || echo "./target/release/isotope")"
        info "Identity '${ID_FILE}' will be created on first run."
        info "When prompted, enter your REAL password, then your DURESS (decoy) password."
    else
        info "Skipping identity creation. Run 'isotope server' or 'isotope client' to create one later."
    fi
}

# ── Generate a quick-start wrapper script ─────────────────────────────────────
generate_quickstart() {
    step "Generating Quick-Start Scripts"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # ── Server launcher ────────────────────────────────────────────────────────
    cat > "$SCRIPT_DIR/start-server.sh" << 'SERVERSCRIPT'
#!/usr/bin/env bash
# ISOTOPE — Start Hub (Server) Mode
set -euo pipefail

PORT="${1:-7878}"
ID_FILE="${2:-server.id}"

echo "[*] Starting ISOTOPE server on port $PORT with identity: $ID_FILE"
echo "[*] Tor must be running on 127.0.0.1:9050"
echo ""

isotope server --port "$PORT" --identity "$ID_FILE"
SERVERSCRIPT
    chmod +x "$SCRIPT_DIR/start-server.sh"

    # ── Client launcher ────────────────────────────────────────────────────────
    cat > "$SCRIPT_DIR/start-client.sh" << 'CLIENTSCRIPT'
#!/usr/bin/env bash
# ISOTOPE — Start Client (Connect) Mode
set -euo pipefail

usage() {
    echo "Usage: $0 <onion_address:port> <username> <server_fingerprint> [identity_file]"
    echo "  onion_address  — The .onion address and port shared by the server operator"
    echo "  username       — Your display name / call sign"
    echo "  fingerprint    — Server public key fingerprint (shared out-of-band)"
    echo "  identity_file  — (optional) Path to .id file [default: isotope.id]"
    echo ""
    echo "Example:"
    echo "  $0 abc123...xyz.onion:7878 Ghost AABBCC...FF ghost.id"
    exit 1
}

[[ $# -lt 3 ]] && usage

ADDRESS="$1"
USERNAME="$2"
FINGERPRINT="$3"
ID_FILE="${4:-isotope.id}"

echo "[*] Connecting to $ADDRESS as '$USERNAME'"
echo "[*] Tor must be running on 127.0.0.1:9050"
echo ""

isotope client \
    --address "$ADDRESS" \
    --username "$USERNAME" \
    --peer-fingerprint "$FINGERPRINT" \
    --identity "$ID_FILE"
CLIENTSCRIPT
    chmod +x "$SCRIPT_DIR/start-client.sh"

    # ── Ephemeral (no-trace) client launcher ───────────────────────────────────
    cat > "$SCRIPT_DIR/start-ephemeral.sh" << 'EPHEMERALSCRIPT'
#!/usr/bin/env bash
# ISOTOPE — Start Ephemeral (No-Trace) Client
# No identity file is created or stored. Session keys are lost on exit.
set -euo pipefail

usage() {
    echo "Usage: $0 <onion_address:port> <username> <server_fingerprint>"
    exit 1
}

[[ $# -lt 3 ]] && usage

ADDRESS="$1"
USERNAME="$2"
FINGERPRINT="$3"

echo "[*] Starting EPHEMERAL session (no identity stored)"
echo "[*] Tor must be running on 127.0.0.1:9050"
echo ""

isotope client \
    --address "$ADDRESS" \
    --username "$USERNAME" \
    --peer-fingerprint "$FINGERPRINT" \
    --temp
EPHEMERALSCRIPT
    chmod +x "$SCRIPT_DIR/start-ephemeral.sh"

    # ── Tor status checker ─────────────────────────────────────────────────────
    cat > "$SCRIPT_DIR/check-tor.sh" << 'TORSCRIPT'
#!/usr/bin/env bash
# ISOTOPE — Check Tor Connectivity
set -euo pipefail

echo "[*] Checking Tor SOCKS proxy on 127.0.0.1:9050..."
if nc -z 127.0.0.1 9050 2>/dev/null; then
    echo "[OK] Tor SOCKS5 port is open."
else
    echo "[FAIL] Tor SOCKS port 9050 is NOT reachable."
    echo "       Start Tor with: sudo systemctl start tor"
    exit 1
fi

echo "[*] Testing Tor network connectivity..."
if command -v curl &>/dev/null; then
    RESULT=$(curl -s --socks5-hostname 127.0.0.1:9050 --max-time 20 https://check.torproject.org/api/ip 2>/dev/null || echo "FAILED")
    if echo "$RESULT" | grep -q '"IsTor":true'; then
        TOR_IP=$(echo "$RESULT" | grep -o '"IP":"[^"]*"' | cut -d'"' -f4)
        echo "[OK] Connected via Tor! Exit node IP: $TOR_IP"
    else
        echo "[WARN] Could not confirm Tor routing. Response: $RESULT"
    fi
else
    echo "[INFO] curl not found. Cannot verify Tor routing. Install curl for full diagnostics."
fi
TORSCRIPT
    chmod +x "$SCRIPT_DIR/check-tor.sh"

    success "Quick-start scripts created:"
    echo -e "  ${GREEN}→${NC} ${BOLD}./start-server.sh${NC}    — Launch ISOTOPE as a Hub/Server"
    echo -e "  ${GREEN}→${NC} ${BOLD}./start-client.sh${NC}    — Connect to an existing Hub"
    echo -e "  ${GREEN}→${NC} ${BOLD}./start-ephemeral.sh${NC} — Connect with zero-trace ephemeral mode"
    echo -e "  ${GREEN}→${NC} ${BOLD}./check-tor.sh${NC}       — Verify Tor is running and routing correctly"
}

# ── Final summary ──────────────────────────────────────────────────────────────
print_summary() {
    divider
    echo ""
    echo -e "${GREEN}${BOLD}  ISOTOPE installation complete!${NC}"
    echo ""
    echo -e "  ${BOLD}Quick Start:${NC}"
    echo -e "  ${DIM}# Start a server (share onion address + fingerprint with team):${NC}"
    echo -e "  ${CYAN}  ./start-server.sh 7878 my-server.id${NC}"
    echo ""
    echo -e "  ${DIM}# Connect as a client (persistent identity):${NC}"
    echo -e "  ${CYAN}  ./start-client.sh <onion>.onion:7878 Ghost <FINGERPRINT>${NC}"
    echo ""
    echo -e "  ${DIM}# Connect with zero trace (ephemeral, no identity file):${NC}"
    echo -e "  ${CYAN}  ./start-ephemeral.sh <onion>.onion:7878 Ghost <FINGERPRINT>${NC}"
    echo ""
    echo -e "  ${DIM}# Verify Tor is working:${NC}"
    echo -e "  ${CYAN}  ./check-tor.sh${NC}"
    echo ""
    echo -e "  ${YELLOW}⚠  Emergency:${NC}  Press ${BOLD}Ctrl+X${NC} inside ISOTOPE to trigger instant panic wipe."
    echo ""
    divider
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    banner
    detect_os
    check_root
    install_dependencies
    install_rust

    # Ensure cargo is in PATH for this session
    export PATH="$HOME/.cargo/bin:$PATH"

    build_isotope
    install_binary
    configure_tor
    setup_identity
    generate_quickstart
    print_summary
}

main "$@"
