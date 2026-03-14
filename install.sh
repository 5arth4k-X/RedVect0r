#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  RedVect0r — Install Script
#  Usage: sudo bash install.sh
# ─────────────────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  [✓] $*${NC}"; }
info() { echo -e "${CYAN}  [*] $*${NC}"; }
warn() { echo -e "${YELLOW}  [!] $*${NC}"; }
err()  { echo -e "${RED}  [✗] $*${NC}"; }
sep()  { echo -e "${WHITE}──────────────────────────────────────────────────────────${NC}"; }

# ── Must run as root ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    echo "    Run:  sudo bash install.sh"
    exit 1
fi

# ── Identify the real (non-root) user ─────────────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${RED}"
cat << 'BANNER'
$$$$$$$\                  $$\ $$\    $$\                       $$\      $$$$$$\
$$  __$$\                 $$ |$$ |   $$ |                      $$ |    $$$ __$$\
$$ |  $$ | $$$$$$\   $$$$$$$ |$$ |   $$ | $$$$$$\   $$$$$$$\ $$$$$$\   $$$$\ $$ | $$$$$$\
$$$$$$$  |$$  __$$\ $$  __$$ |\$$\  $$  |$$  __$$\ $$  _____|\_$$  _|  $$\$$\$$ |$$  __$$\
$$  __$$ |$$$$$$$$ |$$ /  $$ | \$$\$$  / $$$$$$$$ |$$ /        $$ |    $$ \$$$$ |$$ |  \__|
$$ |  $$ |$$   ____|$$ |  $$ |  \$$$  /  $$   ____|$$ |        $$ |$$\ $$ |\$$$ |$$ |
$$ |  $$ |\$$$$$$$\ \$$$$$$$ |   \$  /   \$$$$$$$\ \$$$$$$$\   \$$$$  |\$$$$$$  /$$ |
\__|  \__| \_______| \_______|    \_/     \_______| \_______|   \____/  \______/ \__|
BANNER
echo -e "${WHITE}  RedVect0r — Attack Surface Mapper  |  Install Script${NC}"
echo ""
sep
echo ""

# ── Step 1: System packages ───────────────────────────────────────
info "Installing system dependencies (nmap, whatweb, golang, python3-venv)..."
apt-get update -qq
apt-get install -y -qq nmap whatweb golang python3 python3-pip python3-venv
ok "System packages installed."

# ── Step 2: Go + Subfinder ────────────────────────────────────────
sep
info "Installing subfinder via Go (as user: $REAL_USER)..."

# Run go install as the real user so binaries land in their ~/go/bin
sudo -u "$REAL_USER" bash -c \
    "export HOME='$REAL_HOME'; \
     export GOPATH='$REAL_HOME/go'; \
     export PATH=\"\$PATH:\$GOPATH/bin:/usr/local/go/bin\"; \
     go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>&1" \
    | tail -3

SUBFINDER_BIN="$REAL_HOME/go/bin/subfinder"
if [[ ! -f "$SUBFINDER_BIN" ]]; then
    warn "subfinder binary not found at $SUBFINDER_BIN"
    warn "You may need to run: go install ... manually as $REAL_USER"
else
    ok "subfinder installed at $SUBFINDER_BIN"
fi

# Permanent PATH fix for the real user
GOPATH_LINE='export PATH="$PATH:$HOME/go/bin"'
for RC in "$REAL_HOME/.bashrc" "$REAL_HOME/.zshrc"; do
    if [[ -f "$RC" ]]; then
        if ! grep -qF "go/bin" "$RC"; then
            echo "$GOPATH_LINE" >> "$RC"
            ok "Added go/bin to PATH in $RC"
        else
            ok "go/bin already in $RC"
        fi
    fi
done

# Also symlink into /usr/local/bin so root and all users can find it
if [[ -f "$SUBFINDER_BIN" ]]; then
    ln -sf "$SUBFINDER_BIN" /usr/local/bin/subfinder
    ok "subfinder symlinked to /usr/local/bin/subfinder"
fi

# ── Step 3: Python venv + pip install ────────────────────────────
sep
info "Creating Python virtual environment at $INSTALL_DIR/venv ..."
sudo -u "$REAL_USER" python3 -m venv "$INSTALL_DIR/venv"
ok "venv created."

info "Installing Python dependencies..."
sudo -u "$REAL_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$REAL_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
ok "Python dependencies installed."

# ── Step 4: redvect0r system command ──────────────────────────────
sep
info "Installing 'redvect0r' command to /usr/local/bin ..."

cat > /usr/local/bin/redvect0r << WRAPPER
#!/usr/bin/env bash
# RedVect0r launcher — activates venv and runs main.py
SCRIPT_DIR="$INSTALL_DIR"
source "\$SCRIPT_DIR/venv/bin/activate"
exec python "\$SCRIPT_DIR/main.py" "\$@"
WRAPPER

chmod +x /usr/local/bin/redvect0r
ok "'redvect0r' command installed. You can now run: redvect0r <domain> <flags>"

# ── Step 5: Playwright (optional) ─────────────────────────────────
sep
echo ""
echo -e "${YELLOW}  [?] Install Playwright for screenshot capture? (optional)${NC}"
echo -e "${WHITE}      This installs playwright + downloads Chromium (~170 MB)${NC}"
echo -ne "${CYAN}  Install Playwright? [y/N]: ${NC}"
read -r PLAYWRIGHT_ANSWER

if [[ "$PLAYWRIGHT_ANSWER" =~ ^[Yy]$ ]]; then
    info "Installing playwright..."
    sudo -u "$REAL_USER" "$INSTALL_DIR/venv/bin/pip" install --quiet playwright
    info "Downloading Chromium (this may take a moment)..."
    sudo -u "$REAL_USER" "$INSTALL_DIR/venv/bin/playwright" install chromium
    ok "Playwright + Chromium installed. --screenshots flag is ready to use."
else
    info "Skipping Playwright. To install later, run:"
    echo -e "      ${WHITE}source $INSTALL_DIR/venv/bin/activate${NC}"
    echo -e "      ${WHITE}pip install playwright && playwright install chromium${NC}"
fi

# ── Step 6: Verification summary ──────────────────────────────────
sep
info "Verifying installed tools..."
echo ""

check_tool() {
    local name="$1"
    local cmd="$2"
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$($cmd --version 2>&1 | head -1 || true)
        ok "$name  →  $ver"
    else
        warn "$name not found in PATH — may require a new shell session"
    fi
}

check_tool "nmap"      "nmap"
check_tool "whatweb"   "whatweb"
check_tool "subfinder" "subfinder"
check_tool "python3"   "python3"

if "$INSTALL_DIR/venv/bin/python" -c "import playwright" 2>/dev/null; then
    ok "playwright  →  installed"
else
    info "playwright  →  not installed (--screenshots will be unavailable)"
fi

# ── Done ──────────────────────────────────────────────────────────
sep
echo ""
echo -e "${GREEN}  RedVect0r is ready!${NC}"
echo ""
echo -e "${WHITE}  Quick start:${NC}"
echo -e "${CYAN}    redvect0r <domain> --fast${NC}"
echo -e "${CYAN}    redvect0r <domain> --os --delay 0.5${NC}"
echo -e "${CYAN}    redvect0r -h${NC}"
echo ""
echo -e "${YELLOW}  Note: If 'redvect0r' command is not found, open a new terminal${NC}"
echo -e "${YELLOW}  or run: source ~/.bashrc${NC}"
echo ""