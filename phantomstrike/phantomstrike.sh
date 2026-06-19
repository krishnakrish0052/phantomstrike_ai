#!/usr/bin/env bash
set -euo pipefail

# PhantomStrike v3.2 — main entrypoint
#
# Usage:
#   ./phantomstrike.sh install                # Full auto-install: detect OS, install ALL tools
#   ./phantomstrike.sh start                  # Start Flask server + MCP server (recommended)
#   ./phantomstrike.sh stop                   # Graceful shutdown
#   ./phantomstrike.sh update                 # Git pull + reinstall deps
#   ./phantomstrike.sh tools                  # List all tools with install status
#   ./phantomstrike.sh health                 # Check server health + tool count
#
#   ./phantomstrike.sh                        # MCP launcher mode (default, used by 5ire)
#   ./phantomstrike.sh -a                     # Update + start server  (legacy)
#   ./phantomstrike.sh -a -ai                 # Same + AI model (~8.4 GB RAM)
#   ./phantomstrike.sh -a -ai-small           # Same + smaller AI model (~2.5 GB RAM)
#
#   ./phantomstrike.sh --server               # Start server only (no update/install)
#   ./phantomstrike.sh --mcp                  # Start MCP client only
#   ./phantomstrike.sh --server --mcp         # Start server in background + MCP client
#
#   ./phantomstrike.sh -s                     # Update repo only
#   ./phantomstrike.sh -t                     # Install external tools only
#   ./phantomstrike.sh -t -b                  # Install tools + heavy Python extras
#   ./phantomstrike.sh -y                     # Force reinstall Python requirements
#   ./phantomstrike.sh -ai                    # Install Ollama + 9b model
#   ./phantomstrike.sh -ai-small              # Install Ollama + 4b model

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/phantomstrike-env"
PYTHON_BIN="python3"
GIT_TOOLS_DIR="${ROOT_DIR}/git_tools"

# --- install flags ---
INSTALL_TOOLS=false
INSTALL_BIG_PACKAGES=false
UPDATE_SELF=false
UPDATE_PYTHON_PACKAGES=false
PIP_BOOTSTRAPPED=false
INSTALL_AI_MODEL=false
AI_SMALL_MODE=false
AI_LARGE_MODE=false

OLLAMA_MODEL_BASE="huihui_ai/gemma-4-abliterated:e4b"
OLLAMA_MODEL_NAME="phantomstrike-ai"
OLLAMA_MODELFILE=""

# --- run flags ---
RUN_SERVER=false
RUN_MCP=false
RUN_INSTALL=false
RUN_STOP=false
RUN_TOOLS=false
RUN_HEALTH=false
SERVER_URL="http://127.0.0.1:8888"
PROFILE="default"

# --- do any setup at all? ---
DO_SETUP=false

# ---------------------------------------------------------------------------
# Setup functions (formerly install.sh)
# ---------------------------------------------------------------------------


update_self_repo() {
  if [[ "${UPDATE_SELF}" != true ]]; then
    return
  fi

  if ! command -v git >/dev/null 2>&1; then
    echo "Skipping self update: git is not installed."
    return
  fi

  if [[ ! -d "${ROOT_DIR}/.git" ]]; then
    echo "Skipping self update: repository metadata not found."
    return
  fi

  if ! git -C "${ROOT_DIR}" diff --quiet || \
     ! git -C "${ROOT_DIR}" diff --cached --quiet || \
     [[ -n "$(git -C "${ROOT_DIR}" ls-files --others --exclude-standard)" ]]; then
    echo "Skipping self update: local changes detected in project repo."
    return
  fi

  echo "Updating project repository..."
  if ! git -C "${ROOT_DIR}" pull --ff-only --quiet; then
    echo "Self update failed (non-fast-forward or remote issue). Continuing."
  fi
}




ensure_pip_ready() {
  if [[ "${PIP_BOOTSTRAPPED}" == true ]]; then
    return
  fi
  "${VENV_DIR}/bin/python3" -m pip --disable-pip-version-check install --quiet --upgrade pip
  PIP_BOOTSTRAPPED=true
}

install_requirements_file() {
  local requirements_file="$1"
  local requirements_name
  requirements_name="$(basename "${requirements_file}")"
  local stamp_file="${VENV_DIR}/.app_python_deps_${requirements_name}.stamp"

  if [[ "${UPDATE_PYTHON_PACKAGES}" != true && -f "${stamp_file}" && "${stamp_file}" -nt "${requirements_file}" ]]; then
    return
  fi

  ensure_pip_ready
  echo "Installing Python deps from: ${requirements_name}"
  "${VENV_DIR}/bin/python3" -m pip --disable-pip-version-check install --quiet --progress-bar off -r "${requirements_file}"
  touch "${stamp_file}"
}

write_model_to_config_local() {
  local model="$1"
  local data_dir="${PHANTOMSTRIKE_DATA_DIR:-${ROOT_DIR}/.phantomstrike_data}"
  local config_file="${PHANTOMSTRIKE_CONFIG_FILE:-${data_dir}/config/config_local.json}"
  local config_dir
  config_dir="$(dirname "${config_file}")"

  if ! command -v python3 >/dev/null 2>&1; then
    echo "Warning: python3 not found; could not update config_local.json with model '${model}'."
    echo "Set PHANTOMSTRIKE_LLM_MODEL=${model} manually in ${config_file}."
    return
  fi

  local existing="{}"
  if [[ -f "${config_file}" ]]; then
    existing="$(cat "${config_file}")"
  else
    mkdir -p "${config_dir}"
  fi

  python3 - "${config_file}" "${model}" "${existing}" <<'PYEOF'
import sys, json
config_file, model, existing_json = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    data = json.loads(existing_json)
except Exception:
    data = {}
data["PHANTOMSTRIKE_LLM_MODEL"] = model
with open(config_file, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
PYEOF
}

install_ollama_model() {
  if [[ "${INSTALL_AI_MODEL}" != true ]]; then
    return
  fi

  if ! command -v ollama >/dev/null 2>&1; then
    echo "Ollama not found. Installing via official install script..."
    if ! curl -fsSL https://ollama.com/install.sh | sh; then
      echo "Ollama install failed. Skipping AI model setup."
      return
    fi
  fi

  if ! ollama list 2>/dev/null | grep -qF "${OLLAMA_MODEL_BASE}"; then
    echo "Pulling base model: ${OLLAMA_MODEL_BASE} (this may take a while)..."
    if ! ollama pull "${OLLAMA_MODEL_BASE}"; then
      echo "Failed to pull base model. Skipping AI model creation."
      return
    fi
  fi

  if [[ -n "${OLLAMA_MODELFILE}" && -f "${OLLAMA_MODELFILE}" ]]; then
    if ollama list 2>/dev/null | grep -qF "${OLLAMA_MODEL_NAME}"; then
      write_model_to_config_local "${OLLAMA_MODEL_NAME}"
    else
      echo "Creating custom model '${OLLAMA_MODEL_NAME}' from ${OLLAMA_MODELFILE}..."
      if ! ollama create "${OLLAMA_MODEL_NAME}" -f "${OLLAMA_MODELFILE}"; then
        echo "Failed to create custom model. Falling back to base model."
        write_model_to_config_local "${OLLAMA_MODEL_BASE}"
        return
      fi
      write_model_to_config_local "${OLLAMA_MODEL_NAME}"
    fi
  elif [[ "${AI_SMALL_MODE}" == true || "${AI_LARGE_MODE}" == true ]]; then
    write_model_to_config_local "${OLLAMA_MODEL_BASE}"
  fi
}

run_setup() {
  update_self_repo

  echo "[1/4] Preparing virtual environment..."
  if [[ ! -d "${VENV_DIR}" ]]; then
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  fi

  echo "[2/4] Syncing Python dependencies... (may take a while on first run)"
  install_requirements_file "${ROOT_DIR}/dependencies/requirements.txt"

  if [[ "${INSTALL_TOOLS}" == true && -f "${ROOT_DIR}/dependencies/requirements-extra.txt" ]]; then
    install_requirements_file "${ROOT_DIR}/dependencies/requirements-extra.txt"
  fi

  if [[ "${INSTALL_TOOLS}" == true && "${INSTALL_BIG_PACKAGES}" == true && -f "${ROOT_DIR}/dependencies/requirements-big.txt" ]]; then
    echo "Installing big optional Python packages..."
    install_requirements_file "${ROOT_DIR}/dependencies/requirements-big.txt"
  fi

  if [[ "${INSTALL_TOOLS}" == true ]]; then
    echo "[3/4] Installing external tools via scripts/install_tools.sh..."
    bash "${ROOT_DIR}/scripts/install_tools.sh"
  else
    echo "[3/4] Skipping external tools (use -t to enable)."
  fi

  if [[ "${INSTALL_AI_MODEL}" == true ]]; then
    echo "[4/4] Setting up AI model..."
    install_ollama_model
  else
    echo "[4/4] Skipping AI model setup (use -ai or -ai-small to enable)."
  fi

  echo "Setup complete."
}

# ---------------------------------------------------------------------------
# v3.2 GODMODE Functions
# ---------------------------------------------------------------------------

# check_tool — check if a tool is installed (search PATH + common locations)
check_tool() {
  local tool="$1"
  # First try: command -v
  if command -v "$tool" >/dev/null 2>&1; then
    return 0
  fi
  # Search common binary locations
  local search_dirs=(/usr/bin /usr/sbin /usr/local/bin /opt /snap/bin /usr/lib \
    "$HOME/.local/bin" "$HOME/go/bin" "$HOME/.cargo/bin" \
    "$HOME/.gem/ruby" "$HOME/.local/share")
  for dir in "${search_dirs[@]}"; do
    if [[ -x "${dir}/${tool}" ]]; then
      return 0
    fi
  done
  # Also check pip, gem, npm for installed packages
  case "$tool" in
    *.py|*.pl)
      return 1 ;;  # Scripts, not CLI tools
  esac
  return 1
}

# install_tool_single — Install a single tool, trying apt first, then go, pip, gem, npm
install_tool_single() {
  local tool="$1"

  local GREEN='\033[0;32m'
  local RED='\033[0;31m'
  local CYAN='\033[0;36m'
  local RESET='\033[0m'
  local BOLD='\033[1m'

  if check_tool "$tool"; then
    echo -e "  ${GREEN}[✓]${RESET} ${tool} already installed"
    return 0
  fi

  echo -ne "  ${CYAN}[→]${RESET} Installing ${BOLD}${tool}${RESET} ... "

  # Try apt first
  if command -v apt-get >/dev/null 2>&1; then
    if sudo apt-get install -y -qq "$tool" >/dev/null 2>&1; then
      if check_tool "$tool"; then
        echo -e "${GREEN}done (apt)${RESET}"
        return 0
      fi
    fi
  fi

  # Try go install
  if command -v go >/dev/null 2>&1; then
    local go_pkg=""
    case "$tool" in
      amass)     go_pkg="github.com/owasp-amass/amass/v4/cmd/amass@latest" ;;
      subfinder) go_pkg="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
      nuclei)    go_pkg="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
      httpx)     go_pkg="github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
      katana)    go_pkg="github.com/projectdiscovery/katana/cmd/katana@latest" ;;
      hakrawler) go_pkg="github.com/hakluke/hakrawler@latest" ;;
      gau)       go_pkg="github.com/lc/gau/v2/cmd/gau@latest" ;;
      waybackurls) go_pkg="github.com/tomnomnom/waybackurls@latest" ;;
      ffuf)      go_pkg="github.com/ffuf/ffuf/v2@latest" ;;
      gobuster)  go_pkg="github.com/OJ/gobuster/v3@latest" ;;
    esac
    if [[ -n "$go_pkg" ]]; then
      if go install "$go_pkg" >/dev/null 2>&1; then
        if check_tool "$tool"; then
          echo -e "${GREEN}done (go)${RESET}"
          return 0
        fi
      fi
    fi
  fi

  # Try pip install
  if command -v pip3 >/dev/null 2>&1; then
    local pip_pkg=""
    case "$tool" in
      sqlmap)      pip_pkg="sqlmap" ;;
      dirsearch)   pip_pkg="dirsearch" ;;
      arjun)       pip_pkg="arjun" ;;
      fierce)      pip_pkg="fierce" ;;
      autorecon)   pip_pkg="autorecon" ;;
      netexec|nxc) pip_pkg="netexec" ;;
      smbmap)      pip_pkg="smbmap" ;;
      enum4linux-ng) pip_pkg="enum4linux-ng" ;;
      wafw00f)     pip_pkg="wafw00f" ;;
      impacket)    pip_pkg="impacket" ;;
      bloodhound)  pip_pkg="bloodhound-ce-python" ;;
      scout-suite) pip_pkg="scoutsuite" ;;
      prowler)     pip_pkg="prowler" ;;
      trivy)       pip_pkg="trivy" ;;
      checkov)     pip_pkg="checkov" ;;
      kube-hunter) pip_pkg="kube-hunter" ;;
    esac
    if [[ -n "$pip_pkg" ]]; then
      if pip3 install --user --quiet "$pip_pkg" >/dev/null 2>&1; then
        if check_tool "$tool"; then
          echo -e "${GREEN}done (pip)${RESET}"
          return 0
        fi
      fi
      # Try with --break-system-packages for newer distros
      if pip3 install --user --quiet --break-system-packages "$pip_pkg" >/dev/null 2>&1; then
        if check_tool "$tool"; then
          echo -e "${GREEN}done (pip)${RESET}"
          return 0
        fi
      fi
    fi
  fi

  # Try gem install
  if command -v gem >/dev/null 2>&1; then
    local gem_pkg=""
    case "$tool" in
      wpscan)      gem_pkg="wpscan" ;;
      evil-winrm)  gem_pkg="evil-winrm" ;;
      zsteg)       gem_pkg="zsteg" ;;
    esac
    if [[ -n "$gem_pkg" ]]; then
      if gem install --user-install --no-document --quiet "$gem_pkg" >/dev/null 2>&1; then
        if check_tool "$tool"; then
          echo -e "${GREEN}done (gem)${RESET}"
          return 0
        fi
      fi
    fi
  fi

  # Try npm install
  if command -v npm >/dev/null 2>&1; then
    local npm_pkg=""
    case "$tool" in
      wscat)     npm_pkg="wscat" ;;
      http-server) npm_pkg="http-server" ;;
    esac
    if [[ -n "$npm_pkg" ]]; then
      if npm install -g --silent "$npm_pkg" >/dev/null 2>&1; then
        if check_tool "$tool"; then
          echo -e "${GREEN}done (npm)${RESET}"
          return 0
        fi
      fi
    fi
  fi

  echo -e "${RED}failed${RESET}"
  return 1
}

# full_auto_install — detect Kali, check ALL tools, install missing
full_auto_install() {
  local GREEN='\033[0;32m'
  local RED='\033[0;31m'
  local CYAN='\033[0;36m'
  local RESET='\033[0m'
  local BOLD='\033[1m'

  echo ""
  echo "=============================================="
  echo "  PhantomStrike v3.2 — Full Auto Install"
  echo "=============================================="
  echo ""

  # Detect distro
  local distro="unknown"
  if [[ -f /etc/os-release ]]; then
    source /etc/os-release 2>/dev/null || true
    distro="${ID:-unknown}"
  fi
  echo -e "[i] Detected: ${BOLD}${distro^}${RESET}"

  # Update package lists
  if command -v apt-get >/dev/null 2>&1; then
    echo ""
    echo "[1/5] Updating package lists..."
    sudo apt-get update -qq 2>/dev/null || true
    echo -e "      ${GREEN}done${RESET}"
  fi

  # Install prerequisites
  echo ""
  echo "[2/5] Installing prerequisites..."
  local prereqs=(python3 python3-pip python3-dev git curl wget \
    build-essential libssl-dev libffi-dev ruby ruby-dev golang-go npm)
  for pkg in "${prereqs[@]}"; do
    install_tool_single "$pkg" || true
  done

  # Run the main install_tools.sh
  echo ""
  echo "[3/5] Installing security tools (via install_tools.sh)..."
  if [[ -f "${ROOT_DIR}/scripts/install_tools.sh" ]]; then
    bash "${ROOT_DIR}/scripts/install_tools.sh"
  fi

  # Install requirements
  echo ""
  echo "[4/5] Installing Python requirements..."
  if [[ -f "${ROOT_DIR}/dependencies/requirements.txt" ]]; then
    install_requirements_file "${ROOT_DIR}/dependencies/requirements.txt"
  fi

  # Read and install tools from tools_list.txt if it exists
  echo ""
  echo "[5/5] Installing additional tools from tools_list.txt..."
  local tools_list="${ROOT_DIR}/tools_list.txt"
  if [[ -f "$tools_list" ]]; then
    local count=0
    local installed=0
    while IFS= read -r line; do
      [[ -z "$line" || "$line" =~ ^# ]] && continue
      count=$((count + 1))
      if install_tool_single "$line"; then
        installed=$((installed + 1))
      fi
    done < "$tools_list"
    echo ""
    echo -e "  ${GREEN}[✓]${RESET} ${installed}/${count} tools from tools_list.txt installed"
  fi

  echo ""
  echo "=============================================="
  echo "  Install complete!"
  echo "  Run: ./phantomstrike.sh start"
  echo "=============================================="
  echo ""
}

# stop_server — Find phantomstrike python processes and kill them gracefully
stop_server() {
  echo "Stopping PhantomStrike processes..."

  local GREEN='\033[0;32m'
  local YELLOW='\033[1;33m'
  local RESET='\033[0m'

  local killed=0

  # Find Flask server processes
  local flask_pids=$(pgrep -f "phantomstrike_server.py" 2>/dev/null || true)
  if [[ -n "$flask_pids" ]]; then
    echo "  Found Flask server PIDs: $flask_pids"
    for pid in $flask_pids; do
      kill -TERM "$pid" 2>/dev/null && echo "  Sent SIGTERM to PID $pid" || true
      killed=$((killed + 1))
    done
  fi

  # Find MCP server processes
  local mcp_pids=$(pgrep -f "phantomstrike_mcp.py" 2>/dev/null || true)
  if [[ -n "$mcp_pids" ]]; then
    echo "  Found MCP server PIDs: $mcp_pids"
    for pid in $mcp_pids; do
      kill -TERM "$pid" 2>/dev/null && echo "  Sent SIGTERM to PID $pid" || true
      killed=$((killed + 1))
    done
  fi

  # Find any remaining python processes with phantomstrike in the name
  local rem_pids=$(pgrep -f "python.*phantomstrike" 2>/dev/null || true)
  if [[ -n "$rem_pids" ]]; then
    echo "  Found other phantomstrike PIDs: $rem_pids"
    for pid in $rem_pids; do
      kill -TERM "$pid" 2>/dev/null && echo "  Sent SIGTERM to PID $pid" || true
    done
  fi

  # Wait for graceful shutdown
  sleep 1

  # Force kill remaining
  flask_pids=$(pgrep -f "phantomstrike_server.py" 2>/dev/null || true)
  mcp_pids=$(pgrep -f "phantomstrike_mcp.py" 2>/dev/null || true)
  if [[ -n "${flask_pids}${mcp_pids}" ]]; then
    echo "  Force-killing remaining processes..."
    for pid in ${flask_pids} ${mcp_pids}; do
      kill -9 "$pid" 2>/dev/null || true
    done
  fi

  if [[ $killed -gt 0 ]]; then
    echo -e "${GREEN}[✓]${RESET} Stopped PhantomStrike. Clean shutdown."
  else
    echo -e "${YELLOW}[i]${RESET} No running PhantomStrike processes found."
  fi
}

# list_all_tools — Read from tools_list.txt and check each with status
list_all_tools() {
  local tools_list="${ROOT_DIR}/tools_list.txt"

  echo ""
  echo "=============================================="
  echo "  PhantomStrike v3.2 — Tool Inventory"
  echo "=============================================="
  echo ""

  if [[ ! -f "$tools_list" ]]; then
    echo -e "${YELLOW}[!]${RESET} tools_list.txt not found at: $tools_list"
    echo "    Run './phantomstrike.sh tools' after creating the file."
    echo ""
    # Show tools from install_tools.sh if available
    if [[ -f "${ROOT_DIR}/scripts/install_tools.sh" ]]; then
      echo "Available categories (from install_tools.sh):"
      bash "${ROOT_DIR}/scripts/install_tools.sh" --list 2>/dev/null || true
    fi
    return 1
  fi

  local total=0
  local found=0
  local missing=0
  local partial=0

  # Color codes
  local GREEN='\033[0;32m'
  local RED='\033[0;31m'
  local YELLOW='\033[1;33m'
  local CYAN='\033[0;36m'
  local RESET='\033[0m'
  local BOLD='\033[1m'
  local DIM='\033[2m'

  echo -e "  ${BOLD}Legend:${RESET}  ${GREEN}[✓]${RESET} installed  ${RED}[✗]${RESET} missing  ${YELLOW}[~]${RESET} partial"
  echo ""

  local current_category=""

  while IFS= read -r line; do
    # Handle category headers (lines starting with ##)
    if [[ "$line" =~ ^##[[:space:]]+(.*) ]]; then
      current_category="${BASH_REMATCH[1]}"
      echo ""
      echo -e "  ${BOLD}${CYAN}━━━ ${current_category} ━━━${RESET}"
      continue
    fi

    # Skip empty lines and comments
    [[ -z "$line" || "$line" =~ ^# ]] && continue

    local tool="$line"
    total=$((total + 1))

    if check_tool "$tool"; then
      echo -e "  ${GREEN}[✓]${RESET} ${tool}"
      found=$((found + 1))
    else
      # Check for partial (e.g., related tools or config exists)
      local partial_match=false
      if command -v "${tool}3" >/dev/null 2>&1 || command -v "${tool}2" >/dev/null 2>&1; then
        partial_match=true
      fi
      if [[ "$partial_match" == true ]]; then
        echo -e "  ${YELLOW}[~]${RESET} ${tool} ${DIM}(variant found)${RESET}"
        partial=$((partial + 1))
      else
        echo -e "  ${RED}[✗]${RESET} ${tool}"
        missing=$((missing + 1))
      fi
    fi
  done < "$tools_list"

  echo ""
  echo "  ─────────────────────────────────────────"
  echo -e "  ${BOLD}Total:${RESET}   ${total}"
  echo -e "  ${GREEN}Installed:${RESET} ${found}"
  echo -e "  ${RED}Missing:${RESET}   ${missing}"
  echo -e "  ${YELLOW}Partial:${RESET}  ${partial}"
  echo "  ─────────────────────────────────────────"
  echo ""
}

# health_check — Curl the server health endpoint, count available tools
health_check() {
  local server_url="${SERVER_URL}"
  local token="${API_TOKEN:-}"

  local GREEN='\033[0;32m'
  local RED='\033[0;31m'
  local YELLOW='\033[1;33m'
  local CYAN='\033[0;36m'
  local RESET='\033[0m'
  local BOLD='\033[1m'

  echo ""
  echo "=============================================="
  echo "  PhantomStrike v3.2 — Health Check"
  echo "=============================================="
  echo ""

  # Check if server is running
  echo -ne "  Server (${server_url}) ... "
  if curl -s --connect-timeout 3 "${server_url}/health" >/dev/null 2>&1; then
    echo -e "${GREEN}UP${RESET}"
  else
    echo -e "${RED}DOWN${RESET}"
    echo ""
    echo -e "${YELLOW}[!]${RESET} Server is not running."
    echo "    Start it with: ./phantomstrike.sh start"
    echo ""
    return 1
  fi

  # Get health details
  local health_json
  local curl_opts=(-s --connect-timeout 5)
  if [[ -n "$token" ]]; then
    curl_opts+=(-H "Authorization: Bearer ${token}")
  fi
  health_json=$(curl "${curl_opts[@]}" "${server_url}/health" 2>/dev/null || echo '{"status":"error"}')

  local status
  status=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','error'))" 2>/dev/null || echo "parse_error")

  local tools_available
  tools_available=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_tools_available','?'))" 2>/dev/null || echo "?")

  local tools_total
  tools_total=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total_tools_count','?'))" 2>/dev/null || echo "?")

  local version
  version=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version','?'))" 2>/dev/null || echo "?")

  local uptime
  uptime=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); u=d.get('uptime',0); print(f'{int(u//3600)}h {int((u%3600)//60)}m {int(u%60)}s')" 2>/dev/null || echo "?")

  echo ""
  echo -e "  ${BOLD}Status:${RESET}        ${status}"
  echo -e "  ${BOLD}Version:${RESET}       ${version}"
  echo -e "  ${BOLD}Uptime:${RESET}        ${uptime}"
  echo -e "  ${BOLD}Tools Available:${RESET} ${tools_available} / ${tools_total}"
  echo ""

  # Show category breakdown
  local category_stats
  category_stats=$(echo "$health_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
cats = d.get('category_stats', {})
for cat, stats in sorted(cats.items()):
    a = stats.get('available', 0)
    t = stats.get('total', 0)
    pct = (a/t*100) if t > 0 else 0
    icon = '✓' if pct >= 80 else ('~' if pct >= 50 else '✗')
    print(f'  [{icon}] {cat}: {a}/{t} ({pct:.0f}%)')
" 2>/dev/null || echo "  (could not parse category stats)")

  echo "  ─── Category Breakdown ───"
  echo "$category_stats"
  echo ""

  # Essential tools check
  local all_essential
  all_essential=$(echo "$health_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if d.get('all_essential_tools_available',False) else 'false')" 2>/dev/null || echo "false")
  if [[ "$all_essential" == "true" ]]; then
    echo -e "  ${GREEN}[✓]${RESET} All essential tools available"
  else
    echo -e "  ${RED}[✗]${RESET} Some essential tools are missing"
  fi
  echo ""
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--python)
      PYTHON_BIN="$2"
      shift 2
      ;;
    -s|--update-self)
      UPDATE_SELF=true
      DO_SETUP=true
      shift
      ;;
    -t|--install-tools)
      INSTALL_TOOLS=true
      DO_SETUP=true
      shift
      ;;
    -b|--install-big-packages)
      INSTALL_BIG_PACKAGES=true
      INSTALL_TOOLS=true
      DO_SETUP=true
      shift
      ;;
    -y|--update-python-packages)
      UPDATE_PYTHON_PACKAGES=true
      DO_SETUP=true
      shift
      ;;
    -a|--all)
      UPDATE_SELF=true
      DO_SETUP=true
      RUN_SERVER=true
      shift
      ;;
    -ai)
      INSTALL_AI_MODEL=true
      AI_LARGE_MODE=true
      OLLAMA_MODEL_BASE="huihui_ai/gemma-4-abliterated:e4b"
      OLLAMA_MODELFILE="${ROOT_DIR}/Modelfiles/Modelfile.gemma4-e4b"
      export PHANTOMSTRIKE_LLM_WARMUP=1
      DO_SETUP=true
      shift
      ;;
    -ai-small)
      INSTALL_AI_MODEL=true
      AI_SMALL_MODE=true
      OLLAMA_MODEL_BASE="huihui_ai/qwen3.5-abliterated:2B"
      OLLAMA_MODELFILE="${ROOT_DIR}/Modelfiles/Modelfile.qwen3-2b"
      export PHANTOMSTRIKE_LLM_WARMUP=1
      DO_SETUP=true
      shift
      ;;
    --server)
      RUN_SERVER=true
      shift
      ;;
    --mcp)
      RUN_MCP=true
      shift
      ;;
    --server-url)
      SERVER_URL="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    install)
      RUN_INSTALL=true
      shift
      ;;
    start)
      RUN_SERVER=true
      RUN_MCP=true
      shift
      ;;
    stop)
      RUN_STOP=true
      shift
      ;;
    update)
      UPDATE_SELF=true
      UPDATE_PYTHON_PACKAGES=true
      DO_SETUP=true
      shift
      ;;
    tools)
      RUN_TOOLS=true
      shift
      ;;
    health)
      RUN_HEALTH=true
      shift
      ;;
    -h|--help)
      echo "PhantomStrike v3.2"
      echo ""
      echo "Setup:"
      echo "  install                 Full auto-install: detect OS, install ALL tools"
      echo "  -a, --all               Start here — update repo + start server"
      echo "  -s, --update-self       git pull this repo (skips if local changes present)"
      echo "  -t, --install-tools     Install security tools via scripts/install_tools.sh"
      echo "                          (run scripts/install_tools.sh --help for category/dry-run options)"
      echo "  -b, --install-big-packages  Install heavy optional Python extras (implies -t)"
      echo "  -u, --update-git-tools  Pull latest for already-cloned git_tools repos (implies -t)"
      echo "  -y, --update-python-packages  Force reinstall of Python requirements"
      echo "  -p, --python <bin>      Python binary to use (default: python3)"
      echo "  -ai                     Install Ollama + pull 9b model (~8.4 GB RAM)"
      echo "  -ai-small               Install Ollama + pull 4b model (~2.5 GB RAM)"
      echo ""
      echo "Run:"
      echo "  start                   Start Flask server + MCP server (recommended)"
      echo "  stop                    Graceful shutdown of all PhantomStrike processes"
      echo "  --server                Start the PhantomStrike API server"
      echo "  --mcp                   Start the MCP client (default when no flags given)"
      echo "  --server --mcp          Start server in background + MCP client"
      echo "  --server-url <url>      MCP target server URL (default: ${SERVER_URL})"
      echo "  --profile <name>        MCP profile (default: ${PROFILE})"
      echo ""
      echo "Maintenance:"
      echo "  update                  Git pull + reinstall deps (same as -s -y)"
      echo "  tools                   List all tools with install status [✓/✗/~]"
      echo "  health                  Check server health + tool availability count"
      echo ""
      echo "Examples:"
      echo "  ./phantomstrike.sh install            # first-time setup (auto-detect + install everything)"
      echo "  ./phantomstrike.sh start              # start server + MCP (daily driver)"
      echo "  ./phantomstrike.sh stop               # graceful shutdown"
      echo "  ./phantomstrike.sh update             # pull latest + reinstall deps"
      echo "  ./phantomstrike.sh tools              # check what's installed"
      echo "  ./phantomstrike.sh health             # server health + tool counts"
      echo "  ./phantomstrike.sh -a                 # legacy: update + start server"
      echo "  ./phantomstrike.sh -a -ai-small       # with local AI model (low-spec)"
      echo "  ./phantomstrike.sh --server           # just start the server"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Run with --help for usage."
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# v3.2 Commands: stop, tools, health — can run without venv
# ---------------------------------------------------------------------------

if [[ "${RUN_STOP}" == true ]]; then
  stop_server
  exit 0
fi

if [[ "${RUN_TOOLS}" == true ]]; then
  list_all_tools
  exit 0
fi

if [[ "${RUN_HEALTH}" == true ]]; then
  health_check
  exit 0
fi

# ---------------------------------------------------------------------------
# v3.2: install — full auto-install, then exit
# ---------------------------------------------------------------------------

if [[ "${RUN_INSTALL}" == true ]]; then
  # Create venv if needed for pip operations
  if [[ ! -d "${VENV_DIR}" ]]; then
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  fi
  export PATH="${VENV_DIR}/bin:${PATH}"
  full_auto_install
  exit 0
fi

# ---------------------------------------------------------------------------
# Default: no args → MCP launcher mode (preserves 5ire compatibility)
# ---------------------------------------------------------------------------

if [[ "${DO_SETUP}" == false && "${RUN_SERVER}" == false && "${RUN_MCP}" == false ]]; then
  RUN_MCP=true
fi

# ---------------------------------------------------------------------------
# Resolve venv (must exist before we can run anything)
# ---------------------------------------------------------------------------

if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
  if [[ "${DO_SETUP}" == true ]]; then
    # venv will be created inside run_setup
    true
  else
    echo "No virtualenv found. Run: ./phantomstrike.sh install"
    exit 1
  fi
fi

export PATH="${VENV_DIR}/bin:${PATH}"
cd "${ROOT_DIR}"

# ---------------------------------------------------------------------------
# Run setup phase if requested
# ---------------------------------------------------------------------------

if [[ "${DO_SETUP}" == true ]]; then
  run_setup
fi

# ---------------------------------------------------------------------------
# Run phase
# ---------------------------------------------------------------------------

if [[ "${RUN_SERVER}" == true && "${RUN_MCP}" == true ]]; then
  echo "Starting API server in background..."
  "${VENV_DIR}/bin/python3" "${ROOT_DIR}/phantomstrike_server.py" &
  server_pid=$!

  cleanup() {
    kill "${server_pid}" >/dev/null 2>&1 || true
  }
  trap cleanup EXIT

  echo "Starting MCP client..."
  exec "${VENV_DIR}/bin/python3" "${ROOT_DIR}/phantomstrike_mcp.py" --server "${SERVER_URL}" --profile "${PROFILE}"
fi

if [[ "${RUN_SERVER}" == true ]]; then
  exec "${VENV_DIR}/bin/python3" "${ROOT_DIR}/phantomstrike_server.py"
fi

if [[ "${RUN_MCP}" == true ]]; then
  exec "${VENV_DIR}/bin/python3" "${ROOT_DIR}/phantomstrike_mcp.py" --server "${SERVER_URL}" --profile "${PROFILE}"
fi
