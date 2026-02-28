#!/bin/bash
# ================================================
# CCDC Red Team Scripts — Setup & Aliases
# Source this file:  source setup.sh  (or . setup.sh)
# Makes all .sh scripts executable and creates
# short aliases so you can type  spray 5  instead
# of  ./spray.sh 5
# ================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Make every .sh file executable
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null

# Register aliases (name = filename without .sh)
for script in "$SCRIPT_DIR"/*.sh; do
  name="$(basename "$script" .sh)"
  [[ "$name" == "setup" ]] && continue   # don't alias ourselves
  alias "$name"="$script"
done

echo "[+] All scripts marked executable"
echo "[+] Aliases registered:"
alias | grep -E "$(ls "$SCRIPT_DIR"/*.sh | xargs -I{} basename {} .sh | grep -v setup | paste -sd'|')" 2>/dev/null || true
echo ""
echo "    spray <team>          — password spray"
echo "    exec <team> [host]    — remote exec"
echo "    forgegold <team|all>  — golden ticket forge"
echo "    zero <team|all>       — zerologon"
echo "    planter <team> [host] — beacon planter"
echo "    ligo <team|all>       — eternalblue + meterpreter pivot"
echo "    pivot <team>          — sliver socks5 pivot switcher"
