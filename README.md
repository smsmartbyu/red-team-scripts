# CCDC Red Team Scripts

Toolkit for Aperture Science Labs CCDC environment. All scripts target `192.168.20<TEAM>.*` hosts by default. Use the `-x` flag on any script to target internal `172.16.x.x` IPs through proxychains.

Run `source setup.sh` once to make every script executable and register short aliases.

## Internal IP Map (for `-x` / proxychains)

| Host | Role | Internal IP | Subnet |
|------|------|------------|--------|
| curiosity | DC (Win Server 2016) | 172.16.3.140 | Workstation |
| morality | Win Server 2016 | 172.16.1.10 | DMZ |
| intelligence | Win Server 2019 | 172.16.1.11 | DMZ |
| anger | Win Server 2019 | 172.16.2.70 | Internal |
| fact | Win Server 2022 | 172.16.2.71 | Internal |
| space | Windows 10 | 172.16.3.141 | Workstation |
| adventure | Windows XP (pivot) | 172.16.2.72 | Internal |
| schrodinger | OPNSense 25.7 | 172.16.1.1 / .2.1 / .3.1 | Router |

---

## spray — Password Spray

Sprays credentials across all team boxes. Uses netexec for SMB/WinRM/WMI and hydra for SSH/RDP. DA accounts are tried first. Stops on first hit by default.

```
spray <team> [-a] [-u user] [-x] ...
```

| Flag | Description |
|------|-------------|
| `-a` | Continue spraying after first hit (full coverage) |
| `-u USER` | Prepend extra user(s) to spray list (repeatable) |
| `-x` | Use internal 172.16.x.x IPs (via proxychains) |

Requires `users.txt` and `passwords.txt` in the current directory.

---

## exec — Remote Command Execution

Runs a command on a single host, cycling through protocols until one works: SMB → WinRM → WMI → smbexec → RDP → SSH. Tries DA accounts first, then `users.txt`.

```
exec <team> [host] [-c "command"] [-p password_or_hash] [-s] [-x]
```

| Flag | Description |
|------|-------------|
| `-c CMD` | Command to run (default: `whoami /all`) |
| `-p PASS` | Password or NTLM hash (default: `Th3cake1salie!`) |
| `-s` | Shell mode — drop into interactive shell on first successful auth |
| `-x` | Use internal 172.16.x.x IPs (via proxychains) |

Host can be a name (`curiosity`, `anger`, etc.) or number (1–7). Omit host to list all boxes.

---

## forgegold — Golden Ticket Forge

Forges Kerberos golden tickets using impacket. Extracts the krbtgt hash from the DC, then generates a `.ccache` and a ready-to-use helper script per team.

```
forgegold [-z] [-x] <team | all> [user:password]
```

| Flag | Description |
|------|-------------|
| `-z` | Use `zero.sh` dump output for offline forge (no live DC auth needed) |
| `-x` | Use internal 172.16.x.x IPs (generated use-scripts will have internal IPs) |
| `all` | Forge tickets for teams 1–5 in one run |

---

## zero — Zerologon Exploit

Runs CVE-2020-1472 against the DC (`CURIOSITY$`) to zero the machine account password, then optionally dumps all domain hashes via secretsdump.

```
zero [-d | -jd] [-x] <team | all>
```

| Flag | Description |
|------|-------------|
| `-d` | Dump hashes after exploit |
| `-jd` | Just dump (skip exploit — DC must already be zeroed) |
| `-x` | Use internal 172.16.x.x IPs (via proxychains) |

---

## planter — Beacon Planter

Plants a beacon (first `.exe` in CWD) on one or all team boxes. Auto-detects golden ticket, falls back to explicit creds or DA spray. Tries multiple transfer and execution methods.

```
planter <team> [host] [-p password_or_hash] [-u user] [-w http_url] [-x]
```

| Flag | Description |
|------|-------------|
| `-p PASS` | Password or NTLM hash |
| `-u USER` | Specify user (default: `Administrator`) |
| `-w URL` | Fallback HTTP URL to download beacon if file transfer fails |
| `-x` | Use internal 172.16.x.x IPs (via proxychains) |

**Auth priority:** golden ticket (`team<N>.ccache`) → explicit `-p` creds → DA password spray

**Transfer methods (tried in order):** SMB put → WinRM base64 upload → certutil from URL → PowerShell IWR from URL → SCP (SSH)

**Exec methods:** SMB → WinRM → WMI → smbexec → SSH

Omit host to target all 7 boxes. Drop path is randomized; falls back to `C:\Windows\Temp`, `C:\ProgramData`, or `%TEMP%`.

---

## ligo — EternalBlue + Meterpreter Pivot

Exploits Adventure XP box (`.72`) via EternalBlue (MS17-010), sets up Meterpreter reverse shell with autoroute and SOCKS proxy for proxychains pivoting into internal networks.

```
ligo <team | all> [attacker_ip]
```

Generates per-team:
- `proxychains_team<N>.conf` — proxychains config pointing to SOCKS5 on `127.0.0.1:108<N>`
- `team<N>_proxy.sh` — helper script with aliases (`pc<N>`, `p<N>`) for easy proxychains use

Attacker IP auto-detected if omitted. Use `all` to exploit teams 1–5.

**Workflow:** Run `ligo 5`, wait for SOCKS proxy, then `source team5_proxy.sh` and use `pc5 netexec smb 172.16.3.140 ...`

---

## pivot — Rapid Pivot Switcher (Sliver)

Configures proxychains to route through a Sliver SOCKS5 pivot running on a team's DC beacon. For EternalBlue/Meterpreter pivots, use `ligo` instead.

```
pivot <team> [port]
```

Port defaults to `108<team>` (e.g. team 5 → `1085`).
