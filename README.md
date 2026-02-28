# CCDC Red Team Scripts

Toolkit for Aperture Science Labs CCDC environment. All scripts target `192.168.20<TEAM>.*` hosts.

Run `source setup.sh` once to make every script executable and register short aliases.

---

## spray — Password Spray

Sprays credentials across all team boxes. Uses netexec for SMB/WinRM/WMI and hydra for SSH/RDP. DA accounts are tried first. Stops on first hit by default.

```
spray <team> [-a] [-u user] ...
```

| Flag | Description |
|------|-------------|
| `-a` | Continue spraying after first hit (full coverage) |
| `-u USER` | Prepend extra user(s) to spray list (repeatable) |

Requires `users.txt` and `passwords.txt` in the current directory.

---

## exec — Remote Command Execution

Runs a command on a single host, cycling through protocols until one works: SMB → WinRM → WMI → smbexec → RDP → SSH. Tries DA accounts first, then `users.txt`.

```
exec <team> [host] [-c "command"] [-p password_or_hash] [-s]
```

| Flag | Description |
|------|-------------|
| `-c CMD` | Command to run (default: `whoami /all`) |
| `-p PASS` | Password or NTLM hash (default: `Th3cake1salie!`) |
| `-s` | Shell mode — drop into interactive shell on first successful auth |

Host can be a name (`curiosity`, `anger`, etc.) or number (1–7). Omit host to list all boxes.

---

## forgegold — Golden Ticket Forge

Forges Kerberos golden tickets using impacket. Extracts the krbtgt hash from the DC, then generates a `.ccache` and a ready-to-use helper script per team.

```
forgegold [-z] <team | all> [user:password]
```

| Flag | Description |
|------|-------------|
| `-z` | Use `zero.sh` dump output for offline forge (no live DC auth needed) |
| `all` | Forge tickets for teams 1–5 in one run |

---

## zero — Zerologon Exploit

Runs CVE-2020-1472 against the DC (`CURIOSITY$`) to zero the machine account password, then optionally dumps all domain hashes via secretsdump.

```
zero [-d | -jd] <team | all>
```

| Flag | Description |
|------|-------------|
| `-d` | Dump hashes after exploit |
| `-jd` | Just dump (skip exploit — DC must already be zeroed) |

---

## ligo — EternalBlue + ligolo-ng

Credential-less exploit chain targeting the Adventure XP box (`.72`) via EternalBlue, then deploys a ligolo-ng tunnel back to the attacker.

```
ligo <team> [attacker_ip]
```

Attacker IP auto-detected if omitted.

---

## pivot — Rapid Pivot Switcher

Configures proxychains to route through a Sliver SOCKS5 pivot running on a team's DC beacon.

```
pivot <team> [port]
```

Port defaults to `108<team>` (e.g. team 5 → `1085`).
