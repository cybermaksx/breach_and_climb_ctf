# Solvers

Standard library only. Default target `192.168.50.116`; pass `-t host[:port]` for another box.

| Script | Stages | What it does |
|---|---|---|
| `gethash.py` | 1–2 | Registers a contractor, dumps `users` through the UNION SQLi in `/api/v1/employees?q=`, cracks the MD5s with a wordlist (`-w rockyou.txt`) → `pprice:bowwow` |
| `revshell.py` | 3 | Logs in as `pprice`, sends the SSTI payload to the email-template preview, catches the shell itself (no `nc`), upgrades to a PTY |

```bash
python3 solve/gethash.py -w /usr/share/wordlists/rockyou.txt
python3 solve/revshell.py            # your IP is auto-detected; --lhost to override
```

From the shell, stages 4–5 (user and root) are in [`WALKTHROUGH.md`](../WALKTHROUGH.md).
