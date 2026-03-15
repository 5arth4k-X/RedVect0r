# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |

---

## Reporting a Vulnerability

If you discover a security vulnerability in RedVect0r, please **do not open a public GitHub issue**.

Report it privately instead:

**Email:** your@email.com  
**Subject line:** `[RedVect0r] Security Vulnerability Report`

Please include as much of the following as possible:

- A clear description of the vulnerability
- Steps to reproduce it
- The potential impact or attack scenario
- Your suggested fix (optional but appreciated)

You can expect an acknowledgement within **48 hours** and a resolution update within **7 days**.

> [!IMPORTANT]
> Vulnerabilities reported publicly before a fix is available put all users at risk.
> Responsible disclosure gives us the chance to patch first.

---

## Scope

The following are considered in scope for vulnerability reports:

- `main.py` — argument parsing and pipeline orchestration
- `modules/` — all scanning and detection modules
- `utils/` — reporter, resolver, runtime helpers
- `install.sh` — setup script security issues

The following are **out of scope**:

- Vulnerabilities in third-party tools (nmap, subfinder, WhatWeb, Playwright)
- Issues arising from running RedVect0r without proper authorisation
- Social engineering or phishing attempts

---

## Responsible Use

> [!CAUTION]
> RedVect0r is a security testing tool intended for **authorised use only**.
>
> - Always obtain **explicit written permission** before scanning any target
> - Never run RedVect0r against systems you do not own or have authorisation to test
> - The authors are not responsible for any misuse, damage, or legal consequences
> - Misuse of this tool may violate local, national, or international laws

---

## Known Security Considerations

The following are known design decisions users should be aware of:

**Subprocess execution** — RedVect0r calls external tools (`subfinder`, `whatweb`, `nmap`) via subprocess with the domain passed as a positional argument. Never modify these calls to use `shell=True` as that would introduce command injection risk.

**Wordlist file access** — The `--wordlist` flag opens a user-supplied file path. Only point it at trusted wordlist files.

**Proxy routing** — The `--proxy` flag routes all HTTP scan traffic through the specified URL. Only use trusted proxy addresses.

**Output directory** — Reports contain discovered endpoints, credentials hints, and vulnerability findings. Store output in a protected location, especially when scanning sensitive targets.

---

## Security Best Practices for Users

```bash
# Run scans only against authorised targets
redvect0r yourowndomain.com --fast

# Use delay to avoid triggering rate limits or IDS alerts
redvect0r target.com --stealthy --delay 1

# Route through Burp only on your own lab environment
redvect0r lab.local --fast --proxy http://127.0.0.1:8080

# Store reports securely
redvect0r target.com --fast --output /encrypted/reports/
```

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

Use of this tool implies acceptance of the responsible use terms stated above.
