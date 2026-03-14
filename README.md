<div align="center">

```
██████╗ ███████╗██████╗ ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═████╗██╔══██╗
██████╔╝█████╗  ██║  ██║██║   ██║█████╗  ██║        ██║   ██║██╔██║██████╔╝
██╔══██╗██╔══╝  ██║  ██║╚██╗ ██╔╝██╔══╝  ██║        ██║   ████╔╝██║██╔══██╗
██║  ██║███████╗██████╔╝ ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═════╝   ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

### Attack Surface Mapper

[![Python](https://img.shields.io/badge/Python-3.10+-red?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=linux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0-orange?style=for-the-badge)](https://github.com/5arth4k-X/RedVect0r)
[![Status](https://img.shields.io/badge/Status-Active-red?style=for-the-badge)](https://github.com/5arth4k-X/RedVect0r)
[![Install](https://img.shields.io/badge/Install-One%20Command-crimson?style=for-the-badge)](https://github.com/5arth4k-X/RedVect0r)

*A fast, modular attack surface mapping tool for penetration testers and bug bounty hunters.*  
*Built for Kali Linux. One install command. Zero configuration required.*

</div>

---

## What is RedVect0r?

RedVect0r is a complete **attack surface mapping framework** that chains together passive recon, active scanning, and vulnerability detection into a single automated pipeline. Point it at a domain and it maps everything — subdomains, ports, technologies, endpoints, misconfigurations, and risk scores — then saves a full report.

```diff
+ Passive subdomain enumeration via subfinder
+ Full DNS record enumeration (A, AAAA, CNAME, MX, TXT, NS, SOA, SPF, DMARC)
+ Subdomain takeover detection across 27 known vulnerable services
+ Port scanning with 7 nmap profiles
+ HTTP probing and technology fingerprinting via WhatWeb
+ Endpoint discovery with built-in or custom wordlists
+ WAF detection across 12 signatures
+ robots.txt and sitemap.xml parsing with sensitive path flagging
+ CORS misconfiguration detection (HIGH / MEDIUM / INFO)
+ SSL/TLS inspection — expiry, weak ciphers, SANs
+ Open redirect detection across 19 common parameters
+ Per-subdomain risk scoring with detailed findings
+ Optional screenshot capture powered by Playwright
+ JSON + TXT reports with graceful Ctrl+C partial save
```

---

## Installation

> [!IMPORTANT]
> RedVect0r is designed for **Kali Linux** or any Debian-based distro. Root/sudo is required for the install script and for nmap OS/SYN scans.

```bash
git clone https://github.com/5arth4k-X/RedVect0r.git
cd RedVect0r
sudo bash install.sh
```

**The install script handles everything in order:**

| Step | What it does |
|------|-------------|
| 1 | `apt install` — nmap, whatweb, golang, python3-venv |
| 2 | Installs `subfinder` via Go + adds `~/go/bin` to PATH permanently |
| 3 | Creates Python virtual environment + installs all pip dependencies |
| 4 | Registers `redvect0r` as a system-wide command |
| 5 | Prompts to optionally install Playwright + Chromium for screenshots |
| 6 | Prints a verification summary of all installed tools |

> [!TIP]
> After install, **open a new terminal** before running the tool so PATH changes take effect.

---

## Usage

```bash
redvect0r <domain> <scan-flag> [nmap-options] [discovery-options] [output-options]
```

```diff
! <scan-flag> is required — all other flags are optional
```

---

### Scan Flags

| Flag | Nmap Args | Description |
|------|-----------|-------------|
| `--fast` | `-T4 --top-ports 100` | Quick overview, top 100 ports |
| `--stealthy` | `-T2 --top-ports 100` | Slower, less noisy on IDS/IPS |
| `--default` | `-T4` | Nmap default, top 1000 ports |
| `--full` | `-T4 -p-` | All 65535 ports (slow) |
| `--version` | `-T4 --top-ports 100 -sV` | Service & version detection |
| `--os` | `-T4 --top-ports 100 -O` | OS fingerprinting *(needs root)* |
| `--syn` | `-T4 -sS --top-ports 100` | SYN stealth scan *(needs root)* |
| `--ports <list>` | `-T4 -p <list>` | Specific ports e.g. `22,80,443` |

---

### Nmap Options *(combine freely with any scan flag)*

| Flag | Description |
|------|-------------|
| `--delay <s>` | Sleep between HTTP requests e.g. `0.5` |
| `--proxy <url>` | Route all HTTP traffic through a proxy e.g. `http://127.0.0.1:8080` |

---

### Discovery Options

| Flag | Description |
|------|-------------|
| `--wordlist <path>` | Custom wordlist for endpoint discovery. Each line = one path. Built-in list used when omitted. e.g. `/usr/share/wordlists/dirb/common.txt` |

---

### Output Options

| Flag | Description |
|------|-------------|
| `--output <dir>` | Directory to save reports. Defaults to `./output` in current directory. |
| `--screenshots <dir>` | Capture screenshots of live subdomains. Saved as `<dir>/<subdomain>.png`. Requires Playwright. |

---

### Help

```bash
redvect0r --help
```

---

## Examples

```bash
# Quick scan — fastest recon
redvect0r example.com --fast

# OS detection with stealth delay and Burp Suite proxy
redvect0r example.com --os --delay 0.5 --proxy http://127.0.0.1:8080

# Service version detection with custom wordlist
redvect0r example.com --version --wordlist /usr/share/wordlists/dirb/common.txt

# Fast scan with screenshots saved to custom folder
redvect0r example.com --fast --screenshots output/screenshots

# Full deep scan — all options, reports saved to custom path
redvect0r example.com --full --delay 1 --wordlist /path/to/list.txt --output /home/user/scans

# Target specific ports only
redvect0r example.com --ports 22,80,443,8080
```

---

## Output Structure

Reports are saved to `./output/` by default or to `--output <path>`:

```
output/
├── report_YYYYMMDD_HHMMSS.json     ← full machine-readable report
├── report_YYYYMMDD_HHMMSS.txt      ← human-readable report
└── screenshots/                    ← only if --screenshots was used
    ├── subdomain1.example.com.png
    └── subdomain2.example.com.png
```

**Both reports contain all sections in pipeline order:**

```diff
+ Subdomains          + Endpoints
+ DNS Records         + WAF Detection
+ Takeover            + Robots / Sitemap
+ Port Scan           + CORS
+ HTTP Probing        + SSL/TLS
+ Fingerprinting      + Open Redirects
+                       Risk Scores
+                       Screenshots
```

---

## Pipeline Overview

```
Domain Input
     │
     ▼
Subdomain Enumeration (subfinder)
     │
     ▼
DNS Resolution ──► DNS Record Enumeration ──► Takeover Detection
     │
     ▼
Port Scanning (nmap)
     │
     ▼
HTTP Probing ──► Technology Fingerprinting
     │
     ▼
Endpoint Discovery ──► WAF Detection ──► robots/sitemap
     │
     ▼
CORS Check ──► SSL/TLS Inspection ──► Open Redirect Detection
     │
     ▼
Risk Scoring ──► Screenshots (optional)
     │
     ▼
JSON + TXT Report
```

---

## Screenshot Capture *(optional)*

> [!NOTE]
> Screenshots require Playwright. You are prompted during `install.sh`. If you skipped it, install manually:

```bash
cd RedVect0r
source venv/bin/activate
pip install playwright
playwright install chromium
```

Then use the flag:

```bash
redvect0r example.com --fast --screenshots output/screenshots
```

---

## Git Setup After Clone & Install

```bash
# Set your identity
git config --global user.email "you@example.com"
git config --global user.name "YourName"

# Rename branch
git branch -m main

# Add remote and push
git remote add origin https://github.com/5arth4k-X/RedVect0r.git
git push -u origin main
```

---

## Disclaimer

> [!CAUTION]
> RedVect0r is intended for **authorized security testing and educational purposes only**.  
> Always obtain **explicit written permission** before scanning any system you do not own.  
> The authors are not responsible for any misuse or damage caused by this tool.  
> Unauthorized use may violate local, national, or international laws.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made for the security community

[![GitHub](https://img.shields.io/badge/GitHub-5arth4k--X-red?style=for-the-badge&logo=github)](https://github.com/5arth4k-X)

</div>
