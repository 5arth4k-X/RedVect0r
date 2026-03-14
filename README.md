```
$$$$$$$\                  $$\ $$\    $$\                       $$\      $$$$$$\
$$  __$$\                 $$ |$$ |   $$ |                      $$ |    $$$ __$$\
$$ |  $$ | $$$$$$\   $$$$$$$ |$$ |   $$ | $$$$$$\   $$$$$$$\ $$$$$$\   $$$$\ $$ | $$$$$$\
$$$$$$$  |$$  __$$\ $$  __$$ |\$$\  $$  |$$  __$$\ $$  _____|\_$$  _|  $$\$$\$$ |$$  __$$\
$$  __$$ |$$$$$$$$ |$$ /  $$ | \$$\$$  / $$$$$$$$ |$$ /        $$ |    $$ \$$$$ |$$ |  \__|
$$ |  $$ |$$   ____|$$ |  $$ |  \$$$  /  $$   ____|$$ |        $$ |$$\ $$ |\$$$ |$$ |
$$ |  $$ |\$$$$$$$\ \$$$$$$$ |   \$  /   \$$$$$$$\ \$$$$$$$\   \$$$$  |\$$$$$$  /$$ |
\__|  \__| \_______| \_______|    \_/     \_______| \_______|   \____/  \______/ \__|
```

# RedVect0r — Attack Surface Mapper

> A fast, modular attack surface mapping tool for penetration testers and bug bounty hunters.  
> Built for Kali Linux. One install command. Zero configuration required.

---

## Features

- **Passive subdomain enumeration** via subfinder  
- **DNS record enumeration** — A, AAAA, CNAME, MX, TXT, NS, SOA + SPF/DMARC extraction  
- **Subdomain takeover detection** — 27 services fingerprinted  
- **Port scanning** — multiple nmap profiles (fast, full, stealth, OS, SYN, version)  
- **HTTP probing** — live host detection with server/tech disclosure  
- **Technology fingerprinting** — passive headers + WhatWeb  
- **Endpoint discovery** — built-in wordlist or custom wordlist via `--wordlist`  
- **WAF detection** — 12 WAF signatures  
- **robots.txt / sitemap.xml parsing** — extracts and flags sensitive paths  
- **CORS misconfiguration detection** — HIGH / MEDIUM / INFO severity  
- **SSL/TLS inspection** — expiry, weak ciphers, SANs  
- **Open redirect detection** — 19 common redirect parameters tested  
- **Risk scoring** — per-subdomain risk score with findings  
- **Screenshot capture** — optional, powered by Playwright  
- **Reports** — JSON + TXT saved to `output/` (or custom path via `--output`)  
- **Graceful Ctrl+C** — partial results always saved on interrupt  

---

## Installation

### Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+
- Root/sudo for nmap OS/SYN scans and install script

### Install

```bash
git clone https://github.com/yourusername/RedVect0r.git
cd RedVect0r
sudo bash install.sh
```

The install script handles everything automatically:

1. Installs `nmap`, `whatweb`, `golang` via apt  
2. Installs `subfinder` via Go and adds it to PATH permanently  
3. Creates a Python virtual environment and installs all dependencies  
4. Registers the `redvect0r` command system-wide  
5. Optionally installs Playwright + Chromium for screenshots  

After install, open a new terminal and you're ready.

---

## Usage

```
redvect0r <domain> <scan-flag> [nmap-options] [discovery-options] [output-options]

<scan-flag> is required. All other flags are optional.
```

### Scan Flags (one required)

| Flag | Nmap Args | Description |
|---|---|---|
| `--fast` | `-T4 --top-ports 100` | Quick overview, top 100 ports |
| `--stealthy` | `-T2 --top-ports 100` | Slower, less noisy on IDS/IPS |
| `--default` | `-T4` | Nmap default, top 1000 ports |
| `--full` | `-T4 -p-` | All 65535 ports (very slow) |
| `--version` | `-T4 --top-ports 100 -sV` | Service & version detection |
| `--os` | `-T4 --top-ports 100 -O` | OS fingerprinting (needs root) |
| `--syn` | `-T4 -sS --top-ports 100` | SYN stealth scan (needs root) |
| `--ports <list>` | `-T4 -p <list>` | Specific ports e.g. `22,80,443` |

### Nmap Options

| Flag | Description |
|---|---|
| `--delay <s>` | Sleep between HTTP requests e.g. `0.5` |
| `--proxy <url>` | Route all HTTP traffic through a proxy e.g. `http://127.0.0.1:8080` |

### Discovery Options

| Flag | Description |
|---|---|
| `--wordlist <path>` | Custom wordlist for endpoint discovery. Each line = one path. Built-in list used when omitted. |

### Output Options

| Flag | Description |
|---|---|
| `--output <dir>` | Directory to save reports. Defaults to `./output` in current directory. |
| `--screenshots <dir>` | Capture screenshots of live subdomains. Saved as `<dir>/<subdomain>.png`. Requires Playwright. |

### Help

```bash
redvect0r -h
```

---

## Examples

```bash
# Quick scan
redvect0r example.com --fast

# OS detection with delay and proxy (Burp Suite)
redvect0r example.com --os --delay 0.5 --proxy http://127.0.0.1:8080

# Service version detection with custom wordlist
redvect0r example.com --version --wordlist /usr/share/wordlists/dirb/common.txt

# Fast scan with screenshots saved to custom folder
redvect0r example.com --fast --screenshots /home/user/screenshots

# Full scan with all options, reports saved to custom path
redvect0r example.com --full --delay 1 --wordlist /path/to/list.txt --output /home/user/scans

# Specific ports only
redvect0r example.com --ports 22,80,443,8080
```

---

## Output

Reports are saved to `./output/` by default (or your `--output` path):

```
output/
├── report_20260313_112230.json
├── report_20260313_112230.txt
└── screenshots/           ← only if --screenshots was used
    ├── testphp.vulnweb.com.png
    └── www.vulnweb.com.png
```

Both JSON and TXT reports contain all scan data in the same section order as the CLI output.

---

## Screenshots (optional)

If you chose to install Playwright during setup:

```bash
redvect0r example.com --fast --screenshots output/screenshots
```

To install Playwright after the fact:

```bash
source /path/to/RedVect0r/venv/bin/activate
pip install playwright
playwright install chromium
```

---

## Enabling Screenshot Support After Install

```bash
cd RedVect0r
source venv/bin/activate
pip install playwright
playwright install chromium
```

---

## Disclaimer

RedVect0r is intended for authorized security testing and educational purposes only.  
Always obtain explicit written permission before scanning any system you do not own.  
The authors are not responsible for any misuse or damage caused by this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for details.