import os
import sys
import signal
from colorama import Fore, init

init(autoreset=True)

# ── Abort flag must be imported BEFORE any module that uses it ────
from utils import abort_flag, runtime

from modules.subdomain_enum   import enumerate_subdomains
from modules.port_scanner     import scan_ports
from modules.http_probe       import http_probe
from modules.endpoint_checker import check_endpoints
from modules.fingerprint      import fingerprint_all
from modules.waf_detector     import detect_waf
from modules.risk_scoring     import calculate_risk
from modules.dns_enum         import enumerate_dns
from modules.takeover         import detect_takeover
from modules.robots_parser    import parse_robots_and_sitemap
from modules.cors_check       import check_cors
from modules.ssl_inspect      import inspect_ssl
from modules.open_redirect    import check_open_redirects
from modules.screenshot       import capture_screenshots
from utils.resolver           import resolve_domains
from utils                    import reporter


CLI_PROFILE_MAP = {
    "--fast":     "-T4 --top-ports 100",
    "--stealthy": "-T2 --top-ports 100",
    "--full":     "-T4 -p-",
    "--default":  "-T4",
    "--version":  "-T4 --top-ports 100 -sV",
    "--os":       "-T4 --top-ports 100 -O",
    "--syn":      "-T4 -sS --top-ports 100",
}

_SEP = Fore.WHITE + "─" * 60


# ── Signal handler ────────────────────────────────────────────────
def _handle_sigint(sig, frame):
    if abort_flag.is_set():
        print(Fore.RED + "\n[!] Force quit.")
        sys.exit(1)
    abort_flag.set()
    print(
        Fore.RED + "\n\n[!] Ctrl+C detected — "
        "stopping after current task...\n"
        "    Press Ctrl+C again to force quit immediately.\n"
    )

signal.signal(signal.SIGINT, _handle_sigint)


def banner():
    print(Fore.RED + r"""
$$$$$$$\                  $$\ $$\    $$\                       $$\      $$$$$$\
$$  __$$\                 $$ |$$ |   $$ |                      $$ |    $$$ __$$\
$$ |  $$ | $$$$$$\   $$$$$$$ |$$ |   $$ | $$$$$$\   $$$$$$$\ $$$$$$\   $$$$\ $$ | $$$$$$\
$$$$$$$  |$$  __$$\ $$  __$$ |\$$\  $$  |$$  __$$\ $$  _____|\_$$  _|  $$\$$\$$ |$$  __$$\
$$  __$$ |$$$$$$$$ |$$ /  $$ | \$$\$$  / $$$$$$$$ |$$ /        $$ |    $$ \$$$$ |$$ |  \__|
$$ |  $$ |$$   ____|$$ |  $$ |  \$$$  /  $$   ____|$$ |        $$ |$$\ $$ |\$$$ |$$ |
$$ |  $$ |\$$$$$$$\ \$$$$$$$ |   \$  /   \$$$$$$$\ \$$$$$$$\   \$$$$  |\$$$$$$  /$$ |
\__|  \__| \_______| \_______|    \_/     \_______| \_______|   \____/  \______/ \__|
""")
    print(Fore.RED + "  RedVect0r — Attack Surface Mapper\n")


def usage():
    print(Fore.YELLOW + "Usage:")
    print(Fore.WHITE
          + "  python main.py <domain> <scan-flag> "
            "[nmap-options] [discovery-options] [output-options]\n")
    print(Fore.WHITE + "  <scan-flag> is required. All other flags are optional.\n")

    # ── Scan Flags ────────────────────────────────────────────────
    print(_SEP)
    print(Fore.YELLOW + "  SCAN FLAGS  (one required)")
    print(_SEP)
    scan_flags = [
        ("--fast",         "-T4 --top-ports 100",       "Quick overview, top 100 ports"),
        ("--stealthy",     "-T2 --top-ports 100",       "Slower, less noisy on IDS/IPS"),
        ("--default",      "-T4",                       "Nmap default, top 1000 ports"),
        ("--full",         "-T4 -p-",                   "All 65535 ports (very slow)"),
        ("--version",      "-T4 --top-ports 100 -sV",  "Service & version detection"),
        ("--os",           "-T4 --top-ports 100 -O",   "OS fingerprinting (needs root)"),
        ("--syn",          "-T4 -sS --top-ports 100",  "SYN stealth scan (needs root)"),
        ("--ports <list>", "",                          "Specific ports  e.g. 22,80,443"),
    ]
    for flag, args, note in scan_flags:
        print(Fore.CYAN  + f"  {flag:<22}"
              + Fore.WHITE + f"  {args:<28}"
              + Fore.WHITE + f"  {note}")

    # ── Nmap Options ──────────────────────────────────────────────
    print()
    print(_SEP)
    print(Fore.YELLOW + "  NMAP OPTIONS  (combine freely with any scan flag)")
    print(_SEP)
    print(Fore.CYAN  + "  --delay <s>          "
          + Fore.WHITE + "  Seconds to sleep between HTTP requests  e.g. 0.5")
    print(Fore.CYAN  + "  --proxy <url>        "
          + Fore.WHITE + "  Route all HTTP traffic through a proxy")
    print(Fore.WHITE + "                          e.g. http://127.0.0.1:8080")

    # ── Discovery Options ─────────────────────────────────────────
    print()
    print(_SEP)
    print(Fore.YELLOW + "  DISCOVERY OPTIONS")
    print(_SEP)
    print(Fore.CYAN  + "  --wordlist <path>    "
          + Fore.WHITE + "  Custom wordlist for endpoint discovery")
    print(Fore.WHITE + "                          Each line = one path")
    print(Fore.WHITE + "                          e.g. /usr/share/wordlists/raft.txt")
    print(Fore.WHITE + "                          (built-in list used when omitted)")

    # ── Output Options ────────────────────────────────────────────
    print()
    print(_SEP)
    print(Fore.YELLOW + "  OUTPUT OPTIONS")
    print(_SEP)
    print(Fore.CYAN  + "  --screenshots <dir>  "
          + Fore.WHITE + "  Capture screenshots of live subdomains")
    print(Fore.WHITE + "                          Saved as <dir>/<subdomain>.png")
    print(Fore.WHITE + "                          e.g. --screenshots output/screenshots")
    print(Fore.WHITE + "                          Requires: pip install playwright")
    print(Fore.WHITE + "                                    playwright install chromium")
    print()
    print(Fore.CYAN  + "  --output <dir>       "
          + Fore.WHITE + "  Directory to save reports (JSON + TXT)")
    print(Fore.WHITE + "                          Defaults to ./output in current directory")
    print(Fore.WHITE + "                          e.g. --output /home/user/scans/results")

    # ── Examples ──────────────────────────────────────────────────
    print()
    print(_SEP)
    print(Fore.YELLOW + "  Examples")
    print(_SEP)
    examples = [
        "redvect0r example.com --fast",
        "redvect0r example.com --os --delay 0.5 --proxy http://127.0.0.1:8080",
        "redvect0r example.com --version --wordlist /path/to/wordlist.txt",
        "redvect0r example.com --fast --screenshots output/screenshots",
        "redvect0r example.com --ports 22,80,443 --delay 1 --wordlist /path/to/list.txt",
        "redvect0r example.com --fast --output /home/user/scans/results",
    ]
    for ex in examples:
        print(Fore.WHITE + f"  {ex}")
    print()


def parse_args(argv):
    if len(argv) < 3:
        usage()
        sys.exit(1)

    domain = argv[1]
    flag   = argv[2]

    # ── Scan flag (required) ──────────────────────────────────────
    if flag in ("-h", "--help"):
        usage()
        sys.exit(0)
    elif flag == "--ports":
        if len(argv) < 4:
            print(Fore.RED + "\n[!] --ports requires a port list.")
            print(Fore.WHITE + "    Example: redvect0r example.com --ports 22,80,443\n")
            sys.exit(1)
        nmap_args = f"-T4 -p {argv[3]}"
        start_idx = 4
    elif flag in CLI_PROFILE_MAP:
        nmap_args = CLI_PROFILE_MAP[flag]
        start_idx = 3
    else:
        print(Fore.RED + f"\n[!] Unknown or missing scan flag: '{flag}'\n")
        usage()
        sys.exit(1)

    # ── Optional flags ────────────────────────────────────────────
    delay           = 0.0
    proxy           = None
    wordlist        = None
    screenshots_dir = None
    output_dir      = None

    i = start_idx
    while i < len(argv):
        tok = argv[i]

        if tok == "--delay":
            if i + 1 >= len(argv):
                print(Fore.RED + "\n[!] --delay requires a value (e.g. --delay 0.5)\n")
                sys.exit(1)
            try:
                delay = float(argv[i + 1])
            except ValueError:
                print(Fore.RED + f"\n[!] Invalid delay value: {argv[i + 1]}\n")
                sys.exit(1)
            i += 2

        elif tok == "--proxy":
            if i + 1 >= len(argv):
                print(Fore.RED + "\n[!] --proxy requires a URL\n")
                sys.exit(1)
            proxy = argv[i + 1]
            i += 2

        elif tok == "--wordlist":
            if i + 1 >= len(argv):
                print(Fore.RED + "\n[!] --wordlist requires a file path\n")
                sys.exit(1)
            wordlist = argv[i + 1]
            if not os.path.isfile(wordlist):
                print(Fore.RED + f"\n[!] Wordlist file not found: {wordlist}\n")
                sys.exit(1)
            i += 2

        elif tok == "--screenshots":
            if i + 1 >= len(argv):
                print(Fore.RED + "\n[!] --screenshots requires a directory path\n")
                sys.exit(1)
            screenshots_dir = argv[i + 1]
            i += 2

        elif tok == "--output":
            if i + 1 >= len(argv):
                print(Fore.RED + "\n[!] --output requires a directory path\n")
                sys.exit(1)
            output_dir = argv[i + 1]
            i += 2

        else:
            print(Fore.RED + f"\n[!] Unknown option: {tok}\n")
            usage()
            sys.exit(1)

    return domain, nmap_args, delay, proxy, wordlist, screenshots_dir, output_dir


def _step(label, fn, *args, **kwargs):
    """Run one pipeline step; skip cleanly if abort was requested."""
    if abort_flag.is_set():
        print(Fore.YELLOW + f"[~] Skipping: {label}")
        return None
    return fn(*args, **kwargs)


def _shutdown():
    if abort_flag.is_set():
        print(Fore.YELLOW + "\n[!] Scan interrupted — saving partial results...\n")
    reporter.generate_reports()
    if abort_flag.is_set():
        print(Fore.YELLOW + "[✓] Partial report saved. RedVect0r stopped.\n")
    else:
        print(Fore.GREEN + "\n[✓] RedVect0r scan complete!\n")


def main():
    banner()

    domain, nmap_args, delay, proxy, wordlist, screenshots_dir, output_dir = parse_args(sys.argv)

    # ── Output directory (resolved before any module touches the reporter) ──
    reporter.set_output_dir(output_dir if output_dir else "output")

    # Apply runtime settings (read by all HTTP modules via utils.runtime)
    if delay:
        runtime.set_delay(delay)
    if proxy:
        runtime.set_proxy(proxy)

    reporter.set_meta(
        domain, nmap_args,
        delay=delay, proxy=proxy,
        wordlist=wordlist,
        screenshots_dir=screenshots_dir,
        output_dir=output_dir,
    )

    print(Fore.WHITE + f"[+] Target      : {Fore.CYAN}{domain}")
    print(Fore.WHITE + f"[+] Nmap profile: {Fore.CYAN}{nmap_args}")
    if delay:
        print(Fore.WHITE + f"[+] Delay       : {Fore.CYAN}{delay}s per request")
    if proxy:
        print(Fore.WHITE + f"[+] Proxy       : {Fore.CYAN}{proxy}")
    if wordlist:
        print(Fore.WHITE + f"[+] Wordlist    : {Fore.CYAN}{wordlist}")
    if screenshots_dir:
        print(Fore.WHITE + f"[+] Screenshots : {Fore.CYAN}{screenshots_dir}")
    print(Fore.WHITE + f"[+] Output dir  : {Fore.CYAN}{reporter._output_dir}")
    print()

    # ── 1. Subdomain Enumeration ──────────────────────────────────
    subdomains = _step("Subdomain Enumeration", enumerate_subdomains, domain) or []

    # ── 2. DNS Resolution ─────────────────────────────────────────
    live_data = _step("DNS Resolution", resolve_domains, subdomains)
    if not live_data:
        if not abort_flag.is_set():
            print(Fore.RED + "[-] No live subdomains found. Exiting.")
        _shutdown()
        return

    print(Fore.GREEN + "\n[+] Live Subdomains:")
    for sub, ip in live_data.items():
        print(f"    {sub} → {ip}")
        reporter.add_subdomain(sub, ip)

    unique_ips = list(set(live_data.values()))
    print(Fore.CYAN + f"\n[+] Unique IPs to scan: {len(unique_ips)}")

    # ── 3. Full DNS Record Enumeration ────────────────────────────
    dns_results = _step("DNS Enumeration", enumerate_dns, list(live_data.keys())) or {}

    # ── 4. Subdomain Takeover Detection ───────────────────────────
    takeover_findings = _step("Takeover Detection", detect_takeover, dns_results) or []

    # ── 5. Port Scanning ──────────────────────────────────────────
    _step("Port Scanning", scan_ports, unique_ips, nmap_args=nmap_args)

    # ── 6. HTTP Probing ───────────────────────────────────────────
    _step("HTTP Probing", http_probe, live_data)

    # ── 7. Technology Fingerprinting ──────────────────────────────
    _step("Fingerprinting", fingerprint_all, live_data)

    # ── 8. Endpoint Discovery ─────────────────────────────────────
    endpoints = _step(
        "Endpoint Discovery", check_endpoints, live_data, wordlist=wordlist
    ) or []

    # ── 9. WAF Detection ──────────────────────────────────────────
    waf_results = _step("WAF Detection", detect_waf, live_data) or {}

    # ── 10. robots.txt / sitemap.xml ──────────────────────────────
    _step("robots/sitemap Parsing", parse_robots_and_sitemap, live_data)

    # ── 11. CORS Check ────────────────────────────────────────────
    cors_findings = _step("CORS Check", check_cors, live_data) or []

    # ── 12. SSL/TLS Inspection ────────────────────────────────────
    ssl_results = _step("SSL Inspection", inspect_ssl, live_data) or {}

    # ── 13. Open Redirect Detection ───────────────────────────────
    open_redirects = _step(
        "Open Redirect", check_open_redirects, reporter._report["endpoints"]
    ) or []

    # ── 14. Risk Scoring ──────────────────────────────────────────
    _step(
        "Risk Scoring",
        calculate_risk,
        live_data,
        reporter._report["ports"],
        reporter._report["http"],
        reporter._report["endpoints"],
        waf_results,
        ssl_results=ssl_results,
        cors_findings=cors_findings,
        takeover_findings=takeover_findings,
        open_redirects=open_redirects,
    )

    # ── 15. Screenshots (optional) ────────────────────────────────
    if screenshots_dir:
        _step("Screenshots", capture_screenshots, live_data, screenshots_dir)

    # ── 16. Report Generation ─────────────────────────────────────
    _shutdown()


if __name__ == "__main__":
    main()