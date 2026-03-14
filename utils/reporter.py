import os
import json
from datetime import datetime
from colorama import Fore

# Resolved at runtime — defaults to <cwd>/output.
# Overridden early in main() via set_output_dir() when --output is given.
_output_dir: str = os.path.join(os.getcwd(), "output")


def set_output_dir(path: str) -> None:
    """Call once at startup to redirect all report output to a custom dir."""
    global _output_dir
    _output_dir = os.path.abspath(path)
    os.makedirs(_output_dir, exist_ok=True)


def _ensure_output_dir() -> str:
    """Return current output dir, creating it if needed."""
    os.makedirs(_output_dir, exist_ok=True)
    return _output_dir

_HTTP_PLACEHOLDER_FINGERPRINTS = {"No fingerprint data", "Fingerprinting failed"}


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ─────────────────────────────────────────────────────────────────
#  In-memory store — key order mirrors the CLI pipeline exactly:
#    1  subdomains        7  endpoints
#    2  dns_records       8  waf
#    3  takeover          9  crawled_paths  (robots / sitemap)
#    4  ports             10 cors
#    5  http              11 ssl
#    6  fingerprinting    12 open_redirects
#                         13 risk_scores
#                         14 screenshots
# ─────────────────────────────────────────────────────────────────
_report = {
    "meta":           {},
    "subdomains":     {},   # { sub: ip }
    "dns_records":    {},   # { sub: { record_type: [values] } }
    "takeover":       [],   # [ { subdomain, cname, service, evidence } ]
    "ports":          {},   # { ip: { scanned, open: [{port,proto,...}] } }
    "http":           [],   # [ { url, status, server, fingerprint } ]
    "fingerprinting": [],   # [ { url, passive: [...], whatweb: "..." } ]
    "endpoints":      [],   # [ { url, status, content_type, size } ]
    "waf":            {},   # { base_url: waf_name }
    "crawled_paths":  [],   # [ { subdomain, source, path } ]
    "cors":           [],   # [ { url, acao, acac, severity } ]
    "ssl":            {},   # { sub: { expiry, days_left, cipher, sans, ... } }
    "open_redirects": [],   # [ { original_url, param, test_url, location } ]
    "risk_scores":    {},   # { target: { score, findings } }
    "screenshots":    [],   # [ { subdomain, url, path } ]
}


# ── Setters ──────────────────────────────────────────────────────

def set_meta(domain, nmap_args=None, delay=0.0, proxy=None,
             wordlist=None, screenshots_dir=None, output_dir=None):
    _report["meta"] = {
        "domain":          domain,
        "scan_time":       datetime.now().isoformat(),
        "nmap_profile":    nmap_args or "N/A",
        "delay":           delay,
        "proxy":           proxy or "none",
        "wordlist":        wordlist or "built-in",
        "screenshots_dir": screenshots_dir or "none",
        "output_dir":      output_dir or _output_dir,
    }


def add_subdomain(sub, ip):
    _report["subdomains"][sub] = ip


def add_dns_records(sub, records: dict):
    _report["dns_records"][sub] = records


def add_takeover(subdomain, cname, service, evidence):
    _report["takeover"].append({
        "subdomain": subdomain,
        "cname":     cname,
        "service":   service,
        "evidence":  evidence,
    })


def add_port_scan_target(ip):
    if ip not in _report["ports"]:
        _report["ports"][ip] = {"scanned": True, "open": []}


def add_port_result(ip, port, proto, service="", product="", version=""):
    add_port_scan_target(ip)
    _report["ports"][ip]["open"].append({
        "port": port, "proto": proto,
        "service": service, "product": product, "version": version,
    })


def add_http_result(url, status, server, fingerprint=None):
    if fingerprint in _HTTP_PLACEHOLDER_FINGERPRINTS:
        fingerprint = None
    _report["http"].append({
        "url": url, "status": status,
        "server": server, "fingerprint": fingerprint,
    })


def add_fingerprint(url: str, passive: list, whatweb: str):
    _report["fingerprinting"].append({
        "url":     url,
        "passive": passive or [],
        "whatweb": whatweb or "",
    })


def add_endpoint(url, status, content_type="", size=0):
    _report["endpoints"].append({
        "url": url, "status": status,
        "content_type": content_type, "size": size,
    })


def add_waf(base_url, waf_name):
    _report["waf"][base_url] = waf_name


def add_crawled_path(subdomain, source, path):
    _report["crawled_paths"].append({
        "subdomain": subdomain, "source": source, "path": path,
    })


def add_cors_finding(url, acao, acac, severity):
    _report["cors"].append({
        "url": url, "acao": acao, "acac": acac, "severity": severity,
    })


def add_ssl_result(subdomain, result: dict):
    _report["ssl"][subdomain] = result


def add_open_redirect(original_url, param, test_url, location):
    _report["open_redirects"].append({
        "original_url": original_url,
        "param":        param,
        "test_url":     test_url,
        "location":     location,
    })


def add_risk(target, score, findings):
    _report["risk_scores"][target] = {"score": score, "findings": findings}


def add_screenshot(subdomain: str, url: str, path: str):
    _report["screenshots"].append({
        "subdomain": subdomain,
        "url":       url,
        "path":      path,
    })


# ── Helpers ───────────────────────────────────────────────────────

def _risk_label(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 35:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


# ── Exporters ────────────────────────────────────────────────────

def save_json():
    fname = os.path.join(_ensure_output_dir(), f"report_{_timestamp()}.json")
    with open(fname, "w") as f:
        json.dump(_report, f, indent=2)
    print(Fore.CYAN + f"\n[+] JSON report saved → {fname}")
    return fname


def save_txt():
    fname = os.path.join(_ensure_output_dir(), f"report_{_timestamp()}.txt")

    with open(fname, "w") as f:
        meta = _report["meta"]

        # ── Header ────────────────────────────────────────────────
        f.write("=" * 60 + "\n")
        f.write("  RedVect0r Scan Report\n")
        f.write(f"  Domain          : {meta.get('domain', 'N/A')}\n")
        f.write(f"  Date            : {meta.get('scan_time', 'N/A')}\n")
        f.write(f"  Nmap Profile    : {meta.get('nmap_profile', 'N/A')}\n")
        f.write(f"  Delay           : {meta.get('delay', 0)}s\n")
        f.write(f"  Proxy           : {meta.get('proxy', 'none')}\n")
        f.write(f"  Wordlist        : {meta.get('wordlist', 'built-in')}\n")
        f.write(f"  Screenshots Dir : {meta.get('screenshots_dir', 'none')}\n")
        f.write("=" * 60 + "\n\n")

        # ── 1. Subdomains ─────────────────────────────────────────
        f.write(f"[SUBDOMAINS]  ({len(_report['subdomains'])} live)\n")
        for sub, ip in _report["subdomains"].items():
            f.write(f"  {sub} → {ip}\n")

        # ── 2. DNS Records ────────────────────────────────────────
        f.write("\n[DNS RECORDS]\n")
        if not _report["dns_records"]:
            f.write("  No DNS records collected.\n")
        else:
            for sub, records in _report["dns_records"].items():
                f.write(f"\n  {sub}:\n")
                for rtype, values in records.items():
                    for v in values:
                        f.write(f"    {rtype:<8}  {v}\n")

        # ── 3. Subdomain Takeover ─────────────────────────────────
        f.write("\n[SUBDOMAIN TAKEOVER]\n")
        if not _report["takeover"]:
            f.write("  No takeover candidates found.\n")
        else:
            for t in _report["takeover"]:
                f.write(f"\n  !! CONFIRMED: {t['subdomain']}\n")
                f.write(f"     CNAME   : {t['cname']}\n")
                f.write(f"     Service : {t['service']}\n")
                f.write(f"     Evidence: {t['evidence']}\n")

        # ── 4. Port Scan ──────────────────────────────────────────
        f.write(f"\n[PORT SCAN]  (profile: {meta.get('nmap_profile', 'N/A')})\n")
        if not _report["ports"]:
            f.write("  No IPs were scanned.\n")
        else:
            for ip, data in _report["ports"].items():
                open_ports = data.get("open", [])
                f.write(f"\n  {ip}:\n")
                if not open_ports:
                    f.write("    Scanned — no open ports found "
                            "(host may be firewalled or blocking nmap probes).\n")
                else:
                    for p in open_ports:
                        svc = f"{p['service']} {p['product']} {p['version']}".strip()
                        f.write(f"    {p['port']}/{p['proto']} - OPEN | {svc}\n")

        # ── 5. HTTP Probing ───────────────────────────────────────
        f.write("\n[HTTP PROBING]\n")
        if not _report["http"]:
            f.write("  No HTTP responses received "
                    "(all targets unreachable or timed out).\n")
        else:
            for h in _report["http"]:
                f.write(f"  {h['url']} → {h['status']} | Server: {h['server']}\n")
                if h.get("fingerprint"):
                    f.write(f"    ↳ {h['fingerprint']}\n")

        # ── 6. Technology Fingerprinting ──────────────────────────
        f.write("\n[TECHNOLOGY FINGERPRINTING]\n")
        if not _report["fingerprinting"]:
            f.write("  No technology data collected.\n")
        else:
            for fp in _report["fingerprinting"]:
                f.write(f"\n  {fp['url']}\n")
                if fp.get("passive"):
                    f.write(f"    ↳ Passive  : {', '.join(fp['passive'])}\n")
                if fp.get("whatweb"):
                    f.write(f"    ↳ WhatWeb  : {fp['whatweb']}\n")

        # ── 7. Endpoints ──────────────────────────────────────────
        f.write("\n[ENDPOINTS]\n")
        if not _report["endpoints"]:
            f.write("  No interesting endpoints found.\n")
        else:
            for e in _report["endpoints"]:
                f.write(f"  [{e['status']}] {e['url']}  ({e['size']} bytes)\n")

        # ── 8. WAF Detection ──────────────────────────────────────
        f.write("\n[WAF DETECTION]\n")
        if not _report["waf"]:
            f.write("  No WAF data collected.\n")
        else:
            for url, waf in _report["waf"].items():
                f.write(f"  {url} → {waf}\n")

        # ── 9. robots.txt / sitemap.xml ───────────────────────────
        f.write("\n[ROBOTS / SITEMAP PATHS]\n")
        if not _report["crawled_paths"]:
            f.write("  No interesting paths discovered.\n")
        else:
            by_sub: dict = {}
            for cp in _report["crawled_paths"]:
                by_sub.setdefault(cp["subdomain"], []).append(cp["path"])
            for sub, paths in by_sub.items():
                f.write(f"  {sub}:\n")
                for p in paths:
                    f.write(f"    {p}\n")

        # ── 10. CORS Misconfigurations ────────────────────────────
        f.write("\n[CORS MISCONFIGURATIONS]\n")
        if not _report["cors"]:
            f.write("  No CORS issues found.\n")
        else:
            for c in _report["cors"]:
                f.write(f"  [{c['severity']}] {c['url']}\n")
                f.write(f"    ACAO: {c['acao']}  |  ACAC: {c['acac']}\n")

        # ── 11. SSL/TLS Inspection ────────────────────────────────
        f.write("\n[SSL/TLS INSPECTION]\n")
        if not _report["ssl"]:
            f.write("  No SSL data collected.\n")
        else:
            has_valid = False
            for sub, d in _report["ssl"].items():
                if d.get("error"):
                    err = d["error"].lower()
                    if "closed" not in err and "port 443" not in err:
                        f.write(f"  [-] {sub}: {d['error']}\n")
                    continue
                has_valid = True
                flag = ""
                if d.get("expired"):
                    flag = " [EXPIRED]"
                elif d.get("expiring_soon"):
                    flag = f" [EXPIRING in {d.get('days_left')} days]"
                if d.get("weak_cipher"):
                    flag += " [WEAK CIPHER]"
                f.write(f"\n  {sub}{flag}\n")
                f.write(f"    Subject : {d.get('subject')}\n")
                f.write(f"    Issuer  : {d.get('issuer')}\n")
                expiry_str = (d.get("expiry") or "N/A")[:10]
                f.write(f"    Expiry  : {expiry_str} ({d.get('days_left')} days)\n")
                f.write(f"    Cipher  : {d.get('cipher')}\n")
                if d.get("sans"):
                    f.write(f"    SANs    : {', '.join(d['sans'][:8])}\n")
            if not has_valid:
                f.write("  All SSL connections failed (see errors above).\n")

        # ── 12. Open Redirects ────────────────────────────────────
        f.write("\n[OPEN REDIRECTS]\n")
        if not _report["open_redirects"]:
            f.write("  No open redirects found.\n")
        else:
            for r in _report["open_redirects"]:
                f.write(f"  {r['original_url']}\n")
                f.write(f"    Param    : ?{r['param']}=...\n")
                f.write(f"    Location : {r['location']}\n")

        # ── 13. Risk Scores ───────────────────────────────────────
        f.write("\n[RISK SCORES]\n")
        if not _report["risk_scores"]:
            f.write("  No risk scores calculated.\n")
        else:
            for target, data in _report["risk_scores"].items():
                score = data["score"]
                label = _risk_label(score)
                f.write(f"\n  {target}  →  Score: {score}  [{label}]\n")
                for finding in data["findings"]:
                    f.write(f"    • {finding}\n")

        # ── 14. Screenshots ───────────────────────────────────────
        f.write("\n[SCREENSHOTS]\n")
        if not _report["screenshots"]:
            f.write("  No screenshots captured.\n")
        else:
            for s in _report["screenshots"]:
                f.write(f"  {s['subdomain']}\n")
                f.write(f"    URL  : {s['url']}\n")
                f.write(f"    File : {s['path']}\n")

    print(Fore.CYAN + f"[+] TXT report saved  → {fname}")
    return fname


def generate_reports():
    save_json()
    save_txt()