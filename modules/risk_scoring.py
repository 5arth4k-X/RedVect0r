from colorama import Fore
from config import RISK_WEIGHTS, CRITICAL_PORTS, SENSITIVE_PATHS
from utils import reporter


def _score_ports(ip, port_data):
    score, findings = 0, []
    if not port_data:
        return score, findings
    for entry in port_data:
        if not isinstance(entry, dict):
            continue
        port    = int(entry.get("port", 0))
        proto   = entry.get("proto", "tcp")
        service = entry.get("service", "")
        product = entry.get("product", "")
        if port in CRITICAL_PORTS:
            score += RISK_WEIGHTS["open_port_critical"]
            findings.append(f"Critical port open: {port}/{proto} ({service} {product})")
        else:
            score += RISK_WEIGHTS["open_port_medium"]
            findings.append(f"Open port: {port}/{proto} ({service} {product})")
    return score, findings


def _score_endpoints(sub, endpoints):
    score, findings = 0, []
    for e in endpoints:
        if sub not in e["url"]:
            continue
        for sp in SENSITIVE_PATHS:
            if sp in e["url"]:
                score += RISK_WEIGHTS["sensitive_endpoint"]
                findings.append(
                    f"Sensitive endpoint exposed: {e['url']} [{e['status']}]")
                break
        if e["status"] == 500:
            score += RISK_WEIGHTS["status_500"]
            findings.append(f"Server error (500) at {e['url']}")
        if e["status"] in (401, 403) and any(
            kw in e["url"] for kw in ("/admin", "/login", "/dashboard")
        ):
            score += RISK_WEIGHTS["auth_bypass_hint"]
            findings.append(
                f"Auth-protected admin path found: {e['url']} [{e['status']}]")
    return score, findings


def _score_http(sub, http_results, waf_results):
    score, findings = 0, []
    http_found = https_found = False
    for h in http_results:
        if sub not in h["url"]:
            continue
        if h["url"].startswith("https://"):
            https_found = True
        if h["url"].startswith("http://"):
            http_found = True
        if h.get("fingerprint") or h.get("server", "Unknown") != "Unknown":
            score += RISK_WEIGHTS["tech_disclosed"]
            findings.append(
                f"Tech/server header disclosed on {h['url']}: {h.get('server')}")
    if http_found and not https_found:
        score += RISK_WEIGHTS["no_https"]
        findings.append(f"No HTTPS detected for {sub}")
    for base_url, waf in waf_results.items():
        if sub in base_url and waf in ("None detected", "Unreachable"):
            score += RISK_WEIGHTS["waf_absent"]
            findings.append(f"No WAF detected on {base_url}")
            break
    return score, findings


def _score_ssl(sub, ssl_results: dict):
    score, findings = 0, []
    result = ssl_results.get(sub)
    if not result or result.get("error"):
        return score, findings
    if result.get("expired"):
        score += RISK_WEIGHTS["ssl_expired"]
        findings.append(
            f"SSL certificate EXPIRED ({abs(result['days_left'])} days ago)")
    elif result.get("expiring_soon"):
        score += RISK_WEIGHTS["ssl_expiring_soon"]
        findings.append(
            f"SSL certificate expiring soon ({result['days_left']} days left)")
    if result.get("weak_cipher"):
        score += RISK_WEIGHTS["ssl_weak_cipher"]
        findings.append(f"Weak cipher suite in use: {result.get('cipher')}")
    return score, findings


def _score_cors(sub, cors_findings: list):
    score, findings = 0, []
    for c in cors_findings:
        if sub not in c["url"]:
            continue
        if c["severity"] == "HIGH":
            score += RISK_WEIGHTS["cors_with_credentials"]
            findings.append(
                f"CORS misconfiguration (with credentials): {c['url']}")
        elif c["severity"] == "MEDIUM":
            score += RISK_WEIGHTS["cors_reflect"]
            findings.append(
                f"CORS reflects arbitrary origin: {c['url']}")
    return score, findings


def _score_takeover(sub, takeover_findings: list):
    score, findings = 0, []
    for t in takeover_findings:
        if t["subdomain"] == sub:
            score += RISK_WEIGHTS["subdomain_takeover"]
            findings.append(
                f"SUBDOMAIN TAKEOVER via {t['service']}: {t['cname']}")
    return score, findings


def _score_open_redirects(sub, redirects: list):
    score, findings = 0, []
    for r in redirects:
        if sub not in r.get("original_url", ""):
            continue
        score += RISK_WEIGHTS["open_redirect"]
        findings.append(
            f"Open redirect: {r['original_url']} ?{r['param']}=...")
        break   # one finding per subdomain is enough
    return score, findings


def calculate_risk(
    live_data,
    port_data,
    http_results,
    endpoints,
    waf_results,
    ssl_results=None,
    cors_findings=None,
    takeover_findings=None,
    open_redirects=None,
):
    """
    Aggregate risk scores per subdomain.
    All new parameters default to empty so the call signature is
    backwards-compatible with callers that haven't been updated.
    """
    print(Fore.YELLOW + "\n[+] Calculating Risk Scores...\n")

    ssl_results       = ssl_results       or {}
    cors_findings     = cors_findings     or []
    takeover_findings = takeover_findings or []
    open_redirects    = open_redirects    or []

    all_scores = {}

    for sub, ip in live_data.items():
        total, findings = 0, []

        ip_ports = port_data.get(ip, []) if isinstance(port_data, dict) else []

        for fn, extra in [
            (_score_ports,          (ip_ports,)),
            (_score_endpoints,      (endpoints,)),
            (_score_http,           (http_results, waf_results)),
            (_score_ssl,            (ssl_results,)),
            (_score_cors,           (cors_findings,)),
            (_score_takeover,       (takeover_findings,)),
            (_score_open_redirects, (open_redirects,)),
        ]:
            s, f = fn(sub, *extra)
            total    += s
            findings += f

        all_scores[sub] = {"score": total, "findings": findings}
        reporter.add_risk(sub, total, findings)

        if total >= 60:
            color, label = Fore.RED,    "CRITICAL"
        elif total >= 35:
            color, label = Fore.YELLOW, "HIGH"
        elif total >= 15:
            color, label = Fore.CYAN,   "MEDIUM"
        else:
            color, label = Fore.GREEN,  "LOW"

        print(color + f"  {sub}  →  Risk Score: {total}  [{label}]")
        for finding in findings:
            print(Fore.WHITE + f"    • {finding}")

    print(Fore.YELLOW + "\n[+] Risk scoring complete.\n")
    return all_scores