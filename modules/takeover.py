"""
modules/takeover.py
Subdomain takeover detection.

Flow:
  1. Look for CNAME records in dns_results pointing to known services.
  2. HTTP GET the subdomain.
  3. If the response body contains the service's "unclaimed" fingerprint
     → confirmed takeover candidate (HIGH severity).
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, HTTP_TIMEOUT, USER_AGENT, TAKEOVER_SIGNATURES
from utils import reporter, abort_flag, runtime

requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": USER_AGENT}


def _cname_matches_service(cname: str) -> tuple[str, str] | None:
    """
    Returns (service_name, fingerprint) if the CNAME points to a
    known vulnerable service, else None.
    """
    cname_lower = cname.lower().rstrip(".")
    for suffix, fingerprint in TAKEOVER_SIGNATURES.items():
        if cname_lower.endswith(suffix):
            return suffix, fingerprint
    return None


def _check_takeover(args: tuple) -> dict | None:
    subdomain, cname, service, fingerprint = args

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            r = requests.get(
                url, headers=HEADERS,
                timeout=HTTP_TIMEOUT, verify=False,
                allow_redirects=True,
                proxies=runtime.get_proxies(),
            )
            if fingerprint.lower() in r.text.lower():
                return {
                    "subdomain":   subdomain,
                    "cname":       cname,
                    "service":     service,
                    "evidence":    fingerprint,
                    "url":         url,
                    "status_code": r.status_code,
                }
        except Exception:
            continue

    return None


def detect_takeover(dns_results: dict) -> list[dict]:
    """
    Check every subdomain that has a CNAME record for takeover.

    Parameters
    ----------
    dns_results : { subdomain: { record_type: [values] } }
    Returns     : list of confirmed takeover findings
    """
    print(Fore.YELLOW + "\n[+] Starting Subdomain Takeover Detection...\n")

    tasks: list[tuple] = []

    for subdomain, records in dns_results.items():
        for cname in records.get("CNAME", []):
            match = _cname_matches_service(cname)
            if match:
                service, fingerprint = match
                tasks.append((subdomain, cname, service, fingerprint))
                print(Fore.CYAN + f"  [?] {subdomain} → CNAME → {cname.rstrip('.')}"
                      + Fore.WHITE + f"  ({service})")

    if not tasks:
        print(Fore.WHITE + "  No CNAMEs pointing to potentially vulnerable services.\n")
        print(Fore.YELLOW + "[+] Takeover detection complete.\n")
        return []

    confirmed: list[dict] = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_check_takeover, task): task for task in tasks}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] Takeover detection aborted.")
                    break

                result = future.result()
                if result:
                    confirmed.append(result)
                    reporter.add_takeover(
                        result["subdomain"],
                        result["cname"],
                        result["service"],
                        result["evidence"],
                    )
                    print(
                        Fore.RED + f"\n  [!!!] TAKEOVER CONFIRMED: {result['subdomain']}\n"
                        + Fore.WHITE
                        + f"        CNAME    : {result['cname'].rstrip('.')}\n"
                        + f"        Service  : {result['service']}\n"
                        + f"        Evidence : \"{result['evidence']}\"\n"
                        + f"        URL      : {result['url']}"
                    )

        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] Takeover detection interrupted.")

    if not confirmed:
        print(Fore.GREEN + "  No confirmed takeover candidates found.")

    print(Fore.YELLOW + f"\n[+] Takeover detection complete. "
          f"{len(confirmed)} confirmed finding(s).\n")

    return confirmed