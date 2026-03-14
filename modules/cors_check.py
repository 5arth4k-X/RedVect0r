"""
modules/cors_check.py
CORS misconfiguration detection.

Sends a request with Origin: https://evil.com to every live subdomain
and checks whether the server reflects the origin back in
Access-Control-Allow-Origin.

Severity levels:
  HIGH   — ACAO reflects evil.com AND ACAC: true  (credentials exposed)
  MEDIUM — ACAO reflects evil.com  (no credentials)
  INFO   — ACAO: * (wildcard, lower risk unless ACAC is set)
"""

import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, HTTP_TIMEOUT, USER_AGENT, CORS_TEST_ORIGIN
from utils import reporter, abort_flag, runtime

requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": USER_AGENT,
    "Origin":     CORS_TEST_ORIGIN,
}


def _check_cors(args: tuple) -> dict | None:
    subdomain, url = args
    delay = runtime.get_delay()

    if delay:
        time.sleep(delay)

    try:
        r = requests.get(
            url, headers=HEADERS,
            timeout=HTTP_TIMEOUT, verify=False,
            allow_redirects=True,
            proxies=runtime.get_proxies(),
        )
    except Exception:
        return None

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

    if not acao:
        return None

    vulnerable = False
    severity   = ""

    if CORS_TEST_ORIGIN in acao:
        vulnerable = True
        severity   = "HIGH" if acac == "true" else "MEDIUM"
    elif acao == "*":
        # Wildcard alone is not exploitable for credentialed requests
        # but worth reporting as INFO
        vulnerable = True
        severity   = "INFO"

    if not vulnerable:
        return None

    return {
        "subdomain": subdomain,
        "url":       url,
        "acao":      acao,
        "acac":      acac or "not set",
        "severity":  severity,
    }


def check_cors(live_data: dict) -> list[dict]:
    """
    Run CORS check against every live subdomain (both http + https).
    Returns list of vulnerable findings.
    """
    print(Fore.YELLOW + "\n[+] Starting CORS Misconfiguration Check...\n")

    tasks: list[tuple] = []
    for sub in live_data:
        tasks.append((sub, f"https://{sub}"))
        tasks.append((sub, f"http://{sub}"))

    findings: list[dict] = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_check_cors, task): task for task in tasks}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] CORS check aborted.")
                    break

                result = future.result()
                if result:
                    findings.append(result)
                    reporter.add_cors_finding(
                        result["url"],
                        result["acao"],
                        result["acac"],
                        result["severity"],
                    )

                    if result["severity"] == "HIGH":
                        color = Fore.RED
                    elif result["severity"] == "MEDIUM":
                        color = Fore.YELLOW
                    else:
                        color = Fore.CYAN

                    print(color + f"  [{result['severity']}] {result['url']}")
                    print(Fore.WHITE
                          + f"        ACAO : {result['acao']}\n"
                          + f"        ACAC : {result['acac']}")

        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] CORS check interrupted.")

    if not findings:
        print(Fore.GREEN + "  No CORS misconfigurations found.")

    print(Fore.YELLOW + f"\n[+] CORS check complete. "
          f"{len(findings)} finding(s).\n")

    return findings