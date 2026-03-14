"""
modules/open_redirect.py
Open redirect detection.

For every discovered endpoint that returned 200/301/302, appends
common redirect parameters pointing at https://evil.com and checks
whether the server issues a redirect to that URL.
"""

import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import (
    THREADS, HTTP_TIMEOUT, USER_AGENT,
    OPEN_REDIRECT_PARAMS, OPEN_REDIRECT_PAYLOAD,
)
from utils import reporter, abort_flag, runtime

requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": USER_AGENT}

# Only test endpoints that could plausibly redirect
_TESTABLE_STATUSES = {200, 301, 302, 403}


def _test_redirect(args: tuple) -> dict | None:
    url, param = args
    delay = runtime.get_delay()

    if delay:
        time.sleep(delay)

    test_url = f"{url}?{param}={OPEN_REDIRECT_PAYLOAD}"
    try:
        r = requests.get(
            test_url,
            headers=HEADERS,
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=False,      # ← must be False to catch the redirect
            proxies=runtime.get_proxies(),
        )
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            if OPEN_REDIRECT_PAYLOAD in location:
                return {
                    "original_url": url,
                    "param":        param,
                    "test_url":     test_url,
                    "location":     location,
                    "status_code":  r.status_code,
                }
    except Exception:
        pass
    return None


def check_open_redirects(endpoints: list[dict]) -> list[dict]:
    """
    Test discovered endpoints for open redirect vulnerabilities.

    Parameters
    ----------
    endpoints : list of { url, status, content_type, size }
    Returns   : list of confirmed redirect findings
    """
    print(Fore.YELLOW + "\n[+] Starting Open Redirect Detection...\n")

    # Build task list — only test endpoints likely to redirect
    tasks: list[tuple] = []
    for ep in endpoints:
        if ep.get("status") in _TESTABLE_STATUSES:
            for param in OPEN_REDIRECT_PARAMS:
                tasks.append((ep["url"], param))

    if not tasks:
        print(Fore.WHITE + "  No testable endpoints found.\n")
        print(Fore.YELLOW + "[+] Open redirect detection complete.\n")
        return []

    print(f"  Testing {len(tasks)} parameter combinations "
          f"across {len(endpoints)} endpoints...\n")

    findings: list[dict] = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_test_redirect, task): task for task in tasks}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] Open redirect detection aborted.")
                    break

                result = future.result()
                if result:
                    # Deduplicate — one finding per URL regardless of param
                    already = any(f["original_url"] == result["original_url"]
                                  for f in findings)
                    if not already:
                        findings.append(result)
                        reporter.add_open_redirect(
                            result["original_url"],
                            result["param"],
                            result["test_url"],
                            result["location"],
                        )
                        print(
                            Fore.RED + f"  [OPEN REDIRECT] {result['original_url']}\n"
                            + Fore.WHITE
                            + f"    Parameter : ?{result['param']}=...\n"
                            + f"    Test URL  : {result['test_url']}\n"
                            + f"    Location  : {result['location']}\n"
                            + f"    Status    : {result['status_code']}"
                        )

        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] Open redirect detection interrupted.")

    if not findings:
        print(Fore.GREEN + "  No open redirects found.")

    print(Fore.YELLOW + f"\n[+] Open redirect detection complete. "
          f"{len(findings)} finding(s).\n")

    return findings