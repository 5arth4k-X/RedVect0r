import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import (
    THREADS, HTTP_TIMEOUT, USER_AGENT,
    COMMON_ENDPOINTS, INTERESTING_STATUS_CODES
)
from utils import reporter, abort_flag, runtime

requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": USER_AGENT}


def _load_wordlist(path: str) -> list[str]:
    """
    Read paths from a wordlist file.
    Skips blank lines and comment lines starting with #.
    Each path is normalised to start with /.
    """
    paths = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith("/"):
                    line = "/" + line
                paths.append(line)
    except Exception as e:
        print(Fore.RED + f"  [!] Could not read wordlist '{path}': {e}")
        print(Fore.YELLOW + "  [~] Falling back to built-in endpoint list.")
        return COMMON_ENDPOINTS
    return paths if paths else COMMON_ENDPOINTS


def _check(args):
    base_url, path = args
    url = base_url.rstrip("/") + path

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
        if r.status_code in INTERESTING_STATUS_CODES:
            ct   = r.headers.get("Content-Type", "")
            size = len(r.content)
            return url, r.status_code, ct, size
    except Exception:
        pass
    return None


def _color(status):
    if status == 200:
        return Fore.GREEN
    if status in (301, 302):
        return Fore.YELLOW
    if status in (401, 403):
        return Fore.MAGENTA
    if status == 500:
        return Fore.RED
    return Fore.WHITE


def check_endpoints(live_data, wordlist: str | None = None):
    """
    For every live subdomain probe the endpoint list.
    If `wordlist` is a file path, load paths from it;
    otherwise fall back to the built-in COMMON_ENDPOINTS list.
    Results are both printed and stored in the reporter.
    """
    print(Fore.YELLOW + "\n[+] Starting Endpoint Discovery...\n")

    # ── Resolve path list ──────────────────────────────────────────
    if wordlist:
        if os.path.isfile(wordlist):
            paths = _load_wordlist(wordlist)
            print(Fore.CYAN + f"  [*] Wordlist  : {wordlist}  ({len(paths)} paths)\n")
        else:
            print(Fore.RED + f"  [!] Wordlist not found: {wordlist}")
            print(Fore.YELLOW + "  [~] Falling back to built-in endpoint list.\n")
            paths = COMMON_ENDPOINTS
    else:
        paths = COMMON_ENDPOINTS
        print(Fore.CYAN + f"  [*] Using built-in endpoint list  ({len(paths)} paths)\n")

    # ── Build task list ────────────────────────────────────────────
    tasks = []
    for sub in live_data:
        for scheme in ("http", "https"):
            base = f"{scheme}://{sub}"
            for path in paths:
                tasks.append((base, path))

    print(f"[DEBUG] Checking {len(tasks)} endpoints across "
          f"{len(live_data)} subdomains...\n")

    hits = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_check, task): task for task in tasks}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] Endpoint discovery aborted.")
                    break
                result = future.result()
                if result:
                    url, status, ct, size = result
                    hits.append(result)
                    reporter.add_endpoint(url, status, ct, size)
                    c = _color(status)
                    print(c + f"  [{status}] {url}  "
                          + Fore.WHITE + f"({size} bytes | {ct.split(';')[0]})")
        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] Endpoint discovery interrupted.")

    print(Fore.YELLOW + f"\n[+] Endpoint discovery stopped. "
          f"{len(hits)} interesting paths found so far.\n")

    return hits