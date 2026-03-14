import time
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, HTTP_TIMEOUT, USER_AGENT
from utils import reporter, abort_flag, runtime

requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": USER_AGENT}


def tech_fingerprint(url):
    try:
        result = subprocess.run(
            ["whatweb", "--no-errors", "--color=never", url],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() if result.stdout else "No fingerprint data"
    except Exception:
        return "Fingerprinting failed"


def probe_target(url):
    delay = runtime.get_delay()
    if delay:
        time.sleep(delay)

    try:
        r = requests.get(
            url, headers=HEADERS,
            timeout=HTTP_TIMEOUT, verify=False,
            proxies=runtime.get_proxies(),
        )
        server      = r.headers.get("Server", "Unknown")
        fingerprint = tech_fingerprint(url) if r.status_code == 200 else None
        return url, r.status_code, server, fingerprint
    except Exception:
        return None


def http_probe(live_data, threads=THREADS):
    print(Fore.YELLOW + "\n[+] Starting HTTP Probing...\n")

    urls = []
    for sub in live_data:
        urls.append(f"http://{sub}")
        urls.append(f"https://{sub}")

    print(f"[DEBUG] URLs to probe: {len(urls)}\n")

    proxy = runtime.get_proxies()
    if proxy:
        print(Fore.CYAN + f"  [*] Routing through proxy: {proxy}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_target, url): url for url in urls}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] HTTP probing aborted.")
                    break
                result = future.result()
                if result:
                    url, status, server, fingerprint = result
                    reporter.add_http_result(url, status, server, fingerprint)
                    print(Fore.GREEN + f"[+] {url} → {status} | Server: {server}")
                    if fingerprint and fingerprint not in (
                        "No fingerprint data", "Fingerprinting failed"
                    ):
                        print(Fore.CYAN + f"    ↳ Fingerprint: {fingerprint}")
        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] HTTP probing interrupted.")

    print(Fore.YELLOW + "\n[+] HTTP probing stopped.\n")