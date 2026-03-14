import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, HTTP_TIMEOUT, USER_AGENT, WAF_PAYLOAD, WAF_SIGNATURES
from utils import reporter, abort_flag, runtime

requests.packages.urllib3.disable_warnings()


def _detect(base_url):
    probe_url = f"{base_url}/?q={WAF_PAYLOAD}"
    headers   = {"User-Agent": USER_AGENT}

    delay = runtime.get_delay()
    if delay:
        time.sleep(delay)

    try:
        r = requests.get(
            probe_url, headers=headers,
            timeout=HTTP_TIMEOUT, verify=False,
            allow_redirects=True,
            proxies=runtime.get_proxies(),
        )
    except Exception:
        return base_url, "Unreachable"

    raw = " ".join(
        [f"{k}: {v}" for k, v in r.headers.items()]
    ).lower() + " " + r.text.lower()

    for waf_name, signatures in WAF_SIGNATURES.items():
        if any(sig.lower() in raw for sig in signatures):
            return base_url, waf_name

    if r.status_code in (403, 406, 429, 501):
        return base_url, f"Unknown WAF (HTTP {r.status_code})"

    return base_url, "None detected"


def detect_waf(live_data):
    print(Fore.YELLOW + "\n[+] Starting WAF Detection...\n")

    base_urls = []
    for sub in live_data:
        base_urls.append(f"http://{sub}")
        base_urls.append(f"https://{sub}")

    waf_results = {}

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_detect, url): url for url in base_urls}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] WAF detection aborted.")
                    break
                base_url, waf = future.result()
                waf_results[base_url] = waf
                reporter.add_waf(base_url, waf)

                if waf == "None detected":
                    color = Fore.WHITE
                elif waf == "Unreachable":
                    color = Fore.RED
                else:
                    color = Fore.CYAN

                print(color + f"  {base_url}  →  WAF: {waf}")
        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] WAF detection interrupted.")

    print(Fore.YELLOW + "\n[+] WAF detection stopped.\n")
    return waf_results