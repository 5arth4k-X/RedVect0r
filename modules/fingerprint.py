import time
import subprocess
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, HTTP_TIMEOUT, USER_AGENT
from utils import abort_flag, runtime, reporter

requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": USER_AGENT}

HEADER_TECH_MAP = {
    "x-powered-by":     lambda v: v,
    "x-generator":      lambda v: v,
    "x-aspnet-version": lambda v: f"ASP.NET {v}",
    "x-drupal-cache":   lambda _: "Drupal",
    "x-wp-total":       lambda _: "WordPress",
    "x-shopify-stage":  lambda _: "Shopify",
    "cf-ray":           lambda _: "Cloudflare",
    "x-amz-cf-id":      lambda _: "AWS CloudFront",
}

BODY_PATTERNS = {
    "WordPress":  r'wp-content|wp-includes',
    "Joomla":     r'joomla|\/components\/com_',
    "Drupal":     r'Drupal\.settings|drupal\.js',
    "Laravel":    r'laravel_session|XSRF-TOKEN',
    "Django":     r'csrfmiddlewaretoken',
    "React":      r'__react|reactroot|react-root',
    "Angular":    r'ng-version|ng-app',
    "Vue.js":     r'__vue__|data-v-',
    "jQuery":     r'jquery\.min\.js|jquery-\d',
    "Bootstrap":  r'bootstrap\.min\.(css|js)',
}


def _passive_fingerprint(url):
    techs = []

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
        for header, extractor in HEADER_TECH_MAP.items():
            val = r.headers.get(header)
            if val:
                techs.append(extractor(val))
        body = r.text
        for tech, pattern in BODY_PATTERNS.items():
            if re.search(pattern, body, re.I):
                techs.append(tech)
    except Exception:
        pass

    return list(dict.fromkeys(techs))


def _whatweb_fingerprint(url):
    try:
        result = subprocess.run(
            ["whatweb", "--no-errors", "--color=never", url],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip() if result.stdout else ""
    except Exception:
        return ""


def fingerprint_target(url):
    passive = _passive_fingerprint(url)
    whatweb = _whatweb_fingerprint(url)
    return url, passive, whatweb


def fingerprint_all(live_data):
    print(Fore.YELLOW + "\n[+] Starting Technology Fingerprinting...\n")

    urls = []
    for sub in live_data:
        urls.append(f"https://{sub}")
        urls.append(f"http://{sub}")

    results = {}

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(fingerprint_target, url): url for url in urls}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] Fingerprinting aborted.")
                    break
                url, passive, whatweb = future.result()
                if not passive and not whatweb:
                    continue
                results[url] = {"passive": passive, "whatweb": whatweb}

                # ── Store in reporter ─────────────────────────────
                reporter.add_fingerprint(url, passive, whatweb)

                print(Fore.GREEN + f"  {url}")
                if passive:
                    print(Fore.CYAN + f"    ↳ Passive  : {', '.join(passive)}")
                if whatweb:
                    print(Fore.CYAN + f"    ↳ WhatWeb  : {whatweb}")
        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] Fingerprinting interrupted.")

    print(Fore.YELLOW + "\n[+] Fingerprinting stopped.\n")
    return results