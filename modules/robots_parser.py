"""
modules/robots_parser.py
Fetches and parses robots.txt and sitemap.xml for every live subdomain.
Newly discovered paths are added to the reporter for inclusion in reports
and are returned so risk_scoring can consider them.
"""

import re
import time
import requests
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, HTTP_TIMEOUT, USER_AGENT, SENSITIVE_PATHS
from utils import reporter, abort_flag, runtime

requests.packages.urllib3.disable_warnings()

HEADERS = {"User-Agent": USER_AGENT}

# Paths discovered in robots.txt/sitemap that look interesting
_INTERESTING_KEYWORDS = {
    "admin", "login", "dashboard", "backup", "config", "api",
    "internal", "private", "secret", "token", "key", "password",
    "upload", "staging", "dev", "test", "debug", "panel",
}


def _is_interesting(path: str) -> bool:
    p = path.lower()
    return any(kw in p for kw in _INTERESTING_KEYWORDS) or any(
        sp in p for sp in SENSITIVE_PATHS
    )


def _fetch_robots(base_url: str) -> list[dict]:
    """Return list of {path, directive} from robots.txt."""
    findings = []
    url = f"{base_url}/robots.txt"
    try:
        r = requests.get(
            url, headers=HEADERS, timeout=HTTP_TIMEOUT,
            verify=False, proxies=runtime.get_proxies(),
        )
        if r.status_code != 200:
            return []

        for line in r.text.splitlines():
            line = line.strip()
            lower = line.lower()
            if lower.startswith("disallow:") or lower.startswith("allow:"):
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                directive = parts[0].strip()
                path      = parts[1].strip()
                if path and path != "/" and path != "*":
                    findings.append({"path": path, "directive": directive})

    except Exception:
        pass
    return findings


def _fetch_sitemap(base_url: str) -> list[str]:
    """Return list of URL paths extracted from sitemap.xml."""
    paths = []
    url = f"{base_url}/sitemap.xml"
    try:
        r = requests.get(
            url, headers=HEADERS, timeout=HTTP_TIMEOUT,
            verify=False, proxies=runtime.get_proxies(),
        )
        if r.status_code != 200 or "xml" not in r.headers.get("Content-Type", ""):
            return []

        # Strip namespace for simpler parsing
        xml = re.sub(r'\sxmlns="[^"]+"', "", r.text, count=1)
        root = ElementTree.fromstring(xml)

        for loc in root.iter("loc"):
            if loc.text:
                # Extract just the path component
                path = re.sub(r'^https?://[^/]+', "", loc.text.strip())
                if path:
                    paths.append(path)

    except Exception:
        pass
    return paths


def _crawl_subdomain(subdomain: str) -> dict:
    delay = runtime.get_delay()
    results = {"robots": [], "sitemap": [], "interesting": []}

    for scheme in ("https", "http"):
        base = f"{scheme}://{subdomain}"

        if delay:
            time.sleep(delay)
        robots_entries = _fetch_robots(base)
        if robots_entries:
            results["robots"] = robots_entries
            break   # got it on this scheme, no need for the other

    for scheme in ("https", "http"):
        base = f"{scheme}://{subdomain}"

        if delay:
            time.sleep(delay)
        sitemap_paths = _fetch_sitemap(base)
        if sitemap_paths:
            results["sitemap"] = sitemap_paths
            break

    # Collect all unique paths and flag interesting ones
    all_paths = set()
    for entry in results["robots"]:
        all_paths.add(entry["path"])
    for path in results["sitemap"]:
        all_paths.add(path)

    results["interesting"] = [p for p in all_paths if _is_interesting(p)]
    return results


def parse_robots_and_sitemap(live_data: dict) -> dict:
    """
    Parse robots.txt and sitemap.xml for every live subdomain.
    Returns { subdomain: { robots: [...], sitemap: [...], interesting: [...] } }
    """
    print(Fore.YELLOW + "\n[+] Starting robots.txt / sitemap.xml Parsing...\n")

    all_results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(_crawl_subdomain, sub): sub
            for sub in live_data
        }
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] robots/sitemap parsing aborted.")
                    break

                subdomain = futures[future]
                data = future.result()
                all_results[subdomain] = data

                robots_count  = len(data["robots"])
                sitemap_count = len(data["sitemap"])
                interesting   = data["interesting"]

                if not robots_count and not sitemap_count:
                    continue

                print(Fore.GREEN + f"  {subdomain}")
                if robots_count:
                    print(Fore.CYAN + f"    ↳ robots.txt : {robots_count} entries")
                    for entry in data["robots"]:
                        directive = entry["directive"]
                        path      = entry["path"]
                        colour    = Fore.RED if "Disallow" in directive else Fore.WHITE
                        print(colour + f"        {directive}: {path}")

                if sitemap_count:
                    print(Fore.CYAN + f"    ↳ sitemap.xml: {sitemap_count} URL(s) found")

                if interesting:
                    print(Fore.MAGENTA + f"    ↳ Interesting paths:")
                    for path in interesting:
                        reporter.add_crawled_path(subdomain, "robots/sitemap", path)
                        print(Fore.MAGENTA + f"        {path}")

        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] robots/sitemap parsing interrupted.")

    total_interesting = sum(len(v["interesting"]) for v in all_results.values())
    print(Fore.YELLOW + f"\n[+] robots/sitemap parsing complete. "
          f"{total_interesting} interesting path(s) discovered.\n")

    return all_results