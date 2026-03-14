"""
modules/screenshot.py
Captures screenshots of every live subdomain using Playwright.

Install once:
    pip install playwright
    playwright install chromium

Tries https:// first, falls back to http:// if https fails.
Saves PNG files to the directory specified by --screenshots.
"""

import os
import re
from colorama import Fore
from config import SCREENSHOT_TIMEOUT
from utils import reporter, abort_flag

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False


def _safe_filename(subdomain: str) -> str:
    """Convert a subdomain to a safe filename, e.g. testphp.vulnweb.com → testphp.vulnweb.com.png"""
    return re.sub(r"[^\w.\-]", "_", subdomain) + ".png"


def capture_screenshots(live_data: dict, output_dir: str) -> list[dict]:
    """
    Take a screenshot of every live subdomain.

    Parameters
    ----------
    live_data   : { subdomain: ip }
    output_dir  : directory where PNGs will be saved

    Returns
    -------
    list of { subdomain, url, path, success, error }
    """
    print(Fore.YELLOW + "\n[+] Starting Screenshot Capture...\n")

    if not _PLAYWRIGHT_OK:
        print(Fore.RED + "  [!] Playwright is not installed.")
        print(Fore.WHITE + "      Run:  pip install playwright && playwright install chromium\n")
        print(Fore.YELLOW + "[+] Screenshot capture skipped.\n")
        return []

    os.makedirs(output_dir, exist_ok=True)
    print(Fore.CYAN + f"  [*] Saving screenshots to: {output_dir}\n")

    results = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
        )

        for subdomain in live_data:
            if abort_flag.is_set():
                print(Fore.YELLOW + "  [~] Screenshot capture aborted.")
                break

            entry = {
                "subdomain": subdomain,
                "url":       None,
                "path":      None,
                "success":   False,
                "error":     None,
            }

            filename   = _safe_filename(subdomain)
            save_path  = os.path.join(output_dir, filename)
            captured   = False

            for scheme in ("https", "http"):
                url  = f"{scheme}://{subdomain}"
                page = context.new_page()
                try:
                    page.goto(
                        url,
                        timeout=SCREENSHOT_TIMEOUT * 1000,   # ms
                        wait_until="domcontentloaded",
                    )
                    page.screenshot(path=save_path, full_page=False)
                    entry["url"]     = url
                    entry["path"]    = save_path
                    entry["success"] = True
                    captured         = True
                    reporter.add_screenshot(subdomain, url, save_path)
                    print(Fore.GREEN + f"  [✓] {subdomain}"
                          + Fore.WHITE + f"  →  {save_path}")
                    page.close()
                    break
                except PWTimeout:
                    entry["error"] = f"Timeout on {url}"
                    page.close()
                except Exception as exc:
                    entry["error"] = str(exc)
                    page.close()

            if not captured:
                print(Fore.RED + f"  [✗] {subdomain}"
                      + Fore.WHITE + f"  —  {entry['error']}")

            results.append(entry)

        context.close()
        browser.close()

    ok    = sum(1 for r in results if r["success"])
    total = len(results)
    print(Fore.YELLOW + f"\n[+] Screenshot capture complete. "
          f"{ok}/{total} succeeded.\n")

    return results