"""
modules/ssl_inspect.py
SSL/TLS certificate inspection using Python's built-in ssl module.
No extra dependencies required.

Checks:
  - Certificate expiry (flags < 30 days or already expired)
  - Weak cipher suites (RC4, DES, NULL, EXPORT, etc.)
  - Subject Alternative Names (SANs) — may reveal hidden subdomains
  - Issuer and subject info
"""

import ssl
import socket
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, SSL_WEAK_CIPHERS, SSL_EXPIRY_WARN_DAYS
from utils import reporter, abort_flag


def _inspect_host(subdomain: str) -> tuple[str, dict]:
    result = {
        "valid":          False,
        "expiry":         None,
        "days_left":      None,
        "expired":        False,
        "expiring_soon":  False,
        "issuer":         None,
        "subject":        None,
        "sans":           [],
        "cipher":         None,
        "weak_cipher":    False,
        "error":          None,
    }

    try:
        ctx = ssl.create_default_context()
        # Don't verify so we still get data from self-signed / expired certs
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((subdomain, 443), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=subdomain) as tls:
                cert   = tls.getpeercert()   # dict, may be empty for CERT_NONE
                cipher = tls.cipher()         # (name, protocol, bits)

                result["valid"]  = True
                result["cipher"] = f"{cipher[0]} / {cipher[1]} / {cipher[2]} bits"

                # Weak cipher check
                cipher_upper = cipher[0].upper()
                for wc in SSL_WEAK_CIPHERS:
                    if wc.upper() in cipher_upper:
                        result["weak_cipher"] = True
                        break

                if cert:
                    # Expiry
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry = datetime.strptime(
                            expiry_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        now       = datetime.now(timezone.utc)
                        days_left = (expiry - now).days
                        result["expiry"]        = expiry.isoformat()
                        result["days_left"]     = days_left
                        result["expired"]       = days_left < 0
                        result["expiring_soon"] = 0 <= days_left < SSL_EXPIRY_WARN_DAYS

                    # Issuer
                    issuer_dict = {k: v for tup in cert.get("issuer", [])
                                   for k, v in tup}
                    result["issuer"] = issuer_dict.get("organizationName",
                                       issuer_dict.get("commonName", "Unknown"))

                    # Subject
                    subj_dict = {k: v for tup in cert.get("subject", [])
                                 for k, v in tup}
                    result["subject"] = subj_dict.get("commonName", "Unknown")

                    # SANs
                    sans = [v for t, v in cert.get("subjectAltName", [])
                            if t == "DNS"]
                    result["sans"] = sans

    except ConnectionRefusedError:
        result["error"] = "Port 443 closed"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except Exception as exc:
        result["error"] = str(exc)

    return subdomain, result


def inspect_ssl(live_data: dict) -> dict:
    """
    Inspect SSL/TLS for every live subdomain.
    Returns { subdomain: result_dict }
    """
    print(Fore.YELLOW + "\n[+] Starting SSL/TLS Inspection...\n")

    all_results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(_inspect_host, sub): sub
            for sub in live_data
        }
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] SSL inspection aborted.")
                    break

                subdomain, result = future.result()
                all_results[subdomain] = result
                reporter.add_ssl_result(subdomain, result)

                if result["error"]:
                    # Only print if it's not just "port closed"
                    if "closed" not in result["error"]:
                        print(Fore.RED + f"  [-] {subdomain}: {result['error']}")
                    continue

                # Determine display colour from worst issue
                if result["expired"] or result["weak_cipher"]:
                    color = Fore.RED
                elif result["expiring_soon"]:
                    color = Fore.YELLOW
                else:
                    color = Fore.GREEN

                print(color + f"  {subdomain}")
                print(Fore.WHITE + f"    ↳ Subject  : {result['subject']}")
                print(Fore.WHITE + f"    ↳ Issuer   : {result['issuer']}")
                print(Fore.WHITE + f"    ↳ Cipher   : {result['cipher']}"
                      + (Fore.RED + "  ⚠ WEAK" if result["weak_cipher"] else ""))

                if result["expiry"]:
                    exp_str = result["expiry"][:10]
                    days    = result["days_left"]
                    if result["expired"]:
                        exp_label = Fore.RED + f"  ⚠ EXPIRED ({abs(days)} days ago)"
                    elif result["expiring_soon"]:
                        exp_label = Fore.YELLOW + f"  ⚠ expiring in {days} days"
                    else:
                        exp_label = Fore.GREEN + f"  ({days} days left)"
                    print(Fore.WHITE + f"    ↳ Expiry   : {exp_str}" + exp_label)

                if result["sans"]:
                    print(Fore.CYAN + f"    ↳ SANs ({len(result['sans'])}):"
                          f"  {', '.join(result['sans'][:6])}"
                          + ("…" if len(result["sans"]) > 6 else ""))

        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] SSL inspection interrupted.")

    print(Fore.YELLOW + f"\n[+] SSL/TLS inspection complete.\n")
    return all_results