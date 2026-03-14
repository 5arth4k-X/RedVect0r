"""
modules/dns_enum.py
Full DNS record enumeration using dnspython.
Queries A, AAAA, CNAME, MX, TXT, NS, SOA for every subdomain
and extracts SPF/DMARC from TXT records automatically.
"""

import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from config import THREADS, DNS_RECORD_TYPES
from utils import reporter, abort_flag


def _query_records(subdomain: str) -> tuple[str, dict]:
    """Query all DNS record types for a single subdomain."""
    results: dict[str, list[str]] = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 10

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(subdomain, rtype, raise_on_no_answer=False)
            if answers.rrset:
                results[rtype] = [str(r) for r in answers.rrset]
        except (dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                Exception):
            pass

    # Extract SPF and DMARC from TXT records as named sub-keys
    for rec in results.get("TXT", []):
        cleaned = rec.strip('"')
        if cleaned.lower().startswith("v=spf1"):
            results.setdefault("SPF", []).append(cleaned)
        if cleaned.lower().startswith("v=dmarc1"):
            results.setdefault("DMARC", []).append(cleaned)

    return subdomain, results


def _print_records(subdomain: str, records: dict) -> None:
    if not records:
        return

    print(Fore.GREEN + f"\n  [{subdomain}]")
    for rtype, values in records.items():
        # SPF/DMARC already shown under TXT — skip duplicate
        if rtype in ("SPF", "DMARC"):
            tag  = Fore.MAGENTA + f"    ↳ {rtype:<8}" + Fore.WHITE
        else:
            tag  = Fore.CYAN    + f"    ↳ {rtype:<8}" + Fore.WHITE
        for v in values:
            print(f"{tag}  {v}")


def enumerate_dns(subdomains: list[str]) -> dict[str, dict]:
    """
    Run full DNS enumeration for every subdomain.
    Returns { subdomain: { record_type: [values] } }
    """
    print(Fore.YELLOW + "\n[+] Starting DNS Record Enumeration...\n")

    all_records: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_query_records, sub): sub for sub in subdomains}
        try:
            for future in as_completed(futures):
                if abort_flag.is_set():
                    for f in futures:
                        f.cancel()
                    print(Fore.YELLOW + "\n  [~] DNS enumeration aborted.")
                    break

                subdomain, records = future.result()
                if records:
                    all_records[subdomain] = records
                    reporter.add_dns_records(subdomain, records)
                    _print_records(subdomain, records)

        except KeyboardInterrupt:
            abort_flag.set()
            for f in futures:
                f.cancel()
            print(Fore.YELLOW + "\n  [~] DNS enumeration interrupted.")

    # Summary
    cnames = sum(1 for r in all_records.values() if "CNAME" in r)
    print(Fore.YELLOW + f"\n[+] DNS enumeration complete. "
          f"{len(all_records)} subdomains with records, "
          f"{cnames} CNAMEs found.\n")

    return all_records