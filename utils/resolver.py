import socket
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore
from config import THREADS, TIMEOUT


def _resolve(subdomain):
    try:
        socket.setdefaulttimeout(TIMEOUT)
        ip = socket.gethostbyname(subdomain)
        return subdomain, ip
    except Exception:
        return subdomain, None


def resolve_domains(subdomains):
    """
    Resolve a list of subdomains to their IPs.
    Returns a dict  { subdomain: ip }  for only live hosts.
    """
    print(f"\n[+] Resolving {len(subdomains)} subdomains...\n")

    live = {}

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = executor.map(_resolve, subdomains)

    for subdomain, ip in results:
        if ip:
            print(Fore.GREEN + f"  [✓] {subdomain} → {ip}")
            live[subdomain] = ip
        else:
            print(Fore.RED + f"  [✗] {subdomain} → unresolvable")

    print(Fore.YELLOW + f"\n[+] {len(live)} live subdomains resolved.\n")
    return live