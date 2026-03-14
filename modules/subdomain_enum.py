import subprocess
from colorama import Fore
from config import SUBFINDER_TIMEOUT
from utils import abort_flag


def enumerate_subdomains(domain, timeout=SUBFINDER_TIMEOUT):
    print(Fore.YELLOW + "\n[+] Starting passive subdomain enumeration...")
    print(f"    Target: {domain}\n")

    process = None
    try:
        process = subprocess.Popen(
            ["subfinder", "-d", domain, "-silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            print(Fore.RED + "[-] Subfinder timed out.")
            return []

        subdomains = list(set(stdout.splitlines()))
        print(Fore.YELLOW + f"\n[+] Subdomain enumeration complete. "
              f"{len(subdomains)} subdomains found.\n")
        return subdomains

    except KeyboardInterrupt:
        abort_flag.set()
        if process:
            process.kill()
        print(Fore.YELLOW + "\n[!] Subdomain enumeration interrupted.")
        return []

    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")
        return []