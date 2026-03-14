import nmap
from colorama import Fore
from config import NMAP_ARGS
from utils import reporter
from utils import abort_flag


def scan_ports(targets, nmap_args=None):
    args = nmap_args or NMAP_ARGS

    print(Fore.YELLOW + "\n[+] Starting Port Scanning...")
    print(Fore.WHITE  + f"    Nmap args: {args}\n")

    nm = nmap.PortScanner()

    for target in targets:
        # Check abort before starting each new target
        if abort_flag.is_set():
            print(Fore.YELLOW + f"  [~] Port scan aborted before scanning {target}.")
            break

        print(Fore.CYAN + f"[+] Scanning {target}...")

        try:
            nm.scan(target, arguments=args)

            # Register the IP as scanned regardless of whether ports are open.
            # This ensures the report shows the IP even with zero open ports.
            reporter.add_port_scan_target(target)

            if target not in nm.all_hosts():
                print(Fore.RED + f"  [-] {target} — no response from host "
                      "(firewalled, offline, or blocking nmap probes)")
                continue

            for host in nm.all_hosts():
                # Also register the resolved host in case nmap returns a
                # different representation (e.g. hostname vs IP)
                reporter.add_port_scan_target(host)

                print(Fore.GREEN + f"\n[+] Results for {host}")

                open_found = False

                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        state = nm[host][proto][port]["state"]

                        if state == "open":
                            open_found = True

                            service = nm[host][proto][port].get("name", "")
                            product = nm[host][proto][port].get("product", "")
                            version = nm[host][proto][port].get("version", "")

                            reporter.add_port_result(
                                host, port, proto, service, product, version
                            )

                            print(
                                Fore.WHITE +
                                f"  Port {port}/{proto} - OPEN | "
                                f"{service} {product} {version}"
                            )

                if not open_found:
                    print(Fore.RED + "  No open ports found.")

        except KeyboardInterrupt:
            # Catch the rare case where signal doesn't fire in time
            abort_flag.set()
            reporter.add_port_scan_target(target)
            print(Fore.YELLOW + f"\n  [~] Port scan of {target} interrupted.")
            break

        except Exception as e:
            print(Fore.RED + f"[-] Error scanning {target}: {e}")
            # Still register so the report shows the attempt
            reporter.add_port_scan_target(target)

    print(Fore.YELLOW + "\n[+] Port scanning stopped.\n")