import socket
import json
import argparse
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def banner_grab(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(1)
            s.connect((ip, port))
            if port in [80, 8080, 8000]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024)
            return banner.decode(errors='ignore').strip()
    except:
        return None

def parse_banner(banner):
    banner = banner.lower()
    for line in banner.split("\n"):
        if "server:" in line:
            line = line.strip()
            if "/" in line:
                parts = line.split("/")
                if len(parts) >= 2:
                    service = parts[0].split(":")[-1].strip()
                    version = parts[1].split()[0].strip()
                    return service, version
    return "", ""

def lookup_cve(service, version):
    try:
        with open("vuln_db.json") as f:
            db = json.load(f)
        service = service.lower()
        if service in db and version in db[service]:
            return db[service][version]
    except FileNotFoundError:
        print(f"{Fore.RED}vuln_db.json not found — skipping offline CVE check{Style.RESET_ALL}")
    return None

def online_cve_lookup(service, version):
    try:
        response = requests.get(f"https://cve.circl.lu/api/search/{service}/{version}")
        if response.status_code == 200:
            data = response.json()
            if data.get("results"):
                top = data["results"][0]
                return f"{top['id']}: {top['summary']}"
    except:
        pass
    return None

def scan_ports(target, port_range, use_online=False):
    print(f"Scanning {target} from port {port_range[0]} to {port_range[1]}")
    scan_results = []
    for port in range(port_range[0], port_range[1] + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                port_info = {"port": port, "status": "open"}
                print(f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} Port {port}")

                banner = banner_grab(target, port)
                if banner:
                    print(f"  {Fore.YELLOW}Banner:{Style.RESET_ALL} {banner}")
                    service, version = parse_banner(banner)
                    if use_online:
                        cve = online_cve_lookup(service, version)
                        if not cve:
                            cve = lookup_cve(service, version)
                    else:
                        cve = lookup_cve(service, version)
                    port_info.update({
                        "banner": banner,
                        "service": service,
                        "version": version,
                        "cve": cve
                    })
                    if cve:
                        print(f"  {Fore.RED}🚨 Possible Vulnerability:{Style.RESET_ALL} {cve}")
                    else:
                        print(f"  {Fore.CYAN}No known CVEs found for {service} {version}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.LIGHTBLACK_EX}No banner received — CVE check skipped{Style.RESET_ALL}")
                scan_results.append(port_info)
    return scan_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--export", help="Export results to a JSON file", default=None)
    parser.add_argument("--online", action="store_true", help="Use live CVE lookup (slower)")
    args = parser.parse_args()

    target = input("Enter target IP or hostname: ")
    start = int(input("Start port: "))
    end = int(input("End port: "))

    results = scan_ports(target, (start, end), use_online=args.online)

    if args.export and results:
        with open(args.export, "w") as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.CYAN}Results exported to {args.export}{Style.RESET_ALL}")
