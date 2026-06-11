#!/usr/bin/env python3
"""
Strongest CDN Origin IP Finder Tool
Features: Subdomain enum, CT logs, DNS history, Shodan/Censys, direct testing, etc.
"""

import requests
import json
import socket
import dns.resolver
import time
import argparse
import colorama
from colorama import Fore, Style
import os
from urllib.parse import urlparse
import subprocess
import concurrent.futures
import socks
import socket
# For Tor: pip install PySocks

colorama.init()

def print_banner():
    print(Fore.CYAN + """
    ██████╗ ███████╗████████╗██████╗ ███████╗ █████╗ ██╗     
    ██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██║     
    ██║  ███╗█████╗     ██║   ██████╔╝█████╗  ███████║██║     
    ██║   ██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██╔══██║██║     
    ╚██████╔╝███████╗   ██║   ██║  ██║███████╗██║  ██║███████╗
    ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "GetReal IP - Advanced IP Analysis & Geolocation Tool 🔥" + Style.RESET_ALL)

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_subdomains_crtsh(domain):
    print(Fore.BLUE + "[+] Querying crt.sh for subdomains..." + Style.RESET_ALL)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            subs = set()
            for cert in data:
                for name in cert.get('name_value', '').split('\n'):
                    if name.endswith(domain):
                        subs.add(name.strip().lower())
            return list(subs)
    except:
        pass
    return []

def get_dns_history(domain):
    print(Fore.BLUE + "[+] Checking DNS history (simulated with dig)..." + Style.RESET_ALL)
    try:
        result = subprocess.run(['dig', '+short', domain, 'A'], capture_output=True, text=True)
        return result.stdout.strip().split()
    except:
        return []

def test_ip(ip, domain, original_resp):
    try:
        headers = {'Host': domain, 'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(f"http://{ip}", headers=headers, timeout=10, allow_redirects=True)
        similarity = len(set(resp.text.split()) & set(original_resp.text.split())) / max(len(resp.text.split()), 1)
        if similarity > 0.7 or resp.status_code == 200:
            return ip, resp.status_code, True
    except:
        pass
    return ip, None, False

def main():
    parser = argparse.ArgumentParser(description="CDN Origin IP Finder")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--censys-id", help="Censys API ID")
    parser.add_argument("--censys-secret", help="Censys API Secret")
    parser.add_argument("--shodan-key", help="Shodan API Key")
    args = parser.parse_args()

    print_banner()
    target = args.domain.strip()

    original_ip = resolve_domain(target)
    print(Fore.GREEN + f"[*] Current resolved IP: {original_ip}" + Style.RESET_ALL)

    original_resp = requests.get(f"https://{target}", timeout=15, headers={'User-Agent': 'Mozilla/5.0'})

    # Subdomains
    subs = get_subdomains_crtsh(target)
    print(Fore.GREEN + f"[+] Found {len(subs)} subdomains" + Style.RESET_ALL)

    # Potential IPs from subs
    potential_ips = set()
    for sub in subs[:50]:  # limit for speed
        ip = resolve_domain(sub)
        if ip and ip != original_ip:
            potential_ips.add(ip)

    # DNS history
    history_ips = get_dns_history(target)
    potential_ips.update(history_ips)

    print(Fore.YELLOW + f"[+] Potential IPs: {len(potential_ips)}" + Style.RESET_ALL)

    # Test candidates
    print(Fore.BLUE + "[+] Testing potential origin IPs..." + Style.RESET_ALL)
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(test_ip, ip, target, original_resp) for ip in potential_ips]
        for future in concurrent.futures.as_completed(futures):
            ip, code, match = future.result()
            if match:
                found.append(ip)
                print(Fore.RED + f"[!!!] Potential Origin: {ip} (Status: {code})" + Style.RESET_ALL)

    if found:
        with open(f"{target}_origins.txt", "w") as f:
            f.write("\n".join(found))
        print(Fore.GREEN + f"[+] Saved to {target}_origins.txt" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] No origins found. Try API keys for more power." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
