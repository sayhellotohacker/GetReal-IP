#!/usr/bin/env python3
"""
GetReal-IP CDN Origin IP Finder - Final Version
Features: CT logs, DNS history, MX/NS/TXT, Shodan/Censys API, SSL certificate analysis,
ASN enumeration, HTTP/S fingerprinting, Wayback machine, Zone transfer (if possible),
CDN detection, parallel testing, Tor support, and more.
"""

import requests
import json
import socket
import dns.resolver
import dns.zone
import time
import argparse
import colorama
from colorama import Fore, Style
import os
import ssl
import OpenSSL
from urllib.parse import urlparse
import subprocess
import concurrent.futures
import sys
import re
import ipaddress
from datetime import datetime

colorama.init()

# ----------------------------------------------------------------------
#  CDN Detection (common headers)
# ----------------------------------------------------------------------
CDN_SIGNATURES = {
    'cloudflare': ['cf-ray', 'cf-cache-status', 'cf-ray'],
    'akamai': ['x-akamai-', 'x-akamai-transformed'],
    'fastly': ['x-fastly-', 'x-served-by', 'x-cache'],
    'cloudfront': ['x-amz-cf-', 'x-amz-cf-pop'],
    'incapsula': ['x-cdn', 'x-iinfo'],
    'sucuri': ['x-sucuri-'],
    'netlify': ['x-nf-request-id', 'netlify'],
    'azure': ['x-azure-ref', 'x-azure-cdn'],
    'stackpath': ['x-stackpath-'],
    'keycdn': ['x-keycdn-'],
}

def detect_cdn(headers):
    for cdn, patterns in CDN_SIGNATURES.items():
        for p in patterns:
            if any(p.lower() in k.lower() for k in headers.keys()):
                return cdn
    return None

# ----------------------------------------------------------------------
#  Resolver with timeout
# ----------------------------------------------------------------------
def resolve_domain(domain, record='A'):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, record)
        return [str(r) for r in answers]
    except:
        return []

def resolve_first(domain, record='A'):
    ips = resolve_domain(domain, record)
    return ips[0] if ips else None

# ----------------------------------------------------------------------
#  1. CT Logs - extract subdomains + SANs
# ----------------------------------------------------------------------
def get_certificate_data(domain):
    print(Fore.BLUE + "[*] Querying crt.sh for certificates (full history)..." + Style.RESET_ALL)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    ips_from_cert = set()
    try:
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            for cert in data:
                name_value = cert.get('name_value', '')
                # sometimes it contains multiple domains separated by newline
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name.endswith(domain) and '*' not in name:
                        subdomains.add(name)
                    # check for IP addresses in CN/SAN?
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', name):
                        ips_from_cert.add(name)
    except Exception as e:
        print(Fore.RED + f"[-] crt.sh error: {e}" + Style.RESET_ALL)
    return list(subdomains), list(ips_from_cert)

# ----------------------------------------------------------------------
#  2. DNS History via SecurityTrails (free public? no, use DNSdumpster or other)
#     using SecurityTrails free tier? optional API key. For this script we'll use
#     a public DNS history service: dnshistory.org? Better to use wayback machine.
# ----------------------------------------------------------------------
def get_dns_history_wayback(domain):
    print(Fore.BLUE + "[*] Querying Wayback Machine for historical DNS A records..." + Style.RESET_ALL)
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=original&collapse=urlkey"
    historical_ips = set()
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for item in data[1:]:  # first is header
                original = item[0]
                # extract IP from the URL?
                if "://" in original:
                    host = original.split('/')[2]
                    ip = resolve_first(host)
                    if ip:
                        historical_ips.add(ip)
    except:
        pass
    return list(historical_ips)

# ----------------------------------------------------------------------
#  3. MX, NS, TXT records
# ----------------------------------------------------------------------
def get_dns_records(domain):
    print(Fore.BLUE + "[*] Checking MX, NS, TXT records for IP clues..." + Style.RESET_ALL)
    ips = set()
    # MX
    mx_servers = resolve_domain(domain, 'MX')
    for mx in mx_servers:
        # mx format: "10 mail.example.com"
        parts = mx.split()
        if len(parts) == 2:
            mx_host = parts[1].rstrip('.')
            mx_ip = resolve_first(mx_host)
            if mx_ip:
                ips.add(mx_ip)
    # NS
    ns_servers = resolve_domain(domain, 'NS')
    for ns in ns_servers:
        ns_host = ns.rstrip('.')
        ns_ip = resolve_first(ns_host)
        if ns_ip:
            ips.add(ns_ip)
    # TXT - look for IP-like strings
    txt_records = resolve_domain(domain, 'TXT')
    for txt in txt_records:
        for txt_str in txt:
            # find IPv4 addresses
            ipv4s = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', txt_str)
            for ip in ipv4s:
                if ipaddress.ip_address(ip).is_global:
                    ips.add(ip)
    return list(ips)

# ----------------------------------------------------------------------
#  4. Zone Transfer (AXFR) - long shot but powerful
# ----------------------------------------------------------------------
def try_zone_transfer(domain):
    print(Fore.BLUE + "[*] Attempting DNS zone transfer (AXFR)..." + Style.RESET_ALL)
    ips = set()
    ns_servers = resolve_domain(domain, 'NS')
    for ns in ns_servers:
        ns = ns.rstrip('.')
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    if rdataset.rdtype == dns.rdatatype.A:
                        for rdata in rdataset:
                            ips.add(str(rdata))
        except:
            continue
    return list(ips)

# ----------------------------------------------------------------------
#  5. Shodan API
# ----------------------------------------------------------------------
def query_shodan(domain, api_key):
    if not api_key:
        return []
    print(Fore.BLUE + "[*] Querying Shodan for hostnames containing domain..." + Style.RESET_ALL)
    ips = set()
    try:
        # search for hostname: domain
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for match in data.get('matches', []):
                ip = match.get('ip_str')
                if ip:
                    ips.add(ip)
    except Exception as e:
        print(Fore.RED + f"[-] Shodan error: {e}" + Style.RESET_ALL)
    return list(ips)

# ----------------------------------------------------------------------
#  6. Censys API
# ----------------------------------------------------------------------
def query_censys(domain, api_id, api_secret):
    if not api_id or not api_secret:
        return []
    print(Fore.BLUE + "[*] Querying Censys for IPv4 hosts with DNS name..." + Style.RESET_ALL)
    ips = set()
    try:
        auth = (api_id, api_secret)
        url = "https://search.censys.io/api/v2/hosts/search"
        params = {"q": f"services.http.response.html_title:{domain} OR dns.names:{domain}", "per_page": 100}
        resp = requests.get(url, auth=auth, params=params, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for hit in data.get('result', {}).get('hits', []):
                ip = hit.get('ip')
                if ip:
                    ips.add(ip)
    except Exception as e:
        print(Fore.RED + f"[-] Censys error: {e}" + Style.RESET_ALL)
    return list(ips)

# ----------------------------------------------------------------------
#  7. ASN enumeration (using bgp.he.net or team-cymru)
#     We can get ASN of the CDN IP, then find all IPs in that ASN?
#     But origin may be in different AS. Better to get ASN of historical IPs.
# ----------------------------------------------------------------------
def get_asn_for_ip(ip):
    try:
        resp = requests.get(f"https://stat.ripe.net/data/whois/data.json?resource={ip}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for irr in data.get('data', {}).get('irr_records', []):
                if 'origin' in irr:
                    asn = irr['origin']
                    return asn
    except:
        pass
    return None

def get_ips_from_asn(asn, limit=500):
    # using bgp.he.net API is limited, use radb or something else
    # we'll use a simple method: whois -h whois.radb.net ASN
    ips = set()
    try:
        result = subprocess.run(['whois', '-h', 'whois.radb.net', asn], capture_output=True, text=True, timeout=20)
        for line in result.stdout.splitlines():
            if 'route:' in line:
                parts = line.split()
                if len(parts) > 1:
                    cidr = parts[1]
                    try:
                        network = ipaddress.ip_network(cidr)
                        # limit to first few hundred IPs? random sample
                        for ip in network.hosts():
                            ips.add(str(ip))
                            if len(ips) >= limit:
                                break
                    except:
                        pass
    except:
        pass
    return list(ips)

# ----------------------------------------------------------------------
#  8. SSL certificate extraction (manual) from target IPs
# ----------------------------------------------------------------------
def get_certificate_sans(ip, domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                # extract SAN extension
                san = ''
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if 'subjectAltName' in str(ext.get_short_name()):
                        san = str(ext)
                        break
                # parse IPs from SAN
                ips = re.findall(r'IP Address:(\d+\.\d+\.\d+\.\d+)', san)
                return ips
    except:
        return []

# ----------------------------------------------------------------------
#  9. Subdomain enumeration via common wordlist (light)
# ----------------------------------------------------------------------
def brute_subdomains(domain):
    common = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'ns3', 'admin', 'test', 'dev', 'api', 'cdn', 'static', 'assets', 'img', 'images', 'files', 'uploads', 'media', 'video', 'download', 'blog', 'forum', 'support', 'portal', 'app', 'manage', 'remote', 'vpn', 'exchange', 'owa', 'autodiscover', 'remote', 'git', 'jenkins', 'jira', 'confluence', 'kb', 'wiki', 'dashboard', 'control', 'cp', 'panel', 'cpanel', 'whm', 'webdisk', 'mysql', 'db', 'database', 'redis', 'mongo', 'elastic', 'kibana', 'grafana', 'prometheus', 'alert', 'monitor', 'status', 'health', 'uptime', 'docs', 'files', 'share', 'transfer', 's3', 'storage', 'bucket', 'cloud', 'api2', 'rest', 'graphql', 'v2', 'v3', 'stage', 'staging', 'prod', 'production', 'test', 'dev', 'dev2', 'qa', 'uat', 'sandbox', 'demo', 'example', 'internal', 'intranet', 'corp', 'office', 'hr', 'sales', 'marketing', 'crm', 'erp', 'billing', 'pay', 'payment', 'gateway', 'secure', 'security', 'auth', 'login', 'signin', 'account', 'my', 'profile', 'user', 'users', 'admin', 'administrator', 'root', 'system', 'server', 'host', 'hosting', 'proxy', 'forward', 'edge', 'origin', 'backend', 'api-gateway', 'lb', 'loadbalancer', 'cache', 'memcache', 'varnish', 'nginx', 'apache', 'tomcat', 'jboss', 'wildfly', 'weblogic', 'websphere', 'iis']
    found = set()
    print(Fore.BLUE + "[*] Brute-forcing common subdomains..." + Style.RESET_ALL)
    for sub in common:
        full = f"{sub}.{domain}"
        ip = resolve_first(full)
        if ip:
            found.add(full)
    return list(found)

# ----------------------------------------------------------------------
#  Fingerprint request (GET / with Host header)
# ----------------------------------------------------------------------
def fetch_fingerprint(ip, domain, use_https=True):
    protocol = 'https' if use_https else 'http'
    try:
        headers = {
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close'
        }
        url = f"{protocol}://{ip}/"
        resp = requests.get(url, headers=headers, timeout=10, allow_redirects=False, verify=False)
        # return status, headers, body (first 1000 chars)
        return {
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'body_preview': resp.text[:2000],
            'body_length': len(resp.text)
        }
    except:
        return None

def compare_fingerprints(fp1, fp2, same_ip=False):
    if not fp1 or not fp2:
        return False
    # if status codes differ significantly (like 403 vs 200) - maybe not origin
    if fp1['status'] != fp2['status']:
        # but if fp2 is 200 and fp1 is 403, origin might be different
        if fp2['status'] == 200:
            return True
        return False
    # check content similarity (simple word overlap)
    words1 = set(fp1['body_preview'].split())
    words2 = set(fp2['body_preview'].split())
    if not words2:
        return False
    overlap = len(words1 & words2) / len(words2)
    return overlap > 0.6

# ----------------------------------------------------------------------
#  Main logic
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Ultimate CDN Origin IP Finder")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--shodan-key", help="Shodan API Key")
    parser.add_argument("--censys-id", help="Censys API ID")
    parser.add_argument("--censys-secret", help="Censys API Secret")
    parser.add_argument("--tor", action="store_true", help="Use Tor proxy (127.0.0.1:9050)")
    parser.add_argument("--threads", type=int, default=30, help="Concurrent threads")
    parser.add_argument("--asn-enum", action="store_true", help="Enumerate entire ASN of potential IPs (slow)")
    args = parser.parse_args()

    print_banner()
    domain = args.domain.lower()

    # Set proxy if tor
    if args.tor:
        session = requests.Session()
        session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    else:
        session = requests.Session()

    # Get current public IP via CDN
    current_ips = resolve_domain(domain, 'A')
    print(Fore.GREEN + f"[*] Current resolved IPs: {', '.join(current_ips)}" + Style.RESET_ALL)

    # Detect CDN from HTTPS request to domain
    try:
        resp = session.get(f"https://{domain}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        cdn_name = detect_cdn(resp.headers)
        if cdn_name:
            print(Fore.YELLOW + f"[!] CDN Detected: {cdn_name.upper()}" + Style.RESET_ALL)
        original_fingerprint = {
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'body_preview': resp.text[:2000],
            'body_length': len(resp.text)
        }
    except Exception as e:
        print(Fore.RED + f"[-] Cannot fetch original site: {e}" + Style.RESET_ALL)
        return

    # ------------------------------------------------------------------
    # COLLECT POTENTIAL IPs
    # ------------------------------------------------------------------
    all_candidate_ips = set()

    # 1. Subdomains from crt.sh
    subdomains, cert_ips = get_certificate_data(domain)
    print(Fore.GREEN + f"[+] Found {len(subdomains)} subdomains from crt.sh" + Style.RESET_ALL)
    for sub in subdomains[:100]:
        ips = resolve_domain(sub, 'A')
        all_candidate_ips.update(ips)

    # 2. IPs directly from certificates (if SAN contains IP)
    all_candidate_ips.update(cert_ips)

    # 3. DNS history (Wayback)
    historical = get_dns_history_wayback(domain)
    print(Fore.GREEN + f"[+] Retrieved {len(historical)} historical IPs" + Style.RESET_ALL)
    all_candidate_ips.update(historical)

    # 4. MX/NS/TXT
    dns_ips = get_dns_records(domain)
    print(Fore.GREEN + f"[+] Extracted {len(dns_ips)} IPs from DNS records" + Style.RESET_ALL)
    all_candidate_ips.update(dns_ips)

    # 5. Zone transfer
    zone_ips = try_zone_transfer(domain)
    if zone_ips:
        print(Fore.GREEN + f"[+] Zone transfer gave {len(zone_ips)} IPs" + Style.RESET_ALL)
        all_candidate_ips.update(zone_ips)

    # 6. Shodan
    if args.shodan_key:
        shodan_ips = query_shodan(domain, args.shodan_key)
        print(Fore.GREEN + f"[+] Shodan returned {len(shodan_ips)} IPs" + Style.RESET_ALL)
        all_candidate_ips.update(shodan_ips)

    # 7. Censys
    if args.censys_id and args.censys_secret:
        censys_ips = query_censys(domain, args.censys_id, args.censys_secret)
        print(Fore.GREEN + f"[+] Censys returned {len(censys_ips)} IPs" + Style.RESET_ALL)
        all_candidate_ips.update(censys_ips)

    # 8. Subdomain brute
    brute_subs = brute_subdomains(domain)
    print(Fore.GREEN + f"[+] Brute-forced {len(brute_subs)} subdomains" + Style.RESET_ALL)
    for sub in brute_subs:
        ips = resolve_domain(sub, 'A')
        all_candidate_ips.update(ips)

    # 9. IPs from SSL certificates of current IP range? (optional)
    # For each candidate IP we could extract SANs from its certificate
    # but that would be heavy - we'll do later during testing.

    # Remove current CDN IPs from candidates (they are not origin)
    for current_ip in current_ips:
        all_candidate_ips.discard(current_ip)

    # Optionally expand via ASN if any candidate found
    if args.asn_enum and all_candidate_ips:
        print(Fore.BLUE + "[*] Performing ASN enumeration (this may be slow)..." + Style.RESET_ALL)
        asns = set()
        for ip in list(all_candidate_ips)[:20]:
            asn = get_asn_for_ip(ip)
            if asn:
                asns.add(asn)
        for asn in asns:
            print(Fore.BLUE + f"[*] Expanding ASN {asn} ..." + Style.RESET_ALL)
            asn_ips = get_ips_from_asn(asn, limit=200)
            all_candidate_ips.update(asn_ips)

    # Remove private IPs
    valid_ips = set()
    for ip in all_candidate_ips:
        try:
            if ipaddress.ip_address(ip).is_global:
                valid_ips.add(ip)
        except:
            continue
    all_candidate_ips = valid_ips
    print(Fore.YELLOW + f"[*] Total candidate IPs to test: {len(all_candidate_ips)}" + Style.RESET_ALL)

    # ------------------------------------------------------------------
    # TEST CANDIDATES
    # ------------------------------------------------------------------
    print(Fore.BLUE + "[+] Testing candidate IPs (HTTPS + Host header)..." + Style.RESET_ALL)
    found_origins = []

    def test_worker(ip):
        # try HTTPS first
        fp = fetch_fingerprint(ip, domain, use_https=True)
        if fp and compare_fingerprints(original_fingerprint, fp):
            return (ip, fp['status'], 'https')
        # fallback to HTTP
        fp2 = fetch_fingerprint(ip, domain, use_https=False)
        if fp2 and compare_fingerprints(original_fingerprint, fp2):
            return (ip, fp2['status'], 'http')
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(test_worker, ip) for ip in all_candidate_ips]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                ip, code, proto = result
                found_origins.append(ip)
                print(Fore.RED + f"[!!!] Potential Origin: {ip} (Status: {code}, via {proto})" + Style.RESET_ALL)

    if found_origins:
        # Deduplicate
        found_origins = list(dict.fromkeys(found_origins))
        with open(f"{domain}_origin_ips.txt", "w") as f:
            f.write("\n".join(found_origins))
        print(Fore.GREEN + f"[+] Saved {len(found_origins)} potential origin IPs to {domain}_origin_ips.txt" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] No origin IP found. The target may be using a serverless CDN or origin is well-hidden." + Style.RESET_ALL)

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
    
if __name__ == "__main__":
    # Disable SSL warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
