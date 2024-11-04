import socket
import dns.resolver
import whois
import requests
from bs4 import BeautifulSoup
import nmap
from colorama import init, Fore
import webtech
from pyfiglet import Figlet
from colorama import Fore, init

init(autoreset=True)

def display_banner():
    f = Figlet(font='slant')
    banner_text = f.renderText('betmenXrecon')
    colored_banner = Fore.CYAN + banner_text
    print(colored_banner)

if __name__ == "__main__":
    display_banner()
    
def dns_enumeration(domain):
    print(Fore.CYAN + "\n[+] Performing DNS Enumeration...")
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            records[record] = [rdata.to_text() for rdata in answers]
        except Exception:
            records[record] = []
    return records

def whois_lookup(domain):
    print(Fore.CYAN + "\n[+] Performing WHOIS Lookup...")
    try:
        w = whois.whois(domain)
        return {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'whois_server': w.whois_server,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers,
            'emails': w.emails,
        }
    except Exception as e:
        return {'error': str(e)}

def ip_range_identification(domain):
    print(Fore.CYAN + "\n[+] Identifying IP Address...")
    try:
        ip = socket.gethostbyname(domain)
        return {'ip_address': ip}
    except Exception as e:
        return {'error': str(e)}

def web_scrape(domain):
    print(Fore.CYAN + "\n[+] Scraping Public-Facing Pages...")
    try:
        url = f"http://{domain}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        data = {
            'title': soup.title.string.strip() if soup.title else '',
            'links': [link.get('href') for link in soup.find_all('a', href=True)],
            'scripts': [script.get('src') for script in soup.find_all('script') if script.get('src')],
            'forms': [form.get('action') for form in soup.find_all('form') if form.get('action')],
        }
        return data
    except Exception as e:
        return {'error': str(e)}

def network_scan(ip):
    print(Fore.CYAN + "\n[+] Performing Network Scan...")
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024', '-sV')
        open_ports = {}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    open_ports[port] = service
        return open_ports
    except Exception as e:
        return {'error': str(e)}

def waf_detection(domain):
    print(Fore.CYAN + "\n[+] Checking for WAF...")
    try:
        url = f"http://{domain}/nonexistentfile"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        waf_signatures = {
            'ModSecurity': 'Mod_Security',
            'Cloudflare': 'cloudflare',
            'Incapsula': 'incapsula',
            'F5 BIG-IP': 'F5',
            'Akamai': 'AkamaiGHost',
        }
        detected_waf = []
        for waf, signature in waf_signatures.items():
            server_header = response.headers.get('Server', '').lower()
            if signature.lower() in server_header:
                detected_waf.append(waf)
        if detected_waf:
            return {'waf_detected': detected_waf}
        else:
            return {'waf_detected': None}
    except Exception as e:
        return {'error': str(e)}

def technology_detection(domain):
    print(Fore.CYAN + "\n[+] Detecting Web Technologies...")
    try:
        url = f"http://{domain}"
        wt = webtech.WebTech()
        report = wt.start_from_url(url)
        technologies = [tech['name'] for tech in report['tech']]
        return {'technologies': technologies}
    except Exception as e:
        return {'error': str(e)}

def summarize_collected_data(domain):
    print(Fore.GREEN + f"\nStarting reconnaissance on: {domain}\n")

    dns_records = dns_enumeration(domain)
    print(Fore.YELLOW + "\n[DNS Records]")
    for record_type, records in dns_records.items():
        print(f"  {record_type}: {records}")

    whois_info = whois_lookup(domain)
    print(Fore.YELLOW + "\n[WHOIS Information]")
    for key, value in whois_info.items():
        print(f"  {key}: {value}")

    ip_info = ip_range_identification(domain)
    ip_address = ip_info.get('ip_address', '')
    print(Fore.YELLOW + f"\n[IP Address]\n  {ip_address}")

    web_data = web_scrape(domain)
    print(Fore.YELLOW + "\n[Web Data Extracted]")
    for key, value in web_data.items():
        print(f"  {key}: {value}")

    open_ports = network_scan(ip_address)
    print(Fore.YELLOW + "\n[Open Ports and Services]")
    for port, service in open_ports.items():
        print(f"  Port {port}: {service}")

    waf_info = waf_detection(domain)
    waf_detected = waf_info.get('waf_detected', None)
    print(Fore.YELLOW + "\n[WAF Detection]")
    if waf_detected:
        print(Fore.RED + f"  WAF Detected: {', '.join(waf_detected)}")
    else:
        print("  No WAF detected.")

    tech_info = technology_detection(domain)
    technologies = tech_info.get('technologies', [])
    print(Fore.YELLOW + "\n[Detected Technologies]")
    for tech in technologies:
        print(f"  {tech}")

    print(Fore.GREEN + "\n[Reconnaissance Summary]")
    high_priority_info = {
        'Subdomains': dns_records.get('NS', []),
        'Email Addresses': whois_info.get('emails', []),
        'Open Ports': list(open_ports.keys()),
        'WAF Detected': waf_detected,
        'Technologies': technologies,
    }
    for key, value in high_priority_info.items():
        print(f"  {key}: {value}")

    print(Fore.BLUE + "\n[Suggestions]")
    if waf_detected:
        print("  - A WAF is detected, which might impede further testing. Consider WAF evasion techniques.")
    if 'WordPress' in technologies:
        print("  - The site uses WordPress. Check for vulnerabilities in plugins and themes.")
    if open_ports:
        print("  - Open ports detected. Investigate services running on these ports for potential vulnerabilities.")
    if whois_info.get('emails'):
        print("  - Emails found in WHOIS data. Be cautious of potential social engineering vectors.")

if __name__ == "__main__":
    target_domain = input("Enter the target domain (e.g., example.com): ")
    summarize_collected_data(target_domain)
