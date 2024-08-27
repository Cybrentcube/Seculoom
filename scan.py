from flask import Flask, render_template, request
import socket
import threading
import requests
import os
import whois
import base64
from queue import Queue
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Dictionary for mapping common ports to services
common_ports = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    115: 'SFTP',
    135: 'RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    194: 'IRC',
    443: 'HTTPS',
    445: 'SMB',
    1433: 'MSSQL',
    3306: 'MySQL',
    3389: 'RDP',
    5632: 'PCAnywhere',
    5900: 'VNC',
    25565: 'Minecraft'
}

# Capture the current date and time
scan_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Predefined settings
port_range = "1-1024"
scan_type = "BOTH"
output_format = "json"
start_port, end_port = map(int, port_range.split('-'))

# Global variables
target_ip = None
queue = Queue()
open_ports = []
mac_address = None
mac_vendor = None

# Security headers and their criticality levels
security_headers = {
    'Content-Security-Policy': 'High',
    'Strict-Transport-Security': 'High',
    'X-Frame-Options': 'High',
    'X-Content-Type-Options': 'Medium',
    'Cross-Origin-Resource-Policy': 'Medium',
    'Referrer-Policy': 'Low',
    'Access-Control-Allow-Origin': 'Low',
    'Permissions-Policy': 'Low',
    'Cross-Origin-Opener-Policy': 'Low',
    'Cross-Origin-Embedder-Policy': 'Low',
    'Set-Cookie': 'Informaional',
    'Server': 'Informaional'
}


def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "connect-src 'self' https://www.cyberentcube.org; "
        "img-src 'self' data:; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = "geolocation=()"
    response.headers['Cross-Origin-Resource-Policy'] = 'same-site'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    return response
# Apply security headers to all responses
@app.after_request
def apply_security_headers(response):
    return set_security_headers(response)



def get_whois_data(domain):
    try:
        w = whois.whois(domain)
        whois_info = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "status": w.status,
            "name_servers": w.name_servers
        }
        print("WHOIS Data:", whois_info)  # Debugging line
        return whois_info
    except Exception as e:
        print(f"Error fetching WHOIS data for {domain}: {e}")
        return None


def scan_tcp_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = common_ports.get(port, 'Unknown')
            banner = grab_banner(sock)
            return port, 'TCP', service, banner
        sock.close()
    except Exception as e:
        print(f'Error scanning TCP port {port}: {e}')
    return port, 'TCP', None, None

def scan_udp_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'', (ip, port))
        result, _ = sock.recvfrom(1024)
        if result:
            service = common_ports.get(port, 'Unknown')
            banner = result.decode().strip()
            return port, 'UDP', service, banner
    except socket.timeout:
        pass
    except Exception as e:
        print(f'Error scanning UDP port {port}: {e}')
    return port, 'UDP', None, None

def grab_banner(sock):
    try:
        sock.send(b'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        banner = sock.recv(1024).decode().strip()
        return banner
    except Exception as e:
        return "No banner"

def threader():
    while True:
        worker = queue.get()
        if worker[1] == 'TCP':
            port, proto, service, banner = scan_tcp_port(target_ip, worker[0])
        elif worker[1] == 'UDP':
            port, proto, service, banner = scan_udp_port(target_ip, worker[0])
        if service:
            open_ports.append({
                "port": port,
                "protocol": proto,
                "service": service,
                "banner": banner
            })
        queue.task_done()

def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"Failed to resolve {domain}")
        return None

def get_mac_address(ip):
    try:
        pid = os.getpid()
        arp_cache = os.popen(f"arp -a {ip}").read()
        for line in arp_cache.splitlines():
            if ip in line:
                parts = line.split()
                mac_address = next((part for part in parts if '-' in part), None)
                return mac_address
    except Exception as e:
        print(f"Error getting MAC address for {ip}: {e}")
    return None

def get_mac_vendor(mac_address):
    try:
        response = requests.get(f'https://api.macvendors.com/{mac_address}')
        if response.status_code == 200:
            return response.text.strip()
    except requests.RequestException as e:
        print(f"Error fetching vendor details for MAC {mac_address}: {e}")
    return "Unknown"

def check_security_headers(url):
    try:
        response = requests.head(url, allow_redirects=True)
        headers = response.headers

        # Extract all headers as raw headers
        raw_headers = {key: value for key, value in headers.items()}

        missing_headers = []
        for header, criticality in security_headers.items():
            if header not in headers:
                missing_headers.append((header, criticality))

        return raw_headers, missing_headers
    except requests.RequestException as e:
        print(f"Error checking security headers: {e}")
        return {}, []

def calculate_security_grade(missing_headers):
    if not missing_headers:
        return "A+"  # All headers are present, return A+

    total_criticality = 0

    for _, criticality in missing_headers:
        if criticality == 'High':
            total_criticality += 16
        elif criticality == 'Medium':
            total_criticality += 10
        elif criticality == 'Low':
            total_criticality += 6
        else:
            total_criticality += 1  # Info headers

    total_headers = len(security_headers)
    grade_percentage = 100 - total_criticality

    # Define grade ranges and return grades based on percentage
    if grade_percentage >= 95:
        return "A+"
    elif grade_percentage >= 86:
        return "A"
    elif grade_percentage >= 70:
        return "B"
    elif grade_percentage >= 41:
        return "C"
    elif grade_percentage >= 10:
        return "D"
    else:
        return "F"


def main_scan(target_domain):
    global target_ip
    global queue
    global open_ports
    global mac_address
    global mac_vendor

    target_ip = resolve_domain_to_ip(target_domain)
    if not target_ip:
        return None

    # Example usage in main_scan
    url = f"http://{target_domain}"
    raw_headers, missing_headers = check_security_headers(url)
    
    mac_address = get_mac_address(target_ip)
    mac_vendor = get_mac_vendor(mac_address) if mac_address else "N/A"
    whois_data = get_whois_data(target_domain)

    
    # Fetch DNS records
    try:
        dns_api_url = f"https://networkcalc.com/api/dns/lookup/{target_domain}"
        response = requests.get(dns_api_url)
        if response.status_code == 200:
            data = response.json()
            dns_records = {
                "A": [{"address": record["address"], "ttl": record["ttl"]} for record in data.get("records", {}).get("A", [])],
                "CNAME": [],
                "MX": [{"exchange": mx["exchange"], "priority": mx["priority"]} for mx in data.get("records", {}).get("MX", [])],
                "NS": [{"nameserver": ns["nameserver"]} for ns in data.get("records", {}).get("NS", [])],
                "SOA": [{"nameserver": soa["nameserver"], "hostmaster": soa["hostmaster"]} for soa in data.get("records", {}).get("SOA", [])],
                "TXT": data.get("records", {}).get("TXT", [])
            }
        else:
            dns_records = {}
            print(f"Failed to fetch DNS records for {target_domain}")
    except requests.RequestException as e:
        print(f"Error fetching DNS records: {e}")
        dns_records = {}

    # Threading
    queue = Queue()
    open_ports = []
    num_threads = 100

    for _ in range(num_threads):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for port in range(start_port, end_port + 1):
        if scan_type == 'TCP' or scan_type == 'BOTH':
            queue.put((port, 'TCP'))
        if scan_type == 'UDP' or scan_type == 'BOTH':
            queue.put((port, 'UDP'))

    queue.join()

    # Check security headers again in case they have changed
    url = f"http://{target_domain}"
    raw_headers, missing_headers = check_security_headers(url)
    security_grade = calculate_security_grade(missing_headers)

    # Compile results
    scan_results = {
        "target_domain": target_domain,
        "resolved_ip": target_ip,
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
        "open_ports": open_ports,
        "missing_headers": missing_headers,
        "security_grade": security_grade,
        "raw_headers": raw_headers,
        "whois_data": whois_data,
        "dns_records": dns_records,
        "scan_datetime": scan_datetime
    }

    return scan_results

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form['target']
        scan_results = main_scan(target)
        if scan_results:
            return render_template('results.html', 
                                   results=scan_results['open_ports'], 
                                   target=target, 
                                   ip=scan_results['resolved_ip'], 
                                   mac=scan_results['mac_address'], 
                                   vendor=scan_results['mac_vendor'], 
                                   missing_headers=scan_results['missing_headers'], 
                                   security_grade=scan_results['security_grade'],
                                   raw_headers=scan_results['raw_headers'],
                                   whois_data=scan_results['whois_data'], 
                                   dns_records=scan_results['dns_records'],
                                   scan_datetime=scan_results['scan_datetime'])
        else:
            return render_template('error.html', message=f"Failed to scan {target}")
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
