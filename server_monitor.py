import socket
import threading
import queue
import sqlite3
import time
import concurrent.futures

# Configuration
TARGET_IP = "36.88.105.236"
DB_NAME = "monitor.db"
MAX_WORKERS = 100
BATCH_SIZE = 5
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 5674, 8000, 8888, 27017, 6379,
    5000, 5432, 1521, 1025, 1026, 1027, 1028, 1029, 3690, 4000, 4444, 4848,
    5001, 5100, 5200, 5222, 5555, 5672, 5901, 5902, 5903, 5984, 6000, 6001,
    6667, 7000, 7001, 8001, 8008, 8081, 8088, 8090, 8181, 8444, 8500, 8800,
    9000, 9001, 9042, 9090, 9092, 9160, 9200, 9418, 9999, 11211, 27018,
    27019, 28017, 50000, 50030, 50060, 50070, 50075, 50090
]

# Shared Queue
scan_queue = queue.Queue()

# Database Setup
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Check if table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_results'")
    if c.fetchone() is None:
        c.execute('''CREATE TABLE scan_results
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      ip TEXT,
                      port INTEGER,
                      banner TEXT,
                      service TEXT,
                      risk TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    else:
        # Check if columns exist (for upgrade)
        c.execute("PRAGMA table_info(scan_results)")
        columns = [col[1] for col in c.fetchall()]
        if 'service' not in columns:
            c.execute("ALTER TABLE scan_results ADD COLUMN service TEXT")
        if 'risk' not in columns:
            c.execute("ALTER TABLE scan_results ADD COLUMN risk TEXT")

    conn.commit()
    conn.close()

def save_result(ip, port, banner, service, risk):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO scan_results (ip, port, banner, service, risk) VALUES (?, ?, ?, ?, ?)",
              (ip, port, banner, service, risk))
    conn.commit()
    conn.close()

# Analysis Logic
def identify_service(port, banner):
    banner = banner.lower()
    if "ssh" in banner:
        return "SSH"
    elif "http" in banner or "apache" in banner or "nginx" in banner or port in [80, 8080, 443, 8443]:
        return "HTTP/HTTPS"
    elif "ftp" in banner or port == 21:
        return "FTP"
    elif "telnet" in banner or port == 23:
        return "Telnet"
    elif "mysql" in banner or port == 3306:
        return "MySQL"
    elif "postgresql" in banner or port == 5432:
        return "PostgreSQL"
    elif "redis" in banner or port == 6379:
        return "Redis"
    elif "mongo" in banner or port == 27017:
        return "MongoDB"
    elif "microsoft-ds" in banner or port == 445:
        return "SMB"
    else:
        return "Unknown"

def assess_risk(port, service, banner):
    service = service.lower()
    banner = banner.lower()

    if "telnet" in service or port == 23:
        return "High" # Cleartext protocol
    if "ftp" in service or port == 21:
        return "Medium" # Often cleartext, older protocol
    if "smb" in service or port == 445:
        return "High" # Frequent target for exploits
    if "ssh" in service:
        if "openssh" in banner:
            # Check for very old versions if possible, strictly speaking
            if "openssh_4" in banner or "openssh_5" in banner:
                return "High"
        return "Low" # Generally secure if configured well
    if "http" in service:
        # Just being open isn't high risk, but unencrypted HTTP is visible
        if port == 80 or port == 8080:
             return "Low" # Standard
        if port == 443 or port == 8443:
             return "Low" # HTTPS is good

    # Check for known vulnerable ports/services broadly
    if port in [3389, 5900]: # RDP, VNC
        return "Medium"

    return "Low"

# Scanning Logic
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((ip, port))
        if result == 0:
            return True
        s.close()
    except:
        pass
    return False

def worker_scan(port):
    if scan_port(TARGET_IP, port):
        print(f"[+] Port {port} is OPEN on {TARGET_IP}")
        scan_queue.put((TARGET_IP, port))

# Deep Scan Logic
def get_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))

        # Heuristic: Send appropriate probe based on port
        if port in [80, 8080, 8000, 8008]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port in [443, 8443]:
             # Basic HTTPS probe without full SSL handshake to avoid complexity dependency
             # (ssl module is standard but handshake might block or fail easily without cert verification)
             # Let's try to wrap it if possible, else just connect check.
             import ssl
             context = ssl.create_default_context()
             context.check_hostname = False
             context.verify_mode = ssl.CERT_NONE
             try:
                 with context.wrap_socket(s, server_hostname=ip) as ss:
                     ss.send(b"HEAD / HTTP/1.0\r\n\r\n")
                     return ss.recv(1024).decode('utf-8', errors='ignore').strip()
             except:
                 # If SSL fails, return empty or error
                 return "SSL Handshake Failed"

        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner
    except Exception as e:
        return ""

def deep_scan_processor():
    while True:
        try:
            item = scan_queue.get()
            if item is None:
                scan_queue.task_done()
                break

            ip, port = item
            print(f"[*] Analyzing {ip}:{port}...")
            banner = get_banner(ip, port)

            service = identify_service(port, banner)
            risk = assess_risk(port, service, banner)

            print(f"    -> {ip}:{port} [{service}] Risk: {risk}")
            save_result(ip, port, banner, service, risk)
            scan_queue.task_done()
        except Exception as e:
            print(f"Error processing queue item: {e}")

def main():
    print(f"Starting advanced scan on {TARGET_IP}...")
    init_db()

    # Start deep scan processor
    processor_thread = threading.Thread(target=deep_scan_processor)
    processor_thread.start()

    # Use ThreadPoolExecutor for scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(worker_scan, COMMON_PORTS)

    # Signal the processor to stop
    scan_queue.put(None)

    print("Scanning finished. Waiting for analysis...")
    processor_thread.join()
    print("All done.")

if __name__ == "__main__":
    main()
