import socket
import threading
import queue
import sqlite3
import time
import concurrent.futures
import json
import ssl

# Configuration (Initial Defaults, will be overridden by DB)
TARGET_IP = "36.88.105.236"
DB_NAME = "monitor.db"
DEFAULT_MAX_WORKERS = 100
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 5674, 8000, 8888, 27017, 6379,
    5000, 5432, 1521, 1025, 1026, 1027, 1028, 1029, 3690, 4000, 4444, 4848,
    5001, 5100, 5200, 5222, 5555, 5672, 5901, 5902, 5903, 5984, 6000, 6001,
    6667, 7000, 7001, 8001, 8008, 8081, 8088, 8090, 8181, 8444, 8500, 8800,
    9000, 9001, 9042, 9090, 9092, 9160, 9200, 9418, 9999, 11211, 27018,
    27019, 28017, 50000, 50030, 50060, 50070, 50075, 50090
]

# Shared Queue and State
scan_queue = queue.Queue()
ports_scanned = 0
start_time = 0
stop_event = threading.Event()
current_config = {}

# Database Setup
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Check if scan_results table exists
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

    # Check if scan_stats table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_stats'")
    if c.fetchone() is None:
        c.execute('''CREATE TABLE scan_stats
                     (key TEXT PRIMARY KEY,
                      value TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    # Check if settings table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
    if c.fetchone() is None:
        c.execute('''CREATE TABLE settings
                     (key TEXT PRIMARY KEY,
                      value TEXT)''')
        # Insert defaults
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ("target_ip", TARGET_IP))
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ("max_workers", str(DEFAULT_MAX_WORKERS)))
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ("ports", ",".join(map(str, DEFAULT_PORTS))))

    conn.commit()
    conn.close()

def get_settings():
    settings = {}
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings")
        for k, v in c.fetchall():
            settings[k] = v
        conn.close()
    except Exception as e:
        print(f"Error reading settings: {e}")

    # Defaults if missing
    if "target_ip" not in settings: settings["target_ip"] = TARGET_IP
    if "max_workers" not in settings: settings["max_workers"] = str(DEFAULT_MAX_WORKERS)
    if "ports" not in settings: settings["ports"] = ",".join(map(str, DEFAULT_PORTS))

    return settings

def save_result(ip, port, banner, service, risk):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Use REPLACE or check existing to update timestamp
    c.execute("INSERT OR REPLACE INTO scan_results (id, ip, port, banner, service, risk, timestamp) VALUES ((SELECT id FROM scan_results WHERE ip=? AND port=?), ?, ?, ?, ?, ?, datetime('now'))",
              (ip, port, ip, port, banner, service, risk))
    conn.commit()
    conn.close()

def update_stat(key, value):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO scan_stats (key, value, timestamp) VALUES (?, ?, datetime('now'))",
                  (key, str(value)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error updating stat {key}: {e}")

# Analysis Logic (Same as before)
def identify_service(port, banner):
    banner = banner.lower()
    if "ssh" in banner: return "SSH"
    elif "http" in banner or "apache" in banner or "nginx" in banner or port in [80, 8080, 443, 8443]: return "HTTP/HTTPS"
    elif "ftp" in banner or port == 21: return "FTP"
    elif "telnet" in banner or port == 23: return "Telnet"
    elif "mysql" in banner or port == 3306: return "MySQL"
    elif "postgresql" in banner or port == 5432: return "PostgreSQL"
    elif "redis" in banner or port == 6379: return "Redis"
    elif "mongo" in banner or port == 27017: return "MongoDB"
    elif "microsoft-ds" in banner or port == 445: return "SMB"
    else: return "Unknown"

def assess_risk(port, service, banner):
    service = service.lower()
    banner = banner.lower()
    if "telnet" in service or port == 23: return "High"
    if "ftp" in service or port == 21: return "Medium"
    if "smb" in service or port == 445: return "High"
    if "ssh" in service:
        if "openssh_4" in banner or "openssh_5" in banner: return "High"
        return "Low"
    if "http" in service: return "Low"
    if port in [3389, 5900]: return "Medium"
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

def worker_scan(args):
    ip, port = args
    if stop_event.is_set(): return

    global ports_scanned
    if scan_port(ip, port):
        # Check stop event again
        if not stop_event.is_set():
            scan_queue.put((ip, port))

    ports_scanned += 1
    if ports_scanned % 10 == 0:
        elapsed = time.time() - start_time
        if elapsed > 0:
            speed = int(ports_scanned / elapsed)
            update_stat("scan_speed", f"{speed}")
            # Format progress as string "scanned/total"
            total = len(current_config.get("ports_list", []))
            update_stat("progress", f"{ports_scanned}/{total}")

# Deep Scan Logic
def get_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        if port in [80, 8080, 8000, 8008]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port in [443, 8443]:
             context = ssl.create_default_context()
             context.check_hostname = False
             context.verify_mode = ssl.CERT_NONE
             try:
                 with context.wrap_socket(s, server_hostname=ip) as ss:
                     ss.send(b"HEAD / HTTP/1.0\r\n\r\n")
                     return ss.recv(1024).decode('utf-8', errors='ignore').strip()
             except:
                 return "SSL Handshake Failed"
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner
    except:
        return ""

def deep_scan_processor():
    while not stop_event.is_set():
        try:
            item = scan_queue.get(timeout=1)
            if item is None: break

            ip, port = item
            banner = get_banner(ip, port)
            service = identify_service(port, banner)
            risk = assess_risk(port, service, banner)

            save_result(ip, port, banner, service, risk)
            scan_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Error processing queue item: {e}")

def run_scan_cycle():
    global start_time, ports_scanned, current_config

    # Reload settings
    settings = get_settings()
    target_ip = settings["target_ip"]
    try:
        max_workers = int(settings["max_workers"])
    except:
        max_workers = DEFAULT_MAX_WORKERS

    try:
        ports_list = [int(p.strip()) for p in settings["ports"].split(",") if p.strip()]
    except:
        ports_list = DEFAULT_PORTS

    current_config = {
        "target_ip": target_ip,
        "max_workers": max_workers,
        "ports_list": ports_list
    }

    print(f"Starting scan on {target_ip} with {len(ports_list)} ports...")

    start_time = time.time()
    ports_scanned = 0
    stop_event.clear()

    update_stat("status", "Scanning")
    update_stat("scan_speed", "0")
    update_stat("progress", f"0/{len(ports_list)}")

    # Start deep scan processor
    processor_thread = threading.Thread(target=deep_scan_processor)
    processor_thread.start()

    # Prepare args for map
    scan_args = [(target_ip, p) for p in ports_list]

    # Use ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = [executor.submit(worker_scan, arg) for arg in scan_args]

        # Wait for completion or stop signal
        # We can't easily cancel threads, but we can set the event
        concurrent.futures.wait(futures)

    # Signal processor to stop (softly)
    # We wait for queue to empty naturally or force stop?
    # Let's wait for queue to be empty
    while not scan_queue.empty():
        time.sleep(0.5)

    stop_event.set() # Stop the processor loop
    processor_thread.join()

    elapsed = time.time() - start_time
    final_speed = int(len(ports_list) / elapsed) if elapsed > 0 else 0
    update_stat("scan_speed", f"{final_speed}")
    update_stat("status", "Completed")
    update_stat("progress", f"{len(ports_list)}/{len(ports_list)}")

    print("Scan cycle finished.")

def main():
    init_db()
    while True:
        try:
            run_scan_cycle()
            # Wait before next scan or check for restart signal
            # For now, just a loop with delay
            print("Waiting 60 seconds before next scheduled scan...")
            for _ in range(60):
                time.sleep(1)
                # Check for "force restart" flag in DB if we implemented it
                # simpler: just sleep
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Cycle error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
