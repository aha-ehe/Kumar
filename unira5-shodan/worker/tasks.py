from celery import Celery
import subprocess
import json
import os
import requests
from elasticsearch import Elasticsearch
import geoip2.database

app = Celery('tasks', broker=os.environ.get('CELERY_BROKER_URL'))
es = Elasticsearch(hosts=[os.environ.get('ELASTICSEARCH_URL')])

GEOIP_DB_PATH = "/usr/share/GeoIP/GeoLite2-City.mmdb"

def get_geoip(ip):
    try:
        if not os.path.exists(GEOIP_DB_PATH):
            return {"error": "GeoIP DB not found"}

        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "asn": response.traits.autonomous_system_number,
                "org": response.traits.autonomous_system_organization
            }
    except Exception as e:
        return {"error": str(e)}

@app.task
def scan_target(target):
    print(f"Scanning target: {target}")

    # 1. Port Discovery (Naabu)
    ports = []
    try:
        cmd = ["naabu", "-host", target, "-silent", "-json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.strip():
                    ports.append(json.loads(line))
    except Exception as e:
        print(f"Naabu error: {e}")

    discovered_ports = [str(p.get('port')) for p in ports]
    print(f"Found ports: {discovered_ports}")

    if not discovered_ports:
        return

    # 2. HTTP Probing (Httpx)
    http_data = []
    try:
        ports_arg = ",".join(discovered_ports)
        cmd = ["httpx", "-u", target, "-ports", ports_arg, "-json", "-silent", "-tech-detect", "-status-code", "-title"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.strip():
                    http_data.append(json.loads(line))
    except Exception as e:
        print(f"Httpx error: {e}")

    # 3. Vulnerability Scanning (Nuclei)
    vulns = []
    try:
        target_urls = [h.get('url') for h in http_data]
        if target_urls:
            with open(f"/tmp/{target}_urls.txt", "w") as f:
                f.write("\n".join(target_urls))

            cmd = ["nuclei", "-l", f"/tmp/{target}_urls.txt", "-json", "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip():
                        vulns.append(json.loads(line))
            os.remove(f"/tmp/{target}_urls.txt")
    except Exception as e:
        print(f"Nuclei error: {e}")

    # 4. Banner Grabbing (ZGrab2)
    banners = {}
    try:
        # ZGrab2 operates on stdin
        # Echo target | zgrab2 http
        # For simplicity, we just try to grab banner for http/https ports using zgrab2's http module if 80/443 open
        # Or raw tcp banner
        input_data = "\n".join([f"{target}" for _ in discovered_ports]) # ZGrab takes IP
        # Actually zgrab2 usually takes input file
        # simplified: Just scan target for common services

        # We will use a simple zgrab2 run for SSH if port 22 is open
        if '22' in discovered_ports:
            cmd = f"echo {target} | zgrab2 ssh --port 22"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                 # ZGrab2 output is JSON per line
                 for line in result.stdout.splitlines():
                     if line.strip():
                         banners['ssh'] = json.loads(line)
    except Exception as e:
        print(f"ZGrab2 error: {e}")

    # 5. Enrichment (GeoIP)
    # Resolve IP if target is domain
    ip = target
    try:
        # crude check
        if not target.replace('.','').isdigit():
            import socket
            ip = socket.gethostbyname(target)
    except:
        pass

    geoip_info = get_geoip(ip)

    # 6. Save to Elasticsearch
    doc = {
        "target": target,
        "ip": ip,
        "ports": discovered_ports,
        "http": http_data,
        "vulns": vulns,
        "banners": banners,
        "geoip": geoip_info,
        "timestamp": "now"
    }

    try:
        res = es.index(index="shodan_scan", body=doc)
        print(f"Indexed result: {res['result']}")
    except Exception as e:
        print(f"ES Index error: {e}")

    return doc
