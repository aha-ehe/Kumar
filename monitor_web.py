import http.server
import socketserver
import sqlite3
import os
import html
import datetime

PORT = 7890
DB_NAME = "monitor.db"

class MonitorHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # Fetch stats
            rows = []
            has_advanced = False
            scan_stats = {}

            try:
                conn = sqlite3.connect(DB_NAME)
                c = conn.cursor()

                # Check for columns
                c.execute("PRAGMA table_info(scan_results)")
                columns = [col[1] for col in c.fetchall()]
                has_advanced = 'service' in columns and 'risk' in columns

                # Get Results
                query = "SELECT * FROM scan_results ORDER BY timestamp DESC"
                c.execute(query)
                rows = c.fetchall()

                # Get Scan Stats
                try:
                    c.execute("SELECT key, value FROM scan_stats")
                    for k, v in c.fetchall():
                        scan_stats[k] = v
                except:
                    pass

                conn.close()
            except Exception as e:
                print(f"DB Error: {e}")

            # Calculate stats
            total_open = len(rows)
            high_risk = 0
            if has_advanced:
                for row in rows:
                    if len(row) > 5 and row[5] == "High": # risk is index 5
                        high_risk += 1

            # Defaults
            scan_speed = scan_stats.get("scan_speed", "0 ports/sec")
            status = scan_stats.get("status", "Idle")
            progress = scan_stats.get("progress", "0/0")

            status_badge = "bg-secondary"
            if status == "Scanning": status_badge = "bg-primary"
            elif status == "Analyzing": status_badge = "bg-warning text-dark"
            elif status == "Completed": status_badge = "bg-success"

            page_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Server Monitor Dashboard</title>
                <!-- Bootstrap 5 -->
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <!-- FontAwesome -->
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
                <style>
                    body {{ background-color: #f4f6f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
                    .navbar {{ box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                    .card {{ border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); transition: transform 0.2s; }}
                    .card:hover {{ transform: translateY(-5px); }}
                    .card-icon {{ font-size: 2.5rem; opacity: 0.8; }}
                    .table-responsive {{ border-radius: 10px; overflow: hidden; background: white; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }}
                    .table thead th {{ background-color: #2c3e50; color: white; border: none; }}
                    .badge-risk-high {{ background-color: #e74c3c; color: white; }}
                    .badge-risk-medium {{ background-color: #f39c12; color: white; }}
                    .badge-risk-low {{ background-color: #27ae60; color: white; }}
                    .status-indicator {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; }}
                </style>
                <meta http-equiv="refresh" content="5">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
                    <div class="container">
                        <a class="navbar-brand" href="#"><i class="fas fa-server me-2"></i>NetMonitor Pro</a>
                        <span class="navbar-text">
                            <span class="badge {status_badge}">{status}</span>
                        </span>
                    </div>
                </nav>

                <div class="container">

                    <!-- Stats Cards -->
                    <div class="row g-4 mb-4">
                        <div class="col-md-3">
                            <div class="card h-100 border-start border-4 border-primary">
                                <div class="card-body d-flex align-items-center justify-content-between">
                                    <div>
                                        <h6 class="text-muted text-uppercase mb-1">Total Open Ports</h6>
                                        <h2 class="mb-0 fw-bold">{total_open}</h2>
                                    </div>
                                    <div class="text-primary card-icon"><i class="fas fa-network-wired"></i></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card h-100 border-start border-4 border-danger">
                                <div class="card-body d-flex align-items-center justify-content-between">
                                    <div>
                                        <h6 class="text-muted text-uppercase mb-1">High Risk</h6>
                                        <h2 class="mb-0 fw-bold">{high_risk}</h2>
                                    </div>
                                    <div class="text-danger card-icon"><i class="fas fa-shield-alt"></i></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card h-100 border-start border-4 border-info">
                                <div class="card-body d-flex align-items-center justify-content-between">
                                    <div>
                                        <h6 class="text-muted text-uppercase mb-1">Scan Speed</h6>
                                        <h4 class="mb-0 fw-bold">{scan_speed}</h4>
                                    </div>
                                    <div class="text-info card-icon"><i class="fas fa-tachometer-alt"></i></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card h-100 border-start border-4 border-success">
                                <div class="card-body d-flex align-items-center justify-content-between">
                                    <div>
                                        <h6 class="text-muted text-uppercase mb-1">Progress</h6>
                                        <h4 class="mb-0 fw-bold">{progress}</h4>
                                    </div>
                                    <div class="text-success card-icon"><i class="fas fa-tasks"></i></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Main Table -->
                    <div class="card mb-4">
                        <div class="card-header bg-white py-3 d-flex justify-content-between align-items-center">
                            <h5 class="m-0 fw-bold text-dark"><i class="fas fa-list me-2"></i>Active Scan Results</h5>
                            <small class="text-muted">Target: 36.88.105.236 | Last Update: {datetime.datetime.now().strftime("%H:%M:%S")}</small>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover mb-0 align-middle">
                                    <thead>
                                        <tr>
                                            <th class="ps-4">Port</th>
                                            <th>Service</th>
                                            <th>Risk Level</th>
                                            <th>Banner Information</th>
                                            <th>Detected At</th>
                                        </tr>
                                    </thead>
                                    <tbody>
            """

            if not rows:
                 page_content += "<tr><td colspan='5' class='text-center py-5 text-muted'><i class='fas fa-spinner fa-spin fa-2x mb-3'></i><p>Waiting for scan data...</p></td></tr>"
            else:
                for row in rows:
                    port = row[2]
                    # Safe fallbacks for schema evolution
                    banner_raw = row[3] if len(row) > 3 else ""
                    banner = html.escape(str(banner_raw)) if banner_raw else "<span class='text-muted'>No banner</span>"
                    timestamp = row[6] if len(row) > 6 else (row[4] if len(row) > 4 else "")

                    service = "Unknown"
                    risk_html = '<span class="badge bg-secondary">Unknown</span>'

                    if has_advanced and len(row) > 5:
                        service = html.escape(str(row[4])) if row[4] else "Unknown"
                        risk_val = str(row[5]) if row[5] else "Unknown"

                        badge_class = "bg-secondary"
                        icon = ""
                        if risk_val == "High":
                            badge_class = "badge-risk-high"
                            icon = "<i class='fas fa-exclamation-triangle me-1'></i>"
                        elif risk_val == "Medium":
                            badge_class = "badge-risk-medium"
                            icon = "<i class='fas fa-exclamation-circle me-1'></i>"
                        elif risk_val == "Low":
                            badge_class = "badge-risk-low"
                            icon = "<i class='fas fa-check-circle me-1'></i>"

                        risk_html = f'<span class="badge {badge_class}">{icon}{risk_val}</span>'

                    # Icon for service
                    service_icon = "fa-question-circle"
                    if "SSH" in service: service_icon = "fa-terminal"
                    elif "HTTP" in service: service_icon = "fa-globe"
                    elif "FTP" in service: service_icon = "fa-file-transfer"
                    elif "Database" in service or "SQL" in service: service_icon = "fa-database"

                    page_content += f"""
                        <tr>
                            <td class="ps-4 fw-bold">{port}</td>
                            <td><i class="fas {service_icon} text-muted me-2"></i>{service}</td>
                            <td>{risk_html}</td>
                            <td><small class="text-secondary font-monospace">{banner[:60]}{'...' if len(banner)>60 else ''}</small></td>
                            <td><small class="text-muted">{timestamp}</small></td>
                        </tr>
                    """

            page_content += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <footer class="text-center text-muted py-4">
                        <small>&copy; 2026 NetMonitor Pro. Secured & Optimized.</small>
                    </footer>
                </div>

                <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
            """

            self.wfile.write(page_content.encode())
        else:
            self.send_error(404, "File Not Found: %s" % self.path)

def run_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MonitorHandler) as httpd:
        print(f"Serving professional dashboard at http://0.0.0.0:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()

if __name__ == "__main__":
    run_server()
