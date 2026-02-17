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
            try:
                conn = sqlite3.connect(DB_NAME)
                c = conn.cursor()

                # Check for columns
                c.execute("PRAGMA table_info(scan_results)")
                columns = [col[1] for col in c.fetchall()]
                has_advanced = 'service' in columns and 'risk' in columns

                query = "SELECT * FROM scan_results ORDER BY timestamp DESC"
                c.execute(query)
                rows = c.fetchall()

                conn.close()
            except Exception as e:
                rows = []
                has_advanced = False
                print(f"DB Error: {e}")

            # Calculate stats
            total_open = len(rows)
            high_risk = 0
            if has_advanced:
                for row in rows:
                    if row[5] == "High": # risk is index 5
                        high_risk += 1

            page_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Server Monitor Dashboard</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    body {{ background-color: #f8f9fa; padding-top: 20px; }}
                    .card {{ margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                    .table-hover tbody tr:hover {{ background-color: #e9ecef; }}
                    .badge-risk-high {{ background-color: #dc3545; color: white; }}
                    .badge-risk-medium {{ background-color: #ffc107; color: black; }}
                    .badge-risk-low {{ background-color: #28a745; color: white; }}
                </style>
                <meta http-equiv="refresh" content="10">
            </head>
            <body>
                <div class="container">
                    <h1 class="text-center mb-4">Server Monitor Dashboard</h1>

                    <div class="row">
                        <div class="col-md-6">
                            <div class="card text-center">
                                <div class="card-body">
                                    <h5 class="card-title">Total Open Ports</h5>
                                    <p class="card-text display-4">{total_open}</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card text-center">
                                <div class="card-body">
                                    <h5 class="card-title">High Risk Vulnerabilities</h5>
                                    <p class="card-text display-4 text-danger">{high_risk}</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                            <span>Active Scan Results (Target: 36.88.105.236)</span>
                            <span class="badge bg-light text-dark">{datetime.datetime.now().strftime("%H:%M:%S")}</span>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover">
                                    <thead>
                                        <tr>
                                            <th>Port</th>
                                            <th>Service</th>
                                            <th>Risk Level</th>
                                            <th>Banner</th>
                                            <th>Last Seen</th>
                                        </tr>
                                    </thead>
                                    <tbody>
            """

            if not rows:
                 page_content += "<tr><td colspan='5' class='text-center'>No scan results yet. Scanner is running...</td></tr>"
            else:
                for row in rows:
                    # Row structure: id, ip, port, banner, service, risk, timestamp
                    # Indexes: 0, 1, 2, 3, 4, 5, 6

                    port = row[2]
                    banner = html.escape(str(row[3])) if row[3] else ""
                    timestamp = row[6] if len(row) > 6 else row[4] # Fallback for old schema

                    service = "Unknown"
                    risk = "Unknown"
                    risk_badge = "bg-secondary"

                    if has_advanced and len(row) > 5:
                        service = html.escape(str(row[4])) if row[4] else "Unknown"
                        risk_val = str(row[5]) if row[5] else "Unknown"

                        if risk_val == "High":
                            risk_badge = "badge-risk-high"
                        elif risk_val == "Medium":
                            risk_badge = "badge-risk-medium"
                        elif risk_val == "Low":
                            risk_badge = "badge-risk-low"
                        risk = f'<span class="badge {risk_badge}">{risk_val}</span>'

                    page_content += f"""
                        <tr>
                            <td><strong>{port}</strong></td>
                            <td>{service}</td>
                            <td>{risk}</td>
                            <td><small class="text-muted">{banner[:50]}</small></td>
                            <td>{timestamp}</td>
                        </tr>
                    """

            page_content += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <footer class="text-center text-muted mt-4">
                        <small>Auto-refreshing every 10 seconds. Powered by Python & Bootstrap.</small>
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
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MonitorHandler) as httpd:
        print(f"Serving advanced dashboard at http://0.0.0.0:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()

if __name__ == "__main__":
    run_server()
