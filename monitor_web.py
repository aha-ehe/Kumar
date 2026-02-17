import http.server
import socketserver
import sqlite3
import os
import html
import datetime
import json
import urllib.parse

PORT = 7890
DB_NAME = "monitor.db"

class MonitorHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve main HTML page
        if self.path == '/':
            self.serve_html()
            return

        # API: Stats
        if self.path == '/api/stats':
            self.serve_json(self.get_stats())
            return

        # API: Results with Pagination
        if self.path.startswith('/api/results'):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            page = int(params.get('page', [1])[0])
            limit = int(params.get('limit', [10])[0])
            self.serve_json(self.get_results(page, limit))
            return

        # API: Settings
        if self.path == '/api/settings':
            self.serve_json(self.get_settings())
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == '/api/settings':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(post_data)
                self.update_settings(data)
                self.serve_json({"status": "ok", "message": "Settings updated"})
            except Exception as e:
                self.send_error(400, f"Bad Request: {e}")
            return

        self.send_error(404, "Not Found")

    def serve_html(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        with open("monitor_dashboard.html", "r") as f:
            self.wfile.write(f.read().encode())

    def serve_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def get_stats(self):
        stats = {}
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            # Scan Stats
            c.execute("SELECT key, value FROM scan_stats")
            for k, v in c.fetchall():
                stats[k] = v

            # Total Open Ports
            c.execute("SELECT COUNT(*) FROM scan_results")
            stats['total_open'] = c.fetchone()[0]

            # High Risk Count
            c.execute("SELECT COUNT(*) FROM scan_results WHERE risk='High'")
            stats['high_risk'] = c.fetchone()[0]

            conn.close()
        except:
            pass
        return stats

    def get_results(self, page, limit):
        offset = (page - 1) * limit
        results = []
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            # Get data
            c.execute(f"SELECT ip, port, banner, service, risk, timestamp FROM scan_results ORDER BY timestamp DESC LIMIT {limit} OFFSET {offset}")
            rows = c.fetchall()

            for row in rows:
                results.append({
                    "ip": row[0],
                    "port": row[1],
                    "banner": row[2],
                    "service": row[3],
                    "risk": row[4],
                    "timestamp": row[5]
                })

            conn.close()
        except Exception as e:
            print(f"DB Error results: {e}")
        return results

    def get_settings(self):
        settings = {}
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT key, value FROM settings")
            for k, v in c.fetchall():
                settings[k] = v
            conn.close()
        except:
            pass
        return settings

    def update_settings(self, data):
        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            for k, v in data.items():
                if k in ['target_ip', 'max_workers', 'ports']:
                    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"DB Update Error: {e}")

def run_server():
    # Ensure HTML template exists (creating inline for simplicity in deployment)
    create_html_template()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MonitorHandler) as httpd:
        print(f"Serving API dashboard at http://0.0.0.0:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()

def create_html_template():
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetMonitor Pro - Realtime</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #f4f6f9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .card { border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        .badge-risk-high { background-color: #e74c3c; }
        .badge-risk-medium { background-color: #f39c12; }
        .badge-risk-low { background-color: #27ae60; }
        .pagination { cursor: pointer; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-server me-2"></i>NetMonitor Pro</a>
            <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#settingsModal">
                <i class="fas fa-cog"></i> Settings
            </button>
        </div>
    </nav>

    <div class="container">
        <!-- Stats -->
        <div class="row g-4 mb-4">
            <div class="col-md-3">
                <div class="card h-100 border-start border-4 border-primary p-3">
                    <h6 class="text-muted text-uppercase">Total Open Ports</h6>
                    <h2 class="mb-0 fw-bold" id="stat-total">0</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card h-100 border-start border-4 border-danger p-3">
                    <h6 class="text-muted text-uppercase">High Risk</h6>
                    <h2 class="mb-0 fw-bold text-danger" id="stat-risk">0</h2>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card h-100 border-start border-4 border-info p-3">
                    <h6 class="text-muted text-uppercase">Scan Speed</h6>
                    <h4 class="mb-0 fw-bold" id="stat-speed">0 ports/sec</h4>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card h-100 border-start border-4 border-success p-3">
                    <h6 class="text-muted text-uppercase">Progress</h6>
                    <h4 class="mb-0 fw-bold" id="stat-progress">0/0</h4>
                </div>
            </div>
        </div>

        <!-- Table -->
        <div class="card mb-4">
            <div class="card-header bg-white py-3 d-flex justify-content-between align-items-center">
                <h5 class="m-0 fw-bold"><i class="fas fa-list me-2"></i>Active Results</h5>
                <div>
                    <button class="btn btn-sm btn-secondary" onclick="prevPage()"><i class="fas fa-chevron-left"></i></button>
                    <span class="mx-2" id="page-indicator">Page 1</span>
                    <button class="btn btn-sm btn-secondary" onclick="nextPage()"><i class="fas fa-chevron-right"></i></button>
                </div>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-striped table-hover mb-0 align-middle">
                        <thead>
                            <tr>
                                <th class="ps-4">Port</th>
                                <th>Service</th>
                                <th>Risk</th>
                                <th>Banner</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody id="results-body">
                            <!-- JS fills this -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div class="modal fade" id="settingsModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Scanner Settings</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="settingsForm">
                        <div class="mb-3">
                            <label class="form-label">Target IP</label>
                            <input type="text" class="form-control" id="setting-ip" name="target_ip">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Max Threads</label>
                            <input type="number" class="form-control" id="setting-threads" name="max_workers">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Ports (comma separated)</label>
                            <textarea class="form-control" id="setting-ports" name="ports" rows="3"></textarea>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary" onclick="saveSettings()">Save Changes</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentPage = 1;
        const limit = 10;

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stat-total').innerText = data.total_open || 0;
                document.getElementById('stat-risk').innerText = data.high_risk || 0;
                document.getElementById('stat-speed').innerText = (data.scan_speed || 0) + ' ports/sec';
                document.getElementById('stat-progress').innerText = data.progress || '0/0';
            } catch (e) { console.error(e); }
        }

        async function fetchResults() {
            try {
                const res = await fetch(`/api/results?page=${currentPage}&limit=${limit}`);
                const data = await res.json();
                const tbody = document.getElementById('results-body');
                tbody.innerHTML = '';

                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4">No results found on this page.</td></tr>';
                    return;
                }

                data.forEach(row => {
                    let riskBadge = 'bg-secondary';
                    if (row.risk === 'High') riskBadge = 'badge-risk-high';
                    if (row.risk === 'Medium') riskBadge = 'badge-risk-medium';
                    if (row.risk === 'Low') riskBadge = 'badge-risk-low';

                    const tr = `
                        <tr>
                            <td class="ps-4 fw-bold">${row.port}</td>
                            <td>${row.service || 'Unknown'}</td>
                            <td><span class="badge ${riskBadge}">${row.risk || 'Unknown'}</span></td>
                            <td><small class="text-muted font-monospace">${(row.banner || '').substring(0, 50)}</small></td>
                            <td><small>${row.timestamp}</small></td>
                        </tr>
                    `;
                    tbody.innerHTML += tr;
                });
                document.getElementById('page-indicator').innerText = `Page ${currentPage}`;
            } catch (e) { console.error(e); }
        }

        async function loadSettings() {
            const res = await fetch('/api/settings');
            const data = await res.json();
            document.getElementById('setting-ip').value = data.target_ip || '';
            document.getElementById('setting-threads').value = data.max_workers || '';
            document.getElementById('setting-ports').value = data.ports || '';
        }

        async function saveSettings() {
            const data = {
                target_ip: document.getElementById('setting-ip').value,
                max_workers: document.getElementById('setting-threads').value,
                ports: document.getElementById('setting-ports').value
            };

            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
            modal.hide();
            alert('Settings saved. Scanner will update on next cycle.');
        }

        function nextPage() { currentPage++; fetchResults(); }
        function prevPage() { if (currentPage > 1) currentPage--; fetchResults(); }

        // Initial Load
        loadSettings();
        fetchStats();
        fetchResults();

        // Real-time polling
        setInterval(fetchStats, 2000);
        setInterval(fetchResults, 5000);
    </script>
</body>
</html>
    """
    with open("monitor_dashboard.html", "w") as f:
        f.write(html_content)

if __name__ == "__main__":
    run_server()
