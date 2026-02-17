import http.server
import socketserver
import sqlite3
import os
import html

PORT = 7890
DB_NAME = "monitor.db"

class MonitorHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            page_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Server Monitor Dashboard</title>
                <style>
                    body { font-family: sans-serif; padding: 20px; }
                    table { border-collapse: collapse; width: 100%; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    h1 { color: #333; }
                </style>
                <meta http-equiv="refresh" content="5">
            </head>
            <body>
                <h1>Active Port Scan Results</h1>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>IP Address</th>
                        <th>Port</th>
                        <th>Service Banner</th>
                        <th>Timestamp</th>
                    </tr>
            """

            try:
                conn = sqlite3.connect(DB_NAME)
                c = conn.cursor()
                c.execute("SELECT * FROM scan_results ORDER BY timestamp DESC")
                rows = c.fetchall()
                conn.close()

                if not rows:
                     page_content += "<tr><td colspan='5'>No scan results yet. Scanner is running...</td></tr>"
                else:
                    for row in rows:
                        # Sanitize banner to prevent XSS
                        banner_safe = html.escape(str(row[3]))

                        page_content += f"""
                        <tr>
                            <td>{row[0]}</td>
                            <td>{row[1]}</td>
                            <td>{row[2]}</td>
                            <td>{banner_safe}</td>
                            <td>{row[4]}</td>
                        </tr>
                        """
            except Exception as e:
                page_content += f"<tr><td colspan='5'>Error reading database: {e}</td></tr>"

            page_content += """
                </table>
                <p>Auto-refreshing every 5 seconds...</p>
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
        print(f"Serving monitor dashboard at http://0.0.0.0:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()

if __name__ == "__main__":
    run_server()
