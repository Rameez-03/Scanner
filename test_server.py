# fake_server_threaded.py
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

PORT = 8080
BANNER = "OpenSSL/1.0.1"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Server", BANNER)
        self.end_headers()
        try:
            self.wfile.write(b"ok\n")
            self.wfile.flush()
        except:
            pass

    def log_message(self, format, *args):
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

if __name__ == "__main__":
    httpd = ThreadedHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Fake server running on http://0.0.0.0:{PORT}  (Server: {BANNER})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        print("Shutting down")

