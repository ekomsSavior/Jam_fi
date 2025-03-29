# 💜 JamFi — Wi-Fi Chaos Toolkit

Welcome to **JamFi**, the ✨ spicy chaos-fueled Wi-Fi auditing tool made with love by ekoms savior.  
Inspired by my BLE tool **Spam-Jam**, JamFi brings you a cute but powerful way to **scan, jam, capture, and crack** Wi-Fi networks.

> 🧠 Built for Kali Linux + Monitor Mode Adapters  
> 🐉 Trusted by researchers & rebels  
> 💜 Fully supports Aircrack-ng & Hashcat

---

## ⚠️ Disclaimer

> 🚨 **For ethical testing only.**  
This tool is intended for authorized network audits, educational purposes, and red team exercises.  
You **must have explicit permission** to test the networks you interact with.  
**Do not run JamFi on networks you do not own or have legal authorization to test.**

---

## 🔥 Features (JamFi v1.3)

- 🔍 **Scan Clients + APs** — auto-nests clients under APs with clean output
- 💥 **Deauth One Client** — target a specific device & optionally capture handshakes
- 💣 **Deauth All Clients + Capture All Handshakes** — powerful bulk deauth mode
- 🔓 **Crack Handshakes**  
  - Choose between **Aircrack-ng** or **Hashcat**
  - Supports `.pcap`, `.cap`, and `.hccapx`
  - Auto-detects loot folder or accept custom file paths
- 📡 **Probe Request Spam** — spam fake SSIDs to confuse clients
- 🧲 **Karma Responder** — reply to probes with fake beacons
- 💣 **Junk Flood** — high-entropy MAC spoofed frames
- 💃 **Chaos Mode** — combines probe spam & junk flood for Wi-Fi mayhem
- 📁 **Loot Viewer** — browse your captured `.pcap` & `.hccapx` files
- 👿 **Evil AP (coming soon!)** — mimic real networks with rogue access points

---

## 📂 Output

Captured WPA handshakes are saved in the `loot/` directory.  
All files are named automatically based on their BSSID.

---

## 💻 Installation (Kali Linux or Debian-based)

```bash

sudo apt update && sudo apt install -y python3 python3-pip aircrack-ng hashcat

sudo pip3 install scapy

git clone https://github.com/ekomsSavior/Jam_fi.git

cd Jam_fi

##📡 Adapter Setup (Monitor Mode)

# replace wlan0 with your interface

```bash
sudo ip link set wlan0 down

sudo iw dev wlan0 set type monitor

sudo ip link set wlan0 up

##🚀 Run JamFi

```bash

sudo python3 jam_fi.py

🔐 Wordlists

JamFi defaults to rockyou.txt for cracking, but you can use any wordlist:

# Common wordlist locations:

# /usr/share/wordlists/rockyou.txt

# /usr/share/seclists/Passwords

# Troubleshooting Handshake Captures
- Make sure client reconnects to network
- Use `--interval 0.1` instead of default
- Extend attack window to 20–30 seconds

💜 Credits & Inspiration

Inspired by the vibes of Spam-Jam BLE Tool

Built with Scapy, Aircrack-ng, Hashcat

Made with deep love for the cybersecurity community by [ekoms savior]

🧠 Contributors & Homies
Big thanks to:

Our frens testing in the field

and Every follower & supporter who made JamFi grow

sending most big hugs to all of you xox ✨🫂✨
