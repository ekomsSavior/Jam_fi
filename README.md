# 💜 Jam_Fi — Wi-Fi Chaos Toolkit

Jam_Fi is a powerful, cute, and spicy Wi-Fi chaos tool made for Linux and monitor-mode-capable adapters. 

It brings together scanning, jamming, deauthing, handshake collecting and more — inspired by my BLE tool, Spam-Jam!

> ✨ Built with love by [ekoms savior]

---

## ⚠️ Disclaimer

> 🧠 **For educational and authorized testing only!**  
This tool is meant for cybersecurity researchers, students, and ethical hackers with permission to test the networks involved.  
**Do not run JamFi on networks you do not own or have written consent to test.**

---

## 📦 Features

- 🔍 Scan for connected clients & access points
- 💥 Deauth clients from access points
- 💾 Capture WPA handshakes (automatically!)
- 💣 Junk packet flood (with randomized vendor MACs)
- 📡 Probe request spam (to confuse Wi-Fi scanners)
- 🧲 Karma responder (auto-responds to probes with fake beacons)

---

📁 Output
Handshakes are saved to the loot/ folder automatically

💜 Credits
Inspired by Spam-Jam BLE Tool & Powered by Scapy

## 🔧 Installation


```bash
sudo apt update && sudo apt install -y python3 python3-pip
sudo pip3 install scapy
git clone https://github.com/ekomsSavior/Jam_fi.git
cd Jam_fi
#set wifi adapter in monitor mode#
sudo ip link set wlan down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo python3 jam_fi.py

