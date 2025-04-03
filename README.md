# 💜 JamFi – Wi-Fi Chaos Tool  
by [@ekomsSavior](https://github.com/ekomsSavior)

> Built with love to teach, explore, and cause a little friendly Wi-Fi mischief. 💅

---

## ✨ What is JamFi?

JamFi is a powerful and playful Wi-Fi chaos and red teaming toolkit written in Python for Kali Linux. It's designed for educational and cybersecurity research purposes, helping you learn how attackers exploit wireless networks—and how to defend against them.

JamFi includes tools for:

- Evil Twin Access Points ☠️  
- Deauthentication Attacks 💥  
- Handshake Capture & Cracking 🔓  
- Probe Request & Junk Flooding 📡  
- Karma Attacks 🧲  
- MITM HID Injection 💻  
- Fake Login Phishing with Auto-Logging 📄  
- and more...

Whether you're a beginner or advanced user, JamFi gives you a hands-on way to experiment and learn in a lab setting.

---

## 🛠️ Installation

1. Clone the repo:
```bash
git clone https://github.com/ekomsSavior/JamFi
cd JamFi
Make sure you have the following installed:

bash
Copy
Edit
sudo apt update
sudo apt install -y aircrack-ng hostapd dnsmasq dnsspoof python3-scapy
Run the tool:

bash
Copy
Edit
sudo python3 jam_fi.py
🌀 Features & Menu
When you run JamFi, you’ll see a menu like this:

🔹 1  Scan Clients & APs 🔍

🔹 2  Deauth One Client 💥

🔹 3  Deauth ALL Clients + Capture 🔓

🔹 4  Crack Captured Handshakes 🔓

🔹 5  Probe Request Spam 📡

🔹 6  Junk Packet Flood 💣

🔹 7  Karma Responder 🧲

🔹 8  Chaos Mode 💃

🔹 9  View Loot 📁

🔹 🔟 Evil AP 👿

🔹 11 MITM HID Injection 🧠

🔹 0  Quit ❌

💼 The loot/ Folder

This folder contains all the important config and phishing assets used by Evil AP and MITM modes:

File	Purpose

index.html	The default captive portal or phishing homepage

login.html	Fake login page that logs entered usernames & passwords

phish_server.py	Hosts the phishing server & saves form data to creds.txt

creds.txt	Stores submitted login form credentials (auto-created)

hostapd.conf	Used to configure and start the Evil Access Point

dnsmasq.conf	Handles DHCP and DNS for the Evil AP

dnsspoof_hosts	Used by dnsspoof to redirect all DNS to the attacker

hotspot-detect.html	Helps trigger captive portal on iOS/macOS devices

injection.html	Used for MITM HID payload simulation (fake keystroke browser page)

All of these files are auto-generated if missing, so don’t stress if you delete them!

🚨 Disclaimer

This tool is for educational and authorized research only.

By using JamFi, you agree that you are responsible for your own actions.

Do not use this tool on networks or devices you don’t have explicit permission to test.

The goal is to educate and empower—not to harm. Use wisely 💜

💜 Built With Love

JamFi is a passion project created by @ekomsSavior

It’s free, open-source, and meant to make learning cybersecurity hands-on, fun, and inclusive for all.

If you like JamFi, give it a ⭐️ on GitHub and share it with your hacker friends!

