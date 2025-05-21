# Jam_Fi – Wi-Fi Chaos Tool  
by [@ekomsSavior]

---

![image3](https://github.com/user-attachments/assets/960cce0f-7854-4080-b977-b0a02fb34418)


## What is Jam_Fi?

Jam_Fi is an offensive wireless toolkit for Kali Linux, built for red team simulation, network disruption research, and Wi-Fi exploitation education. It includes modules for:

- Deauthentication attacks
- WPA handshake capture and cracking
- Probe request and junk frame flooding
- Evil twin access points with credential logging
- Karma responder beacon spoofing
- MITM injection with fake update pages
- Custom captive portals and payload delivery

All features are designed for local lab use and legal environments only.

---

## Installation

Clone the repository

```bash
git clone https://github.com/ekomsSavior/Jam_Fi.git
cd Jam_Fi
```

Install dependencies

```bash
sudo apt update
sudo apt install -y aircrack-ng hostapd dnsmasq dnsspoof python3-scapy
```

Run the tool:

```bash
sudo python3 jam_fi.py
```

To update later:

```bash
cd Jam_Fi
git pull
```

---

## Interface Modes: Monitor vs Managed

Some Jam_Fi modules require **monitor mode**, while others require **managed mode**.

### Monitor Mode (e.g. wlan0mon)

Required for:

- Scan Clients & APs  
- Deauth One Client  
- Deauth All Clients  
- Probe Request Spam  
- Junk Packet Flood  
- Karma Responder  
- Chaos Mode  
- MITM HID Injection

Enable with:

```bash
sudo airmon-ng start wlan0
```

Your monitor interface will usually be called `wlan0mon`.

---

### Managed Mode (e.g. wlan0)

Required for

- Evil AP  
- Captive portal phishing  
- DNS redirection  
- Loot viewing  
- Cracking captured handshakes (optional)

Switch back with

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

---

## Jam_Fi Modules Overview

Each module appears in the menu

```
1  Scan Clients & APs
2  Deauth One Client
3  Deauth All Clients + Capture
4  Crack Captured Handshakes
5  Probe Request Spam
6  Junk Packet Flood
7  Karma Responder
8  Chaos Mode
9  View Loot
10 Evil AP
11 MITM HID Injection
0  Quit
```

Descriptions

- **Scan Clients & APs** – Uses Scapy to sniff for access points and associated clients.
- **Deauth One Client** – Sends deauth packets to a target MAC on a given AP.
- **Deauth ALL Clients + Capture** – Deauths all known clients while capturing WPA handshakes.
- **Crack Captured Handshakes** – Runs Aircrack-ng or Hashcat against captured `.pcap` files.
- **Probe Request Spam** – Broadcasts fake SSIDs based on common public networks.
- **Junk Packet Flood** – Sends randomized frames to clutter the spectrum.
- **Karma Responder** – Replies to probe requests with fake beacons.
- **Chaos Mode** – Combines probe spam, junk flood, and karma attack.
- **View Loot** – Shows saved handshakes and credentials in `loot/`.
- **Evil AP** – Launches a rogue access point with credential logging and DNS spoofing.
- **MITM HID Injection** – Serve payloads + log keystrokes via HTML/JS.

---

## The `loot/` Folder

JamFi logs data, HTML, and attack files to `loot/`:

| File                  | Purpose                                                 |
|-----------------------|---------------------------------------------------------|
| `injection.html`      | JS keylogger + redirect to fake update                  |
| `fake_update.html`    | Auto-download payload on user click                     |
| `keystroke_log_*.txt` | Logs captured JS keystrokes during MITM                 |
| `session_log_*.txt`   | Visitor IPs, paths, user agents                         |
| `hostapd.conf`        | Evil AP config                                          |
| `dnsmasq.conf`        | DHCP/DNS for fake AP                                    |
| `dnsspoof_hosts`      | Forces DNS to attacker (10.0.0.1)                       |
| `wps_*.txt`           | WPS module logs  (coming soon)                                       |

---

## The `payloads/` Folder

Add real payloads here! These get served by the MITM module:

| File Example           | Description                             |
|------------------------|-----------------------------------------|
| `payload.exe`          | Real .exe payload (e.g. msfvenom shell) |
| `reverse_shell.zip`    | Archive with malicious scripts          |
| `payload.bat`          | Batch script for Windows                |
| `keylogger_beacon.py`  | Python beacon/keylogger script          |
| `autostart.html`       | HTML payload w/ JS autostart tricks     |
| `macro.vba`            | Word macro payload (manual delivery)    |
| `loot_dropper.py`      | Python dropper or payload loader        |

also check out the payloads_README in the payloads folder xo
---

---

##  MITM HID Injection Overview

When you choose option `11` in JamFi:

-  Broadcasts a fake SSID using beacon spoofing  
-  Clients connect and are served `injection.html`  
-  JavaScript keylogger logs user keystrokes  
-  Page auto-redirects to `fake_update.html`  
-  Payload downloads when the user clicks **Update**  
-  Logs are saved to `loot/session_log_*.txt` and `loot/keystroke_log_*.txt`

All files are served from:  
`http://10.0.0.1`

To add your own payloads, drop them into the `payloads/` folder. JamFi will automatically load and offer them during MITM mode.

---

##  Ngrok Setup (for Remote Payload Delivery)

Want to serve payloads outside your local network? JamFi supports [Ngrok](https://ngrok.com) for public tunnels.

###  Setup Instructions

1. Download Ngrok for Linux:
   ```bash
   cd ~/Jam_fi
   wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-stable-linux-amd64.zip
   unzip ngrok-stable-linux-amd64.zip
   chmod +x ngrok
   ```

2. Add your Ngrok authtoken (from your [Ngrok Dashboard](https://dashboard.ngrok.com/get-started/your-authtoken)):
   ```bash
   ./ngrok config add-authtoken YOUR_AUTHTOKEN
   ```

That’s it! When you launch MITM Mode and choose Ngrok, JamFi will automatically:

- Start a public tunnel on port 80
- Rewrite your HTML files to use `https://<your-ngrok>.ngrok-free.app`
- Serve your payloads globally

>  **Warning:** Ngrok links are public. Use only in secure test labs.

---


---

## Evil AP Customization

Edit `loot/login.html` to create a custom phishing page:

```html
<h2>Welcome to Starbucks Free Wi-Fi</h2>
<p>Please sign in to continue</p>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Email"><br>
  <input type="password" name="password" placeholder="Wi-Fi Password"><br>
  <input type="submit" value="Connect">
</form>
```

Captured credentials are logged to `loot/creds.txt`.


---

## Disclaimer

Jam_Fi is provided for **educational and authorized security research only**.

Do not use this tool against networks or devices you do not own or have permission to test.

Use responsibly, ethically, and within legal boundaries.

---

## About

Jam_Fi is an open-source red team utility developed by [@ekomsSavior](https://github.com/ekomsSavior).

If you find it useful, consider starring the repo and contributing responsibly.


