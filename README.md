# Jam_Fi – Wi-Fi Chaos Tool  

![ek0ms Banner](https://img.shields.io/badge/ek0ms-certified_ethcial_hacker-blACK)

---

<img width="374" height="109" alt="jamfi" src="https://github.com/user-attachments/assets/47d5a04d-ce40-4bfb-8ca6-759851111389" />


## What is Jam_Fi?

Jam_Fi is an offensive wireless toolkit, built for red team simulations, network disruption research, and Wi-Fi exploitation education. It includes modules for:

- Deauthentication attacks
- WPA handshake capture and cracking
- Probe request and junk frame flooding
- Evil twin access points with credential logging
- Karma responder beacon spoofing
- MITM injection with fake update pages and keystroke logging.
- Custom captive portals and payload delivery
- Now with Ngrok Support!
- **CVE Vulnerability Scanner & Exploit Launcher** (NEW)
- **Auto-Pwn Mode – Full Intrusive Chain** (NEW)
- **Router Exploitation – Over‑the‑Air & IP‑based** (NEW)

DISCLAIMER : All features are designed for local lab use and legal environments only.

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
sudo apt install -y aircrack-ng hostapd dnsmasq python3-scapy
```
---

##  ngrok Setup

```bash
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xvzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/
```

Authenticate your account:

```bash
ngrok config add-authtoken <YOUR_NGROK_AUTH_TOKEN>
```

---

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

Jam_Fi now **automatically handles interface mode switching** for you. When you select a module, the tool will enable monitor mode if needed, and when you exit it will restore your normal network connectivity.

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
- CVE Vulnerability Scanner  
- Auto-Pwn Mode  
- Router Exploits (over‑the‑air attacks)

Enable manually with:

```bash
sudo airmon-ng start wlan0
```

Your monitor interface will usually be called `wlan0mon`.

---

### Managed Mode (e.g. wlan0)

Required for:

- Evil AP  
- Captive portal phishing  
- DNS redirection  
- Loot viewing  
- Cracking captured handshakes (optional)  
- Router Exploits (IP‑based exploits – automatic association)

Switch back with

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

> **Note:** The new Router Exploits module can automatically switch between modes when needed.

---

## Jam_Fi Modules Overview

<img width="688" height="668" alt="IMG_3145" src="https://github.com/user-attachments/assets/db35adb9-6d25-463b-a20e-8e415093c87e" />


### Descriptions

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

## New Modules (Options 12–14)

### 12. CVE Vulnerability Scanner & Exploit Launcher

This module performs deep fingerprinting of nearby Wi‑Fi clients (not APs) to identify known CVEs based on MAC OUI, hostname, user‑agent, and chipset information. It then offers to launch matching exploits.

- **How it works** – Uses the monitor interface to sniff ARP, DHCP, and probe requests, building a detailed profile of each client (OS, vendor, chipset, probed SSIDs).  
- **CVE matching** – Compares client data against a local `loot/cve_db.csv` database (pre‑populated with dozens of high‑impact wireless/client CVEs).  
- **Exploit launching** – For matched CVEs (e.g., KRACK, Broadpwn, FragAttacks) you can automatically trigger the appropriate exploit.  
- **Example** – Detects an iPhone running iOS 14.2 and offers to launch KRACK (CVE‑2019‑15126).

### 13. Auto-Pwn Mode – Full Intrusive Chain

Automated version of the CVE scanner. It fingerprints every client in range, checks for vulnerabilities, and **automatically launches exploits** against those that are vulnerable – no user intervention required. Ideal for fast, unattended red‑team operations.

### 14. Router Exploits – Over‑the‑Air & IP‑based

A comprehensive router exploitation module that works **both in monitor mode (no association)** and **by temporarily associating to the target network** for full IP‑based exploits.

#### Features

- **Channel hopping** – Scans all 13 2.4 GHz channels to discover every AP in range (hundreds found in dense areas).  
- **OUI manufacturer lookup** – Identifies router vendor (TP‑Link, Huawei, Asus, Netgear, D‑Link, Zyxel, Arris, Tenda, Cisco, Linksys, MikroTik, etc.) from the BSSID.  
- **Automatic vulnerability mapping** – Shows known CVEs and botnet exploits for each detected vendor.  

#### Attack Options

1. **Auto‑Connect & IP Exploits**  
   - Temporarily associates with the selected AP (WPA2‑PSK or open).  
   - Automatically obtains a DHCP lease and detects the gateway IP.  
   - Launches **manufacturer‑specific exploits** including:  
     - Quad7 Botnet (CVE‑2023‑50224, CVE‑2025‑9377)  
     - AVrecon (Russian GRU espionage malware)  
     - AyySSHush (Asus persistent SSH backdoor)  
     - Dray:Break (DrayTek multiple RCE)  
     - CVE‑2023‑33538 (EoL TP‑Link Mirai)  
     - Classic exploits: Huawei UPnP, MikroTik WinBox, TP‑Link auth bypass, Netgear CGI, D‑Link Hedwig, Zyxel weblogin  
   - After successful exploitation, can install a **persistent backdoor** (cron job, startup script, or reverse shell).  
   - Automatically restores monitor mode when finished.

2. **Deauth Attack** – Floods the target AP with deauthentication frames, disconnecting all clients (pure monitor mode, no IP needed).

3. **Beacon Flood** – Creates hundreds of fake evil twin APs around the target, causing client confusion.

4. **Client Traffic Capture** – Sniffs nearby client activity (MAC addresses, probe requests) for reconnaissance.

5. **Manual IP Entry** – For when you already know the router’s IP (e.g., your own lab) and want to skip auto‑association.

> **Why over‑the‑air?** Many botnets (Quad7, AVrecon) operate purely by scanning beacon frames and launching deauth/flood attacks. Our module supports that style, but also goes further by associating when a real IP‑based exploit is needed.

#### Supported Router Vendors (Partial List)

- TP‑Link, Huawei, Asus, Netgear, D‑Link, Zyxel, Arris, Tenda, Cisco, Linksys, MikroTik, Actiontec, Verizon, T‑Mobile, Mediatek, DrayTek

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
| `cve_db.csv`          | Local CVE database for client fingerprinting            |
| `handshake_*.pcap`    | Captured WPA handshakes                                 |
| `creds.txt`           | Captured credentials from Evil AP                       |

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

## Evil AP – Rogue Access Point with Credential Harvesting

When you choose option **10** in Jam_Fi, you transform your Wi‑Fi adapter into a fully functional rogue access point. This is a classic “evil twin” attack: victims connect to your fake network, and you capture everything they type on your custom phishing page.

### What it does

- **Broadcasts a fake SSID** – You choose the name (e.g., “Starbucks Free Wi‑Fi”, “Airport Hotspot”, “Cafe Net”). The network can be open or WPA2‑protected (default password: `password123`).
- **Provides DHCP & DNS** – Victims automatically get an IP address (10.0.0.x range). All DNS requests are spoofed to point to your attacker machine (10.0.0.1).
- **Serves a phishing login page** – Any HTTP request is redirected to `http://10.0.0.1`, where your custom `login.html` is displayed.
- **Logs credentials** – When a victim submits the form, the username and password are saved to `loot/creds.txt` with a timestamp.
- **Transparent redirection** – After “logging in”, the victim is redirected to a harmless page (e.g., the real Wi‑Fi login of the target network) to avoid suspicion.

### How it works (technical)

Jam_Fi automatically:
1. Stops monitor mode and switches your adapter to **managed mode** (e.g., `wlan0`).
2. Assigns the IP `10.0.0.1/24` to the interface.
3. Launches `hostapd` to broadcast the rogue SSID (configuration saved in `loot/hostapd.conf`).
4. Launches `dnsmasq` to handle DHCP leases and DNS spoofing (configuration in `loot/dnsmasq.conf`).
5. Starts a custom Python HTTP server that serves your phishing page and logs POST requests.
6. Optionally launches the JamFi DNS spoofer to capture and redirect all DNS queries.

When the victim submits the form, the server writes the credentials to `loot/creds.txt` and returns a “Connected” message. The victim believes they have authenticated successfully.

### Customisation

Edit `loot/login.html` to create your own phishing page. The example below mimics a generic Wi‑Fi login portal:

```html
<h2>Welcome to Starbucks Free Wi-Fi</h2>
<p>Please sign in to continue</p>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Email"><br>
  <input type="password" name="password" placeholder="Wi-Fi Password"><br>
  <input type="submit" value="Connect">
</form>
```

You can customise:
- **Branding** – Replace “Starbucks” with any network name (e.g., “Airport Free Wi‑Fi”, “Hotel Guest”).
- **Fields** – Add more input fields (e.g., “Phone Number”, “Credit Card” – for authorised testing only).
- **Styling** – Use inline CSS or link to external stylesheets (place them in `loot/`).
- **Redirect after POST** – The current server returns a simple “Connected” page. You can modify the Python code in the Evil AP function to redirect to any URL.

### Captured credentials

Every login attempt is appended to `loot/creds.txt` in the format:

```
[2026-04-28 21:34:12] Username: johndoe@example.com Password: mypassword123
```

Check the loot folder anytime using option **9 – View Loot**.

### Important notes

- **Monitor mode is temporarily disabled** – Evil AP runs in managed mode. After you stop the attack (press `Ctrl+C`), Jam_Fi automatically restarts monitor mode on your adapter.
- **The default password is `password123`** – You can change it by editing the generated `loot/hostapd.conf` before launching the attack (look for `wpa_passphrase`).
- **The network is on channel 6** – You can modify the channel in `hostapd.conf` if needed.
- **All configuration files are saved in `loot/`** – This allows you to reuse or tweak them for future attacks.

---

> **Disclaimer and Reminder** – Evil AP attacks are highly effective for credential theft and should only be used in isolated labs or with written permission from the network owner. Misuse is illegal.

---

## MITM HID Injection Overview

When you choose option **11** in Jam_Fi, you launch a full Man‑in‑the‑Middle attack designed to harvest credentials, log keystrokes, and deliver payloads – all while the victim thinks they are connecting to a legitimate Wi‑Fi network.

### How it works

1. **Fake Access Point** – Jam_Fi broadcasts a rogue SSID (you choose the name) using beacon spoofing. Clients in range see it as a real network.

2. **Automatic DNS & Traffic Redirection** – Once a client connects, all their DNS requests are spoofed to point to the attacker’s IP (`10.0.0.1`). Every HTTP request is silently redirected to the attacker’s web server.

3. **Injection Page** – The victim is served `injection.html`, a fake “System Update Required” page.  
   - A **JavaScript keylogger** captures every keystroke (including special keys like Enter, Backspace, Arrows, etc.) and sends them in batches every 2 seconds to the server.  
   - After 5 seconds, the page automatically redirects to `fake_update.html`.

4. **Fake Update Page** – The victim is prompted to click a button to install a “security update”.  
   - If you selected a payload from your `payloads/` folder, the button triggers an automatic download of that file (renamed as `Security_Update.exe`).  
   - After download, the victim is redirected to a harmless site (e.g., Google) to avoid suspicion.

5. **Payload Serving** – Any file you place in the `payloads/` folder will be listed when you start the MITM module. Choose one (or none for keylogger only) and Jam_Fi serves it automatically.  
   - Supported payloads: `.exe`, `.bat`, `.apk`, `.zip`, `.vba`, `.py`, `.html`, etc.

6. **Keystroke Logging** – All captured keystrokes are saved to `loot/keystroke_log_*.txt`.  
   - Session metadata (IP, User‑Agent, requested path) is stored in `loot/session_log_*.txt`.

7. **Ngrok Support** – Want to deliver payloads remotely? When you enable Ngrok, Jam_Fi:  
   - Starts a public tunnel on port 80.  
   - Rewrites the injected HTML to use the public Ngrok URL.  
   - Allows victims outside your local network to interact with the attack (use only in authorized labs).

### Example workflow

1. Victim sees “Free_Public_WiFi” and connects.
2. They open a browser and are greeted with: *“Critical System Update Required”*.
3. While they read, every key they type is sent to your `keystroke_log.txt`.
4. After 5 seconds, they are redirected to a page that says “Click to install the update”.
5. When they click, your chosen payload (e.g., `payload.exe`) downloads.
6. Everything is logged, and you walk away with credentials, keystrokes, and a backdoor on the target machine.

### Customisation

- Edit `loot/injection.html` to change the fake update message or keylogger behaviour.  
- Edit `loot/fake_update.html` to modify the download button or redirection URL.  
- Add your own payloads to `payloads/` – Jam_Fi lists them automatically when you start the MITM module.

All files are served from `http://10.0.0.1`. For remote access, answer `y` when asked about Ngrok and follow the on‑screen URL.

---

> ** Disclaimer** – This module is for educational and authorised testing only. Never deploy against networks or devices you do not own or have explicit permission to assess.

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


<img width="700" height="178" alt="image1(1)" src="https://github.com/user-attachments/assets/4e636110-4be3-4963-ab1d-8968fbac8528" />
