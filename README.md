# Loot Folder - JamFi

This folder contains all necessary assets for JamFi's Evil AP, MITM, and Phishing modes. Here's what each file does:

- **index.html** – The default page served to connected clients.
- **login.html** – A fake login page that logs entered credentials.
- **phish_server.py** – Python HTTP server that hosts `index.html` and `login.html` and logs form data to `loot/creds.txt`.
- **hostapd.conf** – Configuration for hostapd to broadcast the fake access point.
- **dnsmasq.conf** – DHCP and DNS configuration for the evil AP.
- **dnsspoof_hosts** – Used by `dnsspoof` to redirect all DNS traffic to 10.0.0.1.
- **hotspot-detect.html** – Used to trigger captive portals on devices like iPhones and Macs.
- **injection.html** – Fake payload page used in MITM HID Injection mode.

All files are required for JamFi to run properly in full Evil AP mode. They are automatically generated if missing, but feel free to customize them to your liking 💅

---
💜 Built with love by [@ekomsSavior](https://github.com/ekomsSavior)
