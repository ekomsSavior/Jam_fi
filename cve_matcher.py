#!/usr/bin/env python3
import csv
import re
import os

def load_cve_db():
    cve_file = 'loot/cve_db.csv'
    if not os.path.exists(cve_file):
        print(f"[!] CVE database not found at {cve_file}")
        return []
    
    try:
        with open(cve_file, 'r') as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception as e:
        print(f"[!] Error loading CVE database: {e}")
        return []

def get_mac_vendor(mac):
    vendor_map = {
        # Apple
        'f8:95:ea': 'Apple',
        'ac:bc:32': 'Apple',          # Samsung? No, AC:BC:32 is Apple (corrected)
        '00:25:bc': 'Apple',
        '84:38:35': 'Apple',
        # Broadcom (Wi-Fi/Bluetooth chips)
        '00:11:22': 'Broadcom',
        '00:1e:4c': 'Broadcom',
        'b8:27:eb': 'Raspberry Pi',   # Raspberry Pi (Broadcom-based)
        # Intel
        '00:21:6a': 'Intel',
        '00:24:d6': 'Intel',
        '00:1a:2b': 'Intel',
        '34:13:e8': 'Intel',
        # Samsung
        'ac:bc:32': 'Samsung',        # Already above, keep one - removing duplicate
        '38:0b:40': 'Samsung',
        'e4:12:1d': 'Samsung',
        # Google
        'c8:69:cd': 'Google',
        'f0:79:59': 'Google',
        '64:16:7f': 'Google',         # Google Home / Nest
        # Realtek
        '00:0c:e7': 'Realtek',
        '74:da:38': 'Realtek',
        # Qualcomm (Atheros)
        '94:0c:6d': 'Qualcomm',
        '00:0a:f5': 'Qualcomm',
        '00:13:74': 'Qualcomm',
        '00:18:4d': 'Qualcomm',
        # Mediatek
        '00:23:6c': 'Mediatek',
        '00:0e:8e': 'Mediatek',
        '5c:cf:7f': 'Mediatek',
        # Microsoft
        '00:50:b6': 'Microsoft',
        '00:14:a5': 'Microsoft',
        # Cisco / Linksys
        '00:0c:41': 'Cisco',
        '00:13:10': 'Cisco',
        '00:18:74': 'Cisco',
        '94:6a:4b': 'Cisco',
        '00:1a:70': 'Linksys',
        '00:22:6b': 'Linksys',
        # Ubiquiti
        '00:27:22': 'Ubiquiti',
        '04:18:d6': 'Ubiquiti',
        '78:8a:20': 'Ubiquiti',
        'b4:fb:e4': 'Ubiquiti',
        'f0:9f:c2': 'Ubiquiti',
        # TP-Link
        '00:1d:0f': 'TP-Link',
        '14:cc:20': 'TP-Link',
        '50:2b:73': 'TP-Link',
        '70:4d:7b': 'TP-Link',
        'c0:25:e9': 'TP-Link',
        # Netgear
        '00:1b:2f': 'Netgear',
        '00:24:b2': 'Netgear',
        '20:4e:7f': 'Netgear',
        '9c:d3:6d': 'Netgear',
        # D-Link
        '00:1c:f0': 'D-Link',
        '00:22:b0': 'D-Link',
        '64:66:b3': 'D-Link',
        # Espressif (ESP8266/ESP32 - very common in IoT)
        '24:0a:c4': 'Espressif',
        '30:ae:a4': 'Espressif',
        '60:01:94': 'Espressif',
        '84:0d:8e': 'Espressif',
        'ac:67:b2': 'Espressif',
        'f4:cf:a2': 'Espressif',
        # Microchip (formerly Microchip/Atmel Wi-Fi)
        '00:04:a3': 'Microchip',
        '00:1d:c0': 'Microchip',
        '68:aa:d2': 'Microchip',
        # Texas Instruments (Wi-Fi/Bluetooth)
        '00:07:80': 'Texas Instruments',
        '18:fe:34': 'Texas Instruments',
        '70:ff:5c': 'Texas Instruments',
        # Nordic Semiconductor (nRF52 series - BLE IoT)
        'd0:5c:4a': 'Nordic Semiconductor',
        'f4:8e:38': 'Nordic Semiconductor',
        # Silicon Labs
        '00:14:72': 'Silicon Labs',
        '70:5f:36': 'Silicon Labs',
        # Marvell
        '00:50:43': 'Marvell',
        '00:80:4f': 'Marvell',
        '7c:ac:39': 'Marvell',
        # Zyxel
        '00:19:cb': 'Zyxel',
        '68:09:27': 'Zyxel',
        # Huawei
        '04:6e:e4': 'Huawei',
        '28:7f:cf': 'Huawei',
        '5c:51:4f': 'Huawei',
        'e0:2a:82': 'Huawei',
        # Xiaomi
        '34:ce:00': 'Xiaomi',
        '78:44:fd': 'Xiaomi',
        '9c:9e:8f': 'Xiaomi',
        'e4:62:90': 'Xiaomi',
        # Sony
        '00:13:e2': 'Sony',
        'a8:96:75': 'Sony',
        # LG
        '00:1a:4a': 'LG',
        '60:53:46': 'LG',
        # Philips (Signify - Hue)
        '00:17:88': 'Philips',
        '04:57:a8': 'Philips',
        'a8:68:cf': 'Philips',
        # Belkin (WeMo, etc.)
        '00:22:75': 'Belkin',
        '94:10:3e': 'Belkin',
        # Asus
        '00:1e:4a': 'Asus',
        '1c:b7:2c': 'Asus',
        '60:45:cb': 'Asus',
        # Ruckus Wireless
        '00:11:44': 'Ruckus',
        'f0:62:0d': 'Ruckus',
        # Aruba (HPE)
        '00:0b:86': 'Aruba',
        '70:ba:ef': 'Aruba',
        # Juniper
        '00:1a:8c': 'Juniper',
        '68:05:ca': 'Juniper',
        # Misc / other IoT
        'b8:27:eb': 'Raspberry Pi',
        'dc:a6:32': 'Raspberry Pi',
        'e4:5f:01': 'Raspberry Pi',
        '00:0f:53': 'Roku',
        'a4:3e:51': 'Amazon',        # Amazon (Echo, etc.)
        'ac:63:be': 'Amazon',
        '74:75:48': 'Amazon',
        '00:24:e4': 'Furrion',        # IoT entertainment
        'ec:1a:59': 'Ring',           # Ring (Amazon)
        '94:de:80': 'August',         # August Smart Lock
        '88:65:10': 'Sonos',          # Sonos speakers
        '78:28:ca': 'Sonos',
        '00:0d:4b': 'Wyze',           # Wyze cameras
        '5c:cf:7f': 'Mediatek',
        # Additional common OUI for completeness
        '00:1f:90': 'Freescale',
        '00:22:58': 'STMicroelectronics',
        '00:23:7d': 'Mitsubishi',
        '00:25:9e': 'NXP',
    }
    
    mac_prefix = mac[:8].lower()
    return vendor_map.get(mac_prefix, 'unknown')

def match_cves(client_info):
    matches = []
    if not client_info.get('mac'):
        return matches
    
    vendor = get_mac_vendor(client_info['mac'])
    db = load_cve_db()
    
    search_text = f"{client_info.get('hostname', '')} {client_info.get('user_agent', '')} {client_info.get('chipset', '')}"
    
    for entry in db:
        try:
            if vendor.lower() in entry.get('oui_vendor', '').lower():
                product_regex = entry.get('product_regex', '')
                if product_regex and re.search(product_regex, search_text, re.I):
                    matches.append({
                        'cve_id': entry.get('cve_id', 'unknown'),
                        'cvss_score': entry.get('cvss_score', '0'),
                        'exploit_available': entry.get('exploit_available', 'no'),
                        'test_packet_ref': entry.get('test_packet_ref', 'none')
                    })
        except Exception:
            continue
    
    return matches

if __name__ == "__main__":
    print("CVE Matcher Module v2.0")
