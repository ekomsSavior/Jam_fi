#!/usr/bin/env python3
from scapy.all import *
import re

def dhcp_fingerprint(pkt):
    """Extract DHCP options (OS, hostname)"""
    try:
        if DHCP in pkt and pkt[DHCP].options:
            for opt in pkt[DHCP].options:
                if opt[0] == b'hostname' or opt[0] == 'hostname':
                    if isinstance(opt[1], bytes):
                        return opt[1].decode('utf-8', errors='ignore')
                    else:
                        return str(opt[1])
                if opt[0] == b'vendor_class_id' or opt[0] == 'vendor_class_id':
                    if isinstance(opt[1], bytes):
                        return opt[1].decode('utf-8', errors='ignore')
                    else:
                        return str(opt[1])
    except Exception:
        pass
    return None

def http_ua_capture(pkt):
    """Capture HTTP GET User-Agent from port 80"""
    try:
        if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            match = re.search(r'User-Agent: (.*?)\r\n', payload, re.I)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None

def chipset_from_assoc(pkt):
    """Parse vendor-specific tags from association request"""
    try:
        if pkt.haslayer(Dot11AssoReq):
            el = pkt.getlayer(Dot11Elt)
            while el:
                if el.ID == 221:
                    data = el.info.decode('utf-8', errors='ignore').lower()
                    if 'broadcom' in data:
                        return 'Broadcom'
                    elif 'intel' in data:
                        return 'Intel'
                    elif 'qualcomm' in data:
                        return 'Qualcomm'
                    elif 'mediatek' in data:
                        return 'Mediatek'
                    elif 'realtek' in data:
                        return 'Realtek'
                el = el.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return None

def probe_ssid_history(pkt):
    """Extract SSIDs from probe requests"""
    try:
        if pkt.haslayer(Dot11ProbeReq):
            el = pkt.getlayer(Dot11Elt)
            while el:
                if el.ID == 0:
                    return el.info.decode('utf-8', errors='ignore')
                el = el.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return None

if __name__ == "__main__":
    print("Fingerprinter module loaded. Use from jam_fi.py")
