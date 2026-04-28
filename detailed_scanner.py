#!/usr/bin/env python3
from scapy.all import *
import time
import re

class DetailedScanner:
    def __init__(self, interface):
        self.interface = interface
        self.clients = {}
    
    def dhcp_fingerprint(self, pkt):
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
    
    def http_ua_capture(self, pkt):
        try:
            if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                match = re.search(r'User-Agent: (.*?)\r\n', payload, re.I)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None
    
    def chipset_from_assoc(self, pkt):
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
    
    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11):
            mac = None
            if pkt.addr2:
                mac = pkt.addr2
            
            if mac and mac not in self.clients:
                self.clients[mac] = {'mac': mac, 'hostname': 'unknown', 'user_agent': 'unknown', 'chipset': 'unknown', 'probe_ssids': []}
            
            if mac:
                chipset = self.chipset_from_assoc(pkt)
                if chipset:
                    self.clients[mac]['chipset'] = chipset
        
        dhcp_info = self.dhcp_fingerprint(pkt)
        if dhcp_info and hasattr(pkt, 'addr2') and pkt.addr2 in self.clients:
            if 'hostname' not in self.clients[pkt.addr2] or self.clients[pkt.addr2]['hostname'] == 'unknown':
                self.clients[pkt.addr2]['hostname'] = dhcp_info
        
        ua = self.http_ua_capture(pkt)
        if ua and hasattr(pkt, 'addr2') and pkt.addr2 in self.clients:
            self.clients[pkt.addr2]['user_agent'] = ua
    
    def scan(self, duration=30):
        print(f"[*] Scanning for {duration} seconds...")
        self.clients = {}
        sniff(iface=self.interface, prn=self.packet_handler, timeout=duration, store=0)
        return list(self.clients.values())

if __name__ == "__main__":
    print("Detailed Scanner Module v2.0")
