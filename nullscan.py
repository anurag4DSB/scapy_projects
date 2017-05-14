#! /usr/bin/env python

import logging

logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
    print "http://pipy.python.org/pipy/scapy"
    sys.exit()

target = '172.16.1.2'

ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = [22, 111, 125], flags = 0, seq = 0), timeout = 5)

for sent, rec in ans:
    if rec.haslayer(TCP) and str(rec[TCP].flags) == '20':
        print str(sent[TCP].dport) + " is closed"
    if rec.haslayer(TCP) and str(rec[TCP].flags) == '3':
        print str(sent[TCP].dport) + " is filtered"

for sent in unans:
    print str(sent[TCP].dport) + "is open/filtered"
