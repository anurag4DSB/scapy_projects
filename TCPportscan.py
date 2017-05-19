#! /usr/bin/env python

import logging

logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
    print "Scapy is not installed on this system."
    print "Please install scapy from http://pipy.python.org/pipy/scapy and try again."

target = '172.16.1.2'

ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), flags = 'S', dport = (1,1024)), timeout = 5, verbose = 0)

for s, r in ans:
    if r.haslayer(TCP) and str(r[TCP].flags) == '18':
        print str(s[TCP].dport) + " is open"
    if r.haslayer(TCP) and str(r[TCP].flags) == '3':
        print str(s[TCP].dport) + " is filtered"
    if r.haslayer(TCP) and str(r[TCP].flags) == '20':
        print str(s[TCP].dport) + " is closed"


for s in unans:
    print str(s[TCP].dport) + " is filtered"

#print "All other ports are closed"

