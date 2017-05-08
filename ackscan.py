#! /usr/bin/env python

import logging

logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scap.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
   print "Scapy is not installed on this system"
   print "Please download scapy from http://pipy.python.org/pipy/scapy"
   sys.exit()

target = '172.16.1.2'

ans, unans = sr(IP(dst = target, ttl= (1,3)) / TCP(sport = RandShort(), dport = [111, 523, 22], flags = 'A'), timeout = 5)

for sent, received in ans:
    if received.haslayer(TCP) and str(received[TCP].flags) == '4':
        print str(sent[TCP].dport) + " is open"
    elif received.haslayer(TCP) and str(received[TCP].flasgs) == '3':
        print str(sent[TCP].dport) + " is filtered"

for sent in unans:
    print str(sent[TCP].dport) + " is filtered"

