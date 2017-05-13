#! /usr/bin/env python

import logging 

logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
    print "Scapy is not installed. Please download scapy from http://pipy.pythonorg/pipy/scapy/"
    sys.exit()

target = '172.16.1.2'

ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), dport = [111, 22, 125], flags = 'F'), timeout = 5)

for sent, received in ans:
    if received.haslayer(TCP) and str(received[TCP].flags) == '20':
        print str(sent[TCP].dport) + 'port is open'
    if received.haslayer(TCP) and str(received[TCP].flags) == '3':
        print str(sent[TCP].dport) + 'port is filtered'

for sent in unans:
    print str(sent[TCP].dport) + 'port is unfiltered/open'
