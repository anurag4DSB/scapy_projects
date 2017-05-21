#! /usr/bin/env python

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.intractive").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
    print "Scapy is not installed. Please install scapy by going to: "
    print "http://pipy.python.org/pipy/scapy"
    sys.exit()

target = '172.16.1.2'

ans, unans = sr(IP(dst = target, ttl = (1,20)) / TCP(dport = 53, flags = "S"), timeout = 66)
ans.summary(lambda(s,r) : r.sprintf("%IP.src% --> ICMP:%ICMP.type% --> TCP:%TCP.flags%"))
