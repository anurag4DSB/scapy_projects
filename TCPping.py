#! /usr/bin/env python

import logging
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)


from scapy.all import *


ans, unans = sr(IP(dst = '172.16.1.2-20') / TCP (flags = 'S', sport = RandShort(), dport = [22]), timeout = 2, iface = 'enp0s3')

ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive!"))
