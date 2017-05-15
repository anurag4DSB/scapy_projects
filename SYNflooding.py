#! /usr/bin/env python

import logging
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)


from scapy.all import *


packet = IP(dst = '172.16.1.2') / TCP (sport = RandShort(), dport = 111, seq = 32, flags = 'S')

srloop(packet, inter = 0.1, timeout = 2, count = 1000)





