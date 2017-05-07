#! /usr/bin/env python

import logging 

logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

from scapy.all import *

#ans, unans = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP (pdst = '172.16.1.0/24'), timeout = 5, iface = 'enp0s3')

#ans.summary(lambda (s,r): r.sprintf("%Ether.src% - %ARP.psrc%"))

arping('172.16.1.*')
