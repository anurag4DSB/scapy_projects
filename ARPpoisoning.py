#! /usr/bin/env python

import logging
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)


from scapy.all import *


target = 'ff:ff:ff:ff:ff:ff'

send(ARP(hwsrc = get_if_hwaddr('enp0s3'), psrc = '172.16.1.233', hwdst = target, pdst = '172.16.1.2'), iface = 'enp0s3')



