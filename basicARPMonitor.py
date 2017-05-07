#! /usr/bin/env python

import logging
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)


from scapy.all import *

def discover(packet):
    if ARP in packet and packet[ARP].op == 1:
        print packet[ARP].psrc + "reqesting HW address of" + packet[ARP].pdst
    if ARP in packet and packet[ARP].op == 2:
        print packet[ARP].psrc + "replying that my HW addr is" + packet[ARP].hwsrc

sniff(prn = discover, filter = 'arp', store = 0)
