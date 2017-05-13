#! /usr/bin/env python

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

try: 
    from scapy.all import *

except ImportError:
    print "Scapy not installed. Please install scapy from http://pipy.python.org/pipy/scapy"
    sys.exit()

target1 = 'www.google.com'
target2 = 'www.facebook.com'
ans, unans = traceroute([target1, target2], minttl = 1, maxttl = 3, dport = [21, 22, 80], retry = 3, timeout = 2)
ans.show()
