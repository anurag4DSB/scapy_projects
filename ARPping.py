#! /usr/bin/env python

import logging

logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)


try:
    from scapy.all import *

except ImportError:
    print "http://pipy.python.org/pipy/scapy"
    sys.exit()

arping('172.16.1.*')
