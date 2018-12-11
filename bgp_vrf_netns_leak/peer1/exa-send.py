#!/usr/bin/env python

"""
exa-send.py: Send a few testroutes with ExaBGP
"""

from sys import stdout,argv
from time import sleep

sleep(5)

# 1st arg is peer number
# 2nd arg is number of routes to send
peer = int(argv[1])
numRoutes = int(argv[2])
asnum = 100

# Announce numRoutes equal routes per PE - different neighbor AS
for i in range(0, numRoutes):
    stdout.write('announce route 10.101.%s.0/24 next-hop 1.1.1.2\n' % (i ))
    stdout.flush()

#Loop endlessly to allow ExaBGP to continue running
while True:
    sleep(1)

