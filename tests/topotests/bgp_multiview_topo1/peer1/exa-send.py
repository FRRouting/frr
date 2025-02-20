#!/usr/bin/env python3

"""
exa-send.py: Send a few testroutes with ExaBGP
"""

from sys import stdout, argv
from time import sleep

sleep(5)

# 1st arg is peer number
# 2nd arg is number of routes to send
peer = int(argv[1])
numRoutes = int(argv[2])

# Announce numRoutes different routes per PE
for i in range(0, numRoutes):
    stdout.write(
        "announce route 10.%s.%s.0/24 med 100 community %i:1 next-hop 172.16.1.%i\n"
        % ((peer + 100), i, peer, peer)
    )
    stdout.flush()

# Announce 1 overlapping route per peer
stdout.write("announce route 10.0.1.0/24 med %i next-hop 172.16.1.%i\n" % (peer, peer))
stdout.flush()

# Loop endlessly to allow ExaBGP to continue running
while True:
    sleep(1)
