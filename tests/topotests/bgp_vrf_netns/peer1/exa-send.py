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
asnum = 99

# Announce numRoutes equal routes per PE - different neighbor AS
for i in range(0, numRoutes):
    stdout.write(
        "announce route 10.201.%s.0/24 med 100 community %i:1 next-hop 10.0.%i.%i\n"
        % (i, i, (((peer - 1) / 5) + 1), peer + 100)
    )
    stdout.flush()

# Loop endlessly to allow ExaBGP to continue running
while True:
    sleep(1)
