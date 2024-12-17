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
if peer <= 10:
    asnum = 99
else:
    asnum = peer + 100

# Announce numRoutes equal routes per PE - different neighbor AS
for i in range(0, numRoutes):
    stdout.write(
        "announce route 10.201.%s.0/24 med 100 next-hop 10.0.%i.%i origin igp\n"
        % (i, (((peer - 1) / 5) + 1), peer + 100)
    )
    stdout.flush()

# Announce numRoutes equal routes per PE - different neighbor AS, but same source AS
for i in range(0, numRoutes):
    stdout.write(
        "announce route 10.202.%s.0/24 med 100 next-hop 10.0.%i.%i origin igp as-path [ %i 200 ]\n"
        % (i, (((peer - 1) / 5) + 1), peer + 100, asnum)
    )
    stdout.flush()

# Announce numRoutes equal routes with different med per PE and different neighbor AS
for i in range(0, numRoutes):
    stdout.write(
        "announce route 10.203.%s.0/24 med %i next-hop 10.0.%i.%i origin igp\n"
        % (i, peer, (((peer - 1) / 5) + 1), peer + 100)
    )
    stdout.flush()

# Announce numRoutes equal routes with different med per PE and different neighbor AS, but same source AS
for i in range(0, numRoutes):
    stdout.write(
        "announce route 10.204.%s.0/24 med %i next-hop 10.0.%i.%i origin igp as-path [ %i 200 ]\n"
        % (i, peer, (((peer - 1) / 5) + 1), peer + 100, asnum)
    )
    stdout.flush()

# Announce 2 different route per peer
stdout.write(
    "announce route 10.205.%i.0/24 next-hop 10.0.%i.%i origin igp\n"
    % (peer, (((peer - 1) / 5) + 1), peer + 100)
)
stdout.write(
    "announce route 10.206.%i.0/24 next-hop 10.0.%i.%i origin igp as-path [ %i 200 ]\n"
    % (peer, (((peer - 1) / 5) + 1), peer + 100, asnum)
)
stdout.flush()

# Loop endlessly to allow ExaBGP to continue running
while True:
    sleep(1)
