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
if (peer <= 10):
    asnum = 99
else:
    asnum = peer+100

# Announce 2 different route per peer
stdout.write('announce route 10.205.%i.0/24 next-hop 10.0.%i.%i origin igp\n' % (peer, (((peer-1) / 5) + 1), peer+100))
stdout.write('announce flow route destination 30.40.40.0/30 redirect 11:22' + '\n')
stdout.flush()

#Loop endlessly to allow ExaBGP to continue running
while True:
    sleep(1)

