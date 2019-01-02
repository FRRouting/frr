#!/usr/bin/env python

"""
exa-receive.py: Save received routes form ExaBGP into file
"""

from sys import stdin,argv
from datetime import datetime

# 1st arg is peer number
peer = int(argv[1])

# When the parent dies we are seeing continual newlines, so we only access so many before stopping
counter = 0

routesavefile = open('/tmp/peer%s-received.log' % peer, 'w')

while True:
    try:
        line = stdin.readline()
        timestamp = datetime.now().strftime('%Y%m%d_%H:%M:%S - ')
        routesavefile.write(timestamp + line)
        routesavefile.flush()

        if line == "":
            counter += 1
            if counter > 100:
                break
            continue

        counter = 0
    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass

routesavefile.close()
