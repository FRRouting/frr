#!/usr/bin/env python3

"""
exa-receive.py: Save received routes form ExaBGP into file
"""

import argparse
import os
from sys import stdin
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument(
    "--no-timestamp", dest="timestamp", action="store_false", help="Disable timestamps"
)
parser.add_argument(
    "--logdir", default="/tmp/gearlogdir", help="The directory to store the peer log in"
)
parser.add_argument("peer", type=int, help="The peer number")
args = parser.parse_args()

savepath = os.path.join(args.logdir, "peer{}-received.log".format(args.peer))
routesavefile = open(savepath, "w")

while True:
    try:
        line = stdin.readline()
        if not line:
            break

        if not args.timestamp:
            routesavefile.write(line)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H:%M:%S - ")
            routesavefile.write(timestamp + line)
        routesavefile.flush()
    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass

routesavefile.close()
