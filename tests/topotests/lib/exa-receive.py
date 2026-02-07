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

# Ensure log directory exists
logdir = args.logdir
if not os.path.exists(logdir):
    try:
        # Create a new log directory
        os.makedirs(logdir)
    except OSError as e:
        print(f"Error in creating log directory: {e}")
        exit(1)

savepath = os.path.join(logdir, f"peer{args.peer}-received.log")

try:
    routesavefile = open(savepath, "w")
except IOError as e:
    print(f"Error in opening log file: {e}")
    exit(1)

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
