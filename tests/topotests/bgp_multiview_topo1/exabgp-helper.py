#!/usr/bin/env python

from re import match
from sys import argv, stdin, stdout
from datetime import datetime

#
# Handle program arguments.
#

# 1st arg is peer number
peer = int(argv[1])
numRoutes = 10

route_counter = 0
log_fd = open("<log-file>", "w")


#
# Define helper functions.
#


def receive_update():
    "Receive update from ExaBGP. The message received might be an UPDATE or a 'done' reply."
    try:
        line = stdin.readline()
        if match(r"done", line) is not None:
            return
    except KeyboardInterrupt:
        pass
    except IOError:
        # most likely a signal during readline
        pass

    # Log received messages to file.
    timestamp = datetime.now().strftime("%Y%m%d_%H:%M:%S - ")
    log_fd.write(timestamp + line)
    log_fd.flush()

    # Yep, we've got a route, account it.
    if match(r"receive update announced", line):
        global route_counter
        route_counter += 1

    # We've got a shutdown request, lets bail.
    if match(r"shutdown", line):
        exit(0)


def send_route(route):
    "Sends route and expect 'done' message back."
    # Send route.
    stdout.write(route)
    stdout.flush()

    # Expect to receive acknowledgement.
    receive_update()


#
# Program main code.
#

# Announce numRoutes different routes per PE
for i in range(0, numRoutes):
    send_route(
        "announce route 10.{}.{}.0/24 med 100 community {}:1 next-hop 172.16.1.{}\n".format(
            (peer + 100), i, peer, peer
        )
    )

# Announce 1 overlapping route per peer
send_route("announce route 10.0.1.0/24 next-hop 172.16.1.{}\n".format(peer))

# Loop endlessly to allow ExaBGP to continue running
while True:
    receive_update()
