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
log_fd = open('<log-file>', 'w')


#
# Define helper functions.
#

def receive_update():
    "Receive update from ExaBGP. The message received might be an UPDATE or a 'done' reply."
    try:
        line = stdin.readline()
        if match(r'done', line) is not None:
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
    if match(r'receive update announced', line):
        global route_counter
        route_counter += 1

    # We've got a shutdown request, lets bail.
    if match(r'shutdown', line):
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

for i in range(0, numRoutes):
    stdout.write(
        "announce route 10.201.%s.0/24 med 100 community %i:1 next-hop 10.0.%i.%i\n"
        % (i, i, (((peer - 1) / 5) + 1), peer + 100)
    )
    stdout.flush()

# Loop endlessly to allow ExaBGP to continue running
while True:
    receive_update()
