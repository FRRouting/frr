#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""Forward FIFO commands to the ExaBGP process API."""

import sys

fifo = sys.argv[1]

while True:
    with open(fifo) as pipe:
        for line in pipe:
            sys.stdout.write(line)
            sys.stdout.flush()
