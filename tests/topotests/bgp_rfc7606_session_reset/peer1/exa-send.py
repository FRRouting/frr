#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Announce exactly one session-reset case, chosen by /etc/exabgp/case_index.

Every case here kills the session it is announced on, so they cannot share an
ExaBGP lifetime the way the treat-as-withdraw and attribute-discard cases do.
The pytest side writes the index into the peer directory before each
TopoExaBGP.start(), which copies it to /etc/exabgp along with everything else.
"""

import sys
from time import sleep

sys.path.append("/etc/exabgp")

from bgp_rfc7606 import EBGP
from cases import CASES

SORT = EBGP

with open("/etc/exabgp/case_index") as fd:
    INDEX = int(fd.read().strip())

CASE = CASES[INDEX]

sleep(5)

sys.stdout.write(CASE.announce(SORT))
sys.stdout.flush()

while True:
    sleep(1)
