#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""Announce every treat-as-withdraw case from the eBGP-OAD peer."""

import sys
from time import sleep

sys.path.append("/etc/exabgp")

from bgp_rfc7606 import EBGP_OAD, sentinel_announce
from cases import CASES

SORT = EBGP_OAD

sleep(5)

for case in CASES:
    if not case.applies_to(SORT):
        continue
    sys.stdout.write(case.announce(SORT))
    sys.stdout.flush()

# Announced last: its arrival proves everything above has been processed.
sys.stdout.write(sentinel_announce(SORT))
sys.stdout.flush()

while True:
    sleep(1)
