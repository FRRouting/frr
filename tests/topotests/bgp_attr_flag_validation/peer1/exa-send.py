#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# exa-send.py: Dynamic route announcement for BGP attribute flag validation test
#
# Phase 1: announce clean routes (no custom attrs) -> should be accepted
# Phase 2: withdraw clean routes, announce with WRONG flag bits -> treat-as-withdraw

from sys import stdout
from time import sleep

# Wait for BGP session to establish
sleep(5)

# Phase 1: Announce clean routes with only mandatory attributes (origin, as-path).
# These should be accepted and appear in the RIB.
stdout.write("announce route 192.168.1.1/32 next-hop 10.0.0.2 origin igp as-path [ 65001 ]\n")
stdout.flush()
stdout.write("announce route 192.168.2.1/32 next-hop 10.0.0.2 origin igp as-path [ 65001 ]\n")
stdout.flush()

# Wait for routes to be processed and verified by the test
sleep(8)

# Phase 2: Withdraw the clean routes
stdout.write("withdraw route 192.168.1.1/32 next-hop 10.0.0.2 origin igp as-path [ 65001 ]\n")
stdout.write("withdraw route 192.168.2.1/32 next-hop 10.0.0.2 origin igp as-path [ 65001 ]\n")
stdout.flush()

sleep(2)

# Re-announce with WRONG flag bits on optional attributes.
# The flag validation (bgp_attr_flag_invalid) runs before value parsing,
# so the attribute value encoding doesn't matter — wrong flags are caught first.

# Route 1: ENCAP (type 23) with WRONG flags 0x40 (Transitive only).
# Correct is 0xC0 (Optional + Transitive). Valid value: type=7(VXLAN), sub-TLV len=0
stdout.write("announce route 192.168.1.1/32 next-hop 10.0.0.2 origin igp as-path [ 65001 ] attribute [0x17 0x40 0x00070000]\n")
stdout.flush()

# Route 2: LINK_STATE (type 29) with WRONG flags 0x40 (Transitive bit set).
# Correct is 0x80 (Optional only). Valid value: TLV type=1024(node-flags), len=1, val=0x00
stdout.write("announce route 192.168.2.1/32 next-hop 10.0.0.2 origin igp as-path [ 65001 ] attribute [0x1d 0x40 0x0400000100]\n")
stdout.flush()

# Keep ExaBGP running
while True:
    sleep(1)
