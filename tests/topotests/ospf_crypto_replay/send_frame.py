#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# send_frame.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#
"""Send one raw Ethernet frame, given as hex, on the given interface.

Used by test_ospf_crypto_replay.py to replay captured frames byte for
byte (link-layer header included) from the peer's namespace.
"""

import sys

from scapy.all import Ether, conf, sendp

conf.verb = 0

if len(sys.argv) != 3:
    sys.stderr.write("usage: send_frame.py <iface> <frame-hex>\n")
    sys.exit(2)

sendp(Ether(bytes.fromhex(sys.argv[2])), iface=sys.argv[1], verbose=False)
