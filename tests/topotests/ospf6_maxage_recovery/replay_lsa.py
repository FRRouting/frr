#!/usr/bin/env python
# SPDX-License-Identifier: ISC
"""Replay one captured OSPFv3 LSA from an established neighbor."""

import sys

from scapy.all import Ether, IPv6, get_if_hwaddr, sendp, wrpcap
from scapy.contrib.ospf import OSPFv3_Hdr, OSPFv3_LSA_Hdr, OSPFv3_LSUpd

iface, address, router_id, area_id, lsa, capture = sys.argv[1:]
packet = (
    Ether(src=get_if_hwaddr(iface), dst="33:33:00:00:00:05")
    / IPv6(src=address, dst="ff02::5", hlim=1)
    / OSPFv3_Hdr(src=router_id, area=area_id)
    / OSPFv3_LSUpd(lsalist=[OSPFv3_LSA_Hdr(bytes.fromhex(lsa))])
)
wrpcap(capture, packet)
sendp(packet, iface=iface, verbose=False)
