#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""Send directly to a uA SID and observe its rewritten packet on the same LAN."""

import sys

from scapy.all import Ether, IPv6, Raw, conf, get_if_hwaddr


def main():
    interface, router_mac, destination, expected = sys.argv[1:]
    peer_mac = get_if_hwaddr(interface)
    source = "2001:db8::2"
    payload = b"isis-ua-next-csid:" + destination.encode()
    packet = (
        Ether(src=peer_mac, dst=router_mac)
        / IPv6(src=source, dst=destination, hlim=64, nh=59)
        / Raw(payload)
    )

    # Open capture before sending; no readiness sleeps or background processes.
    with conf.L2socket(iface=interface) as sock:
        sock.send(packet)
        received = sock.sniff(
            timeout=5,
            count=1,
            lfilter=lambda p: Ether in p
            and p[Ether].src == router_mac
            and IPv6 in p
            and p[IPv6].src == source,
        )

    assert received, f"No uA packet returned for {destination}"
    forwarded = received[0]
    assert forwarded[Ether].dst == peer_mac, forwarded.show(dump=True)
    assert forwarded[IPv6].dst == expected, forwarded.show(dump=True)
    assert forwarded[IPv6].hlim == 63, forwarded.show(dump=True)
    assert bytes(forwarded[IPv6].payload) == payload, forwarded.show(dump=True)


if __name__ == "__main__":
    main()
