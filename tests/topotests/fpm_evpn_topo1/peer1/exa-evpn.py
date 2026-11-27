#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
exa-evpn.py: advertise the EVPN routes of the VTEP 192.168.1.3 for the VNI
1000 the test asks for:

- its type-3 (IMET) route, with the flood mode (PMSI tunnel type) the test
  writes in /etc/exabgp/flood-mode:
  - "ingress-replication": PMSI tunnel type ingress replication;
  - "no-tunnel": PMSI tunnel type "no tunnel information present";
  - "withdraw": the route is withdrawn.
- its type-1 (EAD) routes for the EVPN-MH ES of r2, per ES and per EVI,
  making it a VTEP of that ES, as the test writes in /etc/exabgp/es-mode:
  - "attach": the routes are advertised;
  - "detach": the routes are withdrawn.

ExaBGP has no syntax for EVPN routes: the routes are encoded here in a
MP_REACH_NLRI (or MP_UNREACH_NLRI) generic attribute, which goes, with
the PMSI tunnel generic attribute for the type-3 route, in the update of
a dummy IPv4 route (one per route type, each update replacing the last
one of its type).
"""

import socket
import struct
import sys
import time

VTEP = "192.168.1.3"
VNI = 1000
ROUTE_TARGET = "target:65000:{}".format(VNI)
# Not in 192.0.2.0/24, where the test adds its marker routes.
DUMMY_ROUTE = "198.51.100.3/32"
MODE_FILE = "/etc/exabgp/flood-mode"
ES_DUMMY_ROUTE = "198.51.100.4/32"
ES_MODE_FILE = "/etc/exabgp/es-mode"
# The ES of r2: type 3 ESI, from its system MAC and local discriminator
ESI = bytes.fromhex("03443839ffff01000001")
# ESI label extended community (RFC 7432): all-active, label 0
ESI_LABEL = "0x0601000000000000"

AFI_L2VPN = 25
SAFI_EVPN = 70
EVPN_EAD_ROUTE = 1
EVPN_IMET_ROUTE = 3
MAX_ETH_TAG = 0xFFFFFFFF
PMSI_NO_TUNNEL = 0
PMSI_INGRESS_REPLICATION = 6

ATTR_MP_REACH_NLRI = 0x0E
ATTR_MP_UNREACH_NLRI = 0x0F
ATTR_PMSI_TUNNEL = 0x16
FLAG_OPTIONAL = 0x80
FLAG_TRANSITIVE = 0x40


def rd(number):
    "Route distinguisher of type 1: the VTEP address and `number`"
    return struct.pack("!H", 1) + socket.inet_aton(VTEP) + struct.pack("!H", number)


def imet_nlri():
    "EVPN type-3 route: RD, Ethernet tag 0 and the VTEP address"
    vtep = socket.inet_aton(VTEP)
    value = rd(VNI) + struct.pack("!IB", 0, 32) + vtep
    return struct.pack("!BB", EVPN_IMET_ROUTE, len(value)) + value


def ead_nlri(eth_tag, label):
    "EVPN type-1 route: RD, ESI, Ethernet tag and MPLS label (the VNI)"
    value = rd(eth_tag & 0xFFFF) + ESI + struct.pack("!I", eth_tag)
    value += struct.pack("!I", label)[1:]
    return struct.pack("!BB", EVPN_EAD_ROUTE, len(value)) + value


def es_nlris():
    "EAD-per-ES and EAD-per-EVI routes: both make the VTEP active in the ES"
    return ead_nlri(MAX_ETH_TAG, 0) + ead_nlri(0, VNI)


def mp_reach_nlri(nlris):
    nexthop = socket.inet_aton(VTEP)
    return (
        struct.pack("!HBB", AFI_L2VPN, SAFI_EVPN, len(nexthop))
        + nexthop
        + b"\x00"
        + nlris
    )


def mp_unreach_nlri(nlris):
    return struct.pack("!HB", AFI_L2VPN, SAFI_EVPN) + nlris


def pmsi_tunnel(tunnel_type):
    # Flags, tunnel type and the VNI in the MPLS label field (RFC 8365).
    value = struct.pack("!BB", 0, tunnel_type) + struct.pack("!I", VNI)[1:]
    if tunnel_type == PMSI_INGRESS_REPLICATION:
        value += socket.inet_aton(VTEP)
    return value


def generic(code, flags, value):
    return "attribute [ 0x{:02x} 0x{:02x} 0x{} ]".format(code, flags, value.hex())


def command(mode):
    announce = "announce route {} next-hop {}".format(DUMMY_ROUTE, VTEP)
    if mode == "withdraw":
        return "{} {}".format(
            announce,
            generic(ATTR_MP_UNREACH_NLRI, FLAG_OPTIONAL, mp_unreach_nlri(imet_nlri())),
        )

    tunnel_type = {
        "ingress-replication": PMSI_INGRESS_REPLICATION,
        "no-tunnel": PMSI_NO_TUNNEL,
    }[mode]
    return "{} extended-community [ {} ] {} {}".format(
        announce,
        ROUTE_TARGET,
        generic(ATTR_MP_REACH_NLRI, FLAG_OPTIONAL, mp_reach_nlri(imet_nlri())),
        generic(
            ATTR_PMSI_TUNNEL, FLAG_OPTIONAL | FLAG_TRANSITIVE, pmsi_tunnel(tunnel_type)
        ),
    )


def es_command(mode):
    announce = "announce route {} next-hop {}".format(ES_DUMMY_ROUTE, VTEP)
    if mode == "detach":
        return "{} {}".format(
            announce,
            generic(ATTR_MP_UNREACH_NLRI, FLAG_OPTIONAL, mp_unreach_nlri(es_nlris())),
        )

    return "{} extended-community [ {} {} ] {}".format(
        announce,
        ROUTE_TARGET,
        ESI_LABEL,
        generic(ATTR_MP_REACH_NLRI, FLAG_OPTIONAL, mp_reach_nlri(es_nlris())),
    )


def read_mode(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except OSError:
        return None


# (state file, command of its state, last state advertised)
states = [[MODE_FILE, command, None], [ES_MODE_FILE, es_command, None]]
while True:
    for state in states:
        mode = read_mode(state[0])
        if mode and mode != state[2]:
            sys.stdout.write(state[1](mode) + "\n")
            sys.stdout.flush()
            state[2] = mode
    time.sleep(0.5)
