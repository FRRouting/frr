#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by 6WIND S.A.
#

"""
Generate the router configurations of bgp_rr_vpe_updgrp:
rr/frr.conf, vpe<N>/frr.conf, bcgw<N>/exabgp.cfg.

The rr configuration is the one of the vmsr0 routers (BGP_VPE_GRP /
BGP_BCGW_GRP peer groups, packet quanta, queue limits, coalesce time,
update delay), with private AS and addresses.

usage: gen_configs.py [--vpe-nb 20] [--routes 20000] [--vrfs 50]
                      [--update-delay 180]

The vpe<N> directories above --vpe-nb are removed. The test takes the
number of VPEs, routes and the update delay from the generated files.
"""

import argparse
import os
import shutil

CWD = os.path.dirname(os.path.realpath(__file__))

VPE_NB = 20
ROUTES = 20000
VRFS = 50
UPDATE_DELAY = 180

RR_AS = 65000
RR_LOCAL_AS_BCGW = 65001
BCGW_AS = 65100
VPE_AS = 65200
RR_ADDR = "10.0.0.1"
BCGWS = {"bcgw1": "10.0.0.101", "bcgw2": "10.0.0.102"}


def vpe_name(index):
    return "vpe{}".format(index)


def vpe_addr(index):
    return "10.0.0.{}".format(10 + index)


def vpe_as(index):
    return VPE_AS + index


def rr_config():
    """vmsr0 configuration, with private AS and addresses."""
    lines = [
        "debug bgp update-groups",
        "!",
        "interface rr-eth0",
        " ip address {}/24".format(RR_ADDR),
        "exit",
        "!",
        "bgp input-queue-limit 500",
        "bgp output-queue-limit 300",
        "!",
    ]
    for afi in ("IPV4", "VPNV4"):
        for group in ("BCGW", "VPE"):
            for direction in ("IN", "OUT"):
                rmap = "BGP:{}:PEER:{}:{}:RM".format(afi, group, direction)
                lines += ["route-map {} permit 10".format(rmap), "exit"]
    lines += [
        "!",
        "router bgp {}".format(RR_AS),
        " bgp router-id {}".format(RR_ADDR),
        " bgp log-neighbor-changes",
        " no bgp ebgp-requires-policy",
        " bgp disable-ebgp-connected-route-check",
        " bgp deterministic-med",
    ]
    if UPDATE_DELAY:
        lines.append(" update-delay {}".format(UPDATE_DELAY))
    lines += [
        " write-quanta 200",
        " read-quanta 64",
        " coalesce-time 200000",
        " no bgp network import-check",
        " neighbor BGP_BCGW_GRP peer-group",
        " neighbor BGP_BCGW_GRP remote-as {}".format(BCGW_AS),
        " neighbor BGP_BCGW_GRP local-as {} no-prepend".format(RR_LOCAL_AS_BCGW),
        " no neighbor BGP_BCGW_GRP enforce-first-as",
        " neighbor BGP_BCGW_GRP timers 10 30",
        " neighbor BGP_BCGW_GRP sender-as-path-loop-detection",
        " neighbor BGP_VPE_GRP peer-group",
        " no neighbor BGP_VPE_GRP enforce-first-as",
        " neighbor BGP_VPE_GRP advertisement-interval 30",
        " neighbor BGP_VPE_GRP timers 60 180",
    ]
    for addr in BCGWS.values():
        lines.append(" neighbor {} peer-group BGP_BCGW_GRP".format(addr))
    for index in range(1, VPE_NB + 1):
        lines += [
            " neighbor {} remote-as {}".format(vpe_addr(index), vpe_as(index)),
            " neighbor {} peer-group BGP_VPE_GRP".format(vpe_addr(index)),
        ]
    # vmsr0 maximum-prefix values
    maximums = {
        "ipv4 unicast": {"BCGW": 10000, "VPE": 100},
        "ipv4 vpn": {"BCGW": 2200000, "VPE": 15000},
    }
    for afi in ("ipv4 unicast", "ipv4 vpn"):
        rmap = "IPV4" if afi == "ipv4 unicast" else "VPNV4"
        lines += [" !", " address-family {}".format(afi)]
        if afi == "ipv4 vpn":
            lines.append("  bgp route-refresh resync")
        for group in ("BCGW", "VPE"):
            peer_group = "BGP_{}_GRP".format(group)
            rmap_name = "BGP:{}:PEER:{}".format(rmap, group)
            maximum = maximums[afi][group]
            if afi == "ipv4 vpn":
                lines.append("  neighbor {} activate".format(peer_group))
            lines += [
                "  neighbor {} maximum-prefix {}".format(peer_group, maximum),
                "  neighbor {} route-map {}:IN:RM in".format(peer_group, rmap_name),
                "  neighbor {} route-map {}:OUT:RM out".format(peer_group, rmap_name),
            ]
            # vmsr0: on VPE only in ipv4 vpn
            if group == "BCGW" or afi == "ipv4 vpn":
                lines.append(
                    "  neighbor {} attribute-unchanged next-hop med".format(peer_group)
                )
        lines.append(" exit-address-family")
    lines += ["exit", ""]
    return "\n".join(lines)


def vpe_config(index):
    name, addr, asn = vpe_name(index), vpe_addr(index), vpe_as(index)
    return "\n".join(
        [
            "interface {}-eth0".format(name),
            " ip address {}/24".format(addr),
            "exit",
            "!",
            "router bgp {}".format(asn),
            " bgp router-id {}".format(addr),
            " no bgp ebgp-requires-policy",
            " neighbor {} remote-as {}".format(RR_ADDR, RR_AS),
            " neighbor {} timers 60 180".format(RR_ADDR),
            " !",
            " address-family ipv4 vpn",
            "  neighbor {} activate".format(RR_ADDR),
            " exit-address-family",
            "exit",
            "!",
            "router bgp {} vrf CUST".format(asn),
            " bgp router-id {}".format(addr),
            " no bgp ebgp-requires-policy",
            " no bgp network import-check",
            " !",
            " address-family ipv4 unicast",
            "  network 172.16.{}.0/24".format(index),
            "  label vpn export auto",
            "  rd vpn export {}:1".format(asn),
            "  rt vpn export {}:1".format(asn),
            "  export vpn",
            " exit-address-family",
            "exit",
            "",
        ]
    )


def exabgp_config(name, addr):
    return "\n".join(
        [
            "process bcgw {",
            "    run /etc/exabgp/exa-bcgw.py {} {} {} {};".format(
                name, addr, ROUTES, VRFS
            ),
            "    encoder text;",
            "}",
            "",
            "neighbor {} {{".format(RR_ADDR),
            "    router-id {};".format(addr),
            "    local-address {};".format(addr),
            "    local-as {};".format(BCGW_AS),
            "    peer-as {};".format(RR_LOCAL_AS_BCGW),
            "    hold-time 30;",
            "    family {",
            "        ipv4 mpls-vpn;",
            "    }",
            "    api {",
            "        processes [ bcgw ];",
            "    }",
            "}",
            "",
        ]
    )


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    global VPE_NB, ROUTES, VRFS, UPDATE_DELAY  # pylint: disable=global-statement

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--vpe-nb", type=int, default=VPE_NB)
    parser.add_argument("--routes", type=int, default=ROUTES)
    parser.add_argument("--vrfs", type=int, default=VRFS)
    parser.add_argument("--update-delay", type=int, default=UPDATE_DELAY)
    args = parser.parse_args()
    assert 1 <= args.vpe_nb <= 80, "--vpe-nb must be in [1, 80]"
    VPE_NB, ROUTES, VRFS = args.vpe_nb, args.routes, args.vrfs
    UPDATE_DELAY = args.update_delay

    write(os.path.join(CWD, "rr", "frr.conf"), rr_config())
    for index in range(1, VPE_NB + 1):
        write(os.path.join(CWD, vpe_name(index), "frr.conf"), vpe_config(index))
    index = VPE_NB + 1
    while os.path.isdir(os.path.join(CWD, vpe_name(index))):
        shutil.rmtree(os.path.join(CWD, vpe_name(index)))
        index += 1
    for name, addr in BCGWS.items():
        write(os.path.join(CWD, name, "exabgp.cfg"), exabgp_config(name, addr))
        # TopoExaBGP.start() copies the peer directory to /etc/exabgp
        link = os.path.join(CWD, name, "exa-bcgw.py")
        if not os.path.lexists(link):
            os.symlink("../exa-bcgw.py", link)


if __name__ == "__main__":
    main()
