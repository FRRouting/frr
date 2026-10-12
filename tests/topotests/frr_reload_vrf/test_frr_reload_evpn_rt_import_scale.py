#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_frr_reload_evpn_rt_import_scale.py
#
# Copyright (c) 2026 by Nvidia, Inc.
#
"""EVPN Type-5 import/withdraw through scaled VRF route-target frr-reload.

Topology (two PEs, iBGP EVPN, one L3VNI):

    pe1-eth0 ---[sw1]--- pe2-eth0
      192.168.12.1         192.168.12.2
      vrf tenant           vrf tenant
      L3VNI 20001          L3VNI 20001

pe1 originates Type-5 prefixes with a single manual export RT (the first
value of the field-scale import set). Auto route-targets are disabled on
both PEs so import cannot happen by accident.

pe2 starts with no import RTs. Type-5s are in the EVPN table (received)
but not in the tenant VRF. Applying the scale import list through
``frr-reload.py --reload`` packs RTLIST, maps the matching RT once per
chunk, and installs the prefixes in the VRF. Rolling the list back uses
the batched ``vtysh -f`` delete (packed ``no route-target import ...``
plus batched ``no route-map``) and withdraws those VRF copies.

Dummy route-map sequences on pe2 exist only so the rollback delta also
covers the tools batched route-map path from the same reload.
"""

from functools import partial
import ipaddress
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.common_config import required_linux_kernel_version, step
from lib.evpn import (
    EVPN_SCALE_RT_ASNS,
    EVPN_SCALE_RT_PER_ASN,
    evpn_count_running_rt_lines,
    evpn_plumb_l3vni,
    evpn_reload_has_packed_rtlist,
    evpn_rt_config_lines,
    evpn_routemap_stanza_lines,
    evpn_scale_rt_list,
    evpn_verify_bgp_vrf_prefixes,
    evpn_verify_evpn_peer_established,
    evpn_verify_type5_prefixes,
    evpn_verify_vni_rt_member,
    evpn_verify_vrf_routes,
)
from lib.topogen import Topogen
from lib.topotest import iproute2_is_vrf_capable

import frr_reload_lib as f_reload

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd, pytest.mark.evpn]

# Daemon names for load_frr_config (strings, not RD_* ints — bare ints are
# unpacked as (daemon, param) tuples and raise TypeError).
NEEDED_DAEMONS = ["zebra", "mgmtd", "staticd", "bgpd"]

AS_NUM = 65000
VRF = "tenant"
VRF_TABLE = 10
L3VNI = 20001
PE1_IP = "192.168.12.1"
PE2_IP = "192.168.12.2"
PREFIX_NET = "198.51.100.0"
PREFIX_COUNT = int(os.environ.get("FRR_RELOAD_RT_PREFIXES", "8"))
RT_LIMIT = os.environ.get("FRR_RELOAD_RT_LIMIT")
RT_LIMIT = int(RT_LIMIT) if RT_LIMIT else None
RELOAD_TIMEOUT = float(os.environ.get("FRR_RELOAD_RT_TIMEOUT", "120"))
ROUTEMAP = "RT_SCALE_BATCH"
ROUTEMAP_SEQS = (10, 20, 30)

IMPORT_RTS = evpn_scale_rt_list(limit=RT_LIMIT)
MATCH_RT = IMPORT_RTS[0]
PREFIXES = [
    "{}/32".format(ipaddress.IPv4Address(int(ipaddress.IPv4Address(PREFIX_NET)) + i))
    for i in range(PREFIX_COUNT)
]


def test_scale_rt_helpers():
    """Daemon-less checks for the shared RT-list helpers this suite uses."""
    rts = evpn_scale_rt_list()
    assert rts[0] == "60005:102011"
    assert len(rts) == len(EVPN_SCALE_RT_ASNS) * EVPN_SCALE_RT_PER_ASN
    assert evpn_rt_config_lines("import", rts[:2], indent="  ") == [
        "  route-target import 60005:102011",
        "  route-target import 60005:102012",
    ]
    packed = "route-target import {} {}".format(rts[0], rts[1])
    assert evpn_reload_has_packed_rtlist(packed, "import", rts, delete=False)
    assert evpn_reload_has_packed_rtlist("no " + packed, "import", rts, delete=True)
    stanzas = evpn_routemap_stanza_lines(ROUTEMAP, (10, 20))
    assert "route-map {} permit 10".format(ROUTEMAP) in stanzas
    assert "route-map {} permit 20".format(ROUTEMAP) in stanzas


def _wait(func, count=60, wait=1):
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, result


def _pe_common(name, local, peer, vrf_body=None):
    lines = [
        "frr defaults datacenter",
        "hostname {}".format(name),
        "!",
        "vrf {}".format(VRF),
    ]
    if vrf_body:
        lines.extend(vrf_body)
    lines.extend(
        [
            " vni {}".format(L3VNI),
            "exit-vrf",
            "!",
            "interface {}-eth0".format(name),
            " ip address {}/24".format(local),
            "exit",
            "!",
            "router bgp {}".format(AS_NUM),
            " bgp router-id {}".format(local),
            " no bgp default ipv4-unicast",
            " neighbor {} remote-as {}".format(peer, AS_NUM),
            " neighbor {} capability extended-nexthop".format(peer),
            " address-family l2vpn evpn",
            "  neighbor {} activate".format(peer),
            "  advertise-all-vni",
            " exit-address-family",
            "exit",
            "!",
        ]
    )
    return lines


def pe1_config():
    """Exporter: Type-5s + one manual export RT + advertise route-map."""
    vrf_body = [" ip route {} Null0".format(prefix) for prefix in PREFIXES]
    lines = _pe_common("pe1", PE1_IP, PE2_IP, vrf_body=vrf_body)
    lines.extend(
        [
            "router bgp {} vrf {}".format(AS_NUM, VRF),
            " bgp router-id {}".format(PE1_IP),
            " address-family ipv4 unicast",
            "  redistribute static",
            " exit-address-family",
            " address-family l2vpn evpn",
            "  auto-route-target import add-never",
            "  auto-route-target export add-never",
            "  route-target export {}".format(MATCH_RT),
            "  advertise ipv4 unicast route-map EVPN_T5_EXPORT",
            " exit-address-family",
            "exit",
            "!",
            "ip prefix-list EVPN_T5 seq 5 permit 198.51.100.0/24 le 32",
            "route-map EVPN_T5_EXPORT permit 10",
            " match ip address prefix-list EVPN_T5",
            "exit",
            "!",
        ]
    )
    return lines


def pe2_config(include_import_rts):
    """Importer. Scale import RTs + dummy route-maps are the reload delta."""
    lines = _pe_common("pe2", PE2_IP, PE1_IP)
    lines.extend(
        [
            "router bgp {} vrf {}".format(AS_NUM, VRF),
            " bgp router-id {}".format(PE2_IP),
            " address-family ipv4 unicast",
            " exit-address-family",
            " address-family l2vpn evpn",
            "  auto-route-target import add-never",
            "  auto-route-target export add-never",
        ]
    )
    if include_import_rts:
        # One RT per line in the target file. frr-reload packs them into
        # RTLIST commands so bgpd rebuilds the import map once per chunk.
        lines.extend(evpn_rt_config_lines("import", IMPORT_RTS, indent="  "))
    lines.extend(
        [
            " exit-address-family",
            "exit",
            "!",
        ]
    )
    if include_import_rts:
        lines.extend(evpn_routemap_stanza_lines(ROUTEMAP, ROUTEMAP_SEQS))
    return lines


@pytest.fixture(scope="module")
def tgen(request):
    def build(tg):
        tg.add_router("pe1")
        tg.add_router("pe2")
        switch = tg.add_switch("sw1")
        switch.add_link(tg.gears["pe1"])
        switch.add_link(tg.gears["pe2"])

    tg = Topogen(build, request.module.__name__)
    tg.start_topology()

    if not iproute2_is_vrf_capable():
        pytest.skip("iproute2 is not VRF capable")
    if required_linux_kernel_version("4.19") is not True:
        pytest.skip("Kernel >= 4.19 required for EVPN L3VNI")

    for name, ip in (("pe1", PE1_IP), ("pe2", PE2_IP)):
        router = tg.gears[name]
        router.cmd_raises("ip addr add {}/24 dev {}-eth0".format(ip, name))
        router.cmd_raises("ip link set dev {}-eth0 up".format(name))
        evpn_plumb_l3vni(router, VRF, VRF_TABLE, L3VNI, ip)

    for name, lines in (("pe1", pe1_config()), ("pe2", pe2_config(False))):
        path = os.path.join(tg.logdir, name, "startup.conf")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        f_reload.write_conf(path, lines)
        tg.gears[name].load_frr_config(path, daemons=NEEDED_DAEMONS)

    tg.start_router()
    yield tg
    tg.stop_topology()


def test_evpn_scale_rt_import_then_withdraw(tgen):
    """Apply scale import RTs, see VRF imports, then roll back and withdraw."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]
    pe2 = tgen.gears["pe2"]
    target = os.path.join(tgen.logdir, "pe2", "reload-target.conf")

    assert len(IMPORT_RTS) >= 2, "need at least two RTs for RTLIST packing"
    assert MATCH_RT in IMPORT_RTS
    if RT_LIMIT is None:
        assert len(IMPORT_RTS) == len(EVPN_SCALE_RT_ASNS) * EVPN_SCALE_RT_PER_ASN

    step("Wait for iBGP EVPN and pe1 Type-5 origination")
    _wait(partial(evpn_verify_evpn_peer_established, pe1, PE2_IP), count=60, wait=1)
    _wait(partial(evpn_verify_evpn_peer_established, pe2, PE1_IP), count=60, wait=1)
    _wait(partial(evpn_verify_type5_prefixes, pe1, PREFIXES, True))
    _wait(
        partial(evpn_verify_vni_rt_member, pe1, "exportRts", MATCH_RT, True, vni=L3VNI)
    )

    step("pe2 has Type-5s in EVPN but not in the tenant VRF (no import RT)")
    _wait(partial(evpn_verify_type5_prefixes, pe2, PREFIXES, True))
    _wait(partial(evpn_verify_bgp_vrf_prefixes, pe2, VRF, PREFIXES, False))
    _wait(partial(evpn_verify_vrf_routes, pe2, VRF, PREFIXES, False))
    _wait(
        partial(evpn_verify_vni_rt_member, pe2, "importRts", MATCH_RT, False, vni=L3VNI)
    )

    step("frr-reload: add field-scale import RTs (packed RTLIST adds)")
    add_result = f_reload.apply_and_verify(pe2, target, pe2_config(True))
    assert evpn_reload_has_packed_rtlist(
        add_result.output, "import", IMPORT_RTS, delete=False
    ), "expected packed route-target import RTLIST in frr-reload add output:\n{}".format(
        add_result.output
    )
    running = f_reload.running_config(pe2)
    assert evpn_count_running_rt_lines(running, "import") == len(IMPORT_RTS)
    f_reload.assert_lines_present(
        pe2, ["route-map {} permit {}".format(ROUTEMAP, seq) for seq in ROUTEMAP_SEQS]
    )

    step("Matching import RT installs Type-5s into pe2 VRF BGP and RIB")
    _wait(
        partial(evpn_verify_vni_rt_member, pe2, "importRts", MATCH_RT, True, vni=L3VNI)
    )
    _wait(partial(evpn_verify_bgp_vrf_prefixes, pe2, VRF, PREFIXES, True))
    _wait(partial(evpn_verify_vrf_routes, pe2, VRF, PREFIXES, True))
    # Received EVPN copies stay; import mapped them, it did not duplicate them.
    _wait(partial(evpn_verify_type5_prefixes, pe2, PREFIXES, True))

    step("frr-reload: remove import RTs + dummy route-maps (batched RTLIST delete)")
    del_result = f_reload.apply_and_verify(
        pe2,
        target,
        pe2_config(False),
        expect_vrf_batch=True,
        max_seconds=RELOAD_TIMEOUT,
    )
    assert evpn_reload_has_packed_rtlist(
        del_result.output, "import", IMPORT_RTS, delete=True
    ), "expected packed no route-target import RTLIST in batch delete:\n{}".format(
        del_result.output
    )
    assert (
        "no route-map {}".format(ROUTEMAP) in del_result.output
    ), "expected batched no route-map {} in reload output:\n{}".format(
        ROUTEMAP, del_result.output
    )
    assert "vtysh (exec file) exited with status 2" not in del_result.output
    assert evpn_count_running_rt_lines(f_reload.running_config(pe2), "import") == 0
    f_reload.assert_lines_absent(
        pe2, ["route-map {} permit {}".format(ROUTEMAP, seq) for seq in ROUTEMAP_SEQS]
    )

    step("Import RT gone: VRF copies withdrawn, EVPN Type-5s still from pe1")
    _wait(
        partial(evpn_verify_vni_rt_member, pe2, "importRts", MATCH_RT, False, vni=L3VNI)
    )
    _wait(partial(evpn_verify_bgp_vrf_prefixes, pe2, VRF, PREFIXES, False))
    _wait(partial(evpn_verify_vrf_routes, pe2, VRF, PREFIXES, False))
    _wait(partial(evpn_verify_type5_prefixes, pe2, PREFIXES, True))
    _wait(partial(evpn_verify_type5_prefixes, pe1, PREFIXES, True))


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", "-v"] + sys.argv[1:]))
