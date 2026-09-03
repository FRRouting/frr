#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""IS-IS uA: one advertised SID, two local representations, shared lifetime.

r1 (MAIN, usid-f3216/usid-f4816) --- LAN --- r2 (LSDB observer)

The LAN's L1 and L2 adjacencies share one nexthop/context. Packet probes
exercise only the two uA representations, not generic IS-IS/SRv6 forwarding.
"""

from collections import namedtuple
import functools
import ipaddress
import os
import shlex
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, ".."))

from lib import topotest
from lib.common_config import required_linux_kernel_version
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.isisd]

SidFormat = namedtuple("SidFormat", "name block node_prefix arg_len")
F3216 = SidFormat(
    "usid-f3216",
    ipaddress.IPv6Network("fcbb:bbbb::/32"),
    ipaddress.IPv6Network("fcbb:bbbb:1::/48"),
    64,
)
F4816 = SidFormat(
    "usid-f4816",
    ipaddress.IPv6Network("fcbb:bbbb:cccc::/48"),
    ipaddress.IPv6Network("fcbb:bbbb:cccc:1::/64"),
    48,
)


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in ("r1", "r2"):
        switch.add_link(tgen.add_router(name))


def setup_module(mod):
    if required_linux_kernel_version("6.17") is not True:
        pytest.skip("uA kernel installation requires Linux >= 6.17")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for name, router in tgen.routers().items():
        # Use only the explicit link-local addresses from zebra.conf.
        router.cmd_raises(f"sysctl -w net.ipv6.conf.{name}-eth0.addr_gen_mode=1")
        router.cmd_raises(f"ip -6 address flush dev {name}-eth0 scope link")
        router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, name, "zebra.conf"))
        router.load_config(TopoRouter.RD_ISIS, os.path.join(CWD, name, "isisd.conf"))
    tgen.gears["r1"].cmd_raises("ip link add sr0 type dummy")
    tgen.gears["r1"].cmd_raises("ip link set sr0 up")
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    if tgen:
        tgen.stop_topology()


@pytest.fixture(autouse=True)
def check_router_status():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def wait_for(check, stable=1):
    successes = 0

    def check_stable():
        nonlocal successes
        result = check()
        successes = successes + 1 if result is None else 0
        if result is None and successes < stable:
            return "waiting for consecutive successful observations"
        return result

    _, result = topotest.run_and_expect(check_stable, None, count=80, wait=0.5)
    assert result is None, result


def check_adjacencies(levels):
    # Neighbor JSON keeps only the last LAN adjacency for each interface.
    output = (
        get_topogen()
        .gears["r1"]
        .vtysh_cmd("show isis interface r1-eth0 json", isjson=True)
    )
    interfaces = [
        circuit.get("interface", {})
        for area in output.get("areas", [])
        for circuit in area.get("circuits", [])
        if circuit.get("interface", {}).get("name") == "r1-eth0"
    ]
    if len(interfaces) != 1:
        return f"missing IS-IS interface: {output}"
    actual = {
        level["level"]: level.get("active-neighbors")
        for level in interfaces[0].get("levels", [])
    }
    expected = {"L1": int(1 in levels), "L2": int(2 in levels)}
    if actual != expected:
        return f"active adjacencies {actual}, expected {expected}"
    return None


def read_endx_sids():
    output = (
        get_topogen()
        .gears["r1"]
        .vtysh_cmd("show segment-routing srv6 sid json", isjson=True)
    )
    return {
        sid: data
        for sid, data in output.items()
        if data.get("behavior") in ("uA", "End.X")
    }


def sid_prefix(sid, sid_format=F3216):
    node_len = 16 if ipaddress.IPv6Address(sid) in sid_format.node_prefix else 0
    length = sid_format.block.prefixlen + node_len + 16
    return f"{sid}/{length}"


def endx_tlvs(value):
    """Collect only End.X advertisements, ignoring unrelated LSP content."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ("srv6EndXSID", "srv6LanEndxSID"):
                yield from child
            else:
                yield from endx_tlvs(child)
    elif isinstance(value, list):
        for child in value:
            yield from endx_tlvs(child)


def check_pair(levels=(1, 2), expected_sids=None, sid_format=F3216):
    r1, r2 = (get_topogen().gears[name] for name in ("r1", "r2"))
    entries = read_endx_sids()
    combined_sids = [
        sid for sid in entries if ipaddress.IPv6Address(sid) in sid_format.node_prefix
    ]
    if len(combined_sids) != 1:
        return f"expected one combined SID, got {entries}"
    combined = combined_sids[0]
    block_len = sid_format.block.prefixlen
    function = (int(ipaddress.IPv6Address(combined)) >> (128 - block_len - 32)) & 0xFFFF
    localonly = str(
        ipaddress.IPv6Address(
            int(sid_format.block.network_address) | (function << (128 - block_len - 16))
        )
    )
    if set(entries) != {combined, localonly}:
        return f"expected exactly the combined/local-only pair, got {entries}"
    if expected_sids is not None and set(entries) != expected_sids:
        return f"pair replaced while still owned: {entries}"

    context = entries[combined].get("context", {})
    expected = {
        sid: {
            "sid": sid,
            "behavior": "uA",
            "locator": "MAIN",
            "allocationMode": "dynamic",
            "context": context,
            "clients": [{"protocol": "isis", "instance": 0}],
        }
        for sid in (combined, localonly)
    }
    diff = topotest.json_cmp(entries, expected)
    if diff:
        return diff
    diff = topotest.json_cmp(
        context, {"interfaceName": "r1-eth0", "nexthopIpv6Address": "fe80::2"}
    )
    if diff:
        return diff
    if (
        not isinstance(context.get("interfaceIndex"), int)
        or context["interfaceIndex"] <= 0
    ):
        return f"missing adjacency ifindex: {context}"

    routes = r1.vtysh_cmd("show ipv6 route isis json", isjson=True)
    ua_routes = {
        prefix: paths
        for prefix, paths in routes.items()
        if any(
            nh.get("seg6local", {}).get("action") == "uA"
            for path in paths
            for nh in path.get("nexthops", [])
        )
    }
    expected = {}
    for sid, node_len in ((combined, 16), (localonly, 0)):
        prefix = sid_prefix(sid, sid_format)
        expected[prefix] = [
            {
                "protocol": "isis",
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "seg6local": {
                            "action": "uA",
                            "sidStructure": {
                                "blockLen": block_len,
                                "nodeLen": node_len,
                                "funcLen": 16,
                                "argLen": 0,
                            },
                        },
                        "seg6localContext": {
                            "nh6": "fe80::2",
                            "interfaceName": "r1-eth0",
                            "interfaceIndex": context.get("interfaceIndex"),
                        },
                    }
                ],
            }
        ]
    if set(ua_routes) != set(expected):
        return f"unexpected uA RIB prefixes: {ua_routes}"
    for prefix, paths in ua_routes.items():
        if len(paths) != 1 or len(paths[0].get("nexthops", [])) != 1:
            return f"duplicate uA RIB entries: {prefix}: {paths}"
    diff = topotest.json_cmp(ua_routes, expected)
    if diff:
        return diff

    database = r2.vtysh_cmd(
        "show isis database detail 0000.0000.0001 json", isjson=True
    )
    peer_levels = [
        level
        for area in database.get("areas", [])
        for level in area.get("levels", [])
        if level.get("id") in levels
    ]
    if {level.get("id") for level in peer_levels} != set(levels):
        return f"missing peer LSPs: {database}"
    for level in peer_levels:
        advertisements = list(endx_tlvs(level))
        if len(advertisements) != 1:
            return (
                f"level {level['id']}: expected one combined End.X, "
                f"got {advertisements}"
            )
        diff = topotest.json_cmp(
            advertisements[0],
            {
                "sid": combined,
                "behavior": "uA",
                "srv6SidStructure": {
                    "locBlockLen": block_len,
                    "locNodeLen": 16,
                    "funcLen": 16,
                    "argLen": sid_format.arg_len,
                },
            },
        )
        if diff:
            return diff
    return None


def configure_locator(sid_format):
    get_topogen().gears["r1"].vtysh_cmd(
        "configure terminal\nsegment-routing\nsrv6\nlocators\nlocator MAIN\n"
        f"prefix {sid_format.node_prefix} block-len {sid_format.block.prefixlen} "
        "node-len 16 func-bits 16\n"
        f"format {sid_format.name}\nbehavior usid"
    )


@pytest.fixture(scope="module")
def sid_format(request):
    """Exercise each layout once, then restore F3216 for lifecycle tests."""
    value = getattr(request, "param", F3216)
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def replace_locator(value):
        tgen.gears["r1"].vtysh_cmd(
            "configure terminal\nsegment-routing\nsrv6\nlocators\nno locator MAIN"
        )
        configure_locator(value)
        wait_for(functools.partial(check_pair, sid_format=value))

    try:
        if value != F3216:
            replace_locator(value)
        yield value
    finally:
        if value != F3216:
            replace_locator(F3216)


@pytest.mark.parametrize(
    "sid_format",
    [F3216, F4816],
    indirect=True,
    scope="module",
    ids=lambda value: value.name,
)
def test_pair_provisioning(sid_format):
    """Both forms share a function/context; only combined is advertised."""
    wait_for(functools.partial(check_adjacencies, (1, 2)))
    wait_for(functools.partial(check_pair, sid_format=sid_format))


@pytest.mark.parametrize(
    "sid_format",
    [F3216, F4816],
    indirect=True,
    scope="module",
    ids=lambda value: value.name,
)
@pytest.mark.parametrize("localonly", [False, True], ids=["combined", "local-only"])
def test_pair_forwarding(sid_format, localonly):
    """Both uA forms shift to the next CSID and use the adjacency nexthop."""
    r1, r2 = (get_topogen().gears[name] for name in ("r1", "r2"))
    wait_for(functools.partial(check_pair, sid_format=sid_format))
    sid = next(
        sid
        for sid in read_endx_sids()
        if (ipaddress.IPv6Address(sid) not in sid_format.node_prefix) == localonly
    )
    # Append G(next)=2 after the current function, without an upstream uN.
    block_len = sid_format.block.prefixlen
    shift = 128 - block_len - (32 if localonly else 48)
    destination = str(
        ipaddress.IPv6Address(int(ipaddress.IPv6Address(sid)) | (2 << shift))
    )
    expected = str(
        ipaddress.IPv6Address(
            int(sid_format.block.network_address) | (2 << (128 - block_len - 16))
        )
    )
    r1_mac = r1.cmd_raises("cat /sys/class/net/r1-eth0/address").strip()
    r2.cmd_raises(
        shlex.join(
            [
                "python3",
                os.path.join(CWD, "probe_ua.py"),
                "r2-eth0",
                r1_mac,
                destination,
                expected,
            ]
        )
    )


def check_pair_withdrawn(prefixes):
    r1 = get_topogen().gears["r1"]
    if read_endx_sids():
        return "SID Manager still owns an End.X representation"
    routes = r1.vtysh_cmd("show ipv6 route isis json", isjson=True)
    for prefix in prefixes:
        if prefix in routes:
            return f"released pair remains in IS-IS RIB: {routes}"
        output = r1.cmd_raises(f"ip -6 route show exact {prefix}").strip()
        if output:
            return f"released pair remains in kernel: {output}"
    return None


def test_shared_pair_lifetime(sid_format):
    """Keep the pair for one LAN owner; release it when its last owner leaves."""
    r1, r2 = (get_topogen().gears[name] for name in ("r1", "r2"))
    wait_for(check_pair)
    sids = set(read_endx_sids())
    prefixes = [sid_prefix(sid) for sid in sids]
    try:
        r2.vtysh_cmd(
            "configure terminal\ninterface r2-eth0\nisis circuit-type level-2-only"
        )
        wait_for(functools.partial(check_adjacencies, (2,)))
        # The old L1 LSP is stale; the remaining L2 advertisement must survive.
        wait_for(
            functools.partial(check_pair, levels=(2,), expected_sids=sids), stable=3
        )
        r1.cmd_raises("ip link set r1-eth0 down")
        wait_for(functools.partial(check_adjacencies, ()))

        wait_for(functools.partial(check_pair_withdrawn, prefixes))
    finally:
        r1.cmd_raises("ip link set r1-eth0 up")
        r2.vtysh_cmd(
            "configure terminal\ninterface r2-eth0\nisis circuit-type level-1-2"
        )
    wait_for(functools.partial(check_adjacencies, (1, 2)))
    wait_for(check_pair)


def test_pair_recreated_after_locator_replacement(sid_format):
    """Withdraw both forms and the advertisement before recreating a locator."""
    r1, r2 = (get_topogen().gears[name] for name in ("r1", "r2"))
    wait_for(check_pair)
    prefixes = [sid_prefix(sid) for sid in read_endx_sids()]
    try:
        r1.vtysh_cmd(
            "configure terminal\nsegment-routing\nsrv6\nlocators\nno locator MAIN"
        )
        wait_for(functools.partial(check_pair_withdrawn, prefixes))

        def unadvertised():
            database = r2.vtysh_cmd(
                "show isis database detail 0000.0000.0001 json", isjson=True
            )
            levels = {
                level.get("id")
                for area in database.get("areas", [])
                for level in area.get("levels", [])
            }
            if levels != {1, 2}:
                return f"missing peer LSPs: {database}"
            if list(endx_tlvs(database)):
                return f"withdrawn End.X remains advertised: {database}"
            return None

        wait_for(unadvertised)
    finally:
        configure_locator(F3216)
    wait_for(check_pair)


def test_pair_recreated_after_isis_restart(sid_format):
    """A new IS-IS session reacquires both forms after the old owner exits."""
    r1 = get_topogen().gears["r1"]
    wait_for(check_pair)
    prefixes = [sid_prefix(sid) for sid in read_endx_sids()]
    r1.killDaemons(["isisd"])
    try:
        wait_for(functools.partial(check_pair_withdrawn, prefixes))
    finally:
        assert r1.startDaemons(["isisd"]) == ""
    wait_for(functools.partial(check_adjacencies, (1, 2)))
    wait_for(check_pair)


def test_pair_replayed_after_zebra_restart(sid_format):
    """A new Zebra session recreates both forms, not just stale kernel routes."""
    r1 = get_topogen().gears["r1"]
    wait_for(check_pair)
    prefixes = [sid_prefix(sid) for sid in read_endx_sids()]
    r1.killDaemons(["zebra"])
    try:
        for prefix in prefixes:
            r1.cmd_raises(f"ip -6 route del {prefix}")
    finally:
        assert r1.startDaemons(["zebra"]) == ""
    wait_for(check_pair)


def test_localonly_kernel_flavor(sid_format):
    """Inspect the new local-only nflen when iproute2 can display it."""
    r1 = get_topogen().gears["r1"]
    help_output = r1.run("ip -6 route help 2>&1")
    if "flavors FLAVORS" not in help_output or "next-csid" not in help_output:
        version = r1.run("ip -Version").strip()
        pytest.skip(f"iproute2 cannot display SEG6_LOCAL_FLAVORS attributes: {version}")
    wait_for(check_pair)
    localonly = next(
        sid
        for sid in read_endx_sids()
        if ipaddress.IPv6Address(sid) not in F3216.node_prefix
    )
    output = r1.run(f"ip -6 -d route show exact {localonly}/48")
    assert "flavors next-csid lblen 32 nflen 16" in output, output


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", __file__] + sys.argv[1:]))
