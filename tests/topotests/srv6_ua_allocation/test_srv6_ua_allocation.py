# SPDX-License-Identifier: ISC

"""Check that static and IS-IS uA SIDs on the same adjacency are independent."""

import pytest

from lib import topotest
from lib.topogen import Topogen


pytestmark = [pytest.mark.isisd, pytest.mark.staticd]

STATIC_SID = "2001:db8:1:fe40::"


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in ("r1", "r2"):
        switch.add_link(tgen.add_router(name))


@pytest.fixture
def router(request):
    tgen = Topogen(build_topo, request.module.__name__)
    try:
        tgen.start_topology()
        for name, node in tgen.routers().items():
            node.cmd_raises(f"ip link set dev {name}-eth0 addrgenmode none")
            node.cmd_raises(f"ip -6 address flush dev {name}-eth0 scope link")
            node.load_frr_config(extra_daemons=["staticd"] if name == "r1" else [])
        r1 = tgen.gears["r1"]
        r1.cmd_raises("ip link add sr0 type dummy")
        r1.cmd_raises("ip link set sr0 up")
        tgen.start_router()
        assert not tgen.routers_have_failure(), tgen.errors
        yield r1
    finally:
        tgen.stop_topology()


def adjacency_sids(router):
    sids = router.vtysh_cmd("show segment-routing srv6 sid json", isjson=True)
    return {
        sid: info
        for sid, info in sids.items()
        if info.get("behavior") == "uA"
        and info.get("locator") == "MAIN"
        and info.get("context", {}).get("interfaceName") == "r1-eth0"
        and info.get("context", {}).get("nexthopIpv6Address") == "fe80::2"
    }


def clients(entry):
    return {client["protocol"] for client in entry.get("clients", [])}


def isis_sids(entries, dynamic_only=False):
    return {
        sid
        for sid, entry in entries.items()
        if "isis" in clients(entry)
        and (not dynamic_only or entry["allocationMode"] == "dynamic")
    }


def wait_for_sids(router, predicate, message):
    entries = {}

    def check():
        nonlocal entries
        entries = adjacency_sids(router)
        return bool(predicate(entries))

    success, _ = topotest.run_and_expect(check, True, count=40, wait=0.5)
    assert success, f"{message}: {entries}"
    return entries


def configure_static(router, add):
    command = (
        f"sid {STATIC_SID}/64 locator MAIN behavior uA "
        "interface r1-eth0 nexthop fe80::2"
        if add
        else f"no sid {STATIC_SID}/64"
    )
    router.vtysh_cmd(
        f"""configure terminal
         segment-routing
          srv6
           static-sids
            {command}
        """
    )


def enable_isis(router):
    router.vtysh_cmd(
        """configure terminal
         interface r1-eth0
          ipv6 router isis 1
          isis network point-to-point
          isis hello-interval 1
          isis hello-multiplier 3
        """
    )


@pytest.mark.parametrize(
    "first", ["static", "isis"], ids=["static-first", "isis-first"]
)
def test_withdraw_static_ua(router, first):
    def static_owned(entries):
        return "static" in clients(entries.get(STATIC_SID, {}))

    original_isis = set()
    if first == "static":
        configure_static(router, True)
        wait_for_sids(
            router,
            lambda entries: static_owned(entries) and not isis_sids(entries),
            "static SID did not arrive before IS-IS",
        )
        enable_isis(router)
    else:
        enable_isis(router)
        initial = wait_for_sids(
            router,
            lambda entries: isis_sids(entries, dynamic_only=True)
            and STATIC_SID not in entries,
            "dynamic SID did not arrive before the static SID",
        )
        original_isis = isis_sids(initial, dynamic_only=True)
        configure_static(router, True)

    mixed = wait_for_sids(
        router,
        lambda entries: static_owned(entries) and isis_sids(entries),
        "static and IS-IS owners did not both allocate a SID",
    )
    expected_isis = isis_sids(mixed, dynamic_only=True)

    configure_static(router, False)
    remaining = wait_for_sids(
        router,
        lambda entries: STATIC_SID not in entries
        and isis_sids(entries, dynamic_only=True),
        f"static SID was not withdrawn independently of IS-IS (before: {mixed})",
    )
    assert clients(mixed[STATIC_SID]) == {"static"}, mixed
    assert original_isis <= expected_isis, mixed
    assert expected_isis and isis_sids(remaining, dynamic_only=True) == expected_isis

    neighbors = router.vtysh_cmd("show isis neighbor detail json", isjson=True)
    assert any(
        circuit.get("interface", {}).get("name") == "r1-eth0"
        and circuit["interface"].get("state") == "Up"
        for area in neighbors["areas"]
        for circuit in area["circuits"]
    ), neighbors
