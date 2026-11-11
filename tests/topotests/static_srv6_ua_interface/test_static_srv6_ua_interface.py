# SPDX-License-Identifier: ISC

"""Check explicit uA allocation when its outgoing interface arrives late."""

import json
import time

import pytest

from lib import topotest
from lib.topogen import Topogen


pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    tgen.add_router("r1")


@pytest.fixture
def router(request):
    tgen = Topogen(build_topo, request.module.__name__)
    try:
        tgen.start_topology()
        r1 = tgen.gears["r1"]
        r1.load_frr_config("frr.conf")
        tgen.start_router()
        assert not tgen.routers_have_failure(), tgen.errors
        yield r1
    finally:
        tgen.stop_topology()


@pytest.mark.parametrize("initially_up", [False, True], ids=["down-then-up", "already-up"])
def test_ua_allocated_when_interface_is_operative(router, initially_up):
    sid = "fcbb:bbbb:1:fe40::"
    removed_sid = "fcbb:bbbb:1:fe41::"
    nexthop = "2001:db8::2"
    sentinel_route = "2001:db8:ffff::/64"

    router.cmd_raises("ip link add sr0 type dummy")
    router.cmd_raises("ip link set sr0 up")

    router.vtysh_cmd(
        f"""
        configure terminal
         ipv6 route {sentinel_route} late0
         segment-routing
          srv6
           static-sids
            sid {sid}/64 locator MAIN behavior uA interface late0 nexthop {nexthop}
            sid {removed_sid}/64 locator MAIN behavior uA interface late0 nexthop 2001:db8::3
            no sid {removed_sid}/64
        """
    )

    def show_sids():
        return json.loads(router.vtysh_cmd("show segment-routing srv6 sid json"))

    def observe_pending():
        # Allow time for a request already queued by staticd to reach Zebra.
        deadline = time.monotonic() + 1
        while True:
            state = show_sids()
            unexpected = {key: state[key] for key in (sid, removed_sid) if key in state}
            if unexpected or time.monotonic() >= deadline:
                return unexpected
            time.sleep(0.25)

    before = observe_pending()

    flags = "up " if initially_up else ""
    router.cmd_raises(f"ip link add name late0 {flags}type dummy")
    link = json.loads(router.cmd_raises("ip -j link show dev late0"))[0]
    assert ("UP" in link["flags"]) == initially_up
    if initially_up:
        assert "LOWER_UP" in link["flags"]

    def check_staticd_ifindex():
        routes = router.vtysh_cmd("show static routes json", isjson=True)
        return topotest.json_cmp(
            routes,
            {
                "default": {
                    "routes": [
                        {
                            "prefix": sentinel_route,
                            "paths": [
                                {
                                    "nexthops": [
                                        {
                                            "interface": "late0",
                                            "interfaceIndex": link["ifindex"],
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
            },
        )

    # The static route provides a barrier for staticd's processing of ADD.
    _, diff = topotest.run_and_expect(check_staticd_ifindex, None, count=30, wait=0.5)
    assert diff is None, diff
    while_down = None
    if not initially_up:
        while_down = observe_pending()
        router.cmd_raises("ip link set dev late0 up")

    def check_context():
        return topotest.json_cmp(
            show_sids(),
            {
                sid: {
                    "context": {
                        "interfaceIndex": link["ifindex"],
                        "interfaceName": "late0",
                        "nexthopIpv6Address": nexthop,
                    },
                },
                removed_sid: None,
            },
        )

    _, context_diff = topotest.run_and_expect(check_context, None, count=30, wait=0.5)

    assert sid not in before, f"uA allocated before interface creation: {before[sid]}"
    assert removed_sid not in before
    if while_down is not None:
        assert sid not in while_down, f"uA allocated while admin-down: {while_down[sid]}"
        assert removed_sid not in while_down
    assert context_diff is None, context_diff

    def local_sid_installed():
        route = router.cmd_raises(f"ip -6 route show exact {sid}/64")
        return all(
            token in route
            for token in ("encap seg6local action End.X", f"nh6 {nexthop}", "dev late0")
        )

    _, installed = topotest.run_and_expect(local_sid_installed, True, count=30, wait=0.5)
    assert installed, router.cmd_raises(f"ip -6 route show exact {sid}/64")
    assert not router.cmd_raises(f"ip -6 route show exact {removed_sid}/64").strip()
