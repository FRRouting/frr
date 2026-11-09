# SPDX-License-Identifier: ISC

"""Check explicit uA allocation when its outgoing interface arrives late."""

import json

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


def test_ua_allocated_when_interface_becomes_real(router):
    sid = "fcbb:bbbb:1:fe40::"
    removed_sid = "fcbb:bbbb:1:fe41::"
    nexthop = "2001:db8::2"

    router.cmd_raises("ip link add sr0 type dummy")
    router.cmd_raises("ip link set sr0 up")

    router.vtysh_cmd(
        f"""
        configure terminal
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

    before = show_sids()

    # A new dummy interface is initially admin-down. There is no interface-up
    # notification to trigger a second allocation attempt.
    router.cmd_raises("ip link add late0 type dummy")
    link = json.loads(router.cmd_raises("ip -j link show dev late0"))[0]
    assert "UP" not in link["flags"]

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

    _, diff = topotest.run_and_expect(check_context, None, count=30, wait=0.5)
    assert diff is None, f"{diff}\nSID Manager before interface creation: {before}"
    assert sid not in before, f"uA allocated before interface creation: {before[sid]}"
    assert removed_sid not in before
