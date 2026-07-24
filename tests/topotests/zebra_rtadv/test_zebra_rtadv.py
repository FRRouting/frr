#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Test zebra router-advertisement interface lifecycle handling."""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter


@pytest.fixture(scope="module")
def tgen(request):
    tgen = Topogen({"s1": ("r1")}, request.module.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    tgen.start_router()

    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def test_rtadv_wheel_remove_after_ifindex_change(tgen):
    """Deleting an RA-enabled interface must not leave it in the RA wheel."""
    r1 = tgen.gears["r1"]
    ifname = "ra-wheel-test"

    r1.cmd_raises("ip link add {} type dummy".format(ifname))
    r1.cmd_raises("ip link set {} up".format(ifname))

    expected = {ifname: {"pseudoInterface": False}}
    ok = topotest.router_json_cmp_retry(
        r1, "show interface {} json".format(ifname), expected, False, 30
    )
    assert ok, "zebra did not learn the test interface"

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface {}\n"
        " no ipv6 nd suppress-ra".format(ifname)
    )
    output = r1.vtysh_cmd("show ipv6 nd ra-interfaces")
    assert ifname in output, "test interface was not armed in the RA wheel"

    # RTM_DELLINK changes ifp->ifindex to IFINDEX_INTERNAL.  Keep the
    # configured interface around until zebra has processed that update, then
    # remove it so its delete hook must find the wheel item using the old key.
    r1.cmd_raises("ip link delete {}".format(ifname))
    expected = {ifname: {"pseudoInterface": True}}
    ok = topotest.router_json_cmp_retry(
        r1, "show interface {} json".format(ifname), expected, False, 30
    )
    assert ok, "zebra did not clear the test interface's ifindex"

    output = r1.vtysh_cmd(
        "configure terminal\nno interface {}".format(ifname)
    )
    assert "%" not in output, "failed to remove the inactive test interface"

    # Removal by the live (now internal) ifindex left a freed pointer in the
    # original slot.  Waiting a full wheel period makes that stale item run.
    topotest.sleep(2, "Waiting for the RA wheel to tick after interface deletion")

    error = r1.check_router_running()
    assert error == "", error


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
