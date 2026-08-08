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
from lib.topogen import Topogen


@pytest.fixture(scope="module")
def tgen(request):
    tgen = Topogen({"s1": ("r1")}, request.module.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_frr_config()
    tgen.start_router()

    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def _wait_interface_live(r1, ifname):
    expected = {ifname: {"pseudoInterface": False}}
    ok = topotest.router_json_cmp_retry(
        r1, "show interface {} json".format(ifname), expected, False, 30
    )
    assert ok, "zebra did not learn the test interface"


def _wait_interface_preconfigured(r1, ifname):
    expected = {ifname: {"pseudoInterface": True}}
    ok = topotest.router_json_cmp_retry(
        r1, "show interface {} json".format(ifname), expected, False, 30
    )
    assert ok, "pre-configured interface not present in zebra"


def _wait_interface_pseudo(r1, ifname):
    expected = {ifname: {"pseudoInterface": True}}
    ok = topotest.router_json_cmp_retry(
        r1, "show interface {} json".format(ifname), expected, False, 30
    )
    assert ok, "zebra did not clear the test interface's ifindex"


def _enable_ra(r1, ifname):
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface {}\n"
        " no ipv6 nd suppress-ra".format(ifname)
    )


def _ra_interface_listed(r1, ifname):
    output = r1.vtysh_cmd("show ipv6 nd ra-interfaces")
    return ifname in output


def _wait_ra_armed(r1, ifname):
    topotest.run_and_expect(
        lambda: _ra_interface_listed(r1, ifname),
        True,
        count=30,
        wait=1,
    )


def _wait_ra_stopped(r1, ifname):
    topotest.run_and_expect(
        lambda: not _ra_interface_listed(r1, ifname),
        True,
        count=30,
        wait=1,
    )


def _wait_zebra_survives_ra_wheel(r1):
    """Poll until a wheel tick would have fired; zebra must stay up."""
    topotest.run_and_expect(
        lambda: r1.check_router_running() == "",
        True,
        count=30,
        wait=1,
    )


def _cleanup_inactive_interface(r1, ifname):
    output = r1.vtysh_cmd(
        "configure terminal\nno interface {}".format(ifname)
    )
    assert "%" not in output, "failed to remove the inactive test interface"


def test_rtadv_delete_up_interface_with_ra(tgen):
    """Delete an operative interface that is armed in the RA wheel."""
    r1 = tgen.gears["r1"]
    ifname = "ra-up-del"

    r1.cmd_raises("ip link add {} type dummy".format(ifname))
    r1.cmd_raises("ip link set {} up".format(ifname))
    _wait_interface_live(r1, ifname)

    _enable_ra(r1, ifname)
    _wait_ra_armed(r1, ifname)

    r1.cmd_raises("ip link delete {}".format(ifname))
    _wait_interface_pseudo(r1, ifname)
    _cleanup_inactive_interface(r1, ifname)

    _wait_zebra_survives_ra_wheel(r1)


def test_rtadv_delete_down_interface_with_ra(tgen):
    """RTM_DELLINK on a down interface with RA armed and no if_down()."""
    r1 = tgen.gears["r1"]
    ifname = "ra-down-del"

    r1.cmd_raises("ip link add {} type dummy".format(ifname))
    _wait_interface_live(r1, ifname)

    _enable_ra(r1, ifname)
    _wait_ra_armed(r1, ifname)

    r1.cmd_raises("ip link delete {}".format(ifname))
    _wait_interface_pseudo(r1, ifname)
    _cleanup_inactive_interface(r1, ifname)

    _wait_zebra_survives_ra_wheel(r1)


def test_rtadv_delete_after_admin_down(tgen):
    """Delete after if_down() already drained RA via rtadv_stop_ra()."""
    r1 = tgen.gears["r1"]
    ifname = "ra-ifdown-del"

    r1.cmd_raises("ip link add {} type dummy".format(ifname))
    r1.cmd_raises("ip link set {} up".format(ifname))
    _wait_interface_live(r1, ifname)

    _enable_ra(r1, ifname)
    _wait_ra_armed(r1, ifname)

    r1.cmd_raises("ip link set {} down".format(ifname))
    _wait_ra_stopped(r1, ifname)

    r1.cmd_raises("ip link delete {}".format(ifname))
    _wait_interface_pseudo(r1, ifname)
    _cleanup_inactive_interface(r1, ifname)

    _wait_zebra_survives_ra_wheel(r1)


def test_rtadv_preconfigured_ifindex_promotion(tgen):
    """IFINDEX_INTERNAL promotion must not pre-start RA; if_up() arms the wheel."""
    r1 = tgen.gears["r1"]
    ifname = "ra-preconf"

    _enable_ra(r1, ifname)
    _wait_interface_preconfigured(r1, ifname)
    assert not _ra_interface_listed(
        r1, ifname
    ), "RA must not start before the kernel assigns an ifindex"

    r1.cmd_raises("ip link add {} type dummy".format(ifname))
    r1.cmd_raises("ip link set {} up".format(ifname))
    _wait_interface_live(r1, ifname)
    _wait_ra_armed(r1, ifname)

    _wait_zebra_survives_ra_wheel(r1)

    r1.cmd_raises("ip link delete {}".format(ifname))
    _wait_interface_pseudo(r1, ifname)
    _cleanup_inactive_interface(r1, ifname)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
