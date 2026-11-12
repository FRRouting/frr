#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""Test that a pipe in a BGP AS-path regexp is not treated as a modifier."""

from functools import partial

import pytest

from lib import topotest
from lib.topogen import Topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    s1 = tgen.add_switch("s1")
    s1.add_link(r1)
    s1.add_link(r2)

    s2 = tgen.add_switch("s2")
    s2.add_link(r1)
    s2.add_link(r3)


@pytest.fixture(scope="module")
def tgen(request):
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()
    yield tgen
    tgen.stop_topology()

def _routes_converged(router):
    """Check whether both expected prefixes are present."""
    output = router.vtysh_cmd("show ip bgp")

    prefixes = (
        "198.51.100.0/24",
        "203.0.113.0/24",
    )

    if all(prefix in output for prefix in prefixes):
        return None

    return output


def test_bgp_regexp_pipe_is_not_output_modifier_delimiter(tgen):
    """The regexp's first '|' must remain in the BGP command argument."""
    r1 = tgen.gears["r1"]

    test_func = partial(_routes_converged, r1)
    _, result = topotest.run_and_expect(
        test_func, None, count=30, wait=2
    )

    assert result is None, (
        "Expected BGP routes did not converge:\n%s" % result
    )

    bgp_command = "show ip bgp regexp ^100$|^200$"

    unfiltered = r1.vtysh_cmd(bgp_command)

    assert "198.51.100.0/24" in unfiltered
    assert "203.0.113.0/24" in unfiltered

    expected = [
        line
        for line in unfiltered.splitlines()
        if "203.0.113.0/24" in line
    ]

    assert expected, (
        "Could not find the AS 200 route row:\n%s" % unfiltered
    )

    actual = r1.vtysh_cmd(
        bgp_command + " | include 203.0.113.0/24"
    )

    assert actual.splitlines() == expected, (
        "Output modifier changed the BGP regexp argument "
        "or selected the wrong lines.\n"
        "Expected:\n%s\nActual:\n%s"
        % ("\n".join(expected), actual)
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
