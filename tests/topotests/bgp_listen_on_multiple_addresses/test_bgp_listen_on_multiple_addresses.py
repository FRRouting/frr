#!/usr/bin/env python

#
# test_bgp_listen_on_multiple_addresses.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by Boeing Defence Australia
# Adriano Marto Reis
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_listen_on_multiple_addresses.py: Test BGP daemon listening for
connections on multiple addresses.

    +------+        +------+        +------+        +------+
    |      |        |      |        |      |        |      |
    |  r1  |--------|  r2  |--------|  r3  |--------|  r4  |
    |      |        |      |        |      |        |      |
    +------+        +------+        +------+        +------+

  |            |                                |             |
  |  AS 1000   |            AS 2000             |   AS 3000   |
  |            |                                |             |
  +------------+--------------------------------+-------------+
"""

import os
import sys
import pytest


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topojson import linux_intf_config_from_json
from lib.common_config import start_topology
from lib.topotest import router_json_cmp, run_and_expect
from functools import partial

pytestmark = [pytest.mark.bgpd]


LISTEN_ADDRESSES = {
    "r1": ["10.0.0.1"],
    "r2": ["10.0.0.2", "10.0.1.1"],
    "r3": ["10.0.1.2", "10.0.2.1"],
    "r4": ["10.0.2.2"],
}


def setup_module(mod):
    "Sets up the test environment."
    json_file = "{}/bgp_listen_on_multiple_addresses.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    # Adds extra parameters to bgpd so they listen for connections on specific
    # multiple addresses.
    for router_name in tgen.routers().keys():
        tgen.net[router_name].daemons_options["bgpd"] = "-l " + " -l ".join(
            LISTEN_ADDRESSES[router_name]
        )

    start_topology(tgen)

    linux_intf_config_from_json(tgen, topo)

    build_config_from_json(tgen, topo)


def teardown_module(_mod):
    "Tears-down the test environment."
    tgen = get_topogen()
    tgen.stop_topology()


def test_peering():
    "Checks if the routers peer-up."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _bgp_converge_initial("r1", "10.0.0.2")
    _bgp_converge_initial("r2", "10.0.0.1")
    _bgp_converge_initial("r2", "10.0.1.2")
    _bgp_converge_initial("r3", "10.0.1.1")
    _bgp_converge_initial("r3", "10.0.2.2")
    _bgp_converge_initial("r4", "10.0.2.1")


def test_listening_address():
    """
    Checks if bgpd is only listening on the specified IP addresses.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        # bgpd must not be listening on the default address.
        output = router.run("netstat -nlt4 | grep 0.0.0.0:179")
        assert output == "", "{}: bpgd is listening on 0.0.0.0:179".format(router.name)

        # bgpd must be listening on the specified addresses.
        for address in LISTEN_ADDRESSES[router.name]:
            output = router.run("netstat -nlt4 | grep {}:179".format(address))
            assert output != "", "{}: bpgd is not listening on {}:179".format(
                router.name, address
            )


def _bgp_converge_initial(router_name, peer_address, timeout=180):
    """
    Waits for the BGP connection between a given router and a given peer
    (specified by its IP address) to be established. If the connection is
    not established within a given timeout, then an exception is raised.
    """
    tgen = get_topogen()
    router = tgen.routers()[router_name]
    expected = {"ipv4Unicast": {"peers": {peer_address: {"state": "Established"}}}}

    test_func = partial(router_json_cmp, router, "show ip bgp summary json", expected)
    _, result = run_and_expect(test_func, None, count=timeout, wait=1)
    assert result is None, "{}: Failed to establish connection with {}".format(
        router_name, peer_address
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
