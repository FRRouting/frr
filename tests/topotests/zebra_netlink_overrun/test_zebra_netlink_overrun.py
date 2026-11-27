#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright 2026 6WIND S.A.
#

"""
Test that zebra does not silently lose netlink messages
"""

import os
import sys
import functools
import pytest
import ipaddress
import shlex

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

IF_COUNT = 4000
IFACE_PREFIX = "du"
# Small enough for the interface burst to overrun the netlink sockets
RCVBUF_SIZE = 32768
# Large enough for zebra not to overrun again once restarted
RESTART_RCVBUF_SIZE = 90000000


def build_topo(tgen):
    "Build function"

    tgen.add_router("r1")


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for _, router in tgen.routers().items():
        router.load_config(TopoRouter.RD_ZEBRA, None, f"-s {RCVBUF_SIZE}")

    tgen.start_router()

    for _, router in tgen.routers().items():
        start_watchfrr(router)


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    for _, router in tgen.routers().items():
        router.cmd("kill $(cat /var/run/frr/watchfrr.pid)")

    # Explicitly delete the dummy interfaces.
    # Destroying a network namespace containing thousands of interfaces
    # is slow and may delay the startup of subsequent tests.
    for name, router in tgen.routers().items():
        router.logger.info(f"Deleting the {IF_COUNT} dummy interfaces")
        batch = os.path.join(tgen.logdir, name, "dummy_del.batch")
        with open(batch, "w") as f:
            for i in range(IF_COUNT):
                f.write(f"link delete {IFACE_PREFIX}{i}\n")
        router.cmd_raises(f"ip -batch {batch}")

    tgen.stop_topology()


def start_watchfrr(router):
    "Start watchfrr to restart zebra automatically"

    pid = router.cmd_raises("cat /var/run/frr/zebra.pid").strip()
    cwd = router.cmd_raises(f"readlink /proc/{pid}/cwd").strip()
    cmdline = [
        arg for arg in router.cmd_raises(f"cat /proc/{pid}/cmdline").split("\0") if arg
    ]
    cmdline[cmdline.index("-s") + 1] = str(RESTART_RCVBUF_SIZE)

    restart = f": %s; cd {shlex.quote(cwd)} && {shlex.join(cmdline)}"
    watchfrr = os.path.join(router.net.daemondir, "watchfrr")
    router.logger.info(f"watchfrr restart command for zebra: {restart}")

    out = os.path.join(cwd, "watchfrr.out")
    router.cmd_raises(
        f"{watchfrr} -d -i 1 --min-restart-interval 1 "
        f"--max-restart-interval 1 -r {shlex.quote(restart)} zebra > {out} 2>&1"
    )


def zebra_if_count(tgen, router):
    output = router.vtysh_cmd("show interface brief")

    return sum(1 for line in output.splitlines() if line.startswith(IFACE_PREFIX))


def test_zebra_netlink_overrun():
    "Create interfaces at once and check that zebra loses none silently"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    start_ip = ipaddress.IPv4Address("10.0.0.1")
    start_iproute = ipaddress.IPv4Address("192.168.0.1")
    start_ipv6 = ipaddress.IPv6Address("2001:db8::1")
    start_ipv6route = ipaddress.IPv6Address("2001:db8:ff::1")
    batch = os.path.join(tgen.logdir, "r1", "dummy.batch")
    with open(batch, "w") as f:
        for i in range(IF_COUNT):
            f.write(
                f"""
link add {IFACE_PREFIX}{i} type dummy
link set {IFACE_PREFIX}{i} up
address add dev {IFACE_PREFIX}{i} {start_ip + i}/32
route add {start_iproute + i}/32 via {start_ip + i}
address add dev {IFACE_PREFIX}{i} {start_ipv6 + i}/128
route add {start_ipv6route + i}/128 dev {IFACE_PREFIX}{i}
        """
            )

    r1.logger.info("Freeze zebra process to force the netlink socket buffer overflow")
    r1.cmd_raises("kill -s STOP $(cat /var/run/frr/zebra.pid)")

    r1.logger.info(f"Batch the creation of {IF_COUNT} dummy interfaces")
    r1.cmd_raises(f"ip -batch {batch}")

    r1.logger.info("Unfreeze zebra process")
    r1.cmd_raises("kill -s CONT $(cat /var/run/frr/zebra.pid)")

    r1.logger.info(
        f"Check the installation of {IF_COUNT} dummy interfaces into the kernel"
    )
    count = int(r1.cmd(f"ip -o link show type dummy | grep -c ' {IFACE_PREFIX}'"))
    assert_msg = f"{IF_COUNT} interfaces expected in the kernel, got {count}"
    assert count == IF_COUNT, assert_msg

    r1.logger.info(f"Check the presence of {IF_COUNT} dummy interfaces in zebra")
    test_func = functools.partial(zebra_if_count, tgen, r1)
    _, count = topotest.run_and_expect(test_func, IF_COUNT, count=120, wait=0.5)

    assert_msg = f"zebra silently lost netlink messages: got {count} of the {IF_COUNT} interfaces"
    assert count == IF_COUNT, assert_msg

    r1.logger.info(f"Check that a recvmsg overrun occurred")
    zebra_log_file = os.path.join(tgen.logdir, r1.name, "zebra.log")
    assert_msg = "recvmsg overrun not reported in the log"
    with open(zebra_log_file) as f:
        assert any("recvmsg overrun" in line for line in f), assert_msg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
