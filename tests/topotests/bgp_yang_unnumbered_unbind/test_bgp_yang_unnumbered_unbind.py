#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_yang_unnumbered_unbind.py
#
# Copyright (c) 2026 by Nvidia Corporation
# Donald Sharp
#

"""
Deleting only the unnumbered peer-group leaf must unbind the neighbor.

The leaf delete is a northbound edit. Classic "no neighbor IFACE peer-group"
removes the whole neighbor, and vtysh does not install the transactional
commands, so this test starts the daemons with --tcli and talks to bgpd's vty.
"""

import os
import shlex
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

# One command per write. bgpd's vtysh socket executes a line and replies with
# three NUL bytes plus the return code; vtysh itself never installs these
# commands, even when the daemon was started with --tcli.
_BGP_VTY = r"""
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(30)
sock.connect("/var/run/frr/bgpd.vty")
for cmd in sys.argv[1:]:
    sock.sendall(cmd.encode() + b"\0")
    data = b""
    while True:
        marker = data.find(b"\0\0\0")
        if marker >= 0 and len(data) >= marker + 4:
            break
        chunk = sock.recv(4096)
        if not chunk:
            sys.stderr.write("bgpd closed the vty during: %s\n" % cmd)
            sys.exit(1)
        data += chunk
    text = data[:marker].decode(errors="replace")
    code = data[marker + 3]
    sys.stdout.write(text)
    if code:
        sys.stderr.write("bgpd rejected (%d): %s\n%s" % (code, cmd, text))
        sys.exit(1)
sock.close()
"""


def bgpd_vty(router, commands):
    "Run transactional commands on bgpd's own vty socket."
    router.cmd_raises(
        "python3 -c {} {}".format(
            shlex.quote(_BGP_VTY),
            " ".join(shlex.quote(cmd) for cmd in commands),
        )
    )


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()
        for daemon, enabled in router.net.daemons.items():
            if enabled:
                router.net.daemons_options[daemon] = "--tcli"

    tgen.start_router()

    # vtysh -f edits the candidate and, with --tcli, does not commit it.
    if not tgen.routers_have_failure():
        bgpd_vty(
            tgen.gears["r1"],
            ["enable", "configure terminal", "commit"],
        )


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_unnumbered_peer_group_leaf_delete_unbinds():
    "An interface neighbor leaves the group when the leaf is deleted"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    detail = r1.vtysh_cmd("show bgp neighbors eth0")
    assert "Member of peer-group PG" in detail

    # bgpd runs as the frr user and cannot read the test directory.
    nobind = "/etc/frr/nobind.conf"
    r1.cmd_raises(
        "cp {} {} && chown frr:frr {} && chmod 644 {}".format(
            shlex.quote(os.path.join(CWD, "nobind.conf")),
            nobind,
            nobind,
            nobind,
        )
    )
    bgpd_vty(
        r1,
        [
            "enable",
            "configure terminal",
            "configuration load file {} replace".format(nobind),
            "commit",
        ],
    )

    running = r1.vtysh_cmd("show running-config")
    assert "neighbor eth0 interface" in running
    assert "neighbor eth0 interface peer-group" not in running
    detail = r1.vtysh_cmd("show bgp neighbors eth0")
    assert "Member of peer-group PG" not in detail


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
