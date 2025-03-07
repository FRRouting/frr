# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# April 23 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
from munet.testing.util import retry


@retry(retry_timeout=10)
def wait_for_route(r, p):
    o = r.cmd_raises(f"ip route show {p}")
    assert p in o


async def test_native_test(unet):
    r1 = unet.hosts["r1"]
    o = r1.cmd_nostatus("ip addr")
    print(o)

    wait_for_route(r1, "10.0.2.0/24")

    r1.cmd_raises("ping -c1 10.0.1.2")
    r1.cmd_raises("ping -c1 10.0.2.2")
    r1.cmd_raises("ping -c1 10.0.2.3")
