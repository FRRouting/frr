# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
pysbd: southbound daemon simulating a software OS/data plane for FRR.

The IGMP/MLD/PIM/OSPF/RIP packets go through the private encapsulation, the
multicast routes come from zebra FPM (installed as kernel MFC entries) and
the data plane events are sent to pimd/pim6d. The interfaces and their
addresses are followed while it runs. It needs root.

Run it with `python3 tests/topotests/lib/pysbd [options]` (`-h` lists
them). Example for pimd/pim6d with FPM, commands on a unix socket:

    python3 tests/topotests/lib/pysbd -n -c /tmp/pysbd.sock \\
        -p ipv4:127.0.0.1 -q 'ipv6:[::1]' -f ipv4:127.0.0.1

Commands can then be sent with `pysbd.send_command("/tmp/pysbd.sock",
"mrt data-start 192.168.1.10 239.1.1.1 2")`; `help` lists them. Topotests
use `pysbd.helper.Pysbd`.

With `-a` it also emulates the data plane events (see `emulation.py`):
the traffic starting and stopping, the SPT switch, asserts and registers.

Unit tests (no privileges needed), from tests/topotests/lib:

    python3 -m pysbd.test_pysbd
"""

from .console import send_command

__all__ = ["send_command"]
