# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright 2023 Quentin Young

import functools
import re
from lib.topogen import get_topogen
from lib.topolog import logger
from lib import topotest


def check_ping(name, dest_addr, expect_connected, count, wait, source_addr=None):
    """
    Assert that ping to dest_addr is expected
    * 'name': the router to set the ping from
    * 'dest_addr': The destination ip address to ping
    * 'expect_connected': True if ping is expected to pass
    * 'count': how many echos to send
    * 'wait': how long ping should wait to receive all replies
    """

    def _check(name, dest_addr, source_addr, expect_connected):
        tgen = get_topogen()
        cmd = "ping {}".format(dest_addr)
        if source_addr:
            cmd += " -I {}".format(source_addr)
        cmd += " -c 1 -w 1"
        output = tgen.gears[name].run(cmd)
        logger.info(output)

        # Extract packet loss percentage from ping output
        match = re.search(r", (\d+)% packet loss", output)
        if not match:
            return "ping fail - no packet loss info found"

        packet_loss = int(match.group(1))

        if expect_connected:
            # For expected connection, allow up to 90% packet loss
            if packet_loss > 90:
                return "ping fail - {}% packet loss exceeds 90% threshold".format(
                    packet_loss
                )
        else:
            # For expected disconnection, require 100% packet loss
            if packet_loss < 100:
                return "ping fail - {}% packet loss, expected 100%".format(packet_loss)

        return None

    logger.info(
        "[+] check {} {} (expect_connected: {})".format(
            name, dest_addr, expect_connected
        )
    )
    tgen = get_topogen()
    func = functools.partial(_check, name, dest_addr, source_addr, expect_connected)
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, "Failed"
