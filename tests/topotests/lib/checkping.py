# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright 2023 Quentin Young

import functools
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

    def _check(name, dest_addr, source_addr, match):
        tgen = get_topogen()
        cmd = "ping {}".format(dest_addr)
        if source_addr:
            cmd += " -I {}".format(source_addr)
        cmd += " -c 1 -w 1"
        output = tgen.gears[name].run(cmd)
        logger.info(output)
        if match not in output:
            return "ping fail"

    match = ", {} packet loss".format("0%" if expect_connected else "100%")
    logger.info("[+] check {} {} {}".format(name, dest_addr, match))
    tgen = get_topogen()
    func = functools.partial(_check, name, dest_addr, source_addr, match)
    _, result = topotest.run_and_expect(func, None, count=count, wait=wait)
    assert result is None, "Failed"
