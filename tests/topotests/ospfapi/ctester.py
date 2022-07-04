#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# January 17 2022, Christian Hopps <chopps@labn.net>
#
# Copyright 2022, LabN Consulting, L.L.C.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import argparse
import asyncio
import logging
import os
import sys

CWD = os.path.dirname(os.path.realpath(__file__))

CLIENTDIR = os.path.abspath(os.path.join(CWD, "../../../ospfclient"))
if not os.path.exists(CLIENTDIR):
    CLIENTDIR = os.path.join(CWD, "/usr/lib/frr")
assert os.path.exists(
    os.path.join(CLIENTDIR, "ospfclient.py")
), "can't locate ospfclient.py"

sys.path[0:0] = [CLIENTDIR]

import ospfclient as api  # pylint: disable=E0401 # noqa: E402


async def do_monitor(c, args):
    cv = asyncio.Condition()

    async def cb(new_router_id, _):
        assert new_router_id == c.router_id
        logging.info("NEW ROUTER ID: %s", new_router_id)
        sys.stdout.flush()
        async with cv:
            cv.notify_all()

    logging.debug("API using monitor router ID callback")
    await c.monitor_router_id(callback=cb)

    for check in args.monitor:
        logging.info("Waiting for %s", check)

        while True:
            async with cv:
                got = c.router_id
                if str(check) == str(got):
                    break
                logging.debug("expected '%s' != '%s'\nwaiting on notify", check, got)
                await cv.wait()

        logging.info("SUCCESS: %s", check)
        print("SUCCESS: {}".format(check))
        sys.stdout.flush()


async def do_wait(c, args):
    cv = asyncio.Condition()

    async def cb(added, removed):
        logging.debug("callback: added: %s removed: %s", added, removed)
        sys.stdout.flush()
        async with cv:
            cv.notify_all()

    logging.debug("API using monitor reachable callback")
    await c.monitor_reachable(callback=cb)

    for w in args.wait:
        check = ",".join(sorted(list(w.split(","))))
        logging.info("Waiting for %s", check)

        while True:
            async with cv:
                got = ",".join(sorted([str(x) for x in c.reachable_routers]))
                if check == got:
                    break
                logging.debug("expected '%s' != '%s'\nwaiting on notify", check, got)
                await cv.wait()

        logging.info("SUCCESS: %s", check)
        print("SUCCESS: {}".format(check))
        sys.stdout.flush()


async def async_main(args):
    c = api.OspfOpaqueClient(args.server)
    await c.connect()
    if sys.version_info[1] > 6:
        asyncio.create_task(c._handle_msg_loop())  # pylint: disable=W0212
    else:
        asyncio.get_event_loop().create_task(
            c._handle_msg_loop()  # pylint: disable=W0212
        )

    if args.monitor:
        await do_monitor(c, args)
    if args.wait:
        await do_wait(c, args)
    return 0


def main(*args):
    ap = argparse.ArgumentParser(args)
    ap.add_argument(
        "--monitor", action="append", help="monitor and wait for this router ID"
    )
    ap.add_argument("--server", default="localhost", help="OSPF API server")
    ap.add_argument(
        "--wait", action="append", help="wait for comma-sep set of reachable routers"
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(asctime)s %(levelname)s: TESTER: %(name)s: %(message)s"
    )

    # We need to flush this output to stdout right away
    h = logging.StreamHandler(sys.stdout)
    h.flush = sys.stdout.flush
    f = logging.Formatter("%(asctime)s %(name)s: %(levelname)s: %(message)s")
    h.setFormatter(f)
    logger = logging.getLogger("ospfclient")
    logger.addHandler(h)
    logger.propagate = False

    logging.info("ctester: starting")
    sys.stdout.flush()

    status = 3
    try:
        if sys.version_info[1] > 6:
            status = asyncio.run(async_main(args))
        else:
            loop = asyncio.get_event_loop()
            try:
                status = loop.run_until_complete(async_main(args))
            finally:
                loop.close()
    except KeyboardInterrupt:
        logging.info("Exiting, received KeyboardInterrupt in main")
    except Exception as error:
        logging.info("Exiting, unexpected exception %s", error, exc_info=True)
    else:
        logging.info("api: clean exit")

    return status


if __name__ == "__main__":
    exit_status = main()
    sys.exit(exit_status)
