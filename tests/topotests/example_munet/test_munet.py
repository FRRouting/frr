# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# April 23 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
import pytest
from munet.base import get_event_loop

pytestmark = [pytest.mark.asyncio]


@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for the session."""
    loop = get_event_loop()
    try:
        # logging.info("event_loop_fixture: yielding with new event loop watcher")
        yield loop
    finally:
        loop.close()


async def test_native_test(unet):
    # o = unet.hosts["r1"].cmd_nostatus("ip addr")
    o = "Hello World"
    print(o)
