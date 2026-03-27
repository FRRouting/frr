#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
topotato OS-dependent submodule imports/dispatching
"""
# pylint: disable=unused-import

import sys
import typing

import pytest

if typing.TYPE_CHECKING:
    from .topobase import NetworkInstance
elif sys.platform == "linux":
    from .topolinux import NetworkInstance
elif sys.platform == "freebsd12":
    from .topofreebsd import NetworkInstance
else:

    class NetworkInstance:
        class RouterNS:
            pass

        def __init__(self, *args, **kwargs):
            raise NotImplementedError("no support for OS %r" % sys.platform)

        @classmethod
        @pytest.hookimpl()
        def pytest_topotato_envcheck(cls, session, result):
            raise NotImplementedError("no support for OS %r" % sys.platform)
