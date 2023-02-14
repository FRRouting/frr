#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
topotato OS-dependent submodule imports/dispatching
"""
# pylint: disable=unused-import

import sys
from .utils import ClassHooks


if sys.platform == "linux":
    from .topolinux import NetworkInstance
elif sys.platform == "freebsd12":
    from .topofreebsd import NetworkInstance
else:

    class NetworkInstance(ClassHooks):
        class RouterNS:
            pass

        def __init__(self, *args, **kwargs):
            raise NotImplementedError("no support for OS %r" % sys.platform)

        @classmethod
        def _check_env(cls, *, result, **kwargs):
            raise NotImplementedError("no support for OS %r" % sys.platform)
