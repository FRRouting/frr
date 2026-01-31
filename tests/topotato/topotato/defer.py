#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023  David Lamparter for NetDEF, Inc.
"""
gevent-or-not topotato integration
"""

# pylint: disable=unused-import
import select
import subprocess
import typing


class _FakeGreenlet:
    """
    Pretend to be a gevent.Greenlet when gevent is not available.
    """

    def __init__(self, run, *args, **kwargs):
        super().__init__()
        self._run = run
        self._args = args
        self._kwargs = kwargs
        self.value = None

    def start(self):
        self.value = self._run(*self._args, **self._kwargs)

    def join(self):
        return None

    @classmethod
    def spawn(cls, function, *args, **kwargs):
        gl = cls(function, *args, **kwargs)
        gl.start()
        return gl


Greenlet = _FakeGreenlet
spawn = _FakeGreenlet.spawn


if not typing.TYPE_CHECKING:
    try:
        import gevent
        import gevent.subprocess
        import gevent.select

        subprocess = gevent.subprocess
        select = gevent.select
        spawn = gevent.spawn
        Greenlet = gevent.Greenlet
    except ImportError:
        pass
