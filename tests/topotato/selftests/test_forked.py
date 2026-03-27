#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
basic tests for topotato.utils.Forked
"""

from subprocess import CalledProcessError
from os import pipe, close, _exit, read, write

import pytest

from topotato.utils import Forked


def test_fork():
    """
    Basic non-failure Forked() test.
    """

    rdfd, wrfd = pipe()

    with Forked("test") as in_child:
        if in_child:
            close(rdfd)
            write(wrfd, b"DONE")
        else:
            close(wrfd)

    assert read(rdfd, 4) == b"DONE"


def test_nonzero():
    """
    Test exit code to CalledProcessError handling.
    """
    with pytest.raises(CalledProcessError):
        with Forked("test") as in_child:
            if in_child:
                _exit(1)


def test_exc():
    """
    Test exception to exit code handling.
    """
    with pytest.raises(CalledProcessError):
        with Forked("test") as in_child:
            if in_child:
                raise RuntimeError("TEST")
