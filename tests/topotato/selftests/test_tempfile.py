#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
basic tests for topotato.utils LockedFile/AtomicPublishFile
"""

import os
import time

from topotato.utils import LockedFile, AtomicPublishFile


class ChdirCtx:
    def __init__(self, dirname):
        self.dirname = dirname
        self._orig = None

    def __enter__(self):
        self._orig = os.getcwd()
        os.chdir(self.dirname)

    def __exit__(self, exc_type, exc_value, tb):
        os.chdir(self._orig)


def test_lockedfile_context(tmp_path):
    """
    Simple use of LockedFile as context manager.
    """

    lockfilename = tmp_path / "lock"
    with LockedFile(lockfilename):
        assert os.path.exists(lockfilename)

    assert not os.path.exists(lockfilename)


def test_lockedfile_direct(tmp_path):
    """
    Use LockedFile directly, w/o context manager.
    """

    lockfilename = tmp_path / "lock"
    lf = LockedFile(lockfilename)
    lf.lock()
    assert os.path.exists(lockfilename)
    lf.lock()
    assert os.path.exists(lockfilename)
    lf.unlock()
    assert os.path.exists(lockfilename)
    lf.unlock()
    assert not os.path.exists(lockfilename)


def test_lockedfile_chdir(tmp_path):
    """
    Change directory after creating LockedFile.
    """

    lockfilename = tmp_path / "lock"

    with ChdirCtx(tmp_path):
        lf = LockedFile("lock")
        os.chdir("/")

        with lf:
            assert os.path.exists(lockfilename)

        assert not os.path.exists(lockfilename)


def test_lockedfile_exc(tmp_path):
    """
    Try context manager with exception.
    """

    class TestException(Exception):
        pass

    lockfilename = tmp_path / "lock"
    try:
        with LockedFile(lockfilename):
            assert os.path.exists(lockfilename)
            raise TestException()

    except TestException:
        assert not os.path.exists(lockfilename)


def test_atomicpublishfile(tmp_path):
    """
    Simple use of AtomicPublishFile
    """

    lockfilename = tmp_path / "lock"
    testdata = str(time.time())

    with AtomicPublishFile(lockfilename, "w", encoding="UTF-8") as fd:
        assert not os.path.exists(lockfilename)

        fd.write(testdata)

    assert os.path.exists(lockfilename)
    with open(lockfilename, "r", encoding="UTF-8") as fd:
        assert fd.read() == testdata
    os.unlink(lockfilename)


def test_atomicpublishfile_twice(tmp_path):
    """
    AtomicPublishFile, twice, with chdir mixed in
    """

    lockfilename = tmp_path / "lock"
    testdata = str(time.time())

    with ChdirCtx(tmp_path):
        apf = AtomicPublishFile("lock", "w", encoding="UTF-8")

        with apf as fd:
            assert not os.path.exists(lockfilename)
            fd.write(testdata)

        assert os.path.exists(lockfilename)
        with open(lockfilename, "r", encoding="UTF-8") as fd:
            assert fd.read() == testdata

        newtestdata = "A" + testdata
        os.chdir("/")
        with apf as fd:
            fd.write(newtestdata)
            with open(lockfilename, "r", encoding="UTF-8") as fd:
                assert fd.read() == testdata

        assert os.path.exists(lockfilename)
        with open(lockfilename, "r", encoding="UTF-8") as fd:
            assert fd.read() == newtestdata

        os.unlink(lockfilename)
