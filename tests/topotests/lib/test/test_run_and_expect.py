#!/usr/bin/env python

#
# test_run_and_expect.py
# Tests for library function: run_and_expect(_type)().
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Tests for the `run_and_expect(_type)()` functions.
"""

import os
import sys
import pytest

# Save the Current Working Directory to find lib files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
from lib.topotest import run_and_expect_type


def test_run_and_expect_type():
    "Test basic `run_and_expect_type` functionality."

    def return_true():
        "Test function that returns `True`."
        return True

    # Test value success.
    success, value = run_and_expect_type(
        return_true, bool, count=1, wait=0, avalue=True
    )
    assert success is True
    assert value is True

    # Test value failure.
    success, value = run_and_expect_type(
        return_true, bool, count=1, wait=0, avalue=False
    )
    assert success is False
    assert value is True

    # Test type success.
    success, value = run_and_expect_type(return_true, bool, count=1, wait=0)
    assert success is True
    assert value is True

    # Test type failure.
    success, value = run_and_expect_type(return_true, str, count=1, wait=0)
    assert success is False
    assert value is True

    # Test type failure, return correct type.
    success, value = run_and_expect_type(return_true, str, count=1, wait=0, avalue=True)
    assert success is False
    assert value is True


if __name__ == "__main__":
    sys.exit(pytest.main())
