#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_run_and_expect.py
# Tests for library function: run_and_expect(_type)().
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
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
