#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_version.py
# Tests for library function: version_cmp().
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
Tests for the version_cmp() function.
"""

import os
import sys
import pytest

# Save the Current Working Directory to find lib files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
from lib.topotest import version_cmp


def test_valid_versions():
    "Test valid version compare results"

    curver = "3.0"
    samever = "3"
    oldver = "2.0"
    newver = "3.0.1"
    newerver = "3.0.11"
    vercustom = "3.0-dev"
    verysmallinc = "3.0.0.0.0.0.0.1"

    assert version_cmp(curver, oldver) == 1
    assert version_cmp(curver, newver) == -1
    assert version_cmp(curver, curver) == 0
    assert version_cmp(curver, newerver) == -1
    assert version_cmp(newver, newerver) == -1
    assert version_cmp(curver, samever) == 0
    assert version_cmp(curver, vercustom) == 0
    assert version_cmp(vercustom, vercustom) == 0
    assert version_cmp(vercustom, oldver) == 1
    assert version_cmp(vercustom, newver) == -1
    assert version_cmp(vercustom, samever) == 0
    assert version_cmp(curver, verysmallinc) == -1
    assert version_cmp(newver, verysmallinc) == 1
    assert version_cmp(verysmallinc, verysmallinc) == 0
    assert version_cmp(vercustom, verysmallinc) == -1


def test_invalid_versions():
    "Test invalid version strings"

    curver = "3.0"
    badver1 = ".1"
    badver2 = "-1.0"
    badver3 = "."
    badver4 = "3.-0.3"

    with pytest.raises(ValueError):
        assert version_cmp(curver, badver1)
        assert version_cmp(curver, badver2)
        assert version_cmp(curver, badver3)
        assert version_cmp(curver, badver4)


def test_regression_1():
    """
    Test regression on the following type of comparison: '3.0.2' > '3'
    Expected result is 1.
    """
    assert version_cmp("3.0.2", "3") == 1
