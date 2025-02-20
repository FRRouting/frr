#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_route_scale2.py
#
# Copyright (c) 2022 by
# Nvidia, Inc.
# Donald Sharp
#

"""
test_route_scale2.py: Testing route scale

"""
import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers

from scale_test_common import (
    scale_build_common,
    scale_setup_module,
    route_install_helper,
    scale_test_memory_leak,
    scale_converge_protocols,
    scale_teardown_module,
)


pytestmark = [pytest.mark.sharpd]


def build(tgen):
    scale_build_common(tgen)


def setup_module(module):
    scale_setup_module(module)


def teardown_module(_mod):
    scale_teardown_module(_mod)


def test_converge_protocols():
    scale_converge_protocols()


def test_route_install_1nh():
    route_install_helper(0)


def test_route_install_8nh():
    route_install_helper(3)


def test_route_install_32nh():
    route_install_helper(5)


def test_memory_leak():
    scale_test_memory_leak()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
