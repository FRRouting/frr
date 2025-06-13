#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_bgp_cbit_topo3.py
#
# Copyright (c) 2019 6WIND
#

"""
test_bfd_bgp_cbit_topo3.py: Test the FRR BFD daemon with multihop and BGP
unnumbered.
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Import common function implementations
from .common_bfd_bgp_cbit_topo3 import (
    common_setup_module,
    common_teardown_module,
    common_protocols_convergence,
    common_bfd_connection,
    common_bfd_loss_intermediate,
    common_bfd_comes_back_again,
    common_memory_leak,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd]


def setup_module(mod):
    "Sets up the pytest environment"
    return common_setup_module({"r1": "bgpd_passive.conf"}, mod)


def teardown_module(_mod):
    "Teardown the pytest environment"
    return common_teardown_module(_mod)


def test_protocols_convergence():
    """
    Assert that all protocols have converged before checking for the BFD
    statuses as they depend on it.
    """
    return common_protocols_convergence()


def test_bfd_connection():
    "Assert that the BFD peers can find themselves."
    return common_bfd_connection()


def test_bfd_loss_intermediate():
    """
    Assert that BGP notices the BFD link down failure.
    The BGP entries should be flushed as the C-bit is set in both directions.
    """
    return common_bfd_loss_intermediate({"r1": "peers_down_passive.json"})


def test_bfd_comes_back_again():
    """
    Assert that BFD notices the bfd link up
    and that ipv6 entries appear back
    """
    return common_bfd_comes_back_again()


def test_memory_leak():
    "Run the memory leak test and report results."
    return common_memory_leak()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
