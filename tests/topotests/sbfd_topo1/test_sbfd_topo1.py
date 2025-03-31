#!/usr/bin/env python

#
# test_sbfd_topo1.py
# basic test cases for sbfd initiator and reflector
#
# Copyright (c) 2025 by Alibaba, Inc.
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
<template>.py: Test <template>.
"""

import os
import sys
import pytest
import json
import re
import time
import pdb
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

"""
test_sbfd_topo1.py: test simple sbfd with IPv6 encap. RT1 is sbfd Initiator, RT2 is sbfd Reflector

 +----+----+        +----+----+
 |         |        |         |
 |   RT1   |   1    |   RT2   |
 |         +--------+         |
 | 2001::10|        | 2001::20|
 +----+----+        +----+----+

"""
pytestmark = [pytest.mark.bfdd]

def show_bfd_check(router, status, type='echo', encap=None):
    output = router.cmd("vtysh -c 'show bfd peers'")
    if encap:
        # check encap data if any
        pattern1 = re.compile(r'encap-data {}'.format(encap))
        ret = pattern1.findall(output)
        if len(ret) <= 0:
            logger.info("encap-data not match")
            return False

    # check  status
    pattern2 = re.compile(r'Status: {}'.format(status))
    ret = pattern2.findall(output)
    if len(ret) <= 0:
        logger.info("Status not match")
        return False

    # check type
    pattern3 = re.compile(r'Peer Type: {}'.format(type))
    ret = pattern3.findall(output)
    if len(ret) <= 0:
        logger.info("Peer Type not match")
        return False

    logger.info("all check passed")
    return True

def build_topo(tgen):
    "Test topology builder"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.
    #
    # Example
    #
    # Create 2 routers
    for routern in range(1, 3):
        tgen.add_router('r{}'.format(routern))

    # Create a switch with just one router connected to it to simulate a
    # empty network.
    switch = tgen.add_switch('s1')
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r2'])

def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None), (TopoRouter.RD_BFD, None)])

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

    # Verify that we are using the proper version and that the BFD
    # daemon exists.
    for router in router_list.values():
        # Check for Version
        if router.has_version('<', '5.1'):
            tgen.set_error('Unsupported FRR version')
            break

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    # This function tears down the whole topology.
    tgen.stop_topology()


# step 1 : config sbfd Initiator and reflector
def test_sbfd_config_check():
    "Assert that config sbfd and check sbfd status."
    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.5")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # config sbfd
    r1 = tgen.net['r1']
    r1.cmd("ping -c 5 2001::20")
    r1.cmd("vtysh -c 'config t' -c 'bfd' -c 'peer 2001::20 bfd-mode sbfd-init bfd-name 2-44 local-address 2001::10 remote-discr 1234'")

    r2 = tgen.net['r2']
    r2.cmd("vtysh -c 'config t' -c 'bfd' -c 'sbfd reflector source-address 2001::20 discriminator 1234'")

    check_func = partial(
        show_bfd_check, r1, 'up', type='sbfd initiator'
    )
    success, _ = topotest.run_and_expect(check_func, True, count=15, wait=1)
    assert success is True, "sbfd not up in 15 seconds"

# step 2: shutdown if and no shutdown if then check sbfd status
def test_sbfd_updown_interface():
    "Assert that updown interface then check sbfd status."
    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.5")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net['r1']
    r2 = tgen.net['r2']

    # shutdown interface
    r2.cmd("vtysh -c 'config t' -c 'interface r2-eth0' -c 'shutdown'")

    check_func = partial(
        show_bfd_check, r1, 'down', type='sbfd initiator'
    )
    success, _ = topotest.run_and_expect(check_func, True, count=15, wait=1)
    assert success is True, "sbfd not down in 15 seconds after shut"

    # up interface
    r2.cmd("vtysh -c 'config t' -c 'interface r2-eth0' -c 'no shutdown'")
    check_func = partial(
        show_bfd_check, r1, 'up', type='sbfd initiator'
    )
    success, _ = topotest.run_and_expect(check_func, True, count=15, wait=1)
    assert success is True, "sbfd not up in 15 seconds after no shut"

# step 3: change transmit-interval and check sbfd status according to the interval time
def test_sbfd_change_transmit_interval():
    "Assert that sbfd status changes align with transmit-interval."
    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.5")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net['r1']
    r2 = tgen.net['r2']

    r1.cmd("vtysh -c 'config t' -c 'bfd' -c 'peer 2001::20 bfd-mode sbfd-init bfd-name 2-44 local-address 2001::10 remote-discr 1234' -c 'transmit-interval 3000'")
    #wait sometime for polling finish
    time.sleep(1)

    # shutdown interface
    r2.cmd("vtysh -c 'config t' -c 'interface r2-eth0' -c 'shutdown'")

    #wait enough time for timeout
    check_func = partial(
        show_bfd_check, r1, 'down', type='sbfd initiator'
    )
    success, _ = topotest.run_and_expect(check_func, True, count=5, wait=3)
    assert success is True, "sbfd not down as expected"

    r2.cmd("vtysh -c 'config t' -c 'interface r2-eth0' -c 'no shutdown'")
    check_func = partial(
        show_bfd_check, r1, 'up', type='sbfd initiator'
    )
    success, _ = topotest.run_and_expect(check_func, True, count=15, wait=1)
    assert success is True, "sbfd not up in 15 seconds after no shut"

    r1.cmd("vtysh -c 'config t' -c 'bfd' -c 'no peer 2001::20 bfd-mode sbfd-init bfd-name 2-44 local-address 2001::10 remote-discr 1234'")
    success = show_bfd_check(r1, 'up', type='sbfd initiator')
    assert success is False, "sbfd not deleted as unexpected"

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
