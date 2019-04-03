#!/usr/bin/env python

#
# test_lm-proxy-topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018 by Volta Networks, Inc.
#
# Requirements, so the test is not skipped:
# - Linux kernel with VRF support
# - 'ip' command with VRF support (e.g. iproute2-ss180129 works)
# - FRR BGP daemon supporting label manager using instance id
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

import os
import sys
import pytest

from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

vrf_name = 'A'

class NetworkTopo(Topo):
    "Label Manager proxy topology"

    # Relationship between routers, switches, and hosts
    def build(self, *_args, **_opts):
        "Build function"

        tgen = get_topogen(self)

        # FRR routers

        for router in ['lm', 'ce1', 'pe1', 'p1', 'pe2', 'ce2']:
            tgen.add_router(router);

        # Connections

        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['ce1'], nodeif='ce1-eth0')
        switch.add_link(tgen.gears['pe1'], nodeif='pe1-eth0')

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['pe1'], nodeif='pe1-eth1')
        switch.add_link(tgen.gears['p1'], nodeif='p1-eth0')

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['p1'], nodeif='p1-eth1')
        switch.add_link(tgen.gears['pe2'], nodeif='pe2-eth1')

        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['ce2'], nodeif='ce2-eth0')
        switch.add_link(tgen.gears['pe2'], nodeif='pe2-eth0')

# Test environment handling

def vrf_destroy(router, vrf):
    router.run('ip link delete dev ' + vrf)

def vrf_setup(router, eth_in, vrf, vrf_table):
    cmds = ['ip link set dev lo up',
            'echo 10000 > /proc/sys/net/mpls/platform_labels',
            'ip link add dev ' + vrf +  ' type vrf table ' + vrf_table,
            'ip link set ' + vrf + ' up',
            'ip link set ' + eth_in + ' vrf ' + vrf,
            'echo 1 > /proc/sys/net/mpls/conf/' + vrf + '/input'
           ]
    vrf_destroy(router, vrf)
    for cmd in cmds:
        logger.info('[vrf_setup] cmd: ' + cmd)
        out = router.run(cmd)
        if out != None and len(out) > 0:
            logger.info('[vrf_setup] "{}" error: out="{}"'.format(cmd, out))

def setup_module(mod):
    "pytest environment setup"

    tgen = Topogen(NetworkTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Load router configuration

    ldp_id = 1
    bgp_id = 101
    lm_sock = '../lm/label_mgr.sock'

    for rname, router in router_list.iteritems():
        if rname == 'lm' :
            router.load_config(
                TopoRouter.RD_ZEBRA,
                os.path.join(CWD, '{}/zebra.conf'.format(rname)),
                '-z ' + lm_sock
            )
            continue

	rtype = ''.join([i for i in rname if not i.isdigit()])

        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname)),
            '-l ' + lm_sock
        )

        if router.check_capability(TopoRouter.RD_ZEBRA, '--vrfwnetns') == False:
            return pytest.skip('Skipping test: no VRF support')

        if rtype == 'ce' or rtype == 'pe':
            if router.check_capability(TopoRouter.RD_BGP, '--int_num') == False:
                return pytest.skip('Skipping test: no BGP LM support')
            router.load_config(
                TopoRouter.RD_BGP,
                os.path.join(CWD, '{}/bgpd.conf'.format(rname)),
                '-I %d' % bgp_id
            )
            bgp_id += 1

	if rtype == 'pe' or rtype == 'p':
            router.load_config(
                TopoRouter.RD_OSPF,
                os.path.join(CWD, '{}/ospfd.conf'.format(rname))
            )
            router.load_config(
                TopoRouter.RD_LDP,
                os.path.join(CWD, '{}/ldpd.conf'.format(rname)),
                '-n %d' % ldp_id
            )
            ldp_id += 1

    # Prepare VRF's

    router = tgen.gears['pe1']
    out = router.run('ip -h 2>&1 | grep vrf | wc -l')
    if int(out) == 0:
        return pytest.skip('Skipping test: ip/iproute2 has no VRF support')

    vrf_setup(tgen.gears['pe1'], 'pe1-eth0', vrf_name, '1')
    vrf_setup(tgen.gears['pe2'], 'pe2-eth0', vrf_name, '1')

    # Start routers

    tgen.start_router(tgen.gears['lm'])
    for rname, router in router_list.iteritems():
        if rname != 'lm':
            tgen.start_router(router)

def teardown_module(mod):
    tgen = get_topogen()
    for router in ['pe1', 'pe2']:
        vrf_destroy(tgen.gears[router], vrf_name)
    tgen.stop_topology()

def test_lm_proxy():
    logger.info('Test: label manager (LDP and BGP)')
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    cmd = 'show mpls ldp binding'

    router = tgen.gears['p1']

    def check_labels(router, cmd):
        output = router.vtysh_cmd(cmd, isjson=False)
        logger.info('chk_labels [' + cmd + ']: ' + output)
        return output.count('\n')

    test_func = partial(check_labels, router, cmd)
    result, diff = topotest.run_and_expect(test_func, 12, count=6, wait=30)
    assert result, 'wrong labels'

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

