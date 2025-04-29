#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_routemap_scale.py: Testing route map conf scale.

"""
import os
import re
import sys
import pytest
import json
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    tgen.add_router("r1")


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_frr_config(os.path.join(CWD, "r1/frr.conf"), [
        (TopoRouter.RD_ZEBRA, None),
        (TopoRouter.RD_BGP, None),
    ])

    tgen.start_router()


def test_config_scale():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    output = r1.vtysh_cmd("show version")
    if '--enable-mgmtd' in output:
        pytest.skip('Huge route map configs take more than one hour to load '
                    'with mgmtd, skipped')

    r1.cmd('echo "configure terminal" > /tmp/rmap_scale_conf')
    # ~70k lines conf
    logger.info('generating configs')
    r1.cmd('for i in {1..9999}; do '
           'echo "route-map rmap1 permit $i "; '
           'echo "description test"; '
           'echo "match ip address prefix-list PL:P_DEFROUTE"; '
           'echo " on-match next"; '
           'echo " set as-path exclude all"; '
           'echo " set community 12345:$i 23456:798 11112:3334 52154:2230023327:11 64499:25706 additive"; '
           'echo "exit"; '
           'echo "!"; '
           'done >> /tmp/rmap_scale_conf')
    r1.cmd('echo "end" >> /tmp/rmap_scale_conf')

    logger.info('load conf /tmp/rmap_scale_conf to vtysh: vtysh < /tmp/rmap_scale_conf')
    output = r1.cmd('{ time vtysh < /tmp/rmap_scale_conf > /dev/null 2>&1; }'
                    ' 2>&1 | grep real')

    lines = r1.cmd('vtysh -c "show running" | wc -l')
    lines = int(lines)
    assert lines > 70000, 'config loss, less than 70k lines config loaded'

    match = re.match(r"real\s+(\d+)m([\d.]+)s", output)
    minutes = int(match.group(1))
    seconds = float(match.group(2))
    logger.info(f'Take: {minutes}m{seconds}seconds')
    assert minutes < 5, 'Regression, loading ~70k route map config lines takes'
    ' more than 5 minutes'


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
