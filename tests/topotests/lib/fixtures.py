# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# SPDX-License-Identifier: MIT
#
# August 27 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C. ("LabN")

import lib.topojson as topojson
import lib.topogen as topogen
from lib.topolog import logger


def tgen_json(request):
    logger.info("Creating/starting topogen topology for %s", request.module.__name__)

    tgen = topojson.setup_module_from_json(request.module.__file__)
    yield tgen

    logger.info("Stopping topogen topology for %s", request.module.__name__)
    tgen.stop_topology()


def topo(tgen):
    """Make tgen json object available as test argument."""
    return tgen.json_topo


def tgen():
    """Make global topogen object available as test argument."""
    return topogen.get_topogen()
