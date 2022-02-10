# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# August 27 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C. ("LabN")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
