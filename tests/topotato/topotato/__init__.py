#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Welcome to 🔝🥔.  Because a potato is better than topotests.
"""

import os

if "TOPOTATO_INNER" not in os.environ:
    from .frr import FRRConfigs
    from .base import TestBase, topotatofunc
    from .fixtures import *
    from .assertions import *
    from .utils import JSONCompareIgnoreContent

del os
