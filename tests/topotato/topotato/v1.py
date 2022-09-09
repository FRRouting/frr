#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Topotato "API version 1" wildcard imports.

The idea here is that if we need to make some breaking changes in how tests
are written, a "v2" can be added with some different behavior.
"""
# pylint: disable=wildcard-import,unused-import,unused-wildcard-import

from .base import (
    TestBase,
    topotatofunc,
)
from .fixtures import (
    topology_fixture,
    config_fixture,
    instance_fixture,
)
from .frr import (
    FRRNetworkInstance,
    FRRConfigs,
)
from .utils import (
    JSONCompareIgnoreContent,
    JSONCompareIgnoreExtraListitems,
    JSONCompareListKeyedDict,
)

# .assertions manages its own __all__
from .assertions import *
