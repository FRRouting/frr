#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""Run with `python3 path/to/pysbd` or `python3 -m pysbd`."""

import os
import sys

if __package__ in (None, ""):
    # Started as `python3 path/to/pysbd`: import the package from its parent
    # directory instead of loading the modules as top level ones.
    package_dir = os.path.dirname(os.path.abspath(__file__))
    if sys.path and os.path.abspath(sys.path[0]) == package_dir:
        sys.path.pop(0)
    sys.path.append(os.path.dirname(package_dir))
    from pysbd.sbd import main
else:
    from .sbd import main

sys.exit(main())
