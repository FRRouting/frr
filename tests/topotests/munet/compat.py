# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# November 16 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.
#
"""Provide compatible APIs."""


class PytestConfig:
    """Pytest config duck-type-compatible object using argprase args."""

    class Namespace:
        """A namespace defined by a dictionary of values."""

        def __init__(self, args):
            self.args = args

        def __getattr__(self, attr):
            return self.args[attr] if attr in self.args else None

    def __init__(self, args):
        self.args = vars(args)
        self.option = PytestConfig.Namespace(self.args)

    def getoption(self, name, default=None, skip=False):
        assert not skip
        if name.startswith("--"):
            name = name[2:]
        name = name.replace("-", "_")
        if name in self.args:
            return self.args[name] if self.args[name] is not None else default
        return default
