#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Topotato topology/config fixtures
"""

import sys
import inspect
import functools

from .parse import Topology
from .toponom import Network


# this is * imported for all tests
__all__ = [
    "mkfixture",
    "mkfixture_pytest",
    "topology_fixture",
    "config_fixture",
    "instance_fixture",
]


def mkfixture_pytest(*args, **kwargs):
    """
    wrap pytest.fixture to allow loading test classes without pulling in
    all of pytest.  Intended to be overridden/replaced when writing a
    standalone script that imports some test class.
    """
    # pylint: disable=import-outside-toplevel
    from pytest import fixture

    return fixture(*args, **kwargs)


mkfixture = mkfixture_pytest


def topology_fixture():
    """
    Fixture to use for defining a test topology

    The topology is immediately instantiated from the docstring, and only one
    instance is created.  The function can modify the result topology (e.g.
    to change IP addresses) through its function parameter.
    """

    def getwrap(fn):
        topo = Topology(fn.__doc__)

        net = Network()
        net.load_parse(topo)

        # partial() used here so fnwrap() doesn't have the topo arg in its
        # function signature.  (would otherwise be visible on
        # inspect.signature() which pytest uses for fixtures)

        fnwrap = functools.partial(fn, net)
        fnwrap()

        net.auto_ifnames()
        net.auto_ip4()
        net.auto_ip6()

        @functools.wraps(fnwrap)
        def wrap():
            return net

        fixture = mkfixture(scope="module")(wrap)
        fixture.net = net
        return fixture

    return getwrap


def config_fixture(cfgclass):
    """
    Fixture to generate configs for a test topology

    The decorator takes 1 argument, which is the FRRConfigs subclass.  This
    class has .prepare() called on it immediately so any template errors are
    apparent before jumping into tests.

    The decorated function has 2 arguments, the first is an instance of the
    Config class (which the function may modify), the second is the topology
    fixture that is used (and handled by pytest).  The function should return
    either "None" or a config instance.
    """

    cfgclass = cfgclass.prepare()

    def getwrap(fn):
        if getattr(fn, "__doc__", None) is None:
            fn.__doc__ = """configuration fixture"""

        params = list(inspect.signature(fn).parameters.keys())
        fnmod = sys.modules[fn.__module__]
        net = getattr(fnmod, params[1]).net

        # we don't really wrap fnwrap... we wrap fn, but with the first arg
        # filled in.  The partial() is just to get the signature right.
        fnwrap = functools.partial(fn, None)

        @functools.wraps(fnwrap)
        def wrap(**kwargs):
            topo_arg = params[1]
            config = cfgclass(kwargs[topo_arg])
            config = fn(config, **kwargs) or config
            config.generate()
            return config

        fixture = mkfixture(scope="module")(wrap)
        fixture.net = net
        fixture.cfgclass = cfgclass
        return fixture

    return getwrap


def instance_fixture():
    def wrap(fn):
        if getattr(fn, "__doc__", None) is None:
            fn.__doc__ = """test environment fixture"""

        params = list(inspect.signature(fn).parameters.keys())
        fnmod = sys.modules[fn.__module__]
        cfgs = getattr(fnmod, params[0])
        net = cfgs.net

        fn.testenv = True
        fn.net = net
        fn.configs = cfgs

        return mkfixture(scope="module")(fn)

    return wrap
