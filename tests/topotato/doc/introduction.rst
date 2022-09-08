Introduction, HOWTO and Patterns
================================


Welcome to 🔝🥔.  This is a work-in-progress test framework for FRRouting
system-level conformance tests, i.e. to run FRR through a variety of scenarios
and validate behavior.  Continue reading for a quick rundown of HOWTOs,
general patterns, design rationales and goals.


Goals
-----

Topotato has been created while FRR already has an existing test framework,
topotests.  As such, a lot of motivation is coming from trying to address
topotests shortcomings.  Topotato tries to achieve the following:

- make it easier to read and understand tests, especially when they fail.

- work towards more reliable tests that consistently pass or fail regardless
  of influences like system load, parallelisation, order, OS or architecture.

- make it easier to write tests.

- reduce the number of different ways a particular test can be expressed,
  ideally to 1.  This is tightly related to all 3 previous points;  it should
  be as easy as possible to find *the correct way* to express a test condition,
  and hard to do things wrong (i.e. writing flaky tests.)  Having fewer ways to
  express a particular test also means fewer things to learn and understand an
  existing test when it fails.

- make test reports more useful, primarily for failures but also for
  successes.  It should not be necessary to dig through a test, maybe even
  add debug statements and run it multiple times, to understand what a test is
  doing and why it is failing.

- have the test suite be easily executable by all developers on their
  development systems.  This also includes making it faster.


Some secondary goals, to some degree motivated by the above, are:

- make tests self-contained in a single file, avoid jumping around a multitude
  of files.

- replace hardcoded IP addresses with semantic expressions to aid readability,
  e.g. ``192.168.13.57`` is an opaque IPv4 address while
  ``r1.iface_to('r2').ip4[0]`` might evaluate to the same address but can be
  read without keeping an address cross-reference around.

- have the testsuite run without requiring ``root`` access to the system, which
  also means without installing FRR.  Along with making it easier to run, this
  provides a guarantee that the testsuite can't break the developer's system.
  The kernel just won't let it.  This also avoids issues with broken or
  mismatched installations.

- support FreeBSD.


Anatomy of a test
-----------------

Header
^^^^^^

All tests begin with a header similar to this::

   #!/usr/bin/env python3
   # SPDX-License-Identifier: GPL-2.0-or-later
   # Copyright (C) 2070  Some Body
   """
   Check that the top of the potato has been baked properly.
   """
   
   from topotato import *

The elements here should be pretty self-explanatory, but a few notes
regardless:

- topotato uses SPDX license identifiers.  Please stick to ``GPL-2.0-or-later``
  unless you have a *very* good reason.

- there should at least be a short docstring describing what this file tests.

- the topotato package is designed to be used with a ``*`` import;  ignore any
  style checker complaints about wildcard imports.

.. todo::

   Compatibility/equivalence markers?  Aka::

      # for topotato framework to make incompatible changes easier?
      __topotato_version__ = 1
      # when rebuilding existing topotests?
      __topotests_file__ = 'potato/test_top.py'
      __topotests_rev__ = 'a770da1b1c6290f53cc69218a30360accd6a0068'


Topology definition
^^^^^^^^^^^^^^^^^^^

A test topology in topotato is defined by drawing an ASCII diagram in a
function marked with a decorator::

    @topology_fixture()
    def topo1(topo):
       """
       [ r1 ]---[ r2 ]
       """
       # optional modifier code operating on topo.* here

The syntax for these diagrams is explained under :ref:`ascii-diagrams`.

The names of the topology fixture function previously included a reference to
the test name, but there's no real need to do that and a generic ``topo1``
works just as well.  Defining multiple topologies in one file is possible, but
probably the test should be split up into multiple files instead.


FRR Configurations
^^^^^^^^^^^^^^^^^^

Topotato generates FRR configuration from jinja2 templates embedded in the
test file::

   class Configs(FRRConfigs):
       # by default, all systems listed in the topology are assumed to run
       # FRR.
       routers = ["r1"]
   
       zebra = """
       #% extends "boilerplate.conf"
       #% block main
       #%   for iface in router.ifaces
       interface {{ iface.ifname }}
        description {{ iface.other.endpoint.name }}
       !
       #%   endfor
       !
       #% endblock
       """

       # which daemons are started is defined by which daemons have a config.
       staticd = """
       #% extends "boilerplate.conf"
       #% block main
       ##   ... etc ...
       #% endblock
       """

   # bind config + topology together
   @config_fixture(Configs)
   def configs(config, topo1):
       return config

.. note::

   While IP addresses, interface names and MAC addresses are deterministic,
   avoid hardcoding them.  While a bit more verbose, it is easier to understand
   ``{{ r1.iface_to('r2').ip4[0] }}`` than ``192.168.13.57``.

.. todo::

   Rework for integrated configuration/vtysh load.

.. todo::
   
   Full documentation section for :py:class:`FRRConfigs`.


Network instance
^^^^^^^^^^^^^^^^

There is a small stub block to set up the actual virtual network instance for
tests::

   @instance_fixture()
   def testenv(configs):
       return FRRNetworkInstance(configs.topology, configs).prepare()

There isn't currently anything to adjust here, but it is left in place to meet
future needs to change some aspect of the network that isn't part of the
topology definition or FRR configuration (e.g. sysctls).


Test class(es)
^^^^^^^^^^^^^^

.. todo::
   
   Write me.
