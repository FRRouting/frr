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


Numbering behavior
""""""""""""""""""

To eliminate common boilerplate, topotato will automatically assign IPv4 and
IPv6 addresses based on an ordinal number assigned to each router in the
topology.

As a first step, each router is assigned an ordinal based on sorting all
routers by their name.  The sort order has special rules in an attempt to make
numbering "natural":

- a router named ``dut`` is first.
- systems named ``r999`` come next, then ``rt999``.
- systems named ``h999`` (for hosts) are sorted after other names.
- runs of digits (e.g. ``999``) are converted to integers for sorting such that
  ``r2`` comes before ``r10``.

(``999`` above means one or more digits.)

LANs (``{ name }`` in the ASCII diagram) are assigned an ordinal in the same
way, but have their own numbering space and don't conflict with routers.

The ordinal can be overwritten in the topology fixture::

    @topology_fixture()
    def topo1(topo):
       """
       [ r1 ]---[ r2 ]
       """
       topo.routers["r1"].num = 10

If an ordinal assigned in this way was automatically assigned before, that
router is bumped off to the end.  (Other routers are not renumbered.)

After the topology fixture's body is executed, these ordinals (including
possible custom values) are used to assign addresses.  To see the assignments
made, use the ``--run-topology`` command line option.

Note that direct (point-to-point) links between 2 routers have different
numbering behavior than links drawn through LANs, even if it is a LAN with
only 2 connections.  A point-to-point link will have only link-local IPv6
addresses, a LAN will receive IPv6 ULAs by default.  Both receive IPv4
addresses but use distinct ranges.

.. todo::

   Document numbering control/customization knobs here.

..
   - ``xx`` is the system's own ordinal
   - ``nn`` is a LAN's ordinal
   - ``1nn`` is a LAN's ordinal plus 100
   - ``yy`` is the "other end's" ordinal (which may be another router or a LAN)
   - ``PP`` is a counter for parallel links that would otherwise be identical,
     counting up from zero.
   - ``GG`` is a global counter for point-to-point links
   - ``TT`` is ``fe`` for point-to-point links, ``bc`` (BroadCast) for LANs.

   - loopback: ``fd00::xx/128``, ``10.255.0.xx/32``
   - MAC addresses: ``fe:xx:PP:TT:yy:PP``  (the parallel counter is used twice,
     that's is not a typo.)
   - all interfaces: IPv6 link-local address based on the MAC address above
   - point-to-point links:  no IPv6 GUA (link-local only), ``10.GG.XX.YY/32``
   - LANs: ``fdbc:nn::/64`` (+ MAC-based addresses), ``10.1nn.0.xx/16``


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

.. note::

   While IP addresses, interface names and MAC addresses are deterministic,
   avoid hardcoding them.  While a bit more verbose, it is easier to understand
   ``{{ r1.iface_to('r2').ip4[0] }}`` than ``192.168.13.57``.

.. todo::

   Rework for integrated configuration/vtysh load.

.. todo::

   Full documentation section for :py:class:`FRRConfigs`.


Test class(es)
^^^^^^^^^^^^^^

All topotato tests are contained in classes inheriting from the
:py:class:`TestBase` class.  The class definition also bind together the test
content with the topology and configurations mentioned above::

   class TestSomething(TestBase, AutoFixture, topo=topo1, configs=Configs):
        """
        This docstring will be included in the HTML report, make it useful.
        """

To execute tests, an instance of this class is created and its test methods
are run in order.  One instance is shared by consecutive methods, so you can
use ``self`` to carry data between test methods.  However, an ``__init__``
constructor is not currently possible due to how pytest works.

.. todo::

   Add ``_topotato_init`` or something.

Topotato test methods are marked with the :py:func:`topotatofunc` decorator::

   @topotatofunc
   def my_test(self, topo, r1, r2):
       """
       This is a test item.
       """

       yield from AssertSomething.make(...)

These methods are executed in the order they occur in the python source in.
Aside from the topology being (optionally) passed as ``topo``, the names of
systems/routers defined in the topology are filled in with their runtime
:py:class:`FRRRouterNS` instances.

Topotato test methods are run in a two-step process.  **The test method, being
a generator, prepares and yields test items in the first stage.  Topotato then
executes these items later, during the test.**  This means that after the
methods in a test class have "assembled" the test and its assertions, the test
run itself is fully under topotato's control.  The only way to affect test
behavior is through the yielded assertions and their inputs (some of which may
be functions that are then used later, e.g. with :py:class:`AssertPacket`.)
This two-step design allows topotato to check tests for consistency and
tightly control and improve runtime test behavior.

.. note::

   While topotato test methods are generators, this has **no relation to
   pytest's historical yield-based tests**.  Yield-based tests were removed
   from pytest some time ago.  The overall pattern is similar but this is
   purely a topotato function, not pytest.


Test method timing
""""""""""""""""""

Other than grouping assertions semantically and feeding documentation into the
output HTML report through the docstring, test methods serve as timing
reference points for assertions inside them.

.. attention::

   TL;DR: **Each test method is a "zero" point for timeouts.  All timeouts
   inside the method are relative to the start of the method.**

It is extremely important to understand this timing behavior and the logic
behind it.  A lot of routing protocol tests perform some action and then wait
for a state machine to reach some particular state.  The time until this
state should be reached can normally be deduced from timer values (which may
be RFC defaults or explicit configuration.)  These checks often need to verify
state on multiple routers and/or verify multiple state displays on the same
router.  But now consider: all of these state changes were triggered by a
shared triggering event.  If a protocol's timing is such that convergence
takes e.g. up to 30 seconds, that's 30 seconds from the original event.  Not
30 seconds again and again.

The particular effect of this distinction is particularly visible when some
failure does in fact occur and state does not converge within the expected
time.  As an overdrawn example, if 3 show commands need to be checked on 10
routers and the maximum protocol delay is 30 seconds, chaining these timeouts
results in a 15 minute delay to detect failure.

Instead of taking these 15 minutes, topotato will wait 30 seconds on the first
assertion, and (assuming the other assertions have the same 30 second timeout),
will only run the other assertions once, and thus finish the test in 30
seconds.

As a consequence of this, **timeout values in assertions within a test method
must be monotonically increasing.**  They may be the same for consecutive
assertions, but going backwards is a symptom of some mistake in determining
the timing.

To begin a new "reference point", simply split items off into a new test
method.  This may sometimes not quite match the semantics of the test, but for
the sake of simplicity this is the expected way to do things.
