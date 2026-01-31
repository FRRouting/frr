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


Developing and debugging tests
------------------------------

To get new tests working, there are two distinct primary types of trouble to
handle:

- issues preventing the test from completing pytest's collection phase
- issues during test execution.

The former kind of issue will essentially prevent topotato / pytest from
running *anything at all*, since pytest won't be able to build the list of
tests.  All syntax errors and a lot of semantic errors (undefined variables,
etc.) will show up here.  On the flipside, by the time topotato starts running
any test, all the test source files it could find are at least syntactically
valid.  There aren't a lot of tools to help fixing issues at this stage, but
Python's exceptions should point at most issues.

Test run-time issues
^^^^^^^^^^^^^^^^^^^^

Issues during test execution are an entirely different matter and can become
very tricky to debug, especially if timing is involved.  The absolute first
thing to do when working on any test is to add the ``--pause-on-fail`` option
to the topotato command line:

.. code-block:: console

   $ ./run_userns.sh --frr-builddir=$FRR_BUILD_DIR -v -v --pause-on-fail test_demo.py
   =================================== topotato initialization ===================================
   ===================================== test session starts =====================================
   [… shortened …]
   test_demo.py::AllStartupTest::startup PASSED (1.87)                                     [ 12%]
   test_demo.py::AllStartupTest::test_running:#90:r1/zebra/vtysh[show version fail] 
   ══════════════════════════════════════ paused on failure ══════════════════════════════════════

   self = <test_demo.AllStartupTest object at 0x7f91fa6bac10>
   topo = <topotato.toponom.Network object at 0x7f91faae7450>, r1 = <Router 1 "r1">
   [… shortened …]
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ paused on failure ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   ━━━━━ topology definition ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           [ r1 ]---[ noprot ]
   [… shortened …]
   ━━━━━ topotato session ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   this topotato session is named  8
   
   to attach to a router in this session, use:
           potatool -s 8 -r ROUTER shell
   
   Dropping into python interactive shell.  Use dir() to see state
   available for inspection.  Press Ctrl+D to continue test run.
   To modify & run a test item, replace "yield from X.make(...)" with
   _yield_from(X.make(...)).
   >>>

At this point, the test run is paused and can be inspected.  The terminal
where topotato was started is occupied with an interactive Python shell.
This shell has access to local variables as they were in the test function,
e.g. ``self`` and ``topo`` above.

.. warning::

   Do not attempt to use Ctrl+Z to suspend the test run.  It will completely
   break the test run.


Running items manually
""""""""""""""""""""""

Custom, temporary test items can be created and executed by using
:py:func:`_yield_from` in place of the ``yield from`` in the source file.
(Using ``yield from`` is not possible because the interactive shell is not a
Python generator and cannot yield.)

.. code-block:: console

   >>> _yield_from(Delay.make(maxwait=1))
   _yield_from(): executing test: <Delay >
   >>>

.. note::

   Tests executed by using :py:func:`_yield_from` are run in an environment
   that is very similar but **not 100% identical** to placing them directly in
   the source file.  In particular, pytest's collection is bypassed.  This
   means in some cases it's possible for the test item to behave differently
   from an identical call in a test source file, or just break.


Using potatool
""""""""""""""

During any point of a topotato run (but, most usefully while the run is paused
with ``--pause-on-fail``), the :program:`potatool` program provides access to
the emulated test network by way of an interactive shell:

.. code-block:: console

   $ ./potatool
   18:20:53.818 DEBUG: topotato[8](85853): running test_demo.py::AllStartupTest::test_running:#90:r1/zebra/vtysh[show version fail]
   topotato:(8) ... # help
   available commands:
   
   addrs               Show interfaces/addresses in currently running topology.
   exit                (no help available)
   help                This help text.
   ip                  Run `ip` in router.
   ps                  Show processes.
   router              Select a router in the current session.
                       Most commands require a router be selected.
   session             Select a topotato session.
                       Not necessary if only one topotato session is running.
   shell               Run a command in currently selected router.
                       If no command is specified, start user's shell (SHELL env var).
   show                Pass through "show" command into vtysh.
   topo                Show currently running topology.
   vtysh               Run `vtysh` in router.
   
   topotato:(8) ... #

Most commands require a virtual router to be selected first and are executed
on that router.  The selected router can be changed at any time with the
``router ...`` command.  What commands exactly are available inside potatool
is expected to change over time as things are added or reworked.

.. warning::

   When the topotato run is resumed (or not paused to begin with) and reaches
   the "shutdown" test item, all **processes inside the topology are terminated
   and the file system may be umounted**.  When making any changes, make sure
   to copy them outside potatool for later reference.

:program:`potatool` can be started as many times as is useful for debugging,
there is no limitation, exclusivity or lock.
