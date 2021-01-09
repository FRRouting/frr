.. _fuzzing:

Fuzzing
=======

This page describes the fuzzing targets and supported fuzzers available in FRR
and how to use them. Familiarity with fuzzing techniques and tools is assumed.

Overview
--------

It is well known that networked applications tend to be difficult to fuzz on
their network-facing attack surfaces. Approaches involving actual network
transmission tend to be slow and are subject to intermediate devices and
networking stacks which tend to drop fuzzed packets, especially if the fuzzing
surface covers IP itself. Some time was spent on fuzzing FRR this way with some
mediocre results but attention quickly turned towards skipping the actual
networking and instead adding fuzzing targets directly in the packet processing
code for use by more traditional in- and out-of-process fuzzers. Results from
this approach have been very fruitful.

The patches to add fuzzing targets are kept in a separate git branch. Typically
it is better to keep them in the main branch so they are kept up to date and do
not need to be constantly synchronized with the main codebase. Unfortunately,
changes to FRR to support fuzzing necessarily extend far beyond the
entrypoints. Checksums must be disarmed, interactions with the kernel must be
skipped, sockets and files must be avoided, desired under/overflows must be
marked, etc. There are the usual ``LD_PRELOAD`` libraries to emulate these
things (preeny et al) but FRR is a very kernel-reliant program and these
libraries tend to create annoying problems when used with FRR for whatever
reason. Keeping this code in the main codebase is cluttering, difficult to work
with / around, and runs the risk of accidentally introducing bugs even if
``#ifdef``'d out. Consequently it's in a separate branch that is rebased on
``master`` from time to time.


Code
----

The git branch with fuzzing targets is located here:

https://github.com/FRRouting/frr/tree/fuzz

To build libFuzzer targets, pass ``--enable-libfuzzer`` to ``configure``.
To build AFL targets, compile with ``afl-clang`` as usual.

Fuzzing with sanitizers is strongly recommended, especially ASAN, which you can
enable by passing ``--enable-address-sanitizer`` to ``configure``.

Suggested UBSAN flags: ``-fsanitize-recover=unsigned-integer-overflow,implicit-conversion -fsanitize=unsigned-integer-overflow,implicit-conversion,nullability-arg,nullability-assign,nullability-return``
Recommended cflags: ``-Wno-all -g3 -O3 -funroll-loops``

Design
------

All fuzzing targets have support for libFuzzer and AFL. This is done by writing
the target as a libFuzzer entrypoint (``LLVMFuzzerTestOneInput()``) and calling
it from the AFL entrypoint in ``main()``. New targets should use this rule.

When adding AFL entrypoints, it's a good idea to use AFL persistent mode for
better performance. Grep ``bgpd/bgp_main.c`` for ``__AFL_INIT()`` for an
example of how to do this in FRR. Typically it involves moving all internal
daemon setup into a setup function. Then this setup function is called exactly
once for the lifetime of the process. In ``LLVMFuzzerTestOneInput()`` this
means you need to call it at the start of the function protected by a static
boolean that is set to true, since that function is your entrypoint. You also
need to call it prior to ``__AFL_INIT()`` in ``main()`` because ``main()`` is
your entrypoint in the AFL case.

Adding support to daemons
^^^^^^^^^^^^^^^^^^^^^^^^^

This section describes how to add entrypoints to daemons that do not have any
yet.

Because libFuzzer has its own ``main()`` function, when adding fuzzing support
to a daemon that doesn't have any targets already, ``main()`` needs to be
``#ifdef``'d out like so:

.. code:: c

   #ifndef FUZZING_LIBFUZZER

   int main(int argc, char **argv)
   {
   ...
   }

   #endif /* FUZZING_LIBFUZZER */


The ``FUZZING_LIBFUZZER`` macro is set by ``--enable-libfuzzer``.

Because libFuzzer can only be linked into daemons that have
``LLVMFuzzerTestOneInput()`` implemented, we can't pass ``-fsanitize=fuzzer``
to all daemons in ``AM_CFLAGS``. It needs to go into a variable specific to
each daemon. Since it can be thought of as a kind of sanitizer, for daemons
that have libFuzzer support there are now individual flags variables for those
daemons named ``DAEMON_SAN_FLAGS`` (e.g. ``BGPD_SAN_FLAGS``,
``ZEBRA_SAN_FLAGS``). This variable has the contents of the generic
``SAN_FLAGS`` plus any fuzzing-related flags. It is used in daemons'
``subdir.am`` in place of ``SAN_FLAGS``. Daemons that don't support libFuzzer
still use ``SAN_FLAGS``. If you want to add fuzzing support to a daemon you
need to do this flag variable conversion; look at ``configure.ac`` for
examples, it is fairly straightforward. Remember to update ``subdir.am`` to use
the new variable.

Do note that when fuzzing is enabled, ``SAN_FLAGS`` gains
``-fsanitize=fuzzer-no-link``; the result is that all daemons are instrumented
for fuzzing but only the ones with ``LLVMFuzzerTestOneInput()`` actually get
linked with libFuzzer.


Targets
-------

A given daemon can have lots of different paths that are interesting to fuzz.
There's not really a great way to handle this, most fuzzers assume the program
has one entrypoint. The approach taken in FRR for multiple entrypoints is to
control which path is taken within ``LLVMFuzzerTestOneInput()`` using
``#ifdef`` and passing whatever controlling macro definition you want. Take a
look at that function for the daemon you're interested in fuzzing, pick the
target, add ``#define MY_TARGET 1`` somewhere before the ``#ifdef`` switch,
recompile.

.. list-table:: Fuzzing Targets

   * - Daemon
     - Target
     - Fuzzers
   * - bgpd
     - packet parser
     - libfuzzer, afl
   * - ospfd
     - packet parser
     - libfuzzer, afl
   * - pimd
     - packet parser
     - libfuzzer, afl
   * - vrrpd
     - packet parser
     - libfuzzer, afl
   * - vrrpd
     - zapi parser
     - libfuzzer, afl
   * - zebra
     - netlink
     - libfuzzer, afl
   * - zebra
     - zserv / zapi
     - libfuzzer, afl


Fuzzer Notes
------------

Some interesting seed corpuses for various daemons are available `here
<https://github.com/qlyoung/frr-fuzz/tree/master/samples>`_.

For libFuzzer, you need to pass ``-rss_limit_mb=0`` if you are fuzzing with
ASAN enabled, as you should.

For AFL, afl++ is strongly recommended; afl proper isn't really maintained
anymore.
