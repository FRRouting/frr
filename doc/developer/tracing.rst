.. _tracing:

Tracing
=======

FRR has a small but growing number of static tracepoints available for use with
various tracing systems. These tracepoints can assist with debugging,
performance analysis and to help understand program flow. They can also be used
for monitoring.

Developers are encouraged to write new static tracepoints where sensible. They
are not compiled in by default, and even when they are, they have no overhead
unless enabled by a tracer, so it is okay to be liberal with them.


Supported tracers
-----------------

Presently two types of tracepoints are supported:

- `LTTng tracepoints <https://lttng.org/>`_
- `USDT probes <http://dtrace.org/guide/chp-usdt.html>`_

LTTng is a tracing framework for Linux only. It offers extremely low overhead
and very rich tracing capabilities. FRR supports LTTng-UST, which is the
userspace implementation. LTTng tracepoints are very rich in detail. No kernel
modules are needed. Besides only being available for Linux, the primary
downside of LTTng is the need to link to ``lttng-ust``.

USDT probes originate from Solaris, where they were invented for use with
dtrace. They are a kernel feature. At least Linux and FreeBSD support them. No
library is needed; support is compiled in via a system header
(``<sys/sdt.h>``). USDT probes are much slower than LTTng tracepoints and offer
less flexibility in what information can be gleaned from them.

LTTng is capable of tracing USDT probes but has limited support for them.
SystemTap and dtrace both work only with USDT probes.


Usage
-----

To compile with tracepoints, use one of the following configure flags:

.. program:: configure.ac

.. option:: --enable-lttng=yes

   Generate LTTng tracepoints

.. option:: --enable-usdt=yes

   Generate USDT probes

To trace with LTTng, compile with either one (prefer :option:`--enable-lttng`
run the target in non-forking mode (no ``-d``) and use LTTng as usual (refer to
LTTng user manual). When using USDT probes with LTTng, follow the example in
`this article
<https://lttng.org/blog/2019/10/15/new-dynamic-user-space-tracing-in-lttng/>`_.
To trace with dtrace or SystemTap, compile with `--enable-usdt=yes` and
use your tracer as usual.

To see available USDT probes::

   readelf -n /usr/lib/frr/bgpd

Example::

   root@host ~> readelf -n /usr/lib/frr/bgpd

   Displaying notes found in: .note.ABI-tag
     Owner                 Data size	Description
     GNU                  0x00000010	NT_GNU_ABI_TAG (ABI version tag)
       OS: Linux, ABI: 3.2.0

   Displaying notes found in: .note.gnu.build-id
     Owner                 Data size	Description
     GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
       Build ID: 4f42933a69dcb42a519bc459b2105177c8adf55d

   Displaying notes found in: .note.stapsdt
     Owner                 Data size	Description
     stapsdt              0x00000045	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: packet_read
       Location: 0x000000000045ee48, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-96(%rbp) 8@-104(%rbp)
     stapsdt              0x00000047	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: open_process
       Location: 0x000000000047c43b, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-224(%rbp) 2@-226(%rbp)
     stapsdt              0x00000049	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: update_process
       Location: 0x000000000047c4bf, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-208(%rbp) 2@-210(%rbp)
     stapsdt              0x0000004f	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: notification_process
       Location: 0x000000000047c557, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-192(%rbp) 2@-194(%rbp)
     stapsdt              0x0000004c	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: keepalive_process
       Location: 0x000000000047c5db, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-176(%rbp) 2@-178(%rbp)
     stapsdt              0x0000004a	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: refresh_process
       Location: 0x000000000047c673, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-160(%rbp) 2@-162(%rbp)
     stapsdt              0x0000004d	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: capability_process
       Location: 0x000000000047c6f7, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-144(%rbp) 2@-146(%rbp)
     stapsdt              0x0000006f	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: output_filter
       Location: 0x000000000048e33a, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-144(%rbp) 8@-152(%rbp) 4@-156(%rbp) 4@-160(%rbp) 8@-168(%rbp)
     stapsdt              0x0000007d	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: process_update
       Location: 0x0000000000491f10, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-800(%rbp) 8@-808(%rbp) 4@-812(%rbp) 4@-816(%rbp) 4@-820(%rbp) 8@-832(%rbp)
     stapsdt              0x0000006e	NT_STAPSDT (SystemTap probe descriptors)
       Provider: frr_bgp
       Name: input_filter
       Location: 0x00000000004940ed, Base: 0x00000000005a09d2, Semaphore: 0x0000000000000000
       Arguments: 8@-144(%rbp) 8@-152(%rbp) 4@-156(%rbp) 4@-160(%rbp) 8@-168(%rbp)


To see available LTTng probes, run the target, create a session and then::

   lttng list --userspace | grep frr

Example::

   root@host ~> lttng list --userspace | grep frr
   PID: 11157 - Name: /usr/lib/frr/bgpd
         frr_libfrr:route_node_get (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:list_sort (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:list_delete_node (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:list_remove (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:list_add (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:memfree (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:memalloc (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:frr_pthread_stop (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:frr_pthread_run (loglevel: TRACE_DEBUG_LINE (13)) (type: tracepoint)
         frr_libfrr:thread_call (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:thread_cancel_async (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:thread_cancel (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:schedule_write (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:schedule_read (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:schedule_event (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:schedule_timer (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:hash_release (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:hash_insert (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_libfrr:hash_get (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:output_filter (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:input_filter (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:process_update (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:packet_read (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:refresh_process (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:capability_process (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:notification_process (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:update_process (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:keepalive_process (loglevel: TRACE_INFO (6)) (type: tracepoint)
         frr_bgp:open_process (loglevel: TRACE_INFO (6)) (type: tracepoint)

When using LTTng, you can also get zlogs as trace events by enabling
the ``lttng_ust_tracelog:*`` event class.

To see available SystemTap USDT probes, run::

   stap -L 'process("/usr/lib/frr/bgpd").mark("*")'

Example::

   root@host ~> stap -L 'process("/usr/lib/frr/bgpd").mark("*")'
   process("/usr/lib/frr/bgpd").mark("capability_process") $arg1:long $arg2:long
   process("/usr/lib/frr/bgpd").mark("input_filter") $arg1:long $arg2:long $arg3:long $arg4:long $arg5:long
   process("/usr/lib/frr/bgpd").mark("keepalive_process") $arg1:long $arg2:long
   process("/usr/lib/frr/bgpd").mark("notification_process") $arg1:long $arg2:long
   process("/usr/lib/frr/bgpd").mark("open_process") $arg1:long $arg2:long
   process("/usr/lib/frr/bgpd").mark("output_filter") $arg1:long $arg2:long $arg3:long $arg4:long $arg5:long
   process("/usr/lib/frr/bgpd").mark("packet_read") $arg1:long $arg2:long
   process("/usr/lib/frr/bgpd").mark("process_update") $arg1:long $arg2:long $arg3:long $arg4:long $arg5:long $arg6:long
   process("/usr/lib/frr/bgpd").mark("refresh_process") $arg1:long $arg2:long
   process("/usr/lib/frr/bgpd").mark("update_process") $arg1:long $arg2:long

When using SystemTap, you can also easily attach to an existing function::

   stap -L 'process("/usr/lib/frr/bgpd").function("bgp_update_receive")'

Example::

   root@host ~> stap -L 'process("/usr/lib/frr/bgpd").function("bgp_update_receive")'
   process("/usr/lib/frr/bgpd").function("bgp_update_receive@bgpd/bgp_packet.c:1531") $peer:struct peer* $size:bgp_size_t $attr:struct attr $restart:_Bool $nlris:struct bgp_nlri[] $__func__:char const[] const

Complete ``bgp.stp`` example using SystemTap to show BGP peer, prefix and aspath
using ``process_update`` USDT::

   global pkt_size;
   probe begin
   {
     ansi_clear_screen();
     println("Starting...");
   }
   probe process("/usr/lib/frr/bgpd").function("bgp_update_receive")
   {
     pkt_size <<< $size;
   }
   probe process("/usr/lib/frr/bgpd").mark("process_update")
   {
     aspath = @cast($arg6, "attr")->aspath;
     printf("> %s via %s (%s)\n",
       user_string($arg2),
       user_string(@cast($arg1, "peer")->host),
       user_string(@cast(aspath, "aspath")->str));
   }
   probe end
   {
     if (@count(pkt_size))
       print(@hist_linear(pkt_size, 0, 20, 2));
   }

Output::

   Starting...
   > 192.168.0.0/24 via 192.168.0.1 (65534)
   > 192.168.100.1/32 via 192.168.0.1 (65534)
   > 172.16.16.1/32 via 192.168.0.1 (65534 65030)
   ^Cvalue |-------------------------------------------------- count
       0 |                                                   0
       2 |                                                   0
       4 |@                                                  1
       6 |                                                   0
       8 |                                                   0
         ~
     18 |                                                   0
     20 |                                                   0
     >20 |@@@@@                                              5


Concepts
--------

Tracepoints are statically defined points in code where a developer has
determined that outside observers might gain something from knowing what is
going on at that point. It's like logging but with the ability to dump large
amounts of internal data with much higher performance. LTTng has a good summary
`here <https://lttng.org/docs/#doc-what-is-tracing>`_.

Each tracepoint has a "provider" and name. The provider is basically a
namespace; for example, ``bgpd`` uses the provider name ``frr_bgp``. The name
is arbitrary, but because providers share a global namespace on the user's
system, all providers from FRR should be prefixed by ``frr_``. The tracepoint
name is just the name of the event. Events are globally named by their provider
and name. For example, the event when BGP reads a packet from a peer is
``frr_bgp:packet_read``.

To do tracing, the tracing tool of choice is told which events to listen to.
For example, to listen to all events from FRR's BGP implementation, you would
enable the events ``frr_bgp:*``. In the same tracing session you could also
choose to record all memory allocations by enabling the ``malloc`` tracepoints
in ``libc`` as well as all kernel skb operations using the various in-kernel
tracepoints. This allows you to build as complete a view as desired of what the
system is doing during the tracing window (subject to what tracepoints are
available).

Of particular use are the tracepoints for FRR's internal event scheduler;
tracing these allows you to see all events executed by all event loops for the
target(s) in question. Here's a couple events selected from a trace of BGP
during startup::

   ...

   [18:41:35.750131763] (+0.000048901) host frr_libfrr:thread_call: { cpu_id =
   1 }, { threadmaster_name = "default", function_name = "zclient_connect",
   scheduled_from = "lib/zclient.c", scheduled_on_line = 3877, thread_addr =
   0x0, file_descriptor = 0, event_value = 0, argument_ptr = 0xA37F70, timer =
   0 }

   [18:41:35.750175124] (+0.000020001) host frr_libfrr:thread_call: { cpu_id =
   1 }, { threadmaster_name = "default", function_name = "frr_config_read_in",
   scheduled_from = "lib/libfrr.c", scheduled_on_line = 934, thread_addr = 0x0,
   file_descriptor = 0, event_value = 0, argument_ptr = 0x0, timer = 0 }

   [18:41:35.753341264] (+0.000010532) host frr_libfrr:thread_call: { cpu_id =
   1 }, { threadmaster_name = "default", function_name = "bgp_event",
   scheduled_from = "bgpd/bgpd.c", scheduled_on_line = 142, thread_addr = 0x0,
   file_descriptor = 2, event_value = 2, argument_ptr = 0xE4D780, timer = 2 }

   [18:41:35.753404186] (+0.000004910) host frr_libfrr:thread_call: { cpu_id =
   1 }, { threadmaster_name = "default", function_name = "zclient_read",
   scheduled_from = "lib/zclient.c", scheduled_on_line = 3891, thread_addr =
   0x0, file_descriptor = 40, event_value = 40, argument_ptr = 0xA37F70, timer
   = 40 }

   ...


Very useful for getting a time-ordered look into what the process is doing.


Adding Tracepoints
------------------

Adding new tracepoints is a two step process:

1. Define the tracepoint
2. Use the tracepoint

Tracepoint definitions state the "provider" and name of the tracepoint, along
with any values it will produce, and how to format them. This is done with
macros provided by LTTng. USDT probes do not use definitions and are inserted
at the trace site with a single macro. However, to maintain support for both
platforms, you must define an LTTng tracepoint when adding a new one.
``frrtrace()`` will expand to the appropriate ``DTRACE_PROBEn`` macro when USDT
is in use.

If you are adding new tracepoints to a daemon that has no tracepoints, that
daemon's ``subdir.am`` must be updated to conditionally link ``lttng-ust``.
Look at ``bgpd/subdir.am`` for an example of how to do this; grep for
``UST_LIBS``. Create new files named ``<daemon>_trace.[ch]``. Use
``bgpd/bgp_trace.[h]`` as boilerplate. If you are adding tracepoints to a
daemon that already has them, look for the ``<daemon>_trace.h`` file;
tracepoints are written here.

Refer to the `LTTng developer docs
<https://lttng.org/docs/#doc-c-application>`_ for details on how to define
tracepoints.

To use them, simply add a call to ``frrtrace()`` at the point you'd like the
event to be emitted, like so:

.. code-block:: c

   ...

   switch (type) {
   case BGP_MSG_OPEN:
           frrtrace(2, frr_bgp, open_process, peer, size); /* tracepoint */
           atomic_fetch_add_explicit(&peer->open_in, 1,
                                     memory_order_relaxed);
           mprc = bgp_open_receive(peer, size);

   ...

After recompiling this tracepoint will now be available, either as a USDT probe
or LTTng tracepoint, depending on your compilation choice.


trace.h
^^^^^^^

Because FRR supports multiple types of tracepoints, the code for creating them
abstracts away the underlying system being used. This abstraction code is in
``lib/trace.h``. There are 2 function-like macros that are used for working
with tracepoints.

- ``frrtrace()`` defines tracepoints
- ``frrtrace_enabled()`` checks whether a tracepoint is enabled

There is also ``frrtracelog()``, which is used in zlog core code to make zlog
messages available as trace events to LTTng. This should not be used elsewhere.

There is additional documentation in the header. The key thing to note is that
you should never include ``trace.h`` in source where you plan to put
tracepoints; include the tracepoint definition header instead (e.g.
:file:`bgp_trace.h`).


Limitations
-----------

Tracers do not like ``fork()`` or ``dlopen()``. LTTng has some workarounds for
this involving interceptor libraries using ``LD_PRELOAD``.

If you're running FRR in a typical daemonizing way (``-d`` to the daemons)
you'll need to run the daemons like so:

.. code-block:: shell

   LD_PRELOAD=liblttng-ust-fork.so <daemon>


If you're using systemd this you can accomplish this for all daemons by
modifying ``frr.service`` like so:

.. code-block:: diff

   --- a/frr.service
   +++ b/frr.service
   @@ -7,6 +7,7 @@ Before=network.target
    OnFailure=heartbeat-failed@%n

    [Service]
   +Environment="LD_PRELOAD=liblttng-ust-fork.so"
    Nice=-5
    Type=forking
    NotifyAccess=all


USDT tracepoints are relatively high overhead and probably shouldn't be used
for "flight recorder" functionality, i.e. enabling and passively recording all
events for monitoring purposes. It's generally okay to use LTTng like this,
though.
