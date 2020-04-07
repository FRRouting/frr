.. _logging:

Logging
=======

One of the most frequent decisions to make while writing code for FRR is what
to log, what level to log it at, and when to log it.  Here is a list of
recommendations for these decisions.


printfrr()
----------

``printfrr()`` is FRR's modified version of ``printf()``, designed to make
life easier when printing nontrivial datastructures.  The following variants
are available:

.. c:function:: ssize_t snprintfrr(char *buf, size_t len, const char *fmt, ...)
.. c:function:: ssize_t vsnprintfrr(char *buf, size_t len, const char *fmt, va_list)

   These correspond to ``snprintf``/``vsnprintf``.  If you pass NULL for buf
   or 0 for len, no output is written but the return value is still calculated.

   The return value is always the full length of the output, unconstrained by
   `len`.  It does **not** include the terminating ``\0`` character.  A
   malformed format string can result in a ``-1`` return value.

.. c:function:: ssize_t csnprintfrr(char *buf, size_t len, const char *fmt, ...)
.. c:function:: ssize_t vcsnprintfrr(char *buf, size_t len, const char *fmt, va_list)

   Same as above, but the ``c`` stands for "continue" or "concatenate".  The
   output is appended to the string instead of overwriting it.

.. c:function:: char *asprintfrr(struct memtype *mt, const char *fmt, ...)
.. c:function:: char *vasprintfrr(struct memtype *mt, const char *fmt, va_list)

   These functions allocate a dynamic buffer (using MTYPE `mt`) and print to
   that.  If the format string is malformed, they return a copy of the format
   string, so the return value is always non-NULL and always dynamically
   allocated with `mt`.

.. c:function:: char *asnprintfrr(struct memtype *mt, char *buf, size_t len, const char *fmt, ...)
.. c:function:: char *vasnprintfrr(struct memtype *mt, char *buf, size_t len, const char *fmt, va_list)

   This variant tries to use the static buffer provided, but falls back to
   dynamic allocation if it is insufficient.

   The return value can be either `buf` or a newly allocated string using
   `mt`.  You MUST free it like this::

      char *ret = asnprintfrr(MTYPE_FOO, buf, sizeof(buf), ...);
      if (ret != buf)
         XFREE(MTYPE_FOO, ret);

Extensions
^^^^^^^^^^

``printfrr()`` format strings can be extended with suffixes after `%p` or
`%d`.  The following extended format specifiers are available:

+-----------+--------------------------+----------------------------------------------+
| Specifier | Argument                 | Output                                       |
+===========+==========================+==============================================+
| ``%Lu``   | ``uint64_t``             | ``12345``                                    |
+-----------+--------------------------+----------------------------------------------+
| ``%Ld``   | ``int64_t``              | ``-12345``                                   |
+-----------+--------------------------+----------------------------------------------+
| ``%pI4``  | ``struct in_addr *``     | ``1.2.3.4``                                  |
|           |                          |                                              |
|           | ``in_addr_t *``          |                                              |
+-----------+--------------------------+----------------------------------------------+
| ``%pI6``  | ``struct in6_addr *``    | ``fe80::1234``                               |
+-----------+--------------------------+----------------------------------------------+
| ``%pFX``  | ``struct prefix *``      | ``fe80::1234/64``                            |
+-----------+--------------------------+----------------------------------------------+
| ``%pSG4`` | ``struct prefix_sg *``   | ``(*,1.2.3.4)``                              |
+-----------+--------------------------+----------------------------------------------+
| ``%pRN``  | ``struct route_node *``  | ``192.168.1.0/24`` (dst-only node)           |
|           |                          |                                              |
|           |                          | ``2001:db8::/32 from fe80::/64`` (SADR node) |
+-----------+--------------------------+----------------------------------------------+
| ``%pNHv`` | ``struct nexthop *``     | ``1.2.3.4, via eth0``                        |
+-----------+--------------------------+----------------------------------------------+
| ``%pNHs`` | ``struct nexthop *``     | ``1.2.3.4 if 15``                            |
+-----------+--------------------------+----------------------------------------------+

Printf features like field lengths can be used normally with these extensions,
e.g. ``%-15pI4`` works correctly.

The extension specifier after ``%p`` or ``%d`` is always an uppercase letter;
by means of established pattern uppercase letters and numbers form the type
identifier which may be followed by lowercase flags.

You can grep the FRR source for ``printfrr_ext_autoreg`` to see all extended
printers and what exactly they do.  More printers are likely to be added as
needed/useful, so the list above may become outdated.

``%Ld`` is not an "extension" for printfrr; it's wired directly into the main
printf logic.

.. note::

   The ``zlog_*``/``flog_*`` and ``vty_out`` functions all use printfrr
   internally, so these extensions are available there.  However, they are
   **not** available when calling ``snprintf`` directly.  You need to call
   ``snprintfrr`` instead.

AS-Safety
^^^^^^^^^

``printfrr()`` are AS-Safe under the following conditions:

* the ``[v]as[n]printfrr`` variants are not AS-Safe (allocating memory)
* floating point specifiers are not AS-Safe (system printf is used for these)
* the positional ``%1$d`` syntax should not be used (8 arguments are supported
  while AS-Safe)
* extensions are only AS-Safe if their printer is AS-Safe

Log levels
----------

Errors and warnings
^^^^^^^^^^^^^^^^^^^

If it is something that the user will want to look at and maybe do
something, it is either an **error** or a **warning**.

We're expecting that warnings and errors are in some way visible to the
user (in the worst case by looking at the log after the network broke, but
maybe by a syslog collector from all routers.)  Therefore, anything that
needs to get the user in the loop—and only these things—are warnings or
errors.

Note that this doesn't necessarily mean the user needs to fix something in
the FRR instance.  It also includes when we detect something else needs
fixing, for example another router, the system we're running on, or the
configuration.  The common point is that the user should probably do
*something*.

Deciding between a warning and an error is slightly less obvious; the rule
of thumb here is that an error will cause considerable fallout beyond its
direct effect.  Closing a BGP session due to a malformed update is an error
since all routes from the peer are dropped; discarding one route because
its attributes don't make sense is a warning.

This also loosely corresponds to the kind of reaction we're expecting from
the user.  An error is likely to need immediate response while a warning
might be snoozed for a bit and addressed as part of general maintenance.
If a problem will self-repair (e.g. by retransmits), it should be a
warning—unless the impact until that self-repair is very harsh.

Examples for warnings:

* a BGP update, LSA or LSP could not be processed, but operation is
  proceeding and the broken pieces are likely to self-fix later
* some kind of controller cannot be reached, but we can work without it
* another router is using some unknown or unsupported capability

Examples for errors:

* dropping a BGP session due to malformed data
* a socket for routing protocol operation cannot be opened
* desynchronization from network state because something went wrong
* *everything that we as developers would really like to be notified about,
  i.e. some assumption in the code isn't holding up*


Informational messages
^^^^^^^^^^^^^^^^^^^^^^

Anything that provides introspection to the user during normal operation
is an **info** message.

This includes all kinds of operational state transitions and events,
especially if they might be interesting to the user during the course of
figuring out a warning or an error.

By itself, these messages should mostly be statements of fact.  They might
indicate the order and relationship in which things happened.  Also covered
are conditions that might be "operational issues" like a link failure due
to an unplugged cable.  If it's pretty much the point of running a routing
daemon for, it's not a warning or an error, just business as usual.

The user should be able to see the state of these bits from operational
state output, i.e. `show interface` or `show foobar neighbors`.  The log
message indicating the change may have been printed weeks ago, but the
state can always be viewed.  (If some state change has an info message but
no "show" command, maybe that command needs to be added.)

Examples:

* all kinds of up/down state changes

  * interface coming up or going down
  * addresses being added or deleted
  * peers and neighbors coming up or going down

* rejection of some routes due to user-configured route maps
* backwards compatibility handling because another system on the network
  has a different or smaller feature set

.. note::
   The previously used **notify** priority is replaced with *info* in all
   cases.  We don't currently have a well-defined use case for it.


Debug messages and asserts
^^^^^^^^^^^^^^^^^^^^^^^^^^

Everything that is only interesting on-demand, or only while developing,
is a **debug** message.  It might be interesting to the user for a
particularly evasive issue, but in general these are details that an
average user might not even be able to make sense of.

Most (or all?) debug messages should be behind a `debug foobar` category
switch that controls which subset of these messages is currently
interesting and thus printed.  If a debug message doesn't have such a
guard, there should be a good explanation as to why.

Conversely, debug messages are the only thing that should be guarded by
these switches.  Neither info nor warning or error messages should be
hidden in this way.

**Asserts** should only be used as pretty crashes.  We are expecting that
asserts remain enabled in production builds, but please try to not use
asserts in a way that would cause a security problem if the assert wasn't
there (i.e. don't use them for length checks.)

The purpose of asserts is mainly to help development and bug hunting.  If
the daemon crashes, then having some more information is nice, and the
assert can provide crucial hints that cut down on the time needed to track
an issue.  That said, if the issue can be reasonably handled and/or isn't
going to crash the daemon, it shouldn't be an assert.

For anything else where internal constraints are violated but we're not
breaking due to it, it's an error instead (not a debug.)  These require
"user action" of notifying the developers.

Examples:

* mismatched :code:`prev`/:code:`next` pointers in lists
* some field that is absolutely needed is :code:`NULL`
* any other kind of data structure corruption that will cause the daemon
  to crash sooner or later, one way or another

Thread-local buffering
----------------------

The core logging code in :file:`lib/zlog.c` allows setting up per-thread log
message buffers in order to improve logging performance.  The following rules
apply for this buffering:

* Only messages of priority *DEBUG* or *INFO* are buffered.
* Any higher-priority message causes the thread's entire buffer to be flushed,
  thus message ordering is preserved on a per-thread level.
* There is no guarantee on ordering between different threads;  in most cases
  this is arbitrary to begin with since the threads essentially race each
  other in printing log messages.  If an order is established with some
  synchronization primitive, add calls to :c:func:`zlog_tls_buffer_flush()`.
* The buffers are only ever accessed by the thread they are created by.  This
  means no locking is necessary.

Both the main/default thread and additional threads created by
:c:func:`frr_pthread_new()` with the default :c:func:`frr_run()` handler will
initialize thread-local buffering and call :c:func:`zlog_tls_buffer_flush()`
when idle.

If some piece of code runs for an extended period, it may be useful to insert
calls to :c:func:`zlog_tls_buffer_flush()` in appropriate places:

.. c:function:: void zlog_tls_buffer_flush(void)

   Write out any pending log messages that the calling thread may have in its
   buffer.  This function is safe to call regardless of the per-thread log
   buffer being set up / in use or not.

When working with threads that do not use the :c:type:`struct thread_master`
event loop, per-thread buffers can be managed with:

.. c:function:: void zlog_tls_buffer_init(void)

   Set up thread-local buffering for log messages.  This function may be
   called repeatedly without adverse effects, but remember to call
   :c:func:`zlog_tls_buffer_fini()` at thread exit.

   .. warning::

      If this function is called, but :c:func:`zlog_tls_buffer_flush()` is
      not used, log message output will lag behind since messages will only be
      written out when the buffer is full.

      Exiting the thread without calling :c:func:`zlog_tls_buffer_fini()`
      will cause buffered log messages to be lost.

.. c:function:: void zlog_tls_buffer_fini(void)

   Flush pending messages and tear down thread-local log message buffering.
   This function may be called repeatedly regardless of whether
   :c:func:`zlog_tls_buffer_init()` was ever called.

Log targets
-----------

The actual logging subsystem (in :file:`lib/zlog.c`) is heavily separated
from the actual log writers.  It uses an atomic linked-list (`zlog_targets`)
with RCU to maintain the log targets to be called.  This list is intended to
function as "backend" only, it **is not used for configuration**.

Logging targets provide their configuration layer on top of this and maintain
their own capability to enumerate and store their configuration.  Some targets
(e.g. syslog) are inherently single instance and just stuff their config in
global variables.  Others (e.g. file/fd output) are multi-instance capable.
There is another layer boundary here between these and the VTY configuration
that they use.

Basic internals
^^^^^^^^^^^^^^^

.. c:type:: struct zlog_target

   This struct needs to be filled in by any log target and then passed to
   :c:func:`zlog_target_replace()`.  After it has been registered,
   **RCU semantics apply**.  Most changes to associated data should make a
   copy, change that, and then replace the entire struct.

   Additional per-target data should be "appended" by embedding this struct
   into a larger one, for use with `containerof()`, and
   :c:func:`zlog_target_clone()` and :c:func:`zlog_target_free()` should be
   used to allocate/free the entire container struct.

   Do not use this structure to maintain configuration.  It should only
   contain (a copy of) the data needed to perform the actual logging.  For
   example, the syslog target uses this:

   .. code-block:: c

      struct zlt_syslog {
          struct zlog_target zt;
          int syslog_facility;
      };

      static void zlog_syslog(struct zlog_target *zt, struct zlog_msg *msgs[], size_t nmsgs)
      {
          struct zlt_syslog *zte = container_of(zt, struct zlt_syslog, zt);
          size_t i;

          for (i = 0; i < nmsgs; i++)
              if (zlog_msg_prio(msgs[i]) <= zt->prio_min)
                  syslog(zlog_msg_prio(msgs[i]) | zte->syslog_facility, "%s",
                         zlog_msg_text(msgs[i], NULL));
      }


.. c:function:: struct zlog_target *zlog_target_clone(struct memtype *mt, struct zlog_target *oldzt, size_t size)

   Allocates a logging target struct.  Note that the ``oldzt`` argument may be
   ``NULL`` to allocate a "from scratch".  If ``oldzt`` is not ``NULL``, the
   generic bits in :c:type:`struct zlog_target` are copied.  **Target specific
   bits are not copied.**

.. c:function:: struct zlog_target *zlog_target_replace(struct zlog_target *oldzt, struct zlog_target *newzt)

   Adds, replaces or deletes a logging target (either ``oldzt`` or ``newzt`` may be ``NULL``.)

   Returns ``oldzt`` for freeing.  The target remains possibly in use by
   other threads until the RCU cycle ends.  This implies you cannot release
   resources (e.g. memory, file descriptors) immediately.

   The replace operation is not atomic; for a brief period it is possible that
   messages are delivered on both ``oldzt`` and ``newzt``.

   .. warning::

      ``oldzt`` must remain **functional** until the RCU cycle ends.

.. c:function:: void zlog_target_free(struct memtype *mt, struct zlog_target *zt)

   Counterpart to :c:func:`zlog_target_clone()`, frees a target (using RCU.)

.. c:member:: void (*zlog_target.logfn)(struct zlog_target *zt, struct zlog_msg *msgs[], size_t nmsg)

   Called on a target to deliver "normal" logging messages.  ``msgs`` is an
   array of opaque structs containing the actual message.  Use ``zlog_msg_*``
   functions to access message data (this is done to allow some optimizations,
   e.g.  lazy formatting the message text and timestamp as needed.)

   .. note::

      ``logfn()`` must check each individual message's priority value against
      the configured ``prio_min``.  While the ``prio_min`` field is common to
      all targets and used by the core logging code to early-drop unneeded log
      messages, the array is **not** filtered for each ``logfn()`` call.

.. c:member:: void (*zlog_target.logfn_sigsafe)(struct zlog_target *zt, const char *text, size_t len)

   Called to deliver "exception" logging messages (i.e. SEGV messages.)
   Must be Async-Signal-Safe (may not allocate memory or call "complicated"
   libc functions.)  May be ``NULL`` if the log target cannot handle this.

Standard targets
^^^^^^^^^^^^^^^^

:file:`lib/zlog_targets.c` provides the standard file / fd / syslog targets.
The syslog target is single-instance while file / fd targets can be
instantiated as needed.  There are 3 built-in targets that are fully
autonomous without any config:

- startup logging to `stderr`, until either :c:func:`zlog_startup_end()` or
  :c:func:`zlog_aux_init()` is called.
- stdout logging for non-daemon programs using :c:func:`zlog_aux_init()`
- crashlogs written to :file:`/var/tmp/frr.daemon.crashlog`

The regular CLI/command-line logging setup is handled by :file:`lib/log_vty.c`
which makes the appropriate instantiations of syslog / file / fd targets.

.. todo::

  :c:func:`zlog_startup_end()` should do an explicit switchover from
  startup stderr logging to configured logging.  Currently, configured logging
  starts in parallel as soon as the respective setup is executed.  This results
  in some duplicate logging.
