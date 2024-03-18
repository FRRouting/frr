.. _logging:

.. highlight:: c

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

.. c:function:: ssize_t bprintfrr(struct fbuf *fb, const char *fmt, ...)
.. c:function:: ssize_t vbprintfrr(struct fbuf *fb, const char *fmt, va_list)

   These are the "lowest level" functions, which the other variants listed
   above use to implement their functionality on top.  Mainly useful for
   implementing printfrr extensions since those get a ``struct fbuf *`` to
   write their output to.

.. c:macro:: FMT_NSTD(expr)

   This macro turns off/on format warnings as needed when non-ISO-C
   compatible printfrr extensions are used (e.g. ``%.*p`` or ``%Ld``.)::

      vty_out(vty, "standard compatible %pI4\n", &addr);
      FMT_NSTD(vty_out(vty, "non-standard %-47.*pHX\n", (int)len, buf));

   When the frr-format plugin is in use, this macro is a no-op since the
   frr-format plugin supports all printfrr extensions.  Since the FRR CI
   includes a system with the plugin enabled, this means format errors will
   not slip by undetected even with FMT_NSTD.

.. note::

   ``printfrr()`` does not support the ``%n`` format.  It does support ISO C23
   ``%b``, ``%w99d`` and ``%wf99d`` additions, but the latter two are not
   supported by the ``frr-format`` plugin yet, and all 3 aren't supported by
   the older compilers still in use on some supported platforms.

   ``%b`` can be used with ``FMT_NSTD``, but ``%w99d`` and ``%wf99d`` require
   work in the ``frr-format`` plugin before they are really usable.


AS-Safety
^^^^^^^^^

``printfrr()`` are AS-Safe under the following conditions:

* the ``[v]as[n]printfrr`` variants are not AS-Safe (allocating memory)
* floating point specifiers are not AS-Safe (system printf is used for these)
* the positional ``%1$d`` syntax should not be used (8 arguments are supported
  while AS-Safe)
* extensions are only AS-Safe if their printer is AS-Safe

printfrr Extensions
-------------------

``printfrr()`` format strings can be extended with suffixes after `%p` or `%d`.
Printf features like field lengths can be used normally with these extensions,
e.g. ``%-15pI4`` works correctly, **except if the extension consumes the
width or precision**.  Extensions that do so are listed below as ``%*pXX``
rather than ``%pXX``.

The extension specifier after ``%p`` or ``%d`` is always an uppercase letter;
by means of established pattern uppercase letters and numbers form the type
identifier which may be followed by lowercase flags.

You can grep the FRR source for ``printfrr_ext_autoreg`` to see all extended
printers and what exactly they do.  More printers are likely to be added as
needed/useful, so the list here may be outdated.

.. note::

   The ``zlog_*``/``flog_*`` and ``vty_out`` functions all use printfrr
   internally, so these extensions are available there.  However, they are
   **not** available when calling ``snprintf`` directly.  You need to call
   ``snprintfrr`` instead.

Networking data types
^^^^^^^^^^^^^^^^^^^^^

.. role:: frrfmtout(code)

.. frrfmt:: %pI4 (struct in_addr *, in_addr_t *)

   :frrfmtout:`1.2.3.4`

   ``%pI4s``: :frrfmtout:`*` — print star instead of ``0.0.0.0`` (for multicast)

.. frrfmt:: %pI6 (struct in6_addr *)

   :frrfmtout:`fe80::1234`

   ``%pI6s``: :frrfmtout:`*` — print star instead of ``::`` (for multicast)

.. frrfmt:: %pEA (struct ethaddr *)

   :frrfmtout:`01:23:45:67:89:ab`

.. frrfmt:: %pIA (struct ipaddr *)

   :frrfmtout:`1.2.3.4` / :frrfmtout:`fe80::1234`

   ``%pIAs``: — print star instead of zero address (for multicast)

.. frrfmt:: %pFX (struct prefix *)

   :frrfmtout:`1.2.3.0/24` / :frrfmtout:`fe80::1234/64`

   This accepts the following types:

   - :c:struct:`prefix`
   - :c:struct:`prefix_ipv4`
   - :c:struct:`prefix_ipv6`
   - :c:struct:`prefix_eth`
   - :c:struct:`prefix_evpn`
   - :c:struct:`prefix_fs`

   It does **not** accept the following types:

   - :c:struct:`prefix_ls`
   - :c:struct:`prefix_rd`
   - :c:struct:`prefix_sg` (use :frrfmt:`%pPSG4`)
   - :c:union:`prefixptr` (dereference to get :c:struct:`prefix`)
   - :c:union:`prefixconstptr` (dereference to get :c:struct:`prefix`)

   Options:

   ``%pFXh``: (address only) :frrfmtout:`1.2.3.0` / :frrfmtout:`fe80::1234`

.. frrfmt:: %pPSG4 (struct prefix_sg *)

   :frrfmtout:`(*,1.2.3.4)`

   This is *(S,G)* output for use in zebra.  (Note prefix_sg is not a prefix
   "subclass" like the other prefix_* structs.)

.. frrfmt:: %pSU (union sockunion *)

   ``%pSU``: :frrfmtout:`1.2.3.4` / :frrfmtout:`fe80::1234`

   ``%pSUs``: :frrfmtout:`1.2.3.4` / :frrfmtout:`fe80::1234%89`
   (adds IPv6 scope ID as integer)

   ``%pSUp``: :frrfmtout:`1.2.3.4:567` / :frrfmtout:`[fe80::1234]:567`
   (adds port)

   ``%pSUps``: :frrfmtout:`1.2.3.4:567` / :frrfmtout:`[fe80::1234%89]:567`
   (adds port and scope ID)

.. frrfmt:: %pRN (struct route_node *, struct bgp_node *, struct agg_node *)

   :frrfmtout:`192.168.1.0/24` (dst-only node)

   :frrfmtout:`2001:db8::/32 from fe80::/64` (SADR node)

.. frrfmt:: %pNH (struct nexthop *)

   ``%pNHvv``: :frrfmtout:`via 1.2.3.4, eth0` — verbose zebra format

   ``%pNHv``: :frrfmtout:`1.2.3.4, via eth0` — slightly less verbose zebra format

   ``%pNHs``: :frrfmtout:`1.2.3.4 if 15` — same as :c:func:`nexthop2str()`

   ``%pNHcg``: :frrfmtout:`1.2.3.4` — compact gateway only

   ``%pNHci``: :frrfmtout:`eth0` — compact interface only

.. frrfmt:: %dPF (int)

   :frrfmtout:`AF_INET`

   Prints an `AF_*` / `PF_*` constant.  ``PF`` is used here to avoid confusion
   with `AFI` constants, even though the FRR codebase prefers `AF_INET` over
   `PF_INET` & co.

.. frrfmt:: %dSO (int)

   :frrfmtout:`SOCK_STREAM`

Time/interval formats
^^^^^^^^^^^^^^^^^^^^^

.. frrfmt:: %pTS (struct timespec *)

.. frrfmt:: %pTV (struct timeval *)

.. frrfmt:: %pTT (time_t *)

   Above 3 options internally result in the same code being called, support
   the same flags and produce equal output with one exception:  ``%pTT``
   has no sub-second precision and the formatter will never print a
   (nonsensical) ``.000``.

   Exactly one of ``I``, ``M`` or ``R`` must immediately follow after
   ``TS``/``TV``/``TT`` to specify whether the input is an interval, monotonic
   timestamp or realtime timestamp:

   ``%pTVI``: input is an interval, not a timestamp.  Print interval.

   ``%pTVIs``: input is an interval, convert to wallclock by subtracting it
   from current time (i.e. interval has passed **s**\ ince.)

   ``%pTVIu``: input is an interval, convert to wallclock by adding it to
   current time (i.e. **u**\ ntil interval has passed.)

   ``%pTVM`` - input is a timestamp on CLOCK_MONOTONIC, convert to wallclock
   time (by grabbing current CLOCK_MONOTONIC and CLOCK_REALTIME and doing the
   math) and print calendaric date.

   ``%pTVMs`` - input is a timestamp on CLOCK_MONOTONIC, print interval
   **s**\ ince that timestamp (elapsed.)

   ``%pTVMu`` - input is a timestamp on CLOCK_MONOTONIC, print interval
   **u**\ ntil that timestamp (deadline.)

   ``%pTVR`` - input is a timestamp on CLOCK_REALTIME, print calendaric date.

   ``%pTVRs`` - input is a timestamp on CLOCK_REALTIME, print interval
   **s**\ ince that timestamp.

   ``%pTVRu`` - input is a timestamp on CLOCK_REALTIME, print interval
   **u**\ ntil that timestamp.

   ``%pTVA`` - reserved for CLOCK_TAI in case a PTP implementation is
   interfaced to FRR.  Not currently implemented.

   .. note::

      If ``%pTVRs`` or ``%pTVRu`` are used, this is generally an indication
      that a CLOCK_MONOTONIC timestamp should be used instead (or added in
      parallel.) CLOCK_REALTIME might be adjusted by NTP, PTP or similar
      procedures, causing bogus intervals to be printed.

      ``%pTVM`` on first look might be assumed to have the same problem, but
      on closer thought the assumption is always that current system time is
      correct.  And since a CLOCK_MONOTONIC interval is also quite safe to
      assume to be correct, the (past) absolute timestamp to be printed from
      this can likely be correct even if it doesn't match what CLOCK_REALTIME
      would have indicated at that point in the past.  This logic does,
      however, not quite work for *future* times.

      Generally speaking, almost all use cases in FRR should (and do) use
      CLOCK_MONOTONIC (through :c:func:`monotime()`.)

   Flags common to printing calendar times and intervals:

   ``p``: include spaces in appropriate places (depends on selected format.)

   ``%p.3TV...``: specify sub-second resolution (use with ``FMT_NSTD`` to
   suppress gcc warning.)  As noted above, ``%pTT`` will never print sub-second
   digits since there are none.  Only some formats support printing sub-second
   digits and the default may vary.

   The following flags are available for printing calendar times/dates:

   (no flag): :frrfmtout:`Sat Jan  1 00:00:00 2022` - print output from
   ``ctime()``, in local time zone.  Since FRR does not currently use/enable
   locale support, this is always the C locale.  (Locale support getting added
   is unlikely for the time being and would likely break other things worse
   than this.)

   ``i``: :frrfmtout:`2022-01-01T00:00:00.123` - ISO8601 timestamp in local
   time zone (note there is no ``Z`` or ``+00:00`` suffix.)  Defaults to
   millisecond precision.

   ``ip``: :frrfmtout:`2022-01-01 00:00:00.123` - use readable form of ISO8601
   with space instead of ``T`` separator.

   The following flags are available for printing intervals:

   (no flag): :frrfmtout:`9w9d09:09:09.123` - does not match any
   preexisting format;  added because it does not lose precision (like ``t``)
   for longer intervals without printing huge numbers (like ``h``/``m``).
   Defaults to millisecond precision.  The week/day fields are left off if
   they're zero, ``p`` adds a space after the respective letter.

   ``t``: :frrfmtout:`9w9d09h`, :frrfmtout:`9d09h09m`, :frrfmtout:`09:09:09` -
   this replaces :c:func:`frrtime_to_interval()`.  ``p`` adds spaces after
   week/day/hour letters.

   ``d``: print decimal number of seconds.  Defaults to millisecond precision.

   ``x`` / ``tx`` / ``dx``: Like no flag / ``t`` / ``d``, but print
   :frrfmtout:`-` for zero or negative intervals (for use with unset timers.)

   ``h``: :frrfmtout:`09:09:09`

   ``hx``: :frrfmtout:`09:09:09`, :frrfmtout:`--:--:--` - this replaces
   :c:func:`pim_time_timer_to_hhmmss()`.

   ``m``: :frrfmtout:`09:09`

   ``mx``: :frrfmtout:`09:09`, :frrfmtout:`--:--` - this replaces
   :c:func:`pim_time_timer_to_mmss()`.

FRR library helper formats
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. frrfmt:: %pTH (struct event *)

   Print remaining time on timer event. Interval-printing flag characters
   listed above for ``%pTV`` can be added, e.g. ``%pTHtx``.

   ``NULL`` pointers are printed as ``-``.

.. frrfmt:: %pTHD (struct event *)

   Print debugging information for given event.  Sample output:

   .. code-block:: none

      {(thread *)NULL}
      {(thread *)0x55a3b5818910 arg=0x55a3b5827c50 timer  r=7.824      mld_t_query() &mld_ifp->t_query from pimd/pim6_mld.c:1369}
      {(thread *)0x55a3b5827230 arg=0x55a3b5827c50 read   fd=16        mld_t_recv() &mld_ifp->t_recv from pimd/pim6_mld.c:1186}

   (The output is aligned to some degree.)

FRR daemon specific formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following formats are only available in specific daemons, as the code
implementing them is part of the daemon, not the library.

zebra
"""""

.. frrfmt:: %pZN (struct route_node *)

   Print information for a RIB node, including zebra-specific data.

   :frrfmtout:`::/0 src fe80::/64 (MRIB)` (``%pZN``)

   :frrfmtout:`1234` (``%pZNt`` - table number)

bgpd
""""

.. frrfmt:: %pBD (struct bgp_dest *)

   Print prefix for a BGP destination.  When using ``--enable-dev-build`` include
   the pointer value for the bgp_dest.

   :frrfmtout:`fe80::1234/64`

.. frrfmt:: %pBP (struct peer *)

   :frrfmtout:`192.168.1.1(leaf1.frrouting.org)`

   Print BGP peer's IP and hostname together.

pimd/pim6d
""""""""""

.. frrfmt:: %pPA (pim_addr *)

   Format IP address according to IP version (pimd vs. pim6d) being compiled.

   :frrfmtout:`fe80::1234` / :frrfmtout:`10.0.0.1`

   :frrfmtout:`*` (``%pPAs`` - replace 0.0.0.0/:: with star)

.. frrfmt:: %pSG (pim_sgaddr *)

   Format S,G pair according to IP version (pimd vs. pim6d) being compiled.
   Braces are included.

   :frrfmtout:`(*,224.0.0.0)`


General utility formats
^^^^^^^^^^^^^^^^^^^^^^^

.. frrfmt:: %m (no argument)

   :frrfmtout:`Permission denied`

   Prints ``strerror(errno)``.  Does **not** consume any input argument, don't
   pass ``errno``!

   (This is a GNU extension not specific to FRR.  FRR guarantees it is
   available on all systems in printfrr, though BSDs support it in printf too.)

.. frrfmt:: %pSQ (char *)

   ([S]tring [Q]uote.)  Like ``%s``, but produce a quoted string.  Options:

      ``n`` - treat ``NULL`` as empty string instead.

      ``q`` - include ``""`` quotation marks.  Note: ``NULL`` is printed as
      ``(null)``, not ``"(null)"`` unless ``n`` is used too.  This is
      intentional.

      ``s`` - use escaping suitable for RFC5424 syslog.  This means ``]`` is
      escaped too.

   If a length is specified (``%*pSQ`` or ``%.*pSQ``), null bytes in the input
   string do not end the string and are just printed as ``\x00``.

.. frrfmt:: %pSE (char *)

   ([S]tring [E]scape.)  Like ``%s``, but escape special characters.
   Options:

      ``n`` - treat ``NULL`` as empty string instead.

   Unlike :frrfmt:`%pSQ`, this escapes many more characters that are fine for
   a quoted string but not on their own.

   If a length is specified (``%*pSE`` or ``%.*pSE``), null bytes in the input
   string do not end the string and are just printed as ``\x00``.

.. frrfmt:: %pVA (struct va_format *)

   Recursively invoke printfrr, with arguments passed in through:

   .. c:struct:: va_format

      .. c:member:: const char *fmt

         Format string to use for the recursive printfrr call.

      .. c:member:: va_list *va

         Formatting arguments.  Note this is passed as a pointer, not - as in
         most other places - a direct struct reference.  Internally uses
         ``va_copy()`` so repeated calls can be made (e.g. for determining
         output length.)

.. frrfmt:: %pFB (struct fbuf *)

   Insert text from a ``struct fbuf *``, i.e. the output of a call to
   :c:func:`bprintfrr()`.

.. frrfmt:: %*pHX (void *, char *, unsigned char *)

   ``%pHX``: :frrfmtout:`12 34 56 78`

   ``%pHXc``: :frrfmtout:`12:34:56:78` (separate with [c]olon)

   ``%pHXn``: :frrfmtout:`12345678` (separate with [n]othing)

   Insert hexdump.  This specifier requires a precision or width to be
   specified.  A precision (``%.*pHX``) takes precedence, but generates a
   compiler warning since precisions are undefined for ``%p`` in ISO C.  If
   no precision is given, the width is used instead (and normal handling of
   the width is suppressed).

   Note that width and precision are ``int`` arguments, not ``size_t``.  Use
   like::

     char *buf;
     size_t len;

     snprintfrr(out, sizeof(out), "... %*pHX ...", (int)len, buf);

     /* with padding to width - would generate a warning due to %.*p */
     FMT_NSTD(snprintfrr(out, sizeof(out), "... %-47.*pHX ...", (int)len, buf));

.. frrfmt:: %*pHS (void *, char *, unsigned char *)

   ``%pHS``: :frrfmtout:`hex.dump`

   This is a complementary format for :frrfmt:`%*pHX` to print the text
   representation for a hexdump.  Non-printable characters are replaced with
   a dot.

.. frrfmt:: %pIS (struct iso_address *)

   ([IS]o Network address) - Format ISO Network Address

   ``%pIS``: :frrfmtout:`01.0203.04O5`
   ISO Network address is printed as separated byte. The number of byte of the
   address is embeded in the `iso_net` structure.

   ``%pISl``: :frrfmtout:`01.0203.04O5.0607.0809.1011.1213.14` - long format to
   print the long version of the ISO Network address which include the System
   ID and the PSEUDO-ID of the IS-IS system

   Note that the `ISO_ADDR_STRLEN` define gives the total size of the string
   that could be used in conjunction to snprintfrr. Use like::

     char buf[ISO_ADDR_STRLEN];
     struct iso_address addr = {.addr_len = 4, .area_addr = {1, 2, 3, 4}};
     snprintfrr(buf, ISO_ADDR_STRLEN, "%pIS", &addr);

.. frrfmt:: %pSY (uint8_t *)

   (IS-IS [SY]stem ID) - Format IS-IS System ID

   ``%pSY``: :frrfmtout:`0102.0304.0506`

.. frrfmt:: %pPN (uint8_t *)

   (IS-IS [P]seudo [N]ode System ID) - Format IS-IS Pseudo Node System ID

   ``%pPN``: :frrfmtout:`0102.0304.0506.07`

.. frrfmt:: %pLS (uint8_t *)

   (IS-IS [L]sp fragment [S]ystem ID) - Format IS-IS Pseudo System ID

   ``%pLS``: :frrfmtout:`0102.0304.0506.07-08`

   Note that the `ISO_SYSID_STRLEN` define gives the total size of the string
   that could be used in conjunction to snprintfrr. Use like::

     char buf[ISO_SYSID_STRLEN];
     uint8_t id[8] = {1, 2, 3, 4 , 5 , 6 , 7, 8};
     snprintfrr(buf, SYS_ID_SIZE, "%pSY", id);


Integer formats
^^^^^^^^^^^^^^^

.. note::

   These formats currently only exist for advanced type checking with the
   ``frr-format`` GCC plugin.  They should not be used directly since they will
   cause compiler warnings when used without the plugin.  Use with
   :c:macro:`FMT_NSTD` if necessary.

   As anticipated, ISO C23 has introduced new modifiers for this, specifically
   ``%w64d`` (= ``%Ld``) and ``%w64u`` (= ``%Lu``).  Unfortunately, these new
   modifiers are not supported by ``frr-format`` yet.

.. frrfmt:: %Lu (uint64_t)

   :frrfmtout:`12345`

.. frrfmt:: %Ld (int64_t)

   :frrfmtout:`-12345`

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

When working with threads that do not use the :c:struct:`thread_master`
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

.. c:struct:: zlog_target

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
   generic bits in :c:struct:`zlog_target` are copied.  **Target specific
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
