.. _sharp:

*****
SHARP
*****

:abbr:`SHARP (Super Happy Advanced Routing Process)` is a daemon that provides
miscellaneous functionality used for testing FRR and creating proof-of-concept
labs.

.. _starting-sharp:

Starting SHARP
==============

Default configuration file for *sharpd* is :file:`sharpd.conf`.  The typical
location of :file:`sharpd.conf` is |INSTALL_PREFIX_ETC|/sharpd.conf.

If the user is using integrated config, then :file:`sharpd.conf` need not be
present and the :file:`frr.conf` is read instead.

.. program:: sharpd

:abbr:`SHARP` supports all the common FRR daemon start options which are
documented elsewhere.

.. _using-sharp:

Using SHARP
===========

All sharp commands are under the enable node and preceeded by the ``sharp``
keyword. At present, no sharp commands will be preserved in the config.

.. index:: sharp install
.. clicmd:: sharp install routes A.B.C.D <nexthop <E.F.G.H|X:X::X:X>|nexthop-group NAME> (1-1000000) [instance (0-255)] [repeat (2-1000)]

   Install up to 1,000,000 (one million) /32 routes starting at ``A.B.C.D``
   with specified nexthop ``E.F.G.H`` or ``X:X::X:X``. The nexthop is
   a ``NEXTHOP_TYPE_IPV4`` or ``NEXTHOP_TYPE_IPV6`` and must be reachable
   to be installed into the kernel. Alternatively a nexthop-group NAME
   can be specified and used as the nexthops.  The routes are installed into
   zebra as ``ZEBRA_ROUTE_SHARP`` and can be used as part of a normal route
   redistribution. Route installation time is noted in the debug
   log. When zebra successfully installs a route into the kernel and SHARP
   receives success notifications for all routes this is logged as well.
   Instance (0-255) if specified causes the routes to be installed in a different
   instance. If repeat is used then we will install/uninstall the routes the
   number of times specified.

.. index:: sharp remove
.. clicmd:: sharp remove routes A.B.C.D (1-1000000)

   Remove up to 1,000,000 (one million) /32 routes starting at ``A.B.C.D``. The
   routes are removed from zebra. Route deletion start is noted in the debug
   log and when all routes have been successfully deleted the debug log will be
   updated with this information as well.

.. index:: sharp data route
.. clicmd:: sharp data route

   Allow end user doing route install and deletion to get timing information
   from the vty or vtysh instead of having to read the log file.  This command
   is informational only and you should look at sharp_vty.c for explanation
   of the output as that it may change.

.. index:: sharp label
.. clicmd:: sharp label <ipv4|ipv6> vrf NAME label (0-1000000)

   Install a label into the kernel that causes the specified vrf NAME table to
   be used for pop and forward operations when the specified label is seen.

.. index:: sharp watch
.. clicmd:: [no] sharp watch <nexthop|import> <A.B.C.D|X:X::X:X> [connected]

   Instruct zebra to monitor and notify sharp when the specified nexthop is
   changed. The notification from zebra is written into the debug log.
   The nexthop or import choice chooses the type of nexthop we are asking
   zebra to watch for us.  This choice affects zebra's decision on what
   matches.  Connected tells zebra whether or not that we want the route
   matched against to be a static or connected route.  The no form of
   the command obviously turns this watching off.

.. index:: sharp data nexthop
.. clicmd:: sharp data nexthop

   Allow end user to dump associated data with the nexthop tracking that
   may have been turned on.
