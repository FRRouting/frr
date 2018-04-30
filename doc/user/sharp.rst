.. _sharp:

***
SHARP
***

:abbr:`SHARP` Super Happy Advanced Routing Process.  This daemon is useful
for the testing of FRR itself as well as useful for creation of Proof of
Concept labs.
      
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

USING SHARP
===========

All sharp commands are under the enable node and proceeded by the
:abbr:`sharp` keyword.  There are currently no permenent sharp
commands for configuration.

..index:: sharp install
..clicmd:: sharp install routes A.B.C.D nexthop E.F.G.H (1-1000000)

Install up to a million /32 routes starting at A.B.C.D with specified nexthop
E.F.G.H.  The nexthop is a NEXTHOP_TYPE_IPV4 and must be reachable to be
installed into the kernel.  The routes are installed into zebra as
ZEBRA_ROUTE_SHARP and can be used as part of a normal route redistribution.
Route installation time is noted in the debug log and upon zebra successful
installation into the kernel and sharp receiving the notification of all
route installs the success will be noted in the debug log as well.

..index:: sharp remove
..clicmd:: sharp remove routes A.B.C.D (1-1000000)

Remove up 1000000 million /32 routes starting at A.B.C.D.  The routes are
removed from zebra.  Route deletion start is noted in the debug log
and when all routes have been successfully deleted the debug log will
be updated with this information as well.

..index:: sharp label
..clicmd:: sharp label <ipv4|ipv6> vrf NAME label (0-1000000)

Install a label into the kernel that causes the specified vrf NAME table to be
used for pop and forward operations when the specified label is seen.

..index:: sharp watch
..clicmd: sharp watch nexthop <A.B.C.D|X:X::X:X>

Instruct zebra to monitor and notify sharp when the specified nexthop is
changed.  The notification from zebra is written into the debug log.


