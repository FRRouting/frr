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

.. include:: config-include.rst

.. program:: sharpd

:abbr:`SHARP` supports all the common FRR daemon start options which are
documented elsewhere.

.. _using-sharp:

Using SHARP
===========

All sharp commands are under the enable node and preceded by the ``sharp``
keyword. At present, no sharp commands will be preserved in the config.

.. clicmd:: sharp install routes A.B.C.D <nexthop <E.F.G.H|X:X::X:X>|nexthop-group NAME> (1-1000000) [instance (0-255)] [repeat (2-1000)] [opaque WORD]

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
   number of times specified.  If the keyword opaque is specified then the
   next word is sent down to zebra as part of the route installation.

.. clicmd:: sharp remove routes A.B.C.D (1-1000000)

   Remove up to 1,000,000 (one million) /32 routes starting at ``A.B.C.D``. The
   routes are removed from zebra. Route deletion start is noted in the debug
   log and when all routes have been successfully deleted the debug log will be
   updated with this information as well.

.. clicmd:: sharp data route

   Allow end user doing route install and deletion to get timing information
   from the vty or vtysh instead of having to read the log file.  This command
   is informational only and you should look at sharp_vty.c for explanation
   of the output as that it may change.

.. clicmd:: sharp label <ipv4|ipv6> vrf NAME label (0-1000000)

   Install a label into the kernel that causes the specified vrf NAME table to
   be used for pop and forward operations when the specified label is seen.

.. clicmd:: sharp watch [vrf VRF_NAME] neighbor

   Instruct zebra to notify sharpd about neighbor events in the specified vrf.
   If no vrf is specified then assume default.

.. clicmd:: sharp watch <nexthop <A.B.C.D|X:X::X:X>|import <A.B.C.D/M:X:X::X:X/M> [connected]

   Instruct zebra to monitor and notify sharp when the specified nexthop is
   changed. The notification from zebra is written into the debug log.
   The nexthop or import choice chooses the type of nexthop we are asking
   zebra to watch for us.  This choice affects zebra's decision on what
   matches.  Connected tells zebra whether or not that we want the route
   matched against to be a static or connected route for the nexthop keyword,
   for the import keyword connected means exact match.  The no form of
   the command obviously turns this watching off.

.. clicmd:: sharp data nexthop

   Allow end user to dump associated data with the nexthop tracking that
   may have been turned on.

.. clicmd:: sharp watch [vrf NAME] redistribute ROUTETYPE

   Allow end user to monitor redistributed routes of ROUTETYPE
   origin.

.. clicmd:: sharp lsp [update] (0-100000) nexthop-group NAME [prefix A.B.C.D/M TYPE [instance (0-255)]]

   Install an LSP using the specified in-label, with nexthops as
   listed in nexthop-group ``NAME``. If ``update`` is included, the
   update path is used. The LSP is installed as type ZEBRA_LSP_SHARP.
   If ``prefix`` is specified, an existing route with type ``TYPE``
   (and optional ``instance`` id) will be updated to use the LSP.

.. clicmd:: sharp remove lsp (0-100000) nexthop-group NAME [prefix A.B.C.D/M TYPE [instance (0-255)]]

   Remove a SHARPD LSP that uses the specified in-label, where the
   nexthops are specified in nexthop-group ``NAME``. If ``prefix`` is
   specified, remove label bindings from the route of type ``TYPE``
   also.

.. clicmd:: sharp send opaque type (1-255) (1-1000)

   Send opaque ZAPI messages with subtype ``type``. Sharpd will send
   a stream of messages if the count is greater than one.

.. clicmd:: sharp send opaque unicast type (1-255) PROTOCOL [{instance (0-1000) | session (1-1000)}] (1-1000)

   Send unicast opaque ZAPI messages with subtype ``type``. The
   protocol, instance, and session_id identify a single target zapi
   client. Sharpd will send a stream of messages if the count is
   greater than one.

.. clicmd:: sharp send opaque <reg | unreg> PROTOCOL [{instance (0-1000) | session (1-1000)}] type (1-1000)

   Send opaque ZAPI registration and unregistration messages for a
   single subtype. The messages must specify a protocol daemon by
   name, and can include optional zapi ``instance`` and ``session``
   values.

.. clicmd:: sharp create session (1-1024)

   Create an additional zapi client session for testing, using the
   specified session id.

.. clicmd:: sharp remove session (1-1024)

   Remove a test zapi client session that was created with the
   specified session id.

.. clicmd:: sharp neigh discover [vrf NAME] <A.B.C.D|X:X::X:X> IFNAME

   Send an ARP/NDP request to trigger the addition of a neighbor in the ARP
   table.

.. clicmd:: sharp import-te

   Import Traffic Engineering Database produced by OSPF or IS-IS.

.. clicmd:: show sharp ted [verbose|json]

.. clicmd:: show sharp ted [<vertex [A.B.C.D]|edge [A.B.C.D]|subnet [A.B.C.D/M]>] [verbose|json]

   Show imported Traffic Engineering Data Base

.. clicmd:: show sharp cspf source <A.B.C.D|X:X:X:X> destination <A.B.C.D|X:X:X:X> <metric|te-metric|delay> (0-16777215) [rsv-bw (0-7) BANDWIDTH]

   Show the result of a call to the Constraint Shortest Path First (CSPF)
   algorithm that allows to compute a path between a source and a
   destination under various constraints. Standard Metric, TE Metric, Delay
   and Bandwidth are supported constraints. Prior to use this function, it is
   necessary to import a Traffic Engineering Database with `sharp import-te`
   command (see above).

.. clicmd:: sharp install seg6-routes [vrf NAME] <A.B.C.D|X:X::X:X> nexthop-seg6 X:X::X:X encap X:X::X:X (1-1000000)

   This command installs a route for SRv6 Transit behavior (on Linux it is
   known as seg6 route). The count, destination, vrf, etc. have the same
   meaning as in the ``sharp install routes`` command.  With this command,
   sharpd will request zebra to configure seg6 route via ZEBRA_ROUTE_ADD
   ZAPI. As in the following example.

::

   router# sharp install seg6-routes 1::A nexthop-seg6 2001::2 encap A:: 1
   router# sharp install seg6-routes 1::B nexthop-seg6 2001::2 encap B:: 1

   router# show ipv6 route
   D>* 1::A/128 [150/0] via 2001::2, dum0, seg6 a::, weight 1, 00:00:01
   D>* 1::B/128 [150/0] via 2001::2, dum0, seg6 b::, weight 1, 00:00:01

   bash# ip -6 route list
   1::A  encap seg6 mode encap segs 1 [ a:: ] via 2001::2 dev dum0 proto 194 metric 20 pref medium
   1::B  encap seg6 mode encap segs 1 [ b:: ] via 2001::2 dev dum0 proto 194 metric 20 pref medium

.. clicmd:: sharp install seg6local-routes [vrf NAME] X:X::X:X nexthop-seg6local NAME ACTION ARGS.. (1-1000000)

   This command installs a route for SRv6 Endpoint behavior (on Linux it is
   known as seg6local route). The count, destination, vrf, etc. have the same
   meaning as in the ``sharp install routes`` command.  With this command,
   sharpd will request zebra to configure seg6local route via ZEBRA_ROUTE_ADD
   ZAPI. As in the following example.

   There are many End Functions defined in SRv6, which have been standardized
   in RFC 8986. The current implementation supports End, End.X, End.T, End.DX4,
   End.DT6 and End.DT46, which can be configured as follows.

::

   router# sharp install seg6local-routes 1::1 nexthop-seg6local dum0 End 1
   router# sharp install seg6local-routes 1::2 nexthop-seg6local dum0 End_X 2001::1 1
   router# sharp install seg6local-routes 1::3 nexthop-seg6local dum0 End_T 10 1
   router# sharp install seg6local-routes 1::4 nexthop-seg6local dum0 End_DX4 10.0.0.1 1
   router# sharp install seg6local-routes 1::5 nexthop-seg6local dum0 End_DT6 10 1
   router# sharp install seg6local-routes 1::6 nexthop-seg6local dum0 End_DT46 10 1

   router# show ipv6 route
   D>* 1::1/128 [150/0] is directly connected, dum0, seg6local End USP, weight 1, 00:00:05
   D>* 1::2/128 [150/0] is directly connected, dum0, seg6local End.X nh6 2001::1, weight 1, 00:00:05
   D>* 1::3/128 [150/0] is directly connected, dum0, seg6local End.T table 10, weight 1, 00:00:05
   D>* 1::4/128 [150/0] is directly connected, dum0, seg6local End.DX4 nh4 10.0.0.1, weight 1, 00:00:05
   D>* 1::5/128 [150/0] is directly connected, dum0, seg6local End.DT6 table 10, weight 1, 00:00:05
   D>* 1::6/128 [150/0] is directly connected, dum0, seg6local End.DT46 table 10, weight 1, 00:00:05

   bash# ip -6 route
   1::1  encap seg6local action End dev dum0 proto 194 metric 20 pref medium
   1::2  encap seg6local action End.X nh6 2001::1 dev dum0 proto 194 metric 20 pref medium
   1::3  encap seg6local action End.T table 10 dev dum0 proto 194 metric 20 pref medium
   1::4  encap seg6local action End.DX4 nh4 10.0.0.1 dev dum0 proto 194 metric 20 pref medium
   1::5  encap seg6local action End.DT6 table 10 dev dum0 proto 194 metric 20 pref medium
   1::6  encap seg6local action End.DT46 table 10 dev dum0 proto 194 metric 20 pref medium

.. clicmd:: show sharp segment-routing srv6

   This command shows us what SRv6 locator chunk, sharp is holding as zclient.
   An SRv6 locator is defined for each SRv6 router, and a single locator may
   be shared by multiple protocols.

   In the FRRouting implementation, the Locator chunk get request is executed
   by a routing protocol daemon such as sharpd or bgpd, And then Zebra
   allocates a Locator Chunk, which is a subset of the Locator Prefix, and
   notifies the requesting protocol daemon of this information.

   This command example shows how the locator chunk of sharpd itself is
   allocated.

::

   router# show segment-routing srv6 locator
   Locator:
   Name                 ID            2 2001:db8:2:2::/64        Up

   router# show sharp segment-routing srv6
   Locator loc1 has 1 prefix chunks
     2001:db8:1:1::/64

.. clicmd:: sharp srv6-manager get-locator-chunk

   This command requests the SRv6 locator to allocate a locator chunk via ZAPI.
   This chunk can be owned by the protocol daemon, and the chunk obtained by
   sharpd will not be used by the SRv6 mechanism of another routing protocol.

   Since this request is made asynchronously, it can be issued before the SRv6
   locator is configured on the zebra side, and as soon as it is ready on the
   zebra side, sharpd can check the allocated locator chunk via zapi.

::

   router# show segment-routing srv6 locator loc1 detail
   Name: loc1
   Prefix: 2001:db8:1:1::/64
   Chunks:
   - prefix: 2001:db8:1:1::/64, owner: system

   router# show sharp segment-routing srv6
   (nothing)

   router# sharp srv6-manager get-locator-chunk loc1

   router# show segment-routing srv6 locator loc1 detail
   Name: loc1
   Prefix: 2001:db8:1:1::/64
   Chunks:
   - prefix: 2001:db8:1:1::/64, owner: sharp

   router# show sharp segment-routing srv6
   Locator loc1 has 1 prefix chunks
     2001:db8:1:1::/64

.. clicmd:: sharp srv6-manager release-locator-chunk

   This command releases a locator chunk that has already been allocated by
   ZAPI. The freed chunk will have its owner returned to the system and will
   be available to another protocol daemon.

::

   router# show segment-routing srv6 locator loc1 detail
   Name: loc1
   Prefix: 2001:db8:1:1::/64
   Chunks:
   - prefix: 2001:db8:1:1::/64, owner: sharp

   router# show sharp segment-routing srv6
   Locator loc1 has 1 prefix chunks
     2001:db8:1:1::/64

   router# sharp srv6-manager release-locator-chunk loc1

   router# show segment-routing srv6 locator loc1 detail
   Name: loc1
   Prefix: 2001:db8:1:1::/64
   Chunks:
   - prefix: 2001:db8:1:1::/64, owner: system

   router# show sharp segment-routing srv6
   (nothing)

.. clicmd:: sharp interface IFNAME protodown

   Set an interface protodown.
