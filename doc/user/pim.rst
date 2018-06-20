.. _pim:

***
PIM
***

PIM -- Protocol Independent Multicast

*pimd* supports pim-sm as well as igmp v2 and v3. pim is
vrf aware and can work within the context of vrf's in order to
do S,G mrouting.

.. _starting-and-stopping-pimd:

Starting and Stopping pimd
==========================

The default configuration file name of *pimd*'s is :file:`pimd.conf`. When
invoked *pimd* searches directory |INSTALL_PREFIX_ETC|. If
:file:`pimd.conf` is not there then next search current directory.

*pimd* requires zebra for proper operation. Additionally *pimd* depends on
routing properly setup and working in the network that it is working on.

::

   # zebra -d
   # pimd -d


Please note that *zebra* must be invoked before *pimd*.

To stop *pimd* please use::

   kill `cat /var/run/pimd.pid`

Certain signals have special meanings to *pimd*.

+---------+---------------------------------------------------------------------+
| Signal  | Meaning                                                             |
+=========+=====================================================================+
| SIGUSR1 | Rotate the *pimd* logfile                                           |
+---------+---------------------------------------------------------------------+
| SIGINT  | *pimd* sweeps all installed PIM mroutes then terminates gracefully. |
| SIGTERM |                                                                     |
+---------+---------------------------------------------------------------------+

*pimd* invocation options. Common options that can be specified
(:ref:`common-invocation-options`).

.. index:: ip pim rp A.B.C.D A.B.C.D/M
.. clicmd:: ip pim rp A.B.C.D A.B.C.D/M

   In order to use pim, it is necessary to configure a RP for join messages to
   be sent to. Currently the only methodology to do this is via static rp
   commands. All routers in the pim network must agree on these values. The
   first ip address is the RP's address and the second value is the matching
   prefix of group ranges covered. This command is vrf aware, to configure for
   a vrf, enter the vrf submode.

.. index:: ip pim spt-switchover infinity-and-beyond
.. clicmd:: ip pim spt-switchover infinity-and-beyond

   On the last hop router if it is desired to not switch over to the SPT tree.
   Configure this command. This command is vrf aware, to configure for a vrf,
   enter the vrf submode.

.. index:: ip pim ecmp
.. clicmd:: ip pim ecmp

   If pim has the a choice of ECMP nexthops for a particular RPF, pim will
   cause S,G flows to be spread out amongst the nexthops. If this command is
   not specified then the first nexthop found will be used. This command is vrf
   aware, to configure for a vrf, enter the vrf submode.

.. index:: ip pim ecmp rebalance
.. clicmd:: ip pim ecmp rebalance

   If pim is using ECMP and an interface goes down, cause pim to rebalance all
   S,G flows across the remaining nexthops. If this command is not configured
   pim only modifies those S,G flows that were using the interface that went
   down. This command is vrf aware, to configure for a vrf, enter the vrf
   submode.

.. index:: ip pim join-prune-interval (60-600)
.. clicmd:: ip pim join-prune-interval (60-600)

   Modify the join/prune interval that pim uses to the new value. Time is
   specified in seconds. This command is vrf aware, to configure for a vrf,
   enter the vrf submode.

.. index:: ip pim keep-alive-timer (31-60000)
.. clicmd:: ip pim keep-alive-timer (31-60000)

   Modify the time out value for a S,G flow from 31-60000 seconds. 31 seconds
   is chosen for a lower bound because some hardware platforms cannot see data
   flowing in better than 30 second chunks. This command is vrf aware, to
   configure for a vrf, enter the vrf submode.

.. index:: ip pim packets (1-100)
.. clicmd:: ip pim packets (1-100)

   When processing packets from a neighbor process the number of packets
   incoming at one time before moving on to the next task. The default value is
   3 packets.  This command is only useful at scale when you can possibly have
   a large number of pim control packets flowing. This command is vrf aware, to
   configure for a vrf, enter the vrf submode.

.. index:: ip pim register-suppress-time (5-60000)
.. clicmd:: ip pim register-suppress-time (5-60000)

   Modify the time that pim will register suppress a FHR will send register
   notifications to the kernel. This command is vrf aware, to configure for a
   vrf, enter the vrf submode.

.. index:: ip pim send-v6-secondary
.. clicmd:: ip pim send-v6-secondary

   When sending pim hello packets tell pim to send any v6 secondary addresses
   on the interface. This information is used to allow pim to use v6 nexthops
   in it's decision for RPF lookup. This command is vrf aware, to configure for
   a vrf, enter the vrf submode.

.. index:: ip pim ssm prefix-list WORD
.. clicmd:: ip pim ssm prefix-list WORD

   Specify a range of group addresses via a prefix-list that forces pim to
   never do SM over. This command is vrf aware, to configure for a vrf, enter
   the vrf submode.

.. index:: ip multicast rpf-lookup-mode WORD
.. clicmd:: ip multicast rpf-lookup-mode WORD

   Modify how PIM does RPF lookups in the zebra routing table.  You can use
   these choices:

   longer-prefix
      Lookup the RPF in both tables using the longer prefix as a match

   lower-distance
      Lookup the RPF in both tables using the lower distance as a match

   mrib-only
      Lookup in the Multicast RIB only

   mrib-then-urib
      Lookup in the Multicast RIB then the Unicast Rib, returning first found.
      This is the default value for lookup if this command is not entered

   urib-only
      Lookup in the Unicast Rib only.


.. _pim-interface-configuration:

PIM Interface Configuration
===========================

PIM interface commands allow you to configure an interface as either a Receiver
or a interface that you would like to form pim neighbors on. If the interface
is in a vrf, enter the interface command with the vrf keyword at the end.

.. index:: ip pim bfd
.. clicmd:: ip pim bfd

   Turns on BFD support for PIM for this interface.

.. index:: ip pim drpriority (1-4294967295)
.. clicmd:: ip pim drpriority (1-4294967295)

   Set the DR Priority for the interface. This command is useful to allow the
   user to influence what node becomes the DR for a lan segment.

.. index:: ip pim hello (1-180) (1-180)
.. clicmd:: ip pim hello (1-180) (1-180)

   Set the pim hello and hold interval for a interface.

.. index:: ip pim sm
.. clicmd:: ip pim sm

   Tell pim that we would like to use this interface to form pim neighbors
   over. Please note we will *not* accept igmp reports over this interface with
   this command.

.. index:: ip igmp
.. clicmd:: ip igmp

   Tell pim to receive IGMP reports and Query on this interface. The default
   version is v3. This command is useful on the LHR.

.. index:: ip igmp join A.B.C.D A.B.C.D
.. clicmd:: ip igmp join A.B.C.D A.B.C.D

   Join multicast source-group on an interface.

.. index:: ip igmp query-interval (1-1800)
.. clicmd:: ip igmp query-interval (1-1800)

   Set the IGMP query interval that PIM will use.

.. index:: ip igmp query-max-response-time (10-250)
.. clicmd:: ip igmp query-max-response-time (10-250)

   Set the IGMP query response timeout value. If an report is not returned in
   the specified time we will assume the S,G or \*,G has timed out.

.. index:: ip igmp version (2-3)
.. clicmd:: ip igmp version (2-3)

   Set the IGMP version used on this interface. The default value is 3.

.. index:: ip multicat boundary oil WORD
.. clicmd:: ip multicat boundary oil WORD

   Set a pim multicast boundary, based upon the WORD prefix-list. If a pim join
   or IGMP report is received on this interface and the Group is denied by the
   prefix-list, PIM will ignore the join or report.

.. _pim-multicast-rib-insertion:

PIM Multicast RIB insertion:
============================

In order to influence Multicast RPF lookup, it is possible to insert
into zebra routes for the Multicast RIB. These routes are only
used for RPF lookup and will not be used by zebra for insertion
into the kernel *or* for normal rib processing. As such it is
possible to create weird states with these commands. Use with
caution. Most of the time this will not be necessary.

.. index:: ip mroute A.B.C.D/M A.B.C.D (1-255)
.. clicmd:: ip mroute A.B.C.D/M A.B.C.D (1-255)

   Insert into the Multicast Rib Route A.B.C.D/M with specified nexthop. The
   distance can be specified as well if desired.

.. index:: ip mroute A.B.C.D/M INTERFACE (1-255)
.. clicmd:: ip mroute A.B.C.D/M INTERFACE (1-255)

   Insert into the Multicast Rib Route A.B.C.D/M using the specified INTERFACE.
   The distance can be specified as well if desired.

.. _show-pim-information:

Show PIM Information
====================

All PIM show commands are vrf aware and typically allow you to insert a
specified vrf command if information is desired about a specific vrf. If no
vrf is specified then the default vrf is assumed. Finally the special keyword
'all' allows you to look at all vrfs for the command. Naming a vrf 'all' will
cause great confusion.

.. index:: show ip igmp interface
.. clicmd:: show ip igmp interface

   Display IGMP interface information.

.. index:: show ip igmp join
.. clicmd:: show ip igmp join

   Display IGMP static join information.

.. index:: show ip igmp groups
.. clicmd:: show ip igmp groups

   Display IGMP groups information.

.. index:: show ip igmp groups retransmissions
.. clicmd:: show ip igmp groups retransmissions

   Display IGMP group retransmission information.

.. index:: show ip igmp sources
.. clicmd:: show ip igmp sources

   Display IGMP sources information.

.. index:: show ip igmp sources retransmissions
.. clicmd:: show ip igmp sources retransmissions

   Display IGMP source retransmission information.

.. index:: show ip igmp statistics
.. clicmd:: show ip igmp statistics

   Display IGMP statistics information.

.. index:: show ip multicast
.. clicmd:: show ip multicast

   Display various information about the interfaces used in this pim instance.

.. index:: show ip mroute
.. clicmd:: show ip mroute

   Display information about installed into the kernel S,G mroutes.

.. index:: show ip mroute count
.. clicmd:: show ip mroute count

   Display information about installed into the kernel S,G mroutes and in
   addition display data about packet flow for the mroutes.

.. index:: show ip pim assert
.. clicmd:: show ip pim assert

   Display information about asserts in the PIM system for S,G mroutes.

.. index:: show ip pim assert-internal
.. clicmd:: show ip pim assert-internal

   Display internal assert state for S,G mroutes

.. index:: show ip pim assert-metric
.. clicmd:: show ip pim assert-metric

   Display metric information about assert state for S,G mroutes

.. index:: show ip pim assert-winner-metric
.. clicmd:: show ip pim assert-winner-metric

   Display winner metric for assert state for S,G mroutes

.. index:: show ip pim group-type
.. clicmd:: show ip pim group-type

   Display SSM group ranges.

.. index:: show ip pim interface
.. clicmd:: show ip pim interface

   Display information about interfaces PIM is using.

.. index:: show ip pim join
.. clicmd:: show ip pim join

   Display information about PIM joins received.

.. index:: show ip pim local-membership
.. clicmd:: show ip pim local-membership

   Display information about PIM interface local-membership.

.. index:: show ip pim neighbor
.. clicmd:: show ip pim neighbor

   Display information about PIM neighbors.

.. index:: show ip pim nexthop
.. clicmd:: show ip pim nexthop

   Display information about pim nexthops that are being used.

.. index:: show ip pim nexthop-lookup
.. clicmd:: show ip pim nexthop-lookup

   Display information about a S,G pair and how the RPF would be chosen. This
   is especially useful if there are ECMP's available from the RPF lookup.

.. index:: show ip pim rp-info
.. clicmd:: show ip pim rp-info

   Display information about RP's that are configured on this router.

.. index:: show ip pim rpf
.. clicmd:: show ip pim rpf

   Display information about currently being used S,G's and their RPF lookup
   information. Additionally display some statistics about what has been
   happening on the router.

.. index:: show ip pim secondary
.. clicmd:: show ip pim secondary

   Display information about an interface and all the secondary addresses
   associated with it.

.. index:: show ip pim state
.. clicmd:: show ip pim state

   Display information about known S,G's and incoming interface as well as the
   OIL and how they were chosen.

.. index:: show ip pim upstream
.. clicmd:: show ip pim upstream

   Display upstream information about a S,G mroute.

.. index:: show ip pim upstream-join-desired
.. clicmd:: show ip pim upstream-join-desired

   Display upstream information for S,G's and if we desire to
   join the multicast tree

.. index:: show ip pim upstream-rpf
.. clicmd:: show ip pim upstream-rpf

   Display upstream information for S,G's and the RPF data associated with them.

.. index:: show ip rpf
.. clicmd:: show ip rpf

   Display the multicast RIB created in zebra.

.. index:: mtrace A.B.C.D [A.B.C.D]
.. clicmd:: mtrace A.B.C.D [A.B.C.D]

   Display multicast traceroute towards source, optionally for particular group.

PIM Debug Commands
==================

The debugging subsystem for PIM behaves in accordance with how FRR handles
debugging. You can specify debugging at the enable CLI mode as well as the
configure CLI mode. If you specify debug commands in the configuration cli
mode, the debug commands can be persistent across restarts of the FRR pimd if
the config was written out.

.. index:: debug igmp
.. clicmd:: debug igmp

   This turns on debugging for IGMP protocol activity.

.. index:: debug mtrace
.. clicmd:: debug mtrace

   This turns on debugging for mtrace protocol activity.

.. index:: debug mroute
.. clicmd:: debug mroute

   This turns on debugging for PIM interaction with kernel MFC cache.

.. index:: debug pim events
.. clicmd:: debug pim events

   This turns on debugging for PIM system events. Especially timers.

.. index:: debug pim nht
.. clicmd:: debug pim nht

   This turns on debugging for PIM nexthop tracking. It will display
   information about RPF lookups and information about when a nexthop changes.

.. index:: debug pim packet-dump
.. clicmd:: debug pim packet-dump

   This turns on an extraordinary amount of data. Each pim packet sent and
   received is dumped for debugging purposes. This should be considered a
   developer only command.

.. index:: debug pim packets
.. clicmd:: debug pim packets

   This turns on information about packet generation for sending and about
   packet handling from a received packet.

.. index:: debug pim trace
.. clicmd:: debug pim trace

   This traces pim code and how it is running.

.. index:: debug pim zebra
.. clicmd:: debug pim zebra

   This gathers data about events from zebra that come up through the ZAPI.

PIM Clear Commands
==================
Clear commands reset various variables.

.. index:: clear ip interfaces
.. clicmd:: clear ip interfaces

   Reset interfaces.

.. index:: clear ip igmp interfaces
.. clicmd:: clear ip igmp interfaces

   Reset IGMP interfaces.

.. index:: clear ip mroute
.. clicmd:: clear ip mroute

   Reset multicast routes.

.. index:: clear ip pim interfaces
.. clicmd:: clear ip pim interfaces

   Reset PIM interfaces.

.. index:: clear ip pim oil
.. clicmd:: clear ip pim oil

   Rescan PIM OIL (output interface list).
