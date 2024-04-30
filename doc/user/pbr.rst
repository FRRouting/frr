.. _pbr:

***
PBR
***

:abbr:`PBR` is Policy Based Routing.  This implementation supports a very simple
interface to allow admins to influence routing on their router.  At this time
you can only match on destination and source prefixes for an incoming interface.
At this point in time, this implementation will only work on Linux.

.. _starting-pbr:

Starting PBR
============

Default configuration file for *pbrd* is :file:`pbrd.conf`.  The typical
location of :file:`pbrd.conf` is |INSTALL_PREFIX_ETC|/pbrd.conf.

If the user is using integrated config, then :file:`pbrd.conf` need not be
present and the :file:`frr.conf` is read instead.

.. program:: pbrd

:abbr:`PBR` supports all the common FRR daemon start options which are
documented elsewhere.

.. _nexthop-groups:

Nexthop Groups
==============

Nexthop groups are a way to encapsulate ECMP information together.  It's a
listing of ECMP nexthops used to forward packets for when a pbr-map is matched.
For detailed instructions on how to specify a nexthop group on the CLI, see
the nexthop-groups section.

Showing Nexthop Group Information
---------------------------------

.. clicmd:: show pbr nexthop-groups [NAME] [json]

   Display information on a PBR nexthop-group. If ``NAME`` is omitted, all
   nexthop groups are shown. Setting ``json`` will provide the same
   information in an array of objects which obey the schema below:

   +-----------+----------------------------+---------+
   | Key       | Description                | Type    |
   +===========+============================+=========+
   | id        | Unique ID                  | Integer |
   +-----------+----------------------------+---------+
   | name      | Name of this group         | String  |
   +-----------+----------------------------+---------+
   | valid     | Is this group well-formed? | Boolean |
   +-----------+----------------------------+---------+
   | installed | ... and is it installed?   | Boolean |
   +-----------+----------------------------+---------+
   | nexthops  | Nexthops within this group | Array   |
   +-----------+----------------------------+---------+

   Each element within ``nexthops`` describes a single target within this
   group, and its structure is described by the JSON below:

   +---------+------------------------------+---------+
   | Key     | Description                  | Type    |
   +=========+==============================+=========+
   | nexthop | Name of this nexthop         | String  |
   +---------+------------------------------+---------+
   | valid   | Is this nexthop well-formed? | Boolean |
   +---------+------------------------------+---------+

.. _pbr-maps:

PBR Maps
========

PBR maps are a way to group policies that we would like to apply to individual
interfaces. These policies when applied are matched against incoming packets.
If matched the nexthop-group or nexthop is used to forward the packets to the
end destination.

.. clicmd:: pbr-map NAME seq (1-700)

   Create a pbr-map with NAME and sequence number specified.  This command puts
   you into a new submode for pbr-map specification.  To exit this mode type
   exit or end as per normal conventions for leaving a sub-mode.

.. clicmd:: match src-ip PREFIX

   When a incoming packet matches the source prefix specified, take the packet
   and forward according to the nexthops specified.  This command accepts both
   v4 and v6 prefixes.  This command is used in conjunction of the
   :clicmd:`match dst-ip PREFIX` command for matching.

.. clicmd:: match dst-ip PREFIX

   When a incoming packet matches the destination prefix specified, take the
   packet and forward according to the nexthops specified.  This command accepts
   both v4 and v6 prefixes.  This command is used in conjunction of the
   :clicmd:`match src-ip PREFIX` command for matching.

.. clicmd:: match src-port (1-65535)

   When a incoming packet matches the source port specified, take the
   packet and forward according to the nexthops specified.

.. clicmd:: match dst-port (1-65535)

   When a incoming packet matches the destination port specified, take the
   packet and forward according to the nexthops specified.

.. clicmd:: match ip-protocol [tcp|udp]

   When a incoming packet matches the specified ip protocol, take the
   packet and forward according to the nexthops specified.

.. clicmd:: match mark (1-4294967295)

   Select the mark to match.  This is a linux only command and if attempted
   on another platform it will be denied.  This mark translates to the
   underlying `ip rule .... fwmark XXXX` command.

.. clicmd:: match dscp (DSCP|0-63)

   Match packets according to the specified differentiated services code point
   (DSCP) in the IP header; if this value matches then forward the packet
   according to the nexthop(s) specified. The passed DSCP value may also be a
   standard name for a differentiated service code point like cs0 or af11.

   You may only specify one dscp per route map sequence; to match on multiple
   dscp values you will need to create several sequences, one for each value.

.. clicmd:: match ecn (0-3)

   Match packets according to the specified explicit congestion notification
   (ECN) field in the IP header; if this value matches then forward the packet
   according to the nexthop(s) specified.


.. clicmd:: set queue-id (1-65535)

   Set the egress port queue identifier for matched packets. The Linux Kernel
   provider does not currently support packet mangling, so this field will be
   ignored unless another provider is used.

.. clicmd:: set pcp (0-7)

   Set the 802.1Q priority code point (PCP) for matched packets. A PCP of zero
   is the defaul (nominally, "best effort"). The Linux Kernel provider does not 
   currently support packet mangling, so this field will be ignored unless 
   another provider is used.

.. clicmd:: set vlan (1-4094)

   Set the VLAN tag for matched packets. Identifiers 0 and 4095 are reserved.
   The Linux Kernel provider does not currently support packet mangling, so 
   this field will be ignored unless another provider is used.

.. clicmd:: strip vlan

   Strip inner vlan tags from matched packets. The Linux Kernel provider does not currently support packet mangling, so this field will be ignored unless another provider is used. It is invalid to specify both a `strip` and `set
   vlan` action.

.. clicmd:: set nexthop-group NAME

   Use the nexthop-group NAME as the place to forward packets when the match
   commands have matched a packet.

.. clicmd:: set nexthop [A.B.C.D|X:X::X:XX] [interface] [nexthop-vrf NAME]

   Use this individual nexthop as the place to forward packets when the match
   commands have matched a packet.

.. clicmd:: set vrf unchanged|NAME

   If unchanged is set, the rule will use the vrf table the interface is in
   as its lookup. If NAME is specified, the rule will use that vrf table as
   its lookup.

   Not supported with NETNS VRF backend.

.. clicmd:: show pbr map [NAME] [detail|json]

   Display pbr maps either all or by ``NAME``. If ``detail`` is set, it will
   give information about the rules unique ID used internally and some extra
   debugging information about install state for the nexthop/nexthop group.
   Setting ``json`` will provide the same information in an array of objects
   which obey the schema below:

   +----------+--------------------------------+---------+
   | Key      | Description                    | Type    |
   +==========+================================+=========+
   | name     | Map name                       | String  |
   +----------+--------------------------------+---------+
   | valid    | Is the map well-formed?        | Boolean |
   +----------+--------------------------------+---------+
   | policies | Rules to match packets against | Array   |
   +----------+--------------------------------+---------+

   Each element of the ``policies`` array is composed of a handful of objects
   representing the policies associated with this map. Each policy is
   described as below (not all fields are required):

   +-----------------+-------------------------------------------+---------+
   | Key             | Description                               | Type    |
   +=================+===========================================+=========+
   | id              | Unique ID                                 | Integer |
   +-----------------+-------------------------------------------+---------+
   | sequenceNumber  | Order of this policy within the map       | Integer |
   +-----------------+-------------------------------------------+---------+
   | ruleNumber      | Rule number to install into               | Integer |
   +-----------------+-------------------------------------------+---------+
   | vrfUnchanged    | Use interface's VRF                       | Boolean |
   +-----------------+-------------------------------------------+---------+
   | installed       | Is this policy installed?                 | Boolean |
   +-----------------+-------------------------------------------+---------+
   | installedReason | Why (or why not?)                         | String  |
   +-----------------+-------------------------------------------+---------+
   | matchSrc        | Match packets with this source address    | String  |
   +-----------------+-------------------------------------------+---------+
   | matchDst        | ... or with this destination address      | String  |
   +-----------------+-------------------------------------------+---------+
   | matchMark       | ... or with this marker                   | Integer |
   +-----------------+-------------------------------------------+---------+
   | vrfName         | Associated VRF (if relevant)              | String  |
   +-----------------+-------------------------------------------+---------+
   | nexthopGroup    | This policy's nexthop group (if relevant) | Object  |
   +-----------------+-------------------------------------------+---------+

   Finally, the ``nexthopGroup`` object above cotains information we know
   about the configured nexthop for this policy:

   +---------------------+--------------------------------------+---------+
   | Key                 | Description                          | Type    |
   +=====================+======================================+=========+
   | tableId             | Nexthop table ID                     | Integer |
   +---------------------+--------------------------------------+---------+
   | name                | Name of the nexthop group            | String  |
   +---------------------+--------------------------------------+---------+
   | installed           | Is this nexthop group installed?     | Boolean |
   +---------------------+--------------------------------------+---------+
   | installedInternally | Do we think this group is installed? | Integer |
   +---------------------+--------------------------------------+---------+


.. index::
   pair: policy; PBR

.. _pbr-policy:

PBR Policy
==========

After you have specified a PBR map, in order for it to be turned on, you must
apply the PBR map to an interface.  This policy application to an interface
causes the policy to be installed into the kernel.

.. clicmd:: pbr-policy NAME

   This command is available under interface sub-mode.  This turns
   on the PBR map NAME and allows it to work properly.

.. note::
   This will not dynamically create PBR maps on sub-interfaces (i.e. vlans)
   even if one is on the master. Each must have the PBR map explicitly added
   to the interface.

.. clicmd:: show pbr interface [NAME] [json]

   Enumerates all interfaces which ``pbrd`` is keeping track of. Passing
   ``json`` will return an array of interfaces; each returned interface will
   adhere to the JSON schema below:

   +--------+----------------------------+---------+
   | Key    | Description                | Type    |
   +========+============================+=========+
   | name   | Interface name             | String  |
   +--------+----------------------------+---------+
   | index  | Device Index               | Integer |
   +--------+----------------------------+---------+
   | policy | PBR map for this interface | String  |
   +--------+----------------------------+---------+
   | valid  | Is the map well-formed?    | Boolean |
   +--------+----------------------------+---------+

.. clicmd:: pbr table range (10000-4294966272) (10000-4294966272)

   Set or unset the range used to assign numeric table ID's to new
   nexthop-group tables. Existing tables will not be modified to fit in this
   range, so it is recommended to configure this before adding nexthop groups.

   .. seealso:: :ref:`pbr-details`


.. _pbr-debugs:

PBR Debugs
===========

.. clicmd:: debug pbr events|map|nht|zebra

   Debug pbr in pbrd daemon. You specify what types of debugs to turn on.

.. _pbr-details:

PBR Details
===========

Under the covers a PBR map is translated into two separate constructs in the
Linux kernel.


The PBR map specified creates a `ip rule ...` that is inserted into the Linux
kernel that points to a table to use for forwarding once the rule matches.


The creation of a nexthop or nexthop-group is translated to a default route in a
table with the nexthops specified as the nexthops for the default route.


Sample configuration
====================

.. code-block:: frr

   nexthop-group TEST
     nexthop 4.5.6.7
     nexthop 5.6.7.8
   !
   pbr-map BLUE seq 100
     match dst-ip 9.9.9.0/24
     match src-ip 10.10.10.0/24
     set nexthop-group TEST
   !
   int swp1
     pbr-policy BLUE


