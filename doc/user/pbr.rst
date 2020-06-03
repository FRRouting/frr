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

.. clicmd:: nexthop-group NAME

   Create a nexthop-group with an associated NAME.  This will put you into a
   sub-mode where you can specify individual nexthops.  To exit this mode type
   exit or end as per normal conventions for leaving a sub-mode.

.. clicmd:: nexthop [A.B.C.D|X:X::X:XX] [interface [onlink]] [nexthop-vrf NAME] [label LABELS]

   Create a v4 or v6 nexthop.  All normal rules for creating nexthops that you
   are used to are allowed here.  The syntax was intentionally kept the same as
   creating nexthops as you would for static routes.

.. clicmd:: set installable

   Sets the nexthop group to be installable i.e. treated as a separate object in
   the protocol client and zebra's RIB. The proto will send down the object
   separately from the route to install into into the RIB and dataplane.

.. note::
   ``set installable`` is only supported for groups with onlink, interface, and
   gateway/interface nexthop types at the moment. Recursive nexthops
   (gateway only) are considered undefined behavior.

.. clicmd:: [no] pbr table range (10000-4294966272) (10000-4294966272)

   Set or unset the range used to assign numeric table ID's to new
   nexthop-group tables. Existing tables will not be modified to fit in this
   range, so it is recommended to configure this before adding nexthop groups.

   .. seealso:: :ref:`pbr-details`

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

.. clicmd:: match mark (1-4294967295)

   Select the mark to match.  This is a linux only command and if attempted
   on another platform it will be denied.  This mark translates to the
   underlying `ip rule .... fwmark XXXX` command.

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

.. _pbr-policy:

PBR Policy
==========

After you have specified a PBR map, in order for it to be turned on, you must
apply the PBR map to an interface.  This policy application to an interface
causes the policy to be installed into the kernel.

.. index:: pbr-policy
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

.. _pbr-details:

PBR Details
===========

Under the covers a PBR map is translated into two separate constructs in the
Linux kernel.

.. index:: PBR Rules

The PBR map specified creates a `ip rule ...` that is inserted into the Linux
kernel that points to a table to use for forwarding once the rule matches.

.. index:: PBR Tables

The creation of a nexthop or nexthop-group is translated to a default route in a
table with the nexthops specified as the nexthops for the default route.

