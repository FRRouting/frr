.. _pbr:

***
PBR
***

:abbr:`PBR` is Policy Based Routing, which means forwarding based on
packet fields other than solely the destination IP address.
This implementation currently works only on Linux. Note that some
functionality (VLAN matching, packet mangling) is not supported by
the default Linux kernel dataplane provider.

.. _starting-pbr:

Starting PBR
============

Default configuration file for *pbrd* is :file:`pbrd.conf`.  The typical
location of :file:`pbrd.conf` is |INSTALL_PREFIX_ETC|/pbrd.conf.

If FRR is using integrated config, then :file:`pbrd.conf` need not be
present and the :file:`frr.conf` is read instead.

.. program:: pbrd

:abbr:`PBR` supports all the common FRR daemon start options, which are
documented elsewhere.

.. _nexthop-groups:

PBR Nexthop Groups
==================

A nexthop group is a list of ECMP nexthops used to forward packets
when a pbr-map is matched.
For details on specifying a nexthop group in the CLI, see
the nexthop-groups section.

Showing Nexthop Group Information
---------------------------------

.. clicmd:: show pbr nexthop-groups [NAME] [json]

   Display information on a PBR nexthop-group. If ``NAME`` is omitted, all
   nexthop groups are shown. Setting ``json`` will provide the same
   information in an array of objects that adhere to the schema below:

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

PBR maps are a way to specify a set of rules that are applied to
packets received on individual interfaces.
If a received packet matches a rule, the rule's nexthop-group or
nexthop is used to forward it; any other actions
specified in the rule are also applied to the packet.

.. clicmd:: pbr-map NAME seq (1-700)

   Create a pbr-map rule with map NAME and specified sequence number.
   This command puts the CLI into a new submode for pbr-map rule specification.
   To exit this submode, type ``exit`` or ``end``.

.. clicmd:: match src-ip PREFIX

   Match the packet's source IP address.

   This command accepts both v4 and v6 prefixes.

.. clicmd:: match dst-ip PREFIX

   Match the packet's destination IP address.

   This command accepts both v4 and v6 prefixes.

.. clicmd:: match src-port (1-65535)

   Match the packet's UDP or TCP source port.

.. clicmd:: match dst-port (1-65535)

   Match the packet's UDP or TCP destination port.

.. clicmd:: match ip-protocol PROTOCOL

   Match the packet's IP protocol.

   Protocol names are queried from the protocols database (``/etc/protocols``;
   see ``man 5 protocols`` and ``man 3 getprotobyname``).

.. clicmd:: match mark (1-4294967295)

   Match the packet's meta-information mark.
   The mark value is attached to the packet by the kernel/dataplane and
   is platform-specific.
   Currently, this field is supported only on linux and corresponds to
   the underlying `ip rule .... fwmark XXXX` command.

.. clicmd:: match dscp (DSCP|0-63)

   Match the packet's IP differentiated services code point (DSCP).
   The specified DSCP may also be a standard name for a
   differentiated service code point such as ``cs0`` or ``af11``.

   You may only specify one dscp per route map rule; to match on multiple
   dscp values you will need to create several rules, one for each value.

.. clicmd:: match ecn (0-3)

   Match the packet's IP explicit congestion notification (ECN) field.

.. clicmd:: match pcp (0-7)

   Match the packet's 802.1Q Priority Code Point.
   Zero is the default (nominally, "best effort").
   The Linux kernel dataplane provider does not currently support
   matching PCPs,
   so this field will be ignored unless other dataplane providers are used.

.. clicmd:: match vlan (1-4094)

   Match the packet's VLAN (802.1Q) identifier.
   Note that VLAN IDs 0 and 4095 are reserved.
   The Linux kernel dataplane provider does not currently support
   VLAN-matching facilities,
   so this field will be ignored unless other dataplane providers are used.

.. clicmd:: match vlan (tagged|untagged|untagged-or-zero)

   Match packets according to whether or not they have a VLAN tag.
   Use `untagged-or-zero` to also match packets with either no VLAN tag
   or with the reserved VLAN ID of 0 (indicating an untagged frame that
   includes other 802.1Q fields).
   The Linux kernel dataplane provider does not currently support
   VLAN-matching facilities,
   so this field will be ignored unless other dataplane providers are used.

.. clicmd:: set nexthop-group NAME

   Action:
   forward the packet using nexthop-group NAME.

.. clicmd:: set nexthop [A.B.C.D|X:X::X:XX|blackhole] [interface] [nexthop-vrf NAME]

   Action:
   forward the packet using the specified single nexthop.
   If `blackhole`, packets will be sent to a blackhole route and dropped.

.. clicmd:: set vrf unchanged|NAME

   Action:
   If set to ``unchanged``, the rule will use the vrf table the interface
   is in as its lookup.
   If set to NAME, the rule will use that vrf table as its lookup.

   Not supported with NETNS VRF backend.

.. clicmd:: set queue-id (1-65535)

   Action:
   set the egress port queue identifier.
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: set pcp (0-7)

   Action:
   set the 802.1Q priority code point (PCP).
   A PCP of zero is the default (nominally, "best effort").
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: set vlan (1-4094)

   Action:
   set the VLAN tag. Identifiers 0 and 4095 are reserved.
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: strip vlan

   Action:
   strip inner vlan tags.
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.
   It is invalid to specify both a `strip` and `set vlan` action.

.. clicmd:: set src-ip [A.B.C.D/M|X:X::X:X/M]

   Action:
   Set the source IP address of matched packets, possibly using a mask `M`.
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: set dst-ip [A.B.C.D/M|X:X::X:X/M]

   Action:
   set the destination IP address of matched packets, possibly using a mask
   `M`.
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: set src-port (1-65535)

   Action:
   set the source port of matched packets. Note that this action only makes
   sense with layer 4 protocols that use ports, such as TCP, UDP, and SCTP.
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: set dst-port (1-65535)

   Action:
   set the destination port of matched packets. Note that this action only
   makes sense with layer 4 protocols that use ports, such as TCP, UDP, and
   SCTP.
   The Linux Kernel dataplane provider does not currently support
   packet mangling,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: set dscp DSCP

   Action:
   set the differentiated services code point (DSCP) of matched packets.
   The Linux Kernel dataplane provider does not currently support
   this action,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: set ecn (0-3)

   Action:
   set the explicit congestion notification (ECN) of matched packets.
   The Linux Kernel dataplane provider does not currently support
   this action,
   so this field will be ignored unless another dataplane provider is used.

.. clicmd:: show pbr map [NAME] [detail] [json]

   Display pbr maps either all or by ``NAME``. If ``detail`` is set, it will
   give information about each rule's unique internal ID and some extra
   debugging information about install state for the nexthop/nexthop group.
   Setting ``json`` will provide the same information in an array of objects
   that adher to the schema below:

   +----------+--------------------------------+---------+
   | Key      | Description                    | Type    |
   +==========+================================+=========+
   | name     | Map name                       | String  |
   +----------+--------------------------------+---------+
   | valid    | Is the map well-formed?        | Boolean |
   +----------+--------------------------------+---------+
   | policies | Rules to match packets against | Array   |
   +----------+--------------------------------+---------+

   Each element of the ``policies`` array is composed of a set of objects
   representing the policies associated with this map. Each policy is
   described below (not all fields are required):

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

   Finally, the ``nexthopGroup`` object above contains information FRR
   knows about the configured nexthop for this policy:

   +---------------------+--------------------------------------+---------+
   | Key                 | Description                          | Type    |
   +=====================+======================================+=========+
   | tableId             | Nexthop table ID                     | Integer |
   +---------------------+--------------------------------------+---------+
   | name                | Name of the nexthop group            | String  |
   +---------------------+--------------------------------------+---------+
   | installed           | Is this nexthop group installed?     | Boolean |
   +---------------------+--------------------------------------+---------+
   | installedInternally | Does FRR think NHG is installed?     | Integer |
   +---------------------+--------------------------------------+---------+


.. index::
   pair: policy; PBR

.. _pbr-policy:

PBR Policy
==========

After you have specified a PBR map, in order for it to be enabled, it must
be applied to an interface.  This policy application to an interface
causes the policy to be installed into the kernel.

.. clicmd:: pbr-policy NAME

   This command is available under interface sub-mode.
   It enables the PBR map NAME on the interface.

.. note::
   This command will not dynamically create PBR maps on sub-interfaces
   (i.e. vlans), even if one is on the master.
   Each sub-interface must have the PBR map enabled explicitly.

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

   Set or unset the range used to assign numeric table IDs to new
   nexthop-group tables. Existing tables will not be modified to fit in this
   range, so this range should be configured before adding nexthop groups.

   .. seealso:: :ref:`pbr-details`


.. _pbr-debugs:

PBR Debugs
===========

.. clicmd:: debug pbr events|map|nht|zebra

   Debug pbr in pbrd daemon. You must specify what types of debugs to turn on.

.. _pbr-details:

PBR Details
===========

Internally, a PBR map is translated into two separate constructs in the
Linux kernel.


The PBR map creates an `ip rule ...` that is inserted into the Linux
kernel that points to a table to use for forwarding once the rule matches.


The creation of a nexthop or nexthop-group is translated to a
table with a default route having the specified nexthop(s).


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


