.. _pbr:

***
PBR
***

:abbr:`PBR` is Policy Based Routing.  This implementation supports a very
simple interface to allow admins to influence routing on their router.  At
this time you can only match on destination and source prefixes for
an incoming interface.  At this point in time, this implementation will
only work on Linux.

.. _starting-pbr:

STARTING PBR
============

Default configuration file for *pbrd* is :file:`pbrd.conf`.  The typical
location of :file:`pbrd.conf` is |INSTALL_PREFIX_ETC|/pbrd.conf.

If the user is using integrated config, then :file:`pbrd.conf` need
not be present and the :file:`frr.conf` is read instead.

.. program:: pbrd

:abbr:`PBR` supports all the common FRR daemon start options which are
documented elsewhere.

.. _nexthop-groups:

NEXTHOP GROUPS
==============

Nexthop groups are a way to encapsulate ECMP information together.  It's a
listing of ECMP nexthops used to forward packets for when a pbr-map is
matched.

.. index:: nexthop-group
.. clicmd:: nexthop-group NAME

    Create a nexthop-group with an associated NAME.  This will put
    you into a sub-mode where you can specify individual nexthops.
    To exit this mode type exit or end as per normal conventions
    for leaving a sub-mode.

.. clicmd:: nexthop [A.B.C.D|X:X::X:XX] [interface] [nexthop-vrf NAME]

    Create a v4 or v6 nexthop.  All normal rules for creating nexthops
    that you are used to are allowed here.  The syntax was intentionally
    kept the same as creating nexthops as you would for static routes.
	   
.. _pbr-maps:

PBR MAPS
========

PBR MAPS are a way to group policies that we would like to apply
to individual interfaces.  These policies when applied are matched
against incoming packets.  If matched the nexthop-group or nexthop
is used to forward the packets to the end destination

.. index:: pbr-map
.. clicmd:: pbr-map NAME seq (1-1000)

    Create a pbr-map with NAME and sequence number specified.  This
    command puts you into a new submode for pbr-map specification.
    To exit this mode type exit or end as per normal conventions
    for leaving a sub-mode.

.. index:: match
.. clicmd:: match src-ip <PREFIX>

    When a incoming packet matches the source prefix specified, take the packet
    and forward according to the nexthops specified.  This command
    accepts both v4 and v6 prefixes.  This command is used in
    conjunction of the 'match dst-ip <PREFIX>' command for matching.

.. clicmd:: match dst-ip <PREFIX>

    When a incoming packet matches the destination prefix specified, take
    the packet and forward according to the nexthops specified.  This
    command accepts both v4 and v6 prefixes.  This command is used in
    conjuction of the 'match src-ip <PREFIX>' command for matching.

.. clicmd:: set nexthop-group NAME

    Use the nexthop-group NAME as the place to forward packets when
    the match commands have matched a packet.

.. clicmd:: set nexthop [A.B.C.D|X:X::X:XX] [interface] [nexthop-vrf NAME]

    Use this individual nexthop as the place to forward packets when
    the match commands have matched a packet.

.. _pbr-policy:

PBR POLICY
==========

After you have specified a PBR MAP, in order for it to be turned on,
you must apply the PBR MAP to an interface.  This policy application
to an interface causes the policy to be installed into the kernel.

..index:: pbr-policy
.. clicmd:: pbr-policy NAME

    This command is available under interface sub-mode.  This turns
    on the PBR MAP NAME and allows it to work properly.

.. _pbr-details:

PBR DETAILS
===========

Under the covers a PBR MAP is translated into two separate constructs
in the linux kernel.

..index:: Rules

    The PBR MAP specified creates a `ip rule ...` that is inserted into
    the linux kernel that points to a table to use for forwarding once
    the rule matches.
    
..index:: Tables

    The creation of a nexthop or nexthop-group is translated to a default
    route in a table with the nexthops specified as the nexthops for the
    default route.

    
