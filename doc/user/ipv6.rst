.. _ipv6-support:

************
IPv6 Support
************

FRR fully supports IPv6 routing.  As described so far, FRR supports RIPng,
OSPFv3, and BGP-4+.  You can give IPv6 addresses to an interface and configure
static IPv6 routing information.  FRR IPv6 also provides automatic address
configuration via a feature called ``address auto configuration``.  To do it,
the router must send router advertisement messages to the all nodes that exist
on the network.

Previous versions of FRR could be built without IPv6 support.  This is
no longer possible.

Router Advertisement
====================

.. index:: no ipv6 nd suppress-ra
.. clicmd:: no ipv6 nd suppress-ra

   Send router advertisement messages.

.. index:: ipv6 nd suppress-ra
.. clicmd:: ipv6 nd suppress-ra

   Don't send router advertisement messages.

.. index:: ipv6 nd prefix ipv6prefix [valid-lifetime] [preferred-lifetime] [off-link] [no-autoconfig] [router-address]
.. clicmd:: ipv6 nd prefix ipv6prefix [valid-lifetime] [preferred-lifetime] [off-link] [no-autoconfig] [router-address]

   Configuring the IPv6 prefix to include in router advertisements. Several prefix
   specific optional parameters and flags may follow:

   - ``valid-lifetime``: the length of time in seconds during what the prefix is
     valid for the purpose of on-link determination. Value ``infinite`` represents
     infinity (i.e. a value of all one bits (``0xffffffff``)).
     Range: ``(0-4294967295)``  Default: ``2592000``

   - ``preferred-lifetime``: the length of time in seconds during what addresses
     generated from the prefix remain preferred. Value ``infinite`` represents
     infinity.
     Range: ``(0-4294967295)``  Default: ``604800``

   - ``off-link``: indicates that advertisement makes no statement about on-link or
     off-link properties of the prefix.
     Default: not set, i.e. this prefix can be used for on-link determination.

   - ``no-autoconfig``: indicates to hosts on the local link that the specified prefix
     cannot be used for IPv6 autoconfiguration.

     Default: not set, i.e. prefix can be used for autoconfiguration.

   - ``router-address``: indicates to hosts on the local link that the specified
     prefix contains a complete IP address by setting R flag.

     Default: not set, i.e. hosts do not assume a complete IP address is placed.

.. index::
   single: no ipv6 nd ra-interval [(1-1800)]
   single: no ipv6 nd ra-interval [(1-1800)]
.. clicmd:: [no] ipv6 nd ra-interval [(1-1800)]

   The maximum time allowed between sending unsolicited multicast router
   advertisements from the interface, in seconds.
   Default: ``600``

.. index:: ipv6 nd ra-interval msec (70-1800000)
.. index::
   single: no ipv6 nd ra-interval [msec (70-1800000)]
   single: ipv6 nd ra-interval msec (70-1800000)
.. clicmd:: [no] ipv6 nd ra-interval [msec (70-1800000)]

   The maximum time allowed between sending unsolicited multicast router
   advertisements from the interface, in milliseconds.
   Default: ``600000``

.. index::
   single: ipv6 nd ra-fast-retrans
   single: no ipv6 nd ra-fast-retrans
.. clicmd:: [no] ipv6 nd ra-fast-retrans

   RFC4861 states that consecutive RA packets should be sent no more
   frequently than three seconds apart. FRR by default allows faster
   transmissions of RA packets in order to speed convergence and
   neighbor establishment, particularly for unnumbered peering.  By
   turning off ipv6 nd ra-fast-retrans, the implementation is
   compliant with the RFC at the cost of slower convergence
   and neighbor establishment.
   Default: enabled

.. index::
   single: ipv6 nd ra-lifetime (0-9000)
   single: no ipv6 nd ra-lifetime [(0-9000)]
.. clicmd:: [no] ipv6 nd ra-lifetime [(0-9000)]

   The value to be placed in the Router Lifetime field of router advertisements
   sent from the interface, in seconds. Indicates the usefulness of the router
   as a default router on this interface. Setting the value to zero indicates
   that the router should not be considered a default router on this interface.
   Must be either zero or between value specified with ``ipv6 nd ra-interval``
   (or default) and 9000 seconds.
   Default: ``1800``

.. index::
   single: no ipv6 nd reachable-time [(1-3600000)]
   single: ipv6 nd reachable-time (1-3600000)
.. clicmd:: [no] ipv6 nd reachable-time [(1-3600000)]

   The value to be placed in the Reachable Time field in the Router
   Advertisement messages sent by the router, in milliseconds. The configured
   time enables the router to detect unavailable neighbors. The value zero
   means unspecified (by this router).
   Default: ``0``

.. index::
   single: ipv6 nd managed-config-flag
   single: no ipv6 nd managed-config-flag
.. clicmd:: [no] ipv6 nd managed-config-flag

   Set/unset flag in IPv6 router advertisements which indicates to hosts that
   they should use managed (stateful) protocol for addresses autoconfiguration
   in addition to any addresses autoconfigured using stateless address
   autoconfiguration.
   Default: not set

.. index::
   single: ipv6 nd other-config-flag
   single: no ipv6 nd other-config-flag
.. clicmd:: [no] ipv6 nd other-config-flag

   Set/unset flag in IPv6 router advertisements which indicates to hosts that
   they should use administered (stateful) protocol to obtain autoconfiguration
   information other than addresses.
   Default: not set

.. index::
   single: ipv6 nd home-agent-config-flag
   single: no ipv6 nd home-agent-config-flag
.. clicmd:: [no] ipv6 nd home-agent-config-flag

   Set/unset flag in IPv6 router advertisements which indicates to hosts that
   the router acts as a Home Agent and includes a Home Agent Option.
   Default: not set

.. index:: ipv6 nd home-agent-preference (0-65535)

.. index::
   single: no ipv6 nd home-agent-preference [(0-65535)]
   single: ipv6 nd home-agent-preference (0-65535)
.. clicmd:: [no] ipv6 nd home-agent-preference [(0-65535)]

   The value to be placed in Home Agent Option, when Home Agent config flag is
   set, which indicates to hosts Home Agent preference. The default value of 0
   stands for the lowest preference possible.
   Default: ``0``

.. index::
   single: ipv6 nd home-agent-lifetime (0-65520)
   single: no ipv6 nd home-agent-lifetime (0-65520)
.. clicmd:: [no] ipv6 nd home-agent-lifetime [(0-65520)]

   The value to be placed in Home Agent Option, when Home Agent config flag is set,
   which indicates to hosts Home Agent Lifetime. The default value of 0 means to
   place the current Router Lifetime value.

   Default: ``0``

.. index::
   single: ipv6 nd adv-interval-option
   single: no ipv6 nd adv-interval-option
.. clicmd:: [no] ipv6 nd adv-interval-option

   Include an Advertisement Interval option which indicates to hosts the maximum time,
   in milliseconds, between successive unsolicited Router Advertisements.
   Default: not set

.. index::
   single: ipv6 nd router-preference (high|medium|low)
   single: no ipv6 nd router-preference (high|medium|low)
.. clicmd:: [no] ipv6 nd router-preference [(high|medium|low)]

   Set default router preference in IPv6 router advertisements per RFC4191.
   Default: medium

.. index::
   single: ipv6 nd mtu (1-65535)
   single: no ipv6 nd mtu [(1-65535)]
.. clicmd:: [no] ipv6 nd mtu [(1-65535)]

   Include an MTU (type 5) option in each RA packet to assist the attached
   hosts in proper interface configuration. The announced value is not verified
   to be consistent with router interface MTU.

   Default: don't advertise any MTU option.

.. index::
   single: ipv6 nd rdnss ipv6address [lifetime]
   single: no ipv6 nd rdnss ipv6address [lifetime]
.. clicmd:: [no] ipv6 nd rdnss ipv6address [lifetime]

   Recursive DNS server address to advertise using the RDNSS (type 25) option
   described in RFC8106. Can be specified more than once to advertise multiple
   addresses. Note that hosts may choose to limit the number of RDNSS addresses
   to track.

   Optional parameter:

   - ``lifetime``: the maximum time in seconds over which the specified address
     may be used for domain name resolution. Value ``infinite`` represents
     infinity (i.e. a value of all one bits (``0xffffffff``)). A value of 0
     indicates that the address must no longer be used.
     Range: ``(0-4294967295)``  Default: ``3 * ra-interval``

   Default: do not emit RDNSS option

.. index::
   single: ipv6 nd dnssl domain-name-suffix [lifetime]
   single: no ipv6 nd dnssl domain-name-suffix [lifetime]
.. clicmd:: [no] ipv6 nd dnssl domain-name-suffix [lifetime]

   Advertise DNS search list using the DNSSL (type 31) option described in
   RFC8106. Specify more than once to advertise multiple domain name suffixes.
   Host implementations may limit the number of honored search list entries.

   Optional parameter:

   - ``lifetime``: the maximum time in seconds over which the specified domain
     suffix may be used in the course of  name resolution. Value ``infinite``
     represents infinity (i.e. a value of all one bits (``0xffffffff``)). A
     value of 0 indicates that the name suffix must no longer be used.
     Range: ``(0-4294967295)``  Default: ``3 * ra-interval``

   Default: do not emit DNSSL option

Router Advertisement Configuration Example
==========================================
A small example:

.. code-block:: frr

   interface eth0
    no ipv6 nd suppress-ra
    ipv6 nd prefix 2001:0DB8:5009::/64


.. seealso::

   - :rfc:`2462` (IPv6 Stateless Address Autoconfiguration)
   - :rfc:`4861` (Neighbor Discovery for IP Version 6 (IPv6))
   - :rfc:`6275` (Mobility Support in IPv6)
   - :rfc:`4191` (Default Router Preferences and More-Specific Routes)
   - :rfc:`8106` (IPv6 Router Advertisement Options for DNS Configuration)
