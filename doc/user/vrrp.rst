.. _vrrp:

****
VRRP
****

:abbr:`VRRP` stands for Virtual Router Redundancy Protocol. This protocol is
used to allow multiple backup routers on the same segment to take over
operation of each others' IP addresses if the primary router fails. This is
typically used to provide fault-tolerant gateways to hosts on the segment.

FRR implements VRRPv2 (:rfc:`3768`) and VRRPv3 (:rfc:`5798`). For VRRPv2, no
authentication methods are supported; these are deprecated in the VRRPv2
specification as they do not provide any additional security over the base
protocol.

.. note::

   - VRRP is supported on Linux 5.1+
   - VRRP does not implement Accept_Mode

.. _vrrp-starting:

Starting VRRP
=============

The configuration file for *vrrpd* is :file:`vrrpd.conf`. The typical location
of :file:`vrrpd.conf` is |INSTALL_PREFIX_ETC|/vrrpd.conf.

If using integrated config, then :file:`vrrpd.conf` need not be present and
:file:`frr.conf` is read instead.

.. program:: vrrpd

:abbr:`VRRP` supports all the common FRR daemon start options which are
documented elsewhere.

.. _vrrp-protocol-overview:

Protocol Overview
=================

From :rfc:`5798`:

   VRRP specifies an election protocol that dynamically assigns responsibility
   for a virtual router to one of the VRRP routers on a LAN. The VRRP router
   controlling the IPv4 or IPv6 address(es) associated with a virtual router is
   called the Master, and it forwards packets sent to these IPv4 or IPv6
   addresses. VRRP Master routers are configured with virtual IPv4 or IPv6
   addresses, and VRRP Backup routers infer the address family of the virtual
   addresses being carried based on the transport protocol. Within a VRRP
   router, the virtual routers in each of the IPv4 and IPv6 address families
   are a domain unto themselves and do not overlap. The election process
   provides dynamic failover in the forwarding responsibility should the Master
   become unavailable. For IPv4, the advantage gained from using VRRP is a
   higher-availability default path without requiring configuration of dynamic
   routing or router discovery protocols on every end-host. For IPv6, the
   advantage gained from using VRRP for IPv6 is a quicker switchover to Backup
   routers than can be obtained with standard IPv6 Neighbor Discovery
   mechanisms.

VRRP accomplishes these goals primarily by using a virtual MAC address shared
between the physical routers participating in a VRRP virtual router. This
reduces churn in the neighbor tables of hosts and downstream switches and makes
router failover theoretically transparent to these devices.

FRR implements the election protocol and handles changing the operating system
interface configuration in response to protocol state changes.

As a consequence of the shared virtual MAC requirement, VRRP is currently
supported only on Linux, as Linux is the only operating system that provides
the necessary features in its network stack to make implementing this protocol
feasible.

When a VRRP router is acting as the Master router, FRR allows the interface(s)
with the backed-up IP addresses to remain up and functional. When the router
transitions to Backup state, these interfaces are set into ``protodown`` mode.
This is an interface mode that is functionally equivalent to ``NO-CARRIER``.
Physical drivers typically use this state indication to drop traffic on an
interface. In the case of VRRP, the interfaces in question are macvlan devices,
which are virtual interfaces. Since the IP addresses managed by VRRP are on
these interfaces, this has the same effect as removing these addresses from the
interface, but is implemented as a state flag.

.. _vrrp-configuration:

Configuring VRRP
================

VRRP is configured on a per-interface basis, with some global defaults
accessible outside the interface context.

.. _vrrp-system-configuration:

System Configuration
--------------------

FRR's VRRP implementation uses Linux macvlan devices to to implement the shared
virtual MAC feature of the protocol. Currently, it does not create those system
interfaces - they must be configured outside of FRR before VRRP can be enabled
on them.

Each interface on which VRRP will be enabled must have at least one macvlan
device configured with the virtual MAC and placed in the proper operation mode.
The addresses backed up by VRRP are assigned to these interfaces.

Suppose you have an interface ``eth0`` with the following configuration:

.. code-block:: console

   $ ip addr show eth0
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
       link/ether 02:17:45:00:aa:aa brd ff:ff:ff:ff:ff:ff
       inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic eth0
          valid_lft 72532sec preferred_lft 72532sec
       inet6 fe80::17:45ff:fe00:aaaa/64 scope link
          valid_lft forever preferred_lft forever

Suppose that the IPv4 and IPv6 addresses you want to back up are ``10.0.2.16``
and ``2001:db8::370:7334``, and that they will be managed by the virtual router
with id ``5``. A macvlan device with the appropriate MAC address must be created
before VRRP can begin to operate.

If you are using ``ifupdown2``, the configuration is as follows:

.. code-block:: console

   iface eth0
    ...
    vrrp 5 10.0.2.16/24 2001:0db8::0370:7334/64

Applying this configuration with ``ifreload -a`` will create the appropriate
macvlan device. If you are using ``iproute2``, the equivalent configuration is:

.. code-block:: console

   ip link add vrrp4-2-1 link eth0 addrgenmode random type macvlan mode bridge
   ip link set dev vrrp4-2-1 address 00:00:5e:00:01:05
   ip addr add 10.0.2.16/24 dev vrrp4-2-1
   ip link set dev vrrp4-2-1 up

   ip link add vrrp6-2-1 link eth0 addrgenmode random type macvlan mode bridge
   ip link set dev vrrp4-2-1 address 00:00:5e:00:02:05
   ip addr add 2001:db8::370:7334/64 dev vrrp6-2-1
   ip link set dev vrrp6-2-1 up

In either case, the created interfaces will look like this:

.. code-block:: console

   $ ip addr show vrrp4-2-1
   5: vrrp4-2-1@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
       link/ether 00:00:5e:00:01:05 brd ff:ff:ff:ff:ff:ff
       inet 10.0.2.16/24 scope global vrrp4-2-1
          valid_lft forever preferred_lft forever
       inet6 fe80::dc56:d11a:e69d:ea72/64 scope link stable-privacy
          valid_lft forever preferred_lft forever

   $ ip addr show vrrp6-2-1
   8: vrrp6-2-1@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:00:5e:00:02:05 brd ff:ff:ff:ff:ff:ff
    inet6 2001:db8::370:7334/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::f8b7:c9dd:a1e8:9844/64 scope link stable-privacy
       valid_lft forever preferred_lft forever

Using ``vrrp4-2-1`` as an example, a few things to note about this interface:

- It is slaved to ``eth0``; any packets transmitted on this interface will
  egress via ``eth0``
- Its MAC address is set to the VRRP IPv4 virtual MAC specified by the RFC for
  :abbr:`VRID (Virtual Router ID)` ``5``
- The :abbr:`VIP (Virtual IP)` address ``10.0.2.16`` must not be present on
  the parent interface ``eth0``.
- The link local address on the interface is not derived from the interface
  MAC

First to note is that packets transmitted on this interface will egress via
``eth0``, but with their Ethernet source MAC set to the VRRP virtual MAC. This
is how FRR's VRRP implementation accomplishes the virtual MAC requirement on
real hardware.

Ingress traffic is a more complicated matter. Macvlan devices have multiple
operating modes that change how ingress traffic is handled. Of relevance to
FRR's implementation are the ``bridge`` and ``private`` modes. In ``private``
mode, any ingress traffic on ``eth0`` (in our example) with a source MAC
address equal to the MAC address on any of ``eth0``'s macvlan devices will be
placed *only* on that macvlan device. This curious behavior is undesirable,
since FRR's implementation of VRRP needs to be able to receive advertisements
from neighbors while in Backup mode - i.e., while its macvlan devices are in
``protodown on``. If the macvlan devices are instead set to ``bridge`` mode,
all ingress traffic shows up on all interfaces - including ``eth0`` -
regardless of source MAC or any other factor. Consequently, macvlans used by
FRR for VRRP must be set to ``bridge`` mode or the protocol will not function
correctly.

As for the MAC address assigned to this interface, the last byte of the address
holds the :abbr:`VRID (Virtual Router Identifier)`, in this case ``0x05``. The
second to last byte is ``0x01``, as specified by the RFC for IPv4 operation.
The IPv6 MAC address is be identical except that the second to last byte is
defined to be ``0x02``. Two things to note from this arrangement:

1. There can only be up to 255 unique Virtual Routers on an interface (only 1
   byte is available for the VRID)
2. IPv4 and IPv6 addresses must be assigned to different macvlan devices,
   because they have different MAC addresses

Finally, take note of the generated IPv6 link local address on the interface.
For interfaces on which VRRP will operate in IPv6 mode, this link local
*cannot* be derived using the usual EUI-64 method. This is because VRRP
advertisements are sent from the link local address of this interface, and VRRP
uses the source address of received advertisements as part of its election
algorithm. If the IPv6 link local of a router is equivalent to the IPv6 link
local in a received advertisement, this can cause both routers to assume the
Master role (very bad). ``ifupdown`` knows to set the ``addrgenmode`` of the
interface properly, but when using ``iproute2`` to create the macvlan devices,
you must be careful to manually specify ``addrgenmode random``.

A brief note on the Backup state
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is worth noting here that an alternate choice for the implementation of the
Backup state, such as removing all the IP addresses assigned to the macvlan
device or deleting their local routes instead of setting the device into
``protodown on``, would allow the protocol to function regardless of whether
the macvlan device(s) are set to ``private`` or ``bridge`` mode. Indeed, the
strange behavior of the kernel macvlan driver in ``private`` mode, whereby it
performs what may be thought of as a sort of interface-level layer 2 "NAT"
based on source MAC, can be traced back to a patch clearly designed to
accommodate a VRRP implementation from a different vendor. However, the
``protodown`` based implementation allows for a configuration model in which
FRR does not dynamically manage the addresses assigned on a system, but instead
just manages interface state. Such a scenario was in mind when this protocol
implementation was initially built, which is why the other choices are not
currently present. Since support for placing macvlan devices into ``protodown``
was not added to Linux until version 5.1, this also explains the relatively
restrictive kernel versioning requirement.

In the future other methods of implementing Backup state may be added along
with a configuration knob to choose between them.

.. _vrrp-interface-configuration:

Interface Configuration
-----------------------

Continuing with the example from the previous section, we assume the macvlan
interfaces have been properly configured with the proper MAC addresses and the
IPvX addresses assigned.

In FRR, a possible VRRPv3 configuration for this interface is:

.. code-block:: frr

   interface eth0
    vrrp 5 version 3
    vrrp 5 priority 200
    vrrp 5 advertisement-interval 1500
    vrrp 5 ip 10.0.2.16
    vrrp 5 ipv6 2001:0db8::0370:7334

VRRP will activate as soon as the first IPvX address configuration line is
encountered. If you do not want this behavior, use the :clicmd:`vrrp (1-255)
shutdown` command, and apply the ``no`` form when you are ready to activate
VRRP.

At this point executing ``show vrrp`` will display the following:

.. code-block:: console

   ubuntu-bionic# show vrrp

    Virtual Router ID                    5
    Protocol Version                     3
    Autoconfigured                       Yes
    Shutdown                             No
    Interface                            eth0
    VRRP interface (v4)                  vrrp4-2-5
    VRRP interface (v6)                  vrrp6-2-5
    Primary IP (v4)                      10.0.2.15
    Primary IP (v6)                      fe80::9b91:7155:bf6a:d386
    Virtual MAC (v4)                     00:00:5e:00:01:05
    Virtual MAC (v6)                     00:00:5e:00:02:05
    Status (v4)                          Master
    Status (v6)                          Master
    Priority                             200
    Effective Priority (v4)              200
    Effective Priority (v6)              200
    Preempt Mode                         Yes
    Accept Mode                          Yes
    Advertisement Interval               1500 ms
    Master Advertisement Interval (v4)   1000 ms
    Master Advertisement Interval (v6)   1000 ms
    Advertisements Tx (v4)               14
    Advertisements Tx (v6)               14
    Advertisements Rx (v4)               0
    Advertisements Rx (v6)               0
    Gratuitous ARP Tx (v4)               1
    Neigh. Adverts Tx (v6)               1
    State transitions (v4)               2
    State transitions (v6)               2
    Skew Time (v4)                       210 ms
    Skew Time (v6)                       210 ms
    Master Down Interval (v4)            3210 ms
    Master Down Interval (v6)            3210 ms
    IPv4 Addresses                       1
    ..................................   10.0.2.16
    IPv6 Addresses                       1
    ..................................   2001:db8::370:7334

At this point, VRRP has sent gratuitous ARP requests for the IPv4 address,
Unsolicited Neighbor Advertisements for the IPv6 address, and has asked Zebra
to send Router Advertisements on its behalf. It is also transmitting VRRPv3
advertisements on the macvlan interfaces.

The Primary IP fields are of some interest, as the behavior may be
counterintuitive. These fields show the source address used for VRRP
advertisements. Although VRRPv3 advertisements are always transmitted on the
macvlan interfaces, in the IPv4 case the source address is set to the primary
IPv4 address on the base interface, ``eth0`` in this case. This is a protocol
requirement, and IPv4 VRRP will not function unless the base interface has an
IPv4 address assigned. In the IPv6 case the link local of the macvlan interface
is used.

If any misconfiguration errors are detected, VRRP for the misconfigured address
family will not come up and the configuration issue will be logged to FRR's
configured logging destination.

Per the RFC, IPv4 and IPv6 virtual routers are independent of each other. For
instance, it is possible for the IPv4 router to be in Backup state while the
IPv6 router is in Master state; or for either to be completely inoperative
while the other is operative, etc. Instances sharing the same base interface
and VRID are shown together in the show output for conceptual convenience.

To complete your VRRP deployment, configure other routers on the segment with
the exact same system and FRR configuration as shown above. Provided each
router receives the others' VRRP advertisements, the Master election protocol
will run, one Master will be elected, and the other routers will place their
macvlan interfaces into ``protodown on`` until Master fails or priority values
are changed to favor another router.

Switching the protocol version to VRRPv2 is accomplished simply by changing
``version 3`` to ``version 2`` in the VRID configuration line. Note that VRRPv2
does not support IPv6, so any IPv6 configuration will be rejected by FRR when
using VRRPv2.

.. note::

   All VRRP routers initially start in Backup state, and wait for the
   calculated Master Down Interval to pass before they assume Master status.
   This prevents downstream neighbor table churn if another router is already
   Master with higher priority, meaning this box will ultimately assume Backup
   status once the first advertisement is received. However, if the calculated
   Master Down Interval is high and this router is configured such that it will
   ultimately assume Master status, then it will take a while for this to
   happen.  This is a known issue.


All interface configuration commands are documented below.

.. index:: [no] vrrp (1-255) [version (2-3)]
.. clicmd:: [no] vrrp (1-255) [version (2-3)]

   Create a VRRP router with the specified VRID on the interface. Optionally
   specify the protocol version. If the protocol version is not specified, the
   default is VRRPv3.

.. index:: [no] vrrp (1-255) advertisement-interval (10-40950)
.. clicmd:: [no] vrrp (1-255) advertisement-interval (10-40950)

   Set the advertisement interval. This is the interval at which VRRP
   advertisements will be sent. Values are given in milliseconds, but must be
   multiples of 10, as VRRP itself uses centiseconds.

.. index:: [no] vrrp (1-255) ip A.B.C.D
.. clicmd:: [no] vrrp (1-255) ip A.B.C.D

   Add an IPv4 address to the router. This address must already be configured
   on the appropriate macvlan device. Adding an IP address to the router will
   implicitly activate the router; see :clicmd:`[no] vrrp (1-255) shutdown` to
   override this behavior.

.. index:: [no] vrrp (1-255) ipv6 X:X::X:X
.. clicmd:: [no] vrrp (1-255) ipv6 X:X::X:X

   Add an IPv6 address to the router. This address must already be configured
   on the appropriate macvlan device. Adding an IP address to the router will
   implicitly activate the router; see :clicmd:`[no] vrrp (1-255) shutdown` to
   override this behavior.

   This command will fail if the protocol version is set to VRRPv2, as VRRPv2
   does not support IPv6.

.. index:: [no] vrrp (1-255) preempt
.. clicmd:: [no] vrrp (1-255) preempt

   Toggle preempt mode. When enabled, preemption allows Backup routers with
   higher priority to take over Master status from the existing Master. Enabled
   by default.

.. index:: [no] vrrp (1-255) priority (1-254)
.. clicmd:: [no] vrrp (1-255) priority (1-254)

   Set the router priority. The router with the highest priority is elected as
   the Master. If all routers in the VRRP virtual router are configured with
   the same priority, the router with the highest primary IP address is elected
   as the Master. Priority value 255 is reserved for the acting Master router.

.. index:: [no] vrrp (1-255) shutdown
.. clicmd:: [no] vrrp (1-255) shutdown

   Place the router into administrative shutdown. VRRP will not activate for
   this router until this command is removed with the ``no`` form.

.. _vrrp-global-configuration:

Global Configuration
--------------------

Show commands, global defaults and debugging configuration commands.

.. index:: show vrrp [interface INTERFACE] [(1-255)] [json]
.. clicmd:: show vrrp [interface INTERFACE] [(1-255)] [json]

   Shows VRRP status for some or all configured VRRP routers. Specifying an
   interface will only show routers configured on that interface. Specifying a
   VRID will only show routers with that VRID. Specifying ``json`` will dump
   each router state in a JSON array.

.. index:: [no] debug vrrp [{protocol|autoconfigure|packets|sockets|ndisc|arp|zebra}]
.. clicmd:: [no] debug vrrp [{protocol|autoconfigure|packets|sockets|ndisc|arp|zebra}]

   Toggle debugging logs for VRRP components.
   If no component is specified, debugging for all components are turned on/off.

   protocol
      Logs state changes, election protocol decisions, and interface status
      changes.

   autoconfigure
      Logs actions taken by the autoconfiguration procedures. See
      :ref:`vrrp-autoconfiguration`.

   packets
      Logs details of ingress and egress packets. Includes packet decodes and
      hex dumps.

   sockets
      Logs details of socket configuration and initialization.

   ndisc
      Logs actions taken by the Neighbor Discovery component of VRRP.

   arp
      Logs actions taken by the ARP component of VRRP.

   zebra
      Logs communications with Zebra.

.. index:: [no] vrrp default <advertisement-interval (1-4096)|preempt|priority (1-254)|shutdown>
.. clicmd:: [no] vrrp default <advertisement-interval (1-4096)|preempt|priority (1-254)|shutdown>

   Configure defaults for new VRRP routers. These values will not affect
   already configured VRRP routers, but will be applied to newly configured
   ones.

.. _vrrp-autoconfiguration:

Autoconfiguration
-----------------

In light of the complicated configuration required on the base system before
VRRP can be enabled, FRR has the ability to automatically configure VRRP
sessions by inspecting the interfaces present on the system. Since it is quite
unlikely that macvlan devices with VRRP virtual MACs will exist on systems not
using VRRP, this can be a convenient shortcut to automatically generate FRR
configuration.

After configuring the interfaces as described in
:ref:`vrrp-system-configuration`, and configuring any defaults you may want,
execute the following command:

.. index:: [no] vrrp autoconfigure [version (2-3)]
.. clicmd:: [no] vrrp autoconfigure [version (2-3)]

   Generates VRRP configuration based on the interface configuration on the
   base system. If the protocol version is not specified, the default is VRRPv3.
   Any existing interfaces that are configured properly for VRRP -
   i.e. have the correct MAC address, link local address (when required), IPv4
   and IPv6 addresses - are used to create a VRRP router on their parent
   interfaces, with VRRP IPvX addresses taken from the addresses assigned to
   the macvlan devices. The generated configuration appears in the output of
   ``show run``, which can then be modified as needed and written to the config
   file. The ``version`` parameter controls the protocol version; if using
   VRRPv2, keep in mind that IPv6 is not supported and will not be configured.

The following configuration is then generated for you:

.. code-block:: frr

   interface eth0
    vrrp 5
    vrrp 5 ip 10.0.2.16
    vrrp 5 ipv6 2001:db8::370:7334

VRRP is automatically activated. Global defaults, if set, are applied.

You can then edit this configuration with **vtysh** as needed, and commit it by
writing to the configuration file.
