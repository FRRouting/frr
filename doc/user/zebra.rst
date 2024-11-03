.. _zebra:

*****
Zebra
*****

*zebra* is an IP routing manager. It provides kernel routing
table updates, interface lookups, and redistribution of routes between
different routing protocols.

.. _invoking-zebra:

Invoking zebra
==============

Besides the common invocation options (:ref:`common-invocation-options`), the
*zebra* specific invocation options are listed below.

.. program:: zebra

.. option:: -b, --batch

   Runs in batch mode. *zebra* parses configuration file and terminates
   immediately.

.. option:: -K TIME, --graceful_restart TIME

   If this option is specified, the graceful restart time is TIME seconds.
   Zebra, when started, will read in routes.  Those routes that Zebra
   identifies that it was the originator of will be swept in TIME seconds.
   If no time is specified then we will sweep those routes immediately.
   Under the \*BSD's, there is no way to properly store the originating
   route and the route types in this case will show up as a static route
   with an admin distance of 255.

.. option:: -r, --retain

   When program terminates, do not flush routes installed by *zebra* from the
   kernel.

.. option:: -e X, --ecmp X

   Run zebra with a limited ecmp ability compared to what it is compiled to.
   If you are running zebra on hardware limited functionality you can
   force zebra to limit the maximum ecmp allowed to X.  This number
   is bounded by what you compiled FRR with as the maximum number.

.. option:: -n, --vrfwnetns

   When *Zebra* starts with this option, the VRF backend is based on Linux
   network namespaces. That implies that all network namespaces discovered by
   ZEBRA will create an associated VRF. The other daemons will operate on the VRF
   VRF defined by *Zebra*, as usual. If this option is specified when running
   *Zebra*, one must also specify the same option for *mgmtd*.

   .. seealso:: :ref:`zebra-vrf`

.. option:: -z <path_to_socket>, --socket <path_to_socket>

   If this option is supplied on the cli, the path to the zebra
   control socket(zapi), is used.  This option overrides a -N <namespace>
   option if handed to it on the cli.

.. option:: --v6-rr-semantics

   The linux kernel is receiving the ability to use the same route
   replacement semantics for v6 that v4 uses.  If you are using a
   kernel that supports this functionality then run *Zebra* with this
   option and we will use Route Replace Semantics instead of delete
   than add.

.. option:: --routing-table <tableno>

   Specify which kernel routing table *Zebra* should communicate with.
   If this option is not specified the default table (RT_TABLE_MAIN) is
   used.

.. option:: --asic-offload=[notify_on_offload|notify_on_ack]

   The linux kernel has the ability to use asic-offload ( see switchdev
   development ).  When the operator knows that FRR will be working in
   this way, allow them to specify this with FRR.  At this point this
   code only supports asynchronous notification of the offload state.
   In other words the initial ACK received for linux kernel installation
   does not give zebra any data about what the state of the offload
   is.  This option takes the optional parameters notify_on_offload
   or notify_on_ack.  This signals to zebra to notify upper level
   protocols about route installation/update on ack received from
   the linux kernel or from offload notification.


.. option:: -s <SIZE>, --nl-bufsize <SIZE>

   Allow zebra to modify the default receive buffer size to SIZE
   in bytes.  Under \*BSD only the -s option is available.

.. option:: --v6-with-v4-nexthops

   Signal to zebra that v6 routes with v4 nexthops are accepted
   by the underlying dataplane.  This will be communicated to
   the upper level daemons that can install v6 routes with v4
   nexthops.

.. _interface-commands:

Configuration Addresses behaviour
=================================

At startup, *Zebra* will first discover the underlying networking objects
from the operating system. This includes interfaces, addresses of
interfaces, static routes, etc. Then, it will read the configuration
file, including its own interface addresses, static routes, etc. All this
information comprises the operational context from *Zebra*. But
configuration context from *Zebra* will remain the same as the one from
:file:`zebra.conf` config file. As an example, executing the following
:clicmd:`show running-config` will reflect what was in :file:`zebra.conf`.
In a similar way, networking objects that are configured outside of the
*Zebra* like *iproute2* will not impact the configuration context from
*Zebra*. This behaviour permits you to continue saving your own config
file, and decide what is really to be pushed on the config file, and what
is dependent on the underlying system.
Note that inversely, from *Zebra*, you will not be able to delete networking
objects that were previously configured outside of *Zebra*.


Interface Commands
==================

.. _standard-commands:

Standard Commands
-----------------


.. clicmd:: interface IFNAME


.. clicmd:: interface IFNAME vrf VRF


.. clicmd:: shutdown


   Up or down the current interface.


.. clicmd:: ip address ADDRESS/PREFIX

.. clicmd:: ipv6 address ADDRESS/PREFIX



   Set the IPv4 or IPv6 address/prefix for the interface.


.. clicmd:: ip address LOCAL-ADDR peer PEER-ADDR/PREFIX


   Configure an IPv4 Point-to-Point address on the interface. (The concept of
   PtP addressing does not exist for IPv6.)

   ``local-addr`` has no subnet mask since the local side in PtP addressing is
   always a single (/32) address. ``peer-addr/prefix`` can be an arbitrary subnet
   behind the other end of the link (or even on the link in Point-to-Multipoint
   setups), though generally /32s are used.


.. clicmd:: description DESCRIPTION ...

   Set description for the interface.


.. clicmd:: mpls <enable|disable>

   Choose mpls kernel processing value on the interface, for linux. Interfaces
   configured with mpls will not automatically turn on if mpls kernel modules do not
   happen to be loaded. This command will fail on 3.X linux kernels and does not
   work on non-linux systems at all. 'enable' and 'disable' will respectively turn
   on and off mpls on the given interface.

.. clicmd:: multicast <enable|disable>


   Enable or disable multicast flag for the interface.


.. clicmd:: bandwidth (1-1000000)

   Set bandwidth value of the interface in Megabits/sec. This is for
   calculating OSPF cost. This command does not affect the actual device
   configuration.


.. clicmd:: link-detect


   Enable or disable link-detect on platforms which support this. Currently only
   Linux, and only where network interface drivers support reporting
   link-state via the ``IFF_RUNNING`` flag.

   In FRR, link-detect is on by default.

.. _link-parameters-commands:

Link Parameters Commands
------------------------

.. note::

   At this time, FRR offers partial support for some of the routing
   protocol extensions that can be used with MPLS-TE. FRR does not
   support a complete RSVP-TE solution currently.

.. clicmd:: link-params

   Enter into the link parameters sub node. This command activates the link
   parameters and allows to configure routing information that could be used
   as part of Traffic Engineering on this interface. MPLS-TE must be enabled at
   the OSPF (:ref:`ospf-traffic-engineering`) or ISIS
   (:ref:`isis-traffic-engineering`) router level in complement to this. To
   disable link parameters, use the ``no`` version of this command.

Under link parameter statement, the following commands set the different TE values:

.. clicmd:: metric (0-4294967295)

.. clicmd:: max-bw BANDWIDTH

.. clicmd:: max-rsv-bw BANDWIDTH

.. clicmd:: unrsv-bw (0-7) BANDWIDTH

   These commands specifies the Traffic Engineering parameters of the interface
   in conformity to RFC3630 (OSPF) or RFC5305 (ISIS).  There are respectively
   the TE Metric (different from the OSPF or ISIS metric), Maximum Bandwidth
   (interface speed by default), Maximum Reservable Bandwidth, Unreserved
   Bandwidth for each 0-7 priority and Admin Group (ISIS) or Resource
   Class/Color (OSPF).

   Note that BANDWIDTH is specified in IEEE floating point format and express
   in Bytes/second.

.. clicmd:: admin-grp 0x(0-FFFFFFFF)

   This commands configures the Traffic Engineering Admin-Group of the interface
   as specified in RFC3630 (OSPF) or RFC5305 (ISIS). Admin-group is also known
   as Resource Class/Color in the OSPF protocol.

.. clicmd:: affinity AFFINITY-MAP-NAME

   This commands configures the Traffic Engineering Admin-Group of the
   interface using the affinity-map definitions (:ref:`affinity-map`).
   Multiple AFFINITY-MAP-NAME can be specified at the same time. Affinity-map
   names are added or removed if ``no`` is present. It means that specifying one
   value does not override the full list.

   ``admin-grp`` and ``affinity`` commands provide two ways of setting
   admin-groups. They cannot be both set on the same interface.

.. clicmd:: affinity-mode [extended|standard|both]

   This commands configures which admin-group format is set by the affinity
   command. ``extended`` Admin-Group is the default and uses the RFC7308 format.
   ``standard`` mode uses the standard admin-group format that is defined by
   RFC3630, RFC5305 and RFC5329. When the ``standard`` mode is set,
   affinity-maps with bit-positions higher than 31 cannot be applied to the
   interface. The ``both`` mode allows setting standard and extended admin-group
   on the link at the same time. In   this case, the bit-positions 0 to 31 are
   the same on standard and extended admin-groups.

   Note that extended admin-groups are only supported by IS-IS for the moment.

.. clicmd:: delay (0-16777215) [min (0-16777215) | max (0-16777215)]

.. clicmd:: delay-variation (0-16777215)

.. clicmd:: packet-loss PERCENTAGE

.. clicmd:: res-bw BANDWIDTH

.. clicmd:: ava-bw BANDWIDTH

.. clicmd:: use-bw BANDWIDTH

   These command specifies additional Traffic Engineering parameters of the
   interface in conformity to draft-ietf-ospf-te-metrics-extension-05.txt and
   draft-ietf-isis-te-metrics-extension-03.txt. There are respectively the
   delay, jitter, loss, available bandwidth, reservable bandwidth and utilized
   bandwidth.

   Note that BANDWIDTH is specified in IEEE floating point format and express
   in Bytes/second.  Delays and delay variation are express in micro-second
   (µs). Loss is specified in PERCENTAGE ranging from 0 to 50.331642% by step
   of 0.000003.

.. clicmd:: neighbor <A.B.C.D> as (0-65535)

   Specifies the remote ASBR IP address and Autonomous System (AS) number
   for InterASv2 link in OSPF (RFC5392).  Note that this option is not yet
   supported for ISIS (RFC5316).

Global Commands
------------------------

.. clicmd:: zebra protodown reason-bit (0-31)

   This command is only supported for linux and a kernel > 5.1.
   Change reason-bit frr uses for setting protodown. We default to 7, but
   if another userspace app ever conflicts with this, you can change it here.
   The descriptor for this bit should exist in :file:`/etc/iproute2/protodown_reasons.d/`
   to display with :clicmd:`ip -d link show`.

Nexthop Tracking
================

Nexthop tracking doesn't resolve nexthops via the default route by default.
Allowing this might be useful when e.g. you want to allow BGP to peer across
the default route.

.. clicmd:: zebra nexthop-group keep (1-3600)

   Set the time that zebra will keep a created and installed nexthop group
   before removing it from the system if the nexthop group is no longer
   being used.  The default time is 180 seconds.

.. clicmd:: ip nht resolve-via-default

   Allow IPv4 nexthop tracking to resolve via the default route. This parameter
   is configured per-VRF, so the command is also available in the VRF subnode.

   This is enabled by default for a traditional profile.

.. clicmd:: ipv6 nht resolve-via-default

   Allow IPv6 nexthop tracking to resolve via the default route. This parameter
   is configured per-VRF, so the command is also available in the VRF subnode.

   This is enabled by default for a traditional profile.

.. clicmd:: show ip nht [vrf NAME] [A.B.C.D|X:X::X:X] [mrib] [json]

   Show nexthop tracking status for address resolution.  If vrf is not specified
   then display the default vrf.  If ``all`` is specified show all vrf address
   resolution output.  If an ipv4 or ipv6 address is not specified then display
   all addresses tracked, else display the requested address.  The mrib keyword
   indicates that the operator wants to see the multicast rib address resolution
   table.  An alternative form of the command is ``show ip import-check`` and this
   form of the command is deprecated at this point in time.
   User can get that information as JSON string when ``json`` key word
   at the end of cli is presented.

.. clicmd:: show ip nht route-map [vrf <NAME|all>] [json]

   This command displays route-map attach point to nexthop tracking and
   displays list of protocol with its applied route-map.
   When zebra considers sending NHT resoultion, the nofification only
   sent to appropriate client protocol only after applying route-map filter.
   User can get that information as JSON format when ``json`` keyword
   at the end of cli is presented.

PBR dataplane programming
=========================

Some dataplanes require the PBR nexthop to be resolved into a SMAC, DMAC and
outgoing interface

.. clicmd:: pbr nexthop-resolve

   Resolve PBR nexthop via ip neigh tracking

.. _administrative-distance:

Administrative Distance
=======================

Administrative distance allows FRR to make decisions about what routes
should be installed in the rib based upon the originating protocol.
The lowest Admin Distance is the route selected.  This is purely a
subjective decision about ordering and care has been taken to choose
the same distances that other routing suites have chosen.

+------------+-----------+
| Protocol   | Distance  |
+------------+-----------+
| System     | 0         |
+------------+-----------+
| Kernel     | 0         |
+------------+-----------+
| Connect    | 0         |
+------------+-----------+
| Static     | 1         |
+------------+-----------+
| NHRP       | 10        |
+------------+-----------+
| EBGP       | 20        |
+------------+-----------+
| EIGRP      | 90        |
+------------+-----------+
| BABEL      | 100       |
+------------+-----------+
| OSPF       | 110       |
+------------+-----------+
| ISIS       | 115       |
+------------+-----------+
| OPENFABRIC | 115       |
+------------+-----------+
| RIP        | 120       |
+------------+-----------+
| Table      | 150       |
+------------+-----------+
| SHARP      | 150       |
+------------+-----------+
| IBGP       | 200       |
+------------+-----------+
| PBR        | 200       |
+------------+-----------+

An admin distance of 255 indicates to Zebra that the route should not be
installed into the Data Plane. Additionally routes with an admin distance
of 255 will not be redistributed.

Zebra does treat Kernel routes as special case for the purposes of Admin
Distance. Upon learning about a route that is not originated by FRR
we read the metric value as a uint32_t. The top byte of the value
is interpreted as the Administrative Distance and the low three bytes
are read in as the metric. This special case is to facilitate VRF
default routes.

.. code-block:: shell

   $ # Set administrative distance to 255 for Zebra
   $ ip route add 192.0.2.0/24 metric $(( 2**32 - 2**24 )) dev lo
   $ vtysh -c 'show ip route 192.0.2.0/24 json' | jq '."192.0.2.0/24"[] | (.distance, .metric)'
   255
   0
   $ # Set administrative distance to 192 for Zebra
   $ ip route add 192.0.2.0/24 metric $(( 2**31 + 2**30 )) dev lo
   $ vtysh -c 'show ip route 192.0.2.0/24 json' | jq '."192.0.2.0/24"[] | (.distance, .metric)'
   192
   0
   $ # Set administrative distance to 128, and metric 100 for Zebra
   $ ip route add 192.0.2.0/24 metric $(( 2**31 + 100 )) dev lo
   $ vtysh -c 'show ip route 192.0.2.0/24 json' | jq '."192.0.2.0/24"[] | (.distance, .metric)'
   128
   100

Route Replace Semantics
=======================

When using the Linux Kernel as a forwarding plane, routes are installed
with a metric of 20 to the kernel.  Please note that the kernel's metric
value bears no resemblence to FRR's RIB metric or admin distance.  It
merely is a way for the Linux Kernel to decide which route to use if it
has multiple routes for the same prefix from multiple sources.  An example
here would be if someone else was running another routing suite besides
FRR at the same time, the kernel must choose what route to use to forward
on.  FRR choose the value of 20 because of two reasons.  FRR wanted a
value small enough to be chosen but large enough that the operator could
allow route prioritization by the kernel when multiple routing suites are
being run and FRR wanted to take advantage of Route Replace semantics that
the linux kernel offers.  In order for Route Replacement semantics to
work FRR must use the same metric when issuing the replace command.
Currently FRR only supports Route Replace semantics using the Linux
Kernel.

.. _zebra-vrf:

Virtual Routing and Forwarding
==============================

FRR supports :abbr:`VRF (Virtual Routing and Forwarding)`. VRF is a way to
separate networking contexts on the same machine. Those networking contexts are
associated with separate interfaces, thus making it possible to associate one
interface with a specific VRF.

VRF can be used, for example, when instantiating per enterprise networking
services, without having to instantiate the physical host machine or the
routing management daemons for each enterprise. As a result, interfaces are
separate for each set of VRF, and routing daemons can have their own context
for each VRF.

This conceptual view introduces the *Default VRF* case. If the user does not
configure any specific VRF, then by default, FRR uses the *Default VRF*. The
name "default" is used to refer to this VRF in various CLI commands and YANG
models. It is possible to change that name by passing the ``-o`` option to all
daemons, for example, one can use ``-o vrf0`` to change the name to "vrf0".
The easiest way to pass the same option to all daemons is to use the
``frr_global_options`` variable in the
:ref:`Daemons Configuration File <daemons-configuration-file>`.

Configuring VRF networking contexts can be done in various ways on FRR. The VRF
interfaces can be configured by entering in interface configuration mode
:clicmd:`interface IFNAME vrf VRF`.

A VRF backend mode is chosen when running *Zebra*.

If no option is chosen, then the *Linux VRF* implementation as references in
https://www.kernel.org/doc/Documentation/networking/vrf.txt will be mapped over
the *Zebra* VRF. The routing table associated to that VRF is a Linux table
identifier located in the same *Linux network namespace* where *Zebra* started.
Please note when using the *Linux VRF* routing table it is expected that a
default Kernel route will be installed that has a metric as outlined in the
www.kernel.org doc above.  The Linux Kernel does table lookup via a combination
of rule application of the rule table and then route lookup of the specified
table.  If no route match is found then the next applicable rule is applied
to find the next route table to use to look for a route match.  As such if
your VRF table does not have a default blackhole route with a high metric
VRF route lookup will leave the table specified by the VRF, which is undesirable.

If the :option:`-n` option is chosen, then the *Linux network namespace* will
be mapped over the *Zebra* VRF. That implies that *Zebra* is able to configure
several *Linux network namespaces*.  The routing table associated to that VRF
is the whole routing tables located in that namespace. For instance, this mode
matches OpenStack Network Namespaces. It matches also OpenFastPath. The default
behavior remains Linux VRF which is supported by the Linux kernel community,
see https://www.kernel.org/doc/Documentation/networking/vrf.txt.

Because of that difference, there are some subtle differences when running some
commands in relationship to VRF. Here is an extract of some of those commands:

.. clicmd:: vrf VRF

   This command is available on configuration mode. By default, above command
   permits accessing the VRF configuration mode. This mode is available for
   both VRFs. It is to be noted that *Zebra* does not create Linux VRF.
   The network administrator can however decide to provision this command in
   configuration file to provide more clarity about the intended configuration.

.. clicmd:: netns NAMESPACE

   This command is based on VRF configuration mode. This command is available
   when *Zebra* is run in :option:`-n` mode. This command reflects which *Linux
   network namespace* is to be mapped with *Zebra* VRF. It is to be noted that
   *Zebra* creates and detects added/suppressed VRFs from the Linux environment
   (in fact, those managed with iproute2). The network administrator can however
   decide to provision this command in configuration file to provide more clarity
   about the intended configuration.

.. clicmd:: show ip route vrf VRF

   The show command permits dumping the routing table associated to the VRF. If
   *Zebra* is launched with default settings, this will be the ``TABLENO`` of
   the VRF configured on the kernel, thanks to information provided in
   https://www.kernel.org/doc/Documentation/networking/vrf.txt. If *Zebra* is
   launched with :option:`-n` option, this will be the default routing table of
   the *Linux network namespace* ``VRF``.

.. clicmd:: show ip route vrf VRF table TABLENO

   The show command is only available with :option:`-n` option. This command
   will dump the routing table ``TABLENO`` of the *Linux network namespace*
   ``VRF``.

.. clicmd:: show ip route vrf VRF tables

   This command will dump the routing tables within the vrf scope. If ``vrf all``
   is executed, all routing tables will be dumped.

.. clicmd:: show <ip|ipv6> route summary [vrf VRF] [table TABLENO] [prefix]

   This command will dump a summary output of the specified VRF and TABLENO
   combination.  If neither VRF or TABLENO is specified FRR defaults to
   the default vrf and default table.  If prefix is specified dump the
   number of prefix routes.

.. _zebra-table-allocation:

Table Allocation
================

Some services like BGP flowspec allocate routing tables to perform policy
routing based on netfilter criteria and IP rules. In order to avoid
conflicts between VRF allocated routing tables and those services, Zebra
proposes to define a chunk of routing tables to use by other services.

Allocation configuration can be done like below, with the range of the
chunk of routing tables to be used by the given service.

.. clicmd:: ip table range <STARTTABLENO> <ENDTABLENO>

.. _zebra-ecmp:

ECMP
====

FRR supports ECMP as part of normal operations and is generally compiled
with a limit of 64 way ECMP.  This of course can be modified via configure
options on compilation if the end operator desires to do so.  Individual
protocols each have their own way of dictating ECMP policy and their
respective documentation should be read.

ECMP can be inspected in zebra by doing a ``show ip route X`` command.

.. code-block:: shell

   eva# show ip route 4.4.4.4/32
   Codes: K - kernel route, C - connected, S - static, R - RIP,
          O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
          T - Table, v - VNC, V - VNC-Direct, A - Babel, D - SHARP,
          F - PBR, f - OpenFabric,
          > - selected route, * - FIB route, q - queued, r - rejected, b - backup
          t - trapped, o - offload failure

   D>* 4.4.4.4/32 [150/0] via 192.168.161.1, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.2, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.3, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.4, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.5, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.6, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.7, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.8, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.9, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.10, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.11, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.12, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.13, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.14, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.15, enp39s0, weight 1, 00:00:02
     *                    via 192.168.161.16, enp39s0, weight 1, 00:00:02

In this example we have 16 way ecmp for the 4.4.4.4/32 route.  The ``*`` character
tells us that the route is installed in the Data Plane, or FIB.

If you are using the Linux kernel as a Data Plane, this can be inspected
via a ``ip route show X`` command:

.. code-block:: shell

   sharpd@eva ~/f/doc(ecmp_doc_change)> ip route show 4.4.4.4/32
   4.4.4.4 nhid 185483868 proto sharp metric 20
      nexthop via 192.168.161.1 dev enp39s0 weight 1
      nexthop via 192.168.161.10 dev enp39s0 weight 1
      nexthop via 192.168.161.11 dev enp39s0 weight 1
      nexthop via 192.168.161.12 dev enp39s0 weight 1
      nexthop via 192.168.161.13 dev enp39s0 weight 1
      nexthop via 192.168.161.14 dev enp39s0 weight 1
      nexthop via 192.168.161.15 dev enp39s0 weight 1
      nexthop via 192.168.161.16 dev enp39s0 weight 1
      nexthop via 192.168.161.2 dev enp39s0 weight 1
      nexthop via 192.168.161.3 dev enp39s0 weight 1
      nexthop via 192.168.161.4 dev enp39s0 weight 1
      nexthop via 192.168.161.5 dev enp39s0 weight 1
      nexthop via 192.168.161.6 dev enp39s0 weight 1
      nexthop via 192.168.161.7 dev enp39s0 weight 1
      nexthop via 192.168.161.8 dev enp39s0 weight 1
      nexthop via 192.168.161.9 dev enp39s0 weight 1

Once installed into the FIB, FRR currently has little control over what
nexthops are chosen to forward packets on.  Currently the Linux kernel
has a ``fib_multipath_hash_policy`` sysctl which dictates how the hashing
algorithm is used to forward packets.

.. _zebra-svd:

Single Vxlan Device Support
===========================

FRR supports configuring VLAN-to-VNI mappings for EVPN-VXLAN,
when working with the Linux kernel. In this new way, the mapping of a VLAN
to a VNI is configured against a container VXLAN interface which is referred
to as a ‘Single VXLAN device (SVD)’. Multiple VLAN to VNI mappings can be
configured against the same SVD. This allows for a significant scaling of
the number of VNIs since a separate VXLAN interface is no longer required
for each VNI. Sample configuration of SVD with VLAN to VNI mappings is shown
below.

If you are using the Linux kernel as a Data Plane, this can be configured
via `ip link`, `bridge link` and `bridge vlan` commands:

.. code-block:: shell

   # linux shell
   ip link add dev bridge type bridge
   ip link set dev bridge type bridge vlan_filtering 1
   ip link add dev vxlan0 type vxlan external
   ip link set dev vxlan0 master bridge
   bridge link set dev vxlan0 vlan_tunnel on
   bridge vlan add dev vxlan0 vid 100
   bridge vlan add dev vxlan0 vid 100 tunnel_info id 100
   bridge vlan tunnelshow
    port    vlan ids        tunnel id
    bridge  None
    vxlan0   100     100

.. clicmd:: show evpn access-vlan [IFNAME VLAN-ID | detail] [json]

   Show information for EVPN Access VLANs.

   ::

      VLAN         SVI             L2-VNI   VXLAN-IF        # Members
      bridge.20    vlan20          20       vxlan0          0
      bridge.10    vlan10          0        vxlan0          0

.. _zebra-mpls:

MPLS Commands
=============

You can configure static mpls entries in zebra. Basically, handling MPLS
consists of popping, swapping or pushing labels to IP packets.

MPLS Acronyms
-------------

:abbr:`LSR (Labeled Switch Router)`
   Networking devices handling labels used to forward traffic between and through
   them.

:abbr:`LER (Labeled Edge Router)`
   A Labeled edge router is located at the edge of an MPLS network, generally
   between an IP network and an MPLS network.

MPLS Push Action
----------------

The push action is generally used for LER devices, which want to encapsulate
all traffic for a wished destination into an MPLS label. This action is stored
in routing entry, and can be configured like a route:

.. clicmd:: ip route NETWORK MASK GATEWAY|INTERFACE label LABEL

   NETWORK and MASK stand for the IP prefix entry to be added as static
   route entry.
   GATEWAY is the gateway IP address to reach, in order to reach the prefix.
   INTERFACE is the interface behind which the prefix is located.
   LABEL is the MPLS label to use to reach the prefix abovementioned.

   You can check that the static entry is stored in the zebra RIB database, by
   looking at the presence of the entry.

   ::

      zebra(configure)# ip route 1.1.1.1/32 10.0.1.1 label 777
      zebra# show ip route
      Codes: K - kernel route, C - connected, S - static, R - RIP,
      O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
      T - Table, v - VNC, V - VNC-Direct, A - Babel, D - SHARP,
      F - PBR,
      > - selected route, * - FIB route

      S>* 1.1.1.1/32 [1/0] via 10.0.1.1, r2-eth0, label 777, 00:39:42

MPLS Swap and Pop Action
------------------------

The swap action is generally used for LSR devices, which swap a packet with a
label, with an other label. The Pop action is used on LER devices, at the
termination of the MPLS traffic; this is used to remove MPLS header.

.. clicmd:: mpls lsp INCOMING_LABEL GATEWAY OUTGOING_LABEL|explicit-null|implicit-null

   INCOMING_LABEL and OUTGOING_LABEL are MPLS labels with values ranging from 16
   to 1048575.
   GATEWAY is the gateway IP address where to send MPLS packet.
   The outgoing label can either be a value or have an explicit-null label header. This
   specific header can be read by IP devices. The incoming label can also be removed; in
   that case the implicit-null keyword is used, and the outgoing packet emitted is an IP
   packet without MPLS header.

You can check that the MPLS actions are stored in the zebra MPLS table, by looking at the
presence of the entry.

.. clicmd:: show mpls table

::

   zebra(configure)# mpls lsp 18 10.125.0.2 implicit-null
   zebra(configure)# mpls lsp 19 10.125.0.2 20
   zebra(configure)# mpls lsp 21 10.125.0.2 explicit-null
   zebra# show mpls table
   Inbound                            Outbound
   Label     Type          Nexthop     Label
   --------  -------  ---------------  --------
   18     Static       10.125.0.2  implicit-null
   19     Static       10.125.0.2  20
   21     Static       10.125.0.2  IPv4 Explicit Null


MPLS label chunks
-----------------

MPLS label chunks are handled in the zebra label manager service,
which ensures a same label value or label chunk can not be used by
multiple CP routing daemons at the same time.

Label requests originate from CP routing daemons, and are resolved
over the default MPLS range (16-1048575). There are two kind of
requests:
- Static label requests request an exact label value or range. For
instance, segment routing label blocks requests originating from
IS-IS are part of it.
- Dynamic label requests only need a range of label values. The
'bgp l3vpn export auto' command uses such requests.

Allocated label chunks table can be dumped using the command

.. clicmd:: show debugging label-table [json]

::

   zebra# show debugging label-table
   Proto ospf: [300/350]
   Proto srte: [500/500]
   Proto isis: [1200/1300]
   Proto ospf: [20000/21000]
   Proto isis: [22000/23000]

.. clicmd:: mpls label dynamic-block (16-1048575) (16-1048575)

   Define a range of labels where dynamic label requests will
   allocate label chunks from. This command guarantees that
   static label values outside that range will not conflict
   with the dynamic label requests. When the dynamic-block
   range is configured, static label requests that match that
   range are not accepted.

FEC nexthop entry resolution over MPLS networks
-----------------------------------------------

The LSP associated with a BGP labeled route is normally restricted to
directly-connected nexthops. If connected nexthops are not available,
the LSP entry will not be installed. This command permits the use of
recursive resolution for LSPs, similar to that available for IP routes.

.. clicmd:: mpls fec nexthop-resolution

.. _zebra-srv6:

Segment-Routing IPv6
====================

Segment-Routing is source routing paradigm that allows
network operator to encode network intent into the packets.
SRv6 is an implementation of Segment-Routing
with application of IPv6 and segment-routing-header.

All routing daemon can use the Segment-Routing base
framework implemented on zebra to use SRv6 routing mechanism.
In that case, user must configure initial srv6 setting on
FRR's cli or frr.conf or zebra.conf. This section shows how
to configure SRv6 on FRR. Of course SRv6 can be used as standalone,
and this section also helps that case.

.. clicmd:: show segment-routing srv6 manager [json]

   This command dumps the SRv6 information configured on zebra, including
   the encapsulation parameters (e.g., the IPv6 source address used for
   the encapsulated packets).

   Example::

      router# sh segment-routing srv6 manager
      Parameters:
      Encapsulation:
         Source Address:
            Configured: fc00:0:1::1


   To get the same information in json format, you can use the ``json`` keyword::

      rose-srv6# sh segment-routing srv6 manager json
      {
        "parameters":{
          "encapsulation":{
            "sourceAddress":{
              "configured":"fc00:0:1::1"
            }
          }
        }
      }


.. clicmd:: show segment-routing srv6 locator [json]

   This command dump SRv6-locator configured on zebra.  SRv6-locator is used
   to route to the node before performing the SRv6-function. and that works as
   aggregation of SRv6-function's IDs.  Following console log shows two
   SRv6-locators loc1 and loc2.  All locators are identified by unique IPv6
   prefix.  User can get that information as JSON string when ``json`` key word
   at the end of cli is presented.

::

   router# sh segment-routing srv6 locator
   Locator:
   Name                 ID      Prefix                   Status
   -------------------- ------- ------------------------ -------
   loc1                       1 2001:db8:1:1::/64        Up
   loc2                       2 2001:db8:2:2::/64        Up

.. clicmd:: show segment-routing srv6 locator NAME detail [json]

   As shown in the example, by specifying the name of the locator, you
   can see the detailed information for each locator.  Locator can be
   represented by a single IPv6 prefix, but SRv6 is designed to share this
   Locator among multiple Routing Protocols. For this purpose, zebra divides
   the IPv6 prefix block that makes the Locator unique into multiple chunks,
   and manages the ownership of each chunk.

   For example, loc1 has system as its owner. For example, loc1 is owned by
   system, which means that it is not yet proprietary to any routing protocol.
   For example, loc2 has sharp as its owner. This means that the shaprd for
   function development holds the owner of the chunk of this locator, and no
   other routing protocol will use this area.

::

   router# show segment-routing srv6 locator loc1 detail
   Name: loc1
   Prefix: 2001:db8:1:1::/64
   Chunks:
   - prefix: 2001:db8:1:1::/64, owner: system

   router# show segment-routing srv6 locator loc2 detail
   Name: loc2
   Prefix: 2001:db8:2:2::/64
   Chunks:
   - prefix: 2001:db8:2:2::/64, owner: sharp

.. clicmd:: segment-routing

   Move from configure mode to segment-routing node.

.. clicmd:: srv6

   Move from segment-routing node to srv6 node.

.. clicmd:: locators

   Move from srv6 node to locator node. In this locator node, user can
   configure detailed settings such as the actual srv6 locator.

.. clicmd:: locator NAME

   Create a new locator. If the name of an existing locator is specified,
   move to specified locator's configuration node to change the settings it.

.. clicmd:: prefix X:X::X:X/M [func-bits (0-64)] [block-len 40] [node-len 24]

   Set the ipv6 prefix block of the locator. SRv6 locator is defined by
   RFC8986. The actual routing protocol specifies the locator and allocates a
   SID to be used by each routing protocol. This SID is included in the locator
   as an IPv6 prefix.

   Following example console log shows the typical configuration of SRv6
   data-plane. After a new SRv6 locator, named loc1, is created, loc1's prefix
   is configured as ``2001:db8:1:1::/64``.  If user or some routing daemon
   allocates new SID on this locator, new SID will allocated in range of this
   prefix. For example, if some routing daemon creates new SID on locator
   (``2001:db8:1:1::/64``), Then new SID will be ``2001:db8:1:1:7::/80``,
   ``2001:db8:1:1:8::/80``, and so on.  Each locator has default SID that is
   SRv6 local function "End".  Usually default SID is allocated as
   ``PREFIX:1::``.  (``PREFIX`` is locator's prefix) For example, if user
   configure the locator's prefix as ``2001:db8:1:1::/64``, then default SID
   will be ``2001:db8:1:1:1::``)

   This command takes three optional parameters: ``func-bits``, ``block-len``
   and ``node-len``. These parameters allow users to set the format for the SIDs
   allocated from the SRv6 Locator. SID Format is defined in RFC 8986.

   According to RFC 8986, an SRv6 SID consists of BLOCK:NODE:FUNCTION:ARGUMENT,
   where BLOCK is the SRv6 SID block (i.e., the IPv6 prefix allocated for SRv6
   SIDs by the operator), NODE is the identifier of the parent node instantiating
   the SID, FUNCTION identifies the local behavior associated to the SID and
   ARGUMENT encodes additional information used to process the behavior.
   BLOCK and NODE make up the SRv6 Locator.

   The function bits range is 16bits by default.  If operator want to change
   function bits range, they can configure with ``func-bits``
   option.

   The ``block-len`` and ``node-len`` parameters allow the user to configure the
   length of the SRv6 SID block and SRv6 SID node, respectively. Both the lengths
   are expressed in bits.

   ``block-len``, ``node-len`` and ``func-bits`` may be any value as long as
   ``block-len+node-len = locator-len`` and ``block-len+node-len+func-bits <= 128``.

   When both ``block-len`` and ``node-len`` are omitted, the following default
   values are used: ``block-len = 24``, ``node-len = prefix-len-24``.

   If only one parameter is omitted, the other parameter is derived from the first.

::

   router# configure terminal
   router(config)# segment-routing
   router(config-sr)# srv6
   router(config-srv6)# locators
   router(config-srv6-locs)# locator loc1
   router(config-srv6-loc)# prefix 2001:db8:1:1::/64

   router(config-srv6-loc)# show run
   ...
   segment-routing
    srv6
     locators
      locator loc1
       prefix 2001:db8:1:1::/64
      !
   ...

.. clicmd:: behavior usid

   Specify the SRv6 locator as a Micro-segment (uSID) locator. When a locator is
   specified as a uSID locator, all the SRv6 SIDs allocated from the locator by the routing
   protocols are bound to the SRv6 uSID behaviors. For example, if you configure BGP to use
   a locator specified as a uSID locator, BGP instantiates and advertises SRv6 uSID behaviors
   (e.g., ``uDT4`` / ``uDT6`` / ``uDT46``) instead of classic SRv6 behaviors
   (e.g., ``End.DT4`` / ``End.DT6`` / ``End.DT46``).

::

   router# configure terminal
   router(config)# segment-routing
   router(config-sr)# srv6
   router(config-srv6)# locators
   router(config-srv6-locators)# locator loc1
   router(config-srv6-locator)# prefix fc00:0:1::/48 block-len 32 node-len 16 func-bits 16
   router(config-srv6-locator)# behavior usid

   router(config-srv6-locator)# show run
   ...
   segment-routing
    srv6
     locators
      locator loc1
       prefix fc00:0:1::/48
       behavior usid
      !
   ...

.. clicmd:: format NAME

   Specify the SID allocation schema for the SIDs allocated from this locator. Currently,
   FRR supports supports the following allocation schemas:

   - `usid-f3216`
   - `uncompressed`

::

   router# configure terminal
   router(config)# segment-routing
   router(config-sr)# srv6
   router(config-srv6)# locators
   router(config-srv6-locators)# locator loc1
   router(config-srv6-locator)# prefix fc00:0:1::/48
   router(config-srv6-locator)# format usid-f3216

   router(config-srv6-locator)# show run
   ...
   segment-routing
    srv6
     locators
      locator loc1
       prefix fc00:0:1::/48
       format usid-f3216
      !
   ...

.. clicmd:: encapsulation

   Configure parameters for SRv6 encapsulation.

.. clicmd:: source-address X:X::X:X

   Configure the source address of the outer encapsulating IPv6 header.

.. clicmd:: formats

   Configure SRv6 SID formats.

.. clicmd:: format NAME

   Configure SRv6 SID format.

.. clicmd:: compressed usid

   Enable SRv6 uSID compression and configure SRv6 uSID compression parameters.

.. clicmd:: local-id-block start START

   Configure the start value for the Local ID Block (LIB).

.. clicmd:: local-id-block explicit start START end END

   Configure the start/end values for the Explicit LIB (ELIB).

.. clicmd:: wide-local-id-block start START end END

   Configure the start/end values for the Wide LIB (W-LIB).

.. clicmd:: wide-local-id-block explicit start START

   Configure the start value for the Explicit Wide LIB (EW-LIB).

::

   router# configure terminal
   router(config)# segment-routing
   router(config-sr)# srv6
   router(config-srv6)# formats
   router(config-srv6-formats)# format usid-f3216
   router(config-srv6-format)# compressed usid
   router(config-srv6-format-usid)# local-id-block start 0xD000
   router(config-srv6-format-usid)# local-id-block explicit start 0xF000 end 0xFDFF
   router(config-srv6-format-usid)# wide-local-id-block start 0xFFF4 end 0xFFF5
   router(config-srv6-format-usid)# wide-local-id-block explicit start 0xFFF4

   router(config-srv6-locator)# show run
   ...
   segment-routing
    srv6
     formats
      format usid-f3216
       compressed usid
        local-id-block start 0xD000
        local-id-block explicit start 0xF000 end 0xFDFF
        wide-local-id-block start 0xFFF4 end 0xFFF5
        wide-local-id-block explicit start 0xFFF4
      !
   ...

.. _multicast-rib-commands:

Multicast RIB Commands
======================

The Multicast RIB provides a separate table of unicast destinations which
is used for Multicast Reverse Path Forwarding decisions. It is used with
a multicast source's IP address, hence contains not multicast group
addresses but unicast addresses.

This table is fully separate from the default unicast table. However,
RPF lookup can include the unicast table.

WARNING: RPF lookup results are non-responsive in this version of FRR,
i.e. multicast routing does not actively react to changes in underlying
unicast topology!

.. clicmd:: ip multicast rpf-lookup-mode MODE


   MODE sets the method used to perform RPF lookups. Supported modes:

   urib-only
      Performs the lookup on the Unicast RIB. The Multicast RIB is never used.

   mrib-only
      Performs the lookup on the Multicast RIB. The Unicast RIB is never used.

   mrib-then-urib
      Tries to perform the lookup on the Multicast RIB. If any route is found,
      that route is used. Otherwise, the Unicast RIB is tried.

   lower-distance
      Performs a lookup on the Multicast RIB and Unicast RIB each. The result
      with the lower administrative distance is used;  if they're equal, the
      Multicast RIB takes precedence.

   longer-prefix
      Performs a lookup on the Multicast RIB and Unicast RIB each. The result
      with the longer prefix length is used;  if they're equal, the
      Multicast RIB takes precedence.

      The ``mrib-then-urib`` setting is the default behavior if nothing is
      configured. If this is the desired behavior, it should be explicitly
      configured to make the configuration immune against possible changes in
      what the default behavior is.

.. warning::

   Unreachable routes do not receive special treatment and do not cause
   fallback to a second lookup.

.. clicmd:: show [ip|ipv6] rpf ADDR

   Performs a Multicast RPF lookup, as configured with ``ip multicast
   rpf-lookup-mode MODE``. ADDR specifies the multicast source address to look
   up.

   ::

      > show ip rpf 192.0.2.1
      Routing entry for 192.0.2.0/24 using Unicast RIB
      Known via "kernel", distance 0, metric 0, best
      * 198.51.100.1, via eth0


   Indicates that a multicast source lookup for 192.0.2.1 would use an
   Unicast RIB entry for 192.0.2.0/24 with a gateway of 198.51.100.1.

.. clicmd:: show [ip|ipv6] rpf

   Prints the entire Multicast RIB. Note that this is independent of the
   configured RPF lookup mode, the Multicast RIB may be printed yet not
   used at all.

.. clicmd:: ip mroute PREFIX NEXTHOP [DISTANCE]


   Adds a static route entry to the Multicast RIB. This performs exactly as the
   ``ip route`` command, except that it inserts the route in the Multicast RIB
   instead of the Unicast RIB.

.. _zebra-route-filtering:

zebra Route Filtering
=====================

Zebra supports :dfn:`prefix-list` s and :ref:`route-map` s to match routes
received from other FRR components. The permit/deny facilities provided by
these commands can be used to filter which routes zebra will install in the
kernel.

.. clicmd:: ip protocol PROTOCOL route-map ROUTEMAP

   Apply a route-map filter to routes for the specified protocol. PROTOCOL can
   be:

   - any,
   - babel,
   - bgp,
   - connected,
   - eigrp,
   - isis,
   - kernel,
   - nhrp,
   - openfabric,
   - ospf,
   - ospf6,
   - rip,
   - sharp,
   - static,
   - ripng,
   - table,
   - vnc.

   If you choose any as the option that will cause all protocols that are sending
   routes to zebra.  You can specify a :dfn:`ip protocol PROTOCOL route-map ROUTEMAP`
   on a per vrf basis, by entering this command under vrf mode for the vrf you
   want to apply the route-map against.

.. clicmd:: set src ADDRESS

   Within a route-map, set the preferred source address for matching routes
   when installing in the kernel.


The following creates a prefix-list that matches all addresses, a route-map
that sets the preferred source address, and applies the route-map to all
*rip* routes.

.. code-block:: frr

   ip prefix-list ANY permit 0.0.0.0/0 le 32
   route-map RM1 permit 10
     match ip address prefix-list ANY
     set src 10.0.0.1

   ip protocol rip route-map RM1

IPv6 example for OSPFv3.

.. code-block:: frr

   ipv6 prefix-list ANY seq 10 permit any
   route-map RM6 permit 10
     match ipv6 address prefix-list ANY
     set src 2001:db8:425:1000::3

   ipv6 protocol ospf6 route-map RM6


.. note::

   For both IPv4 and IPv6, the IP address has to exist on some interface when
   the route is getting installed into the system. Otherwise, kernel rejects
   the route. To solve the problem of disappearing IPv6 addresses when the
   interface goes down, use ``net.ipv6.conf.all.keep_addr_on_down``
   :ref:`sysctl option <zebra-sysctl>`.

.. clicmd:: zebra route-map delay-timer (0-600)

   Set the delay before any route-maps are processed in zebra.  The
   default time for this is 5 seconds.


.. _zebra-table-import:

zebra Table Import
==================

Zebra supports importing an alternate routing table into the main unicast RIB (URIB).
An imported table will continously sync all changes to the main URIB as routes are
added or deleted from the alternate table.
Zebra also supports importing into the main multicast RIB (MRIB) which can be used
to affect how multicast RPF lookups are performed as described in :ref: `_pim-multicast-rib`.

.. clicmd:: ip import-table (1-252) [mrib] [distance (1-255)] [route-map RMAP_NAME]

   Import table, by given table id, into the main URIB (or MRIB). Optional distance can override
   the default distance when importing routes from the alternate table. An optional route map
   can be provided to filter routes that are imported into the main table.


.. _zebra-fib-push-interface:

zebra FIB push interface
========================

Zebra supports a 'FIB push' interface that allows an external
component to learn the forwarding information computed by the FRR
routing suite. This is a loadable module that needs to be enabled
at startup as described in :ref:`loadable-module-support`.

In FRR, the Routing Information Base (RIB) resides inside
zebra. Routing protocols communicate their best routes to zebra, and
zebra computes the best route across protocols for each prefix. This
latter information makes up the Forwarding Information Base
(FIB). Zebra feeds the FIB to the kernel, which allows the IP stack in
the kernel to forward packets according to the routes computed by
FRR. The kernel FIB is updated in an OS-specific way. For example,
the ``Netlink`` interface is used on Linux, and route sockets are
used on FreeBSD.

The FIB push interface aims to provide a cross-platform mechanism to
support scenarios where the router has a forwarding path that is
distinct from the kernel, commonly a hardware-based fast path. In
these cases, the FIB needs to be maintained reliably in the fast path
as well. We refer to the component that programs the forwarding plane
(directly or indirectly) as the Forwarding Plane Manager or FPM.

.. program:: configure

The relevant zebra code kicks in when zebra is configured with the
:option:`--enable-fpm` flag and started with the module (``-M fpm``
or ``-M dplane_fpm_nl``).

.. note::

   The ``fpm`` implementation attempts to connect to ``127.0.0.1`` port ``2620``
   by default without configurations. The ``dplane_fpm_nl`` only attempts to
   connect to a server if configured.

Zebra periodically attempts to connect to the well-known FPM port (``2620``).
Once the connection is up, zebra starts sending messages containing routes
over the socket to the FPM. Zebra sends a complete copy of the forwarding
table to the FPM, including routes that it may have picked up from the kernel.
The existing interaction of zebra with the kernel remains unchanged -- that
is, the kernel continues to receive FIB updates as before.

The default FPM message format is netlink, however it can be controlled
with the module load-time option. The modules accept the following options:

- ``fpm``: ``netlink`` and ``protobuf``.
- ``dplane_fpm_nl``: none, it only implements netlink.

The zebra FPM interface uses replace semantics. That is, if a 'route
add' message for a prefix is followed by another 'route add' message,
the information in the second message is complete by itself, and
replaces the information sent in the first message.

If the connection to the FPM goes down for some reason, zebra sends
the FPM a complete copy of the forwarding table(s) when it reconnects.

For more details on the implementation, please read the developer's manual FPM
section.

FPM Commands
============

``fpm`` implementation
----------------------

.. clicmd:: fpm connection ip A.B.C.D port (1-65535)

   Configure ``zebra`` to connect to a different FPM server than the default of
   ``127.0.0.1:2620``

.. clicmd:: show zebra fpm stats

   Shows the FPM statistics.

   Sample output:

   ::

       Counter                                       Total     Last 10 secs

       connect_calls                                     3                2
       connect_no_sock                                   0                0
       read_cb_calls                                     2                2
       write_cb_calls                                    2                0
       write_calls                                       1                0
       partial_writes                                    0                0
       max_writes_hit                                    0                0
       t_write_yields                                    0                0
       nop_deletes_skipped                               6                0
       route_adds                                        5                0
       route_dels                                        0                0
       updates_triggered                                11                0
       redundant_triggers                                0                0
       dests_del_after_update                            0                0
       t_conn_down_starts                                0                0
       t_conn_down_dests_processed                       0                0
       t_conn_down_yields                                0                0
       t_conn_down_finishes                              0                0
       t_conn_up_starts                                  1                0
       t_conn_up_dests_processed                        11                0
       t_conn_up_yields                                  0                0
       t_conn_up_aborts                                  0                0
       t_conn_up_finishes                                1                0


.. clicmd:: clear zebra fpm stats

   Reset statistics related to the zebra code that interacts with the
   optional Forwarding Plane Manager (FPM) component.


``dplane_fpm_nl`` implementation
--------------------------------

.. clicmd:: fpm address <A.B.C.D|X:X::X:X> [port (1-65535)]

   Configures the FPM server address. Once configured ``zebra`` will attempt
   to connect to it immediately.

   The ``no`` form disables FPM entirely. ``zebra`` will close any current
   connections and will not attempt to connect to it anymore.

.. clicmd:: fpm use-next-hop-groups

   Use the new netlink messages ``RTM_NEWNEXTHOP`` / ``RTM_DELNEXTHOP`` to
   group repeated route next hop information.

   The ``no`` form uses the old known FPM behavior of including next hop
   information in the route (e.g. ``RTM_NEWROUTE``) messages.

.. clicmd:: fpm use-route-replace

   Use the netlink ``NLM_F_REPLACE`` flag for updating routes instead of
   two different messages to update a route
   (``RTM_DELROUTE`` + ``RTM_NEWROUTE``).

.. clicmd:: show fpm counters [json]

   Show the FPM statistics (plain text or JSON formatted).

   Sample output:

   ::

                        FPM counters
                        ============
                       Input bytes: 0
                      Output bytes: 308
        Output buffer current size: 0
           Output buffer peak size: 308
                 Connection closes: 0
                 Connection errors: 0
        Data plane items processed: 0
         Data plane items enqueued: 0
       Data plane items queue peak: 0
                  Buffer full hits: 0
           User FPM configurations: 1
         User FPM disable requests: 0

.. clicmd:: show fpm status [json]

   Show the FPM status.

.. clicmd:: clear fpm counters

   Reset statistics related to the zebra code that interacts with the
   optional Forwarding Plane Manager (FPM) component.


.. _zebra-dplane:

Dataplane Commands
==================

The zebra dataplane subsystem provides a framework for FIB
programming. Zebra uses the dataplane to program the local kernel as
it makes changes to objects such as IP routes, MPLS LSPs, and
interface IP addresses. The dataplane runs in its own pthread, in
order to off-load work from the main zebra pthread.


.. clicmd:: show zebra dplane [detailed]

   Display statistics about the updates and events passing through the
   dataplane subsystem.


.. clicmd:: show zebra dplane providers

   Display information about the running dataplane plugins that are
   providing updates to a FIB. By default, the local kernel plugin is
   present.


.. clicmd:: zebra dplane limit [NUMBER]

   Configure the limit on the number of pending updates that are
   waiting to be processed by the dataplane pthread.


DPDK dataplane
==============

The zebra DPDK subsystem programs the dataplane via rte_XXX APIs.
This module needs be compiled in via "--enable-dp-dpdk=yes"
and enabled at start up time via the zebra daemon option "-M dplane_dpdk".

To program the PBR rules as rte_flows you additionally need to configure
"pbr nexthop-resolve". This is used to expland the PBR actions into the
{SMAC, DMAC, outgoing port} needed by rte_flow.


.. clicmd:: show dplane dpdk port [detail]

   Displays the mapping table between zebra interfaces and DPDK port-ids.
   Sample output:

   ::
   Port Device           IfName           IfIndex          sw,domain,port

   0    0000:03:00.0     p0               4                0000:03:00.0,0,65535
   1    0000:03:00.0     pf0hpf           6                0000:03:00.0,0,4095
   2    0000:03:00.0     pf0vf0           15               0000:03:00.0,0,4096
   3    0000:03:00.0     pf0vf1           16               0000:03:00.0,0,4097
   4    0000:03:00.1     p1               5                0000:03:00.1,1,65535
   5    0000:03:00.1     pf1hpf           7                0000:03:00.1,1,20479

.. clicmd:: show dplane dpdk pbr flows
   Displays the DPDK stats per-PBR entry.
   Sample output:

   ::
   Rules if pf0vf0
   Seq 1 pri 300
   SRC Match 77.0.0.8/32
   DST Match 88.0.0.8/32
   Tableid: 10000
   Action: nh: 45.0.0.250 intf: p0
   Action: mac: 00:00:5e:00:01:fa
   DPDK flow: installed 0x40
   DPDK flow stats: packets 13 bytes 1586

.. clicmd:: show dplane dpdk counters
 Displays the ZAPI message handler counters

   Sample output:

   ::
             Ignored updates: 0
               PBR rule adds: 1
               PBR rule dels: 0


zebra Terminal Mode Commands
============================

.. clicmd:: show [ip|ipv6] route

   Display current routes which zebra holds in its database.

::

    Router# show ip route
    Codes: K - kernel route, C - connected, L - local, S - static,
           R - RIP, O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
           T - Table, v - VNC, V - VNC-Direct, A - Babel, D - SHARP,
           F - PBR, f - OpenFabric, t - Table-Direct,
           > - selected route, * - FIB route, q - queued, r - rejected, b - backup
           t - trapped, o - offload failure

    K>* 0.0.0.0/0 [0/100] via 192.168.119.1, enp13s0, 00:30:22
    S>  4.5.6.7/32 [1/0] via 192.168.119.1 (recursive), weight 1, 00:30:22
      *                    via 192.168.119.1, enp13s0, weight 1, 00:30:22
    K>* 169.254.0.0/16 [0/1000] is directly connected, virbr2 linkdown, 00:30:22
    L>* 192.168.119.205/32 is directly connected, enp13s0, 00:30:22


.. clicmd:: show [ip|ipv6] route [PREFIX] [nexthop-group]

   Display detailed information about a route. If [nexthop-group] is
   included, it will display the nexthop group ID the route is using as well.

.. clicmd:: show [ip|ipv6] route summary

   Display summary information about routes received from each protocol.
   This command displays the entries received from each route and as such
   this total can be more than the actual number of FIB routes.  Finally
   due to the way that linux supports local and connected routes the FIB
   total may not be exactly what is shown in the equivalent `ip route show`
   command to see the state of the linux kernel.

.. clicmd:: show interface [NAME] [{vrf VRF|brief}] [json]

.. clicmd:: show interface [NAME] [{vrf all|brief}] [json]

.. clicmd:: show interface [NAME] [{vrf VRF|brief}] [nexthop-group]

.. clicmd:: show interface [NAME] [{vrf all|brief}] [nexthop-group]

   Display interface information. If no extra information is added, it will
   dump information on all interfaces. If [NAME] is specified, it will display
   detailed information about that single interface. If [nexthop-group] is
   specified, it will display nexthop groups pointing out that interface.

   If the ``json`` option is specified, output is displayed in JSON format.

.. clicmd:: show ip prefix-list [NAME]

.. clicmd:: show ip protocol

.. clicmd:: show ip forward

   Display whether the host's IP forwarding function is enabled or not.
   Almost any UNIX kernel can be configured with IP forwarding disabled.
   If so, the box can't work as a router.

.. clicmd:: show ipv6 forward

   Display whether the host's IP v6 forwarding is enabled or not.

.. clicmd:: show ip neigh

   Display the ip neighbor table

.. clicmd:: show pbr rule

   Display the pbr rule table with resolved nexthops

.. clicmd:: show zebra

   Display various statistics related to the installation and deletion
   of routes, neighbor updates, and LSP's into the kernel.  In addition
   show various zebra state that is useful when debugging an operator's
   setup.

.. clicmd:: show zebra client [summary]

   Display statistics about clients that are connected to zebra.  This is
   useful for debugging and seeing how much data is being passed between
   zebra and it's clients.  If the summary form of the command is chosen
   a table is displayed with shortened information.

.. clicmd:: show zebra router table summary

   Display summarized data about tables created, their afi/safi/tableid
   and how many routes each table contains.  Please note this is the
   total number of route nodes in the table.  Which will be higher than
   the actual number of routes that are held.

.. clicmd:: show nexthop-group rib [ID] [vrf NAME] [singleton [ip|ip6]] [type] [json]

   Display nexthop groups created by zebra.  The [vrf NAME] option
   is only meaningful if you have started zebra with the --vrfwnetns
   option as that nexthop groups are per namespace in linux.
   If you specify singleton you would like to see the singleton
   nexthop groups that do have an afi. [type] allows you to filter those
   only coming from a specific NHG type (protocol).  A nexthop group
   that has `Initial Delay`, means that this nexthop group entry
   was not installed because no-one was using it at that point and
   Zebra can delay installing this route until it is used by something
   else.

.. clicmd:: show <ip|ipv6> zebra route dump [<vrf> VRFNAME]

   It dumps all the routes from RIB with detailed information including
   internal flags, status etc. This is defined as a hidden command.


Router-id
=========

Many routing protocols require a router-id to be configured. To have a
consistent router-id across all daemons, the following commands are available
to configure and display the router-id:

.. clicmd:: [ip] router-id A.B.C.D

   Allow entering of the router-id.  This command also works under the
   vrf subnode, to allow router-id's per vrf.

.. clicmd:: [ip] router-id A.B.C.D vrf NAME

   Configure the router-id of this router from the configure NODE.
   A show run of this command will display the router-id command
   under the vrf sub node.  This command is deprecated and will
   be removed at some point in time in the future.

.. clicmd:: show [ip] router-id [vrf NAME]

   Display the user configured router-id.

For protocols requiring an IPv6 router-id, the following commands are available:

.. clicmd:: ipv6 router-id X:X::X:X

   Configure the IPv6 router-id of this router. Like its IPv4 counterpart,
   this command works under the vrf subnode, to allow router-id's per vrf.

.. clicmd:: show ipv6 router-id [vrf NAME]

   Display the user configured IPv6 router-id.

.. _zebra-sysctl:

sysctl settings
===============

The linux kernel has a variety of sysctl's that affect it's operation as a router.  This
section is meant to act as a starting point for those sysctl's that must be used in
order to provide FRR with smooth operation as a router.  This section is not meant
as the full documentation for sysctl's.  The operator must use the sysctl documentation
with the linux kernel for that. The following link has helpful references to many relevant
sysctl values:  https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt

Expected sysctl settings
------------------------

.. option:: net.ipv4.ip_forward = 1

   This global option allows the linux kernel to forward (route) ipv4 packets incoming from one
   interface to an outgoing interface. If this is set to 0, the system will not route transit
   ipv4 packets, i.e. packets that are not sent to/from a process running on the local system.

.. option:: net.ipv4.conf.{all,default,<interface>}.forwarding = 1

   The linux kernel can selectively enable forwarding (routing) of ipv4 packets on a per
   interface basis. The forwarding check in the kernel dataplane occurs against the ingress
   Layer 3 interface, i.e. if the ingress L3 interface has forwarding set to 0, packets will not
   be routed.

.. option:: net.ipv6.conf.{all,default,<interface>}.forwarding = 1

   This per interface option allows the linux kernel to forward (route) transit ipv6 packets
   i.e. incoming from one Layer 3 interface to an outgoing Layer 3 interface.
   The forwarding check in the kernel dataplane occurs against the ingress Layer 3 interface,
   i.e. if the ingress L3 interface has forwarding set to 0, packets will not be routed.

.. option:: net.ipv6.conf.all.keep_addr_on_down = 1

   When an interface is taken down, do not remove the v6 addresses associated with the interface.
   This option is recommended because this is the default behavior for v4 as well.

.. option:: net.ipv6.route.skip_notify_on_dev_down = 1

   When an interface is taken down, the linux kernel will not notify, via netlink, about routes
   that used that interface being removed from the FIB.  This option is recommended because this
   is the default behavior for v4 as well.

Optional sysctl settings
------------------------

.. option:: net.ipv4.conf.{all,default,<interface>}.bc_forwarding = 0

   This per interface option allows the linux kernel to optionally allow Directed Broadcast
   (i.e. Routed Broadcast or Subnet Broadcast) packets to be routed onto the connected network
   segment where the subnet exists.
   If the local router receives a routed packet destined for a broadcast address of a connected
   subnet, setting bc_forwarding to 1 on the interface with the target subnet assigned to it will
   allow non locally-generated packets to be routed via the broadcast route.
   If bc_forwarding is set to 0, routed packets destined for a broadcast route will be dropped.
   e.g.
   Host1 (SIP:192.0.2.10, DIP:10.0.0.255) -> (eth0:192.0.2.1/24) Router1 (eth1:10.0.0.1/24) -> BC
   If net.ipv4.conf.{all,default,<interface>}.bc_forwarding=1, then Router1 will forward each
   packet destined to 10.0.0.255 onto the eth1 interface with a broadcast DMAC (ff:ff:ff:ff:ff:ff).

.. option:: net.ipv4.conf.{all,default,<interface>}.arp_accept = 1

   This per interface option allows the linux kernel to optionally skip the creation of ARP
   entries upon the receipt of a Gratuitous ARP (GARP) frame carrying an IP that is not already
   present in the ARP cache. Setting arp_accept to 0 on an interface will ensure NEW ARP entries
   are not created due to the arrival of a GARP frame.
   Note: This does not impact how the kernel reacts to GARP frames that carry a "known" IP
   (that is already in the ARP cache) -- an existing ARP entry will always be updated
   when a GARP for that IP is received.

.. option:: net.ipv4.conf.{all,default,<interface>}.arp_ignore = 0

   This per interface option allows the linux kernel to control what conditions must be met in
   order for an ARP reply to be sent in response to an ARP request targeting a local IP address.
   When arp_ignore is set to 0, the kernel will send ARP replies in response to any ARP Request
   with a Target-IP matching a local address.
   When arp_ignore is set to 1, the kernel will send ARP replies if the Target-IP in the ARP
   Request matches an IP address on the interface the Request arrived at.
   When arp_ignore is set to 2, the kernel will send ARP replies only if the Target-IP matches an
   IP address on the interface where the Request arrived AND the Sender-IP falls within the subnet
   assigned to the local IP/interface.

.. option:: net.ipv4.conf.{all,default,<interface>}.arp_notify = 1

   This per interface option allows the linux kernel to decide whether to send a Gratuitious ARP
   (GARP) frame when the Layer 3 interface comes UP.
   When arp_notify is set to 0, no GARP is sent.
   When arp_notify is set to 1, a GARP is sent when the interface comes UP.

.. option:: net.ipv6.conf.{all,default,<interface>}.ndisc_notify = 1

   This per interface option allows the linux kernel to decide whether to send an Unsolicited
   Neighbor Advertisement (U-NA) frame when the Layer 3 interface comes UP.
   When ndisc_notify is set to 0, no U-NA is sent.
   When ndisc_notify is set to 1, a U-NA is sent when the interface comes UP.

Useful sysctl settings
----------------------

.. option:: net.ipv6.conf.all.use_oif_addrs_only = 1

   When enabled, the candidate source addresses for destinations routed via this interface are
   restricted to the set of addresses configured on this interface (RFC 6724 section 4).  If
   an operator has hundreds of IP addresses per interface this solves the latency problem.

Debugging
=========

.. clicmd:: debug zebra mpls [detailed]

   MPLS-related events and information.

.. clicmd:: debug zebra events

   Zebra events

.. clicmd:: debug zebra nht [detailed]

   Nexthop-tracking / reachability information

.. clicmd:: debug zebra vxlan

   VxLAN (EVPN) events

.. clicmd:: debug zebra pseudowires

   Pseudowire events.

.. clicmd:: debug zebra packet [<recv|send>] [detail]

   ZAPI message and packet details

.. clicmd:: debug zebra kernel

   Kernel / OS events.

.. clicmd:: debug zebra kernel msgdump [<recv|send>]

   Raw OS (netlink) message details.

.. clicmd:: debug zebra rib [detailed]

   RIB events.

.. clicmd:: debug zebra fpm

   FPM (forwarding-plane manager) events.

.. clicmd:: debug zebra dplane [detailed]

   Dataplane / FIB events.

.. clicmd:: debug zebra pbr

   PBR (policy-based routing) events.

.. clicmd:: debug zebra mlag

   MLAG events.

.. clicmd:: debug zebra evpn mh <es|mac|neigh|nh>

   EVPN multi-hop events.

.. clicmd:: debug zebra nexthop [detail]

   Nexthop and nexthop-group events.

.. clicmd:: debug zebra srv6

   Segment Routing for IPv6 dataplane debugging.

Scripting
=========

.. clicmd:: zebra on-rib-process script SCRIPT

   Set a Lua script for :ref:`on-rib-process-dplane-results` hook call.
   SCRIPT is the basename of the script, without ``.lua``.

Data structures
---------------

.. _const-struct-zebra-dplane-ctx:

const struct zebra_dplane_ctx
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   * integer zd_op
   * integer zd_status
   * integer zd_provider
   * integer zd_vrf_id
   * integer zd_table_id
   * integer zd_ifname
   * integer zd_ifindex
   * table rinfo (if zd_op is DPLANE_OP_ROUTE*, DPLANE_NH_*)

     * prefix zd_dest
     * prefix zd_src
     * integer zd_afi
     * integer zd_safi
     * integer zd_type
     * integer zd_old_type
     * integer zd_tag
     * integer zd_old_tag
     * integer zd_metric
     * integer zd_old_metric
     * integer zd_instance
     * integer zd_old_instance
     * integer zd_distance
     * integer zd_old_distance
     * integer zd_mtu
     * integer zd_nexthop_mtu
     * table nhe

       * integer id
       * integer old_id
       * integer afi
       * integer vrf_id
       * integer type
       * nexthop_group ng
       * nh_grp
       * integer nh_grp_count

     * integer zd_nhg_id
     * nexthop_group zd_ng
     * nexthop_group backup_ng
     * nexthop_group zd_old_ng
     * nexthop_group old_backup_ng

   * integer label (if zd_op is DPLANE_OP_LSP_*)
   * table pw (if zd_op is DPLANE_OP_PW_*)

     * integer type
     * integer af
     * integer status
     * integer flags
     * integer local_label
     * integer remote_label

   * table macinfo (if zd_op is DPLANE_OP_MAC_*)

     * integer vid
     * integer br_ifindex
     * ethaddr mac
     * integer vtep_ip
     * integer is_sticky
     * integer nhg_id
     * integer update_flags

   * table rule (if zd_op is DPLANE_OP_RULE_*)

     * integer sock
     * integer unique
     * integer seq
     * string ifname
     * integer priority
     * integer old_priority
     * integer table
     * integer old_table
     * integer filter_bm
     * integer old_filter_bm
     * integer fwmark
     * integer old_fwmark
     * integer dsfield
     * integer old_dsfield
     * integer ip_proto
     * integer old_ip_proto
     * prefix src_ip
     * prefix old_src_ip
     * prefix dst_ip
     * prefix old_dst_ip

   * table iptable (if zd_op is DPLANE_OP_IPTABLE_*)

     * integer sock
     * integer vrf_id
     * integer unique
     * integer type
     * integer filter_bm
     * integer fwmark
     * integer action
     * integer pkt_len_min
     * integer pkt_len_max
     * integer tcp_flags
     * integer dscp_value
     * integer fragment
     * integer protocol
     * integer nb_interface
     * integer flow_label
     * integer family
     * string ipset_name

   * table ipset (if zd_op is DPLANE_OP_IPSET_*)
     * integer sock
     * integer vrf_id
     * integer unique
     * integer type
     * integer family
     * string ipset_name

   * table neigh (if zd_op is DPLANE_OP_NEIGH_*)

     * ipaddr ip_addr
     * table link

       * ethaddr mac
       * ipaddr ip_addr

     * integer flags
     * integer state
     * integer update_flags

   * table br_port (if zd_op is DPLANE_OP_BR_PORT_UPDATE)

     * integer sph_filter_cnt
     * integer flags
     * integer backup_nhg_id

   * table neightable (if zd_op is DPLANE_OP_NEIGH_TABLE_UPDATE)

     * integer family
     * integer app_probes
     * integer ucast_probes
     * integer mcast_probes

   * table gre (if zd_op is DPLANE_OP_GRE_SET)**

     * integer link_ifindex
     * integer mtu


.. _const-struct-nh-grp:

const struct nh_grp
^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   * integer id
   * integer weight


.. _zebra-hook-calls:

Zebra Hook calls
----------------

.. _on-rib-process-dplane-results:

on_rib_process_dplane_results
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Called when RIB processes dataplane events.
Set script location with the ``zebra on-rib-process script SCRIPT`` command.

**Arguments**

* :ref:`const struct zebra_dplane_ctx<const-struct-zebra-dplane-ctx>` ctx


.. code-block:: lua

   function on_rib_process_dplane_results(ctx)
      log.info(ctx.rinfo.zd_dest.network)
      return {}
