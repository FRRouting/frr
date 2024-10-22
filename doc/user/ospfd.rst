.. _ospfv2:

******
OSPFv2
******

:abbr:`OSPF (Open Shortest Path First)` version 2 is a routing protocol which
is described in :rfc:`2328`. OSPF is an :abbr:`IGP (Interior Gateway
Protocol)`. Compared with :abbr:`RIP`, :abbr:`OSPF` can provide scalable
network support and faster convergence times. OSPF is widely used in large
networks such as :abbr:`ISP (Internet Service Provider)` backbone and
enterprise networks.

.. include:: ospf_fundamentals.rst

.. _configuring-ospfd:

Configuring OSPF
================

*ospfd* accepts all :ref:`common-invocation-options`.

.. option:: -n, --instance

   Specify the instance number for this invocation of *ospfd*.

.. option:: -a, --apiserver

   Enable the OSPF API server. This is required to use ``ospfclient``.

.. option:: -l, --apiserver_addr <address>

   Specify the local IPv4 address to which to bind the OSPF API server socket.
   If unspecified, connections are accepted to any address. Specification of
   127.0.0.1 can be used to limit socket access to local applications.

*ospfd* must acquire interface information from *zebra* in order to function.
Therefore *zebra* must be running before invoking *ospfd*. Also, if *zebra* is
restarted then *ospfd* must be too.

.. include:: config-include.rst

.. _ospf-multi-instance:

Multi-instance Support
----------------------

OSPF supports multiple instances. Each instance is identified by a positive
nonzero integer that must be provided when adding configuration items specific
to that instance. Enabling instances is done with :file:`/etc/frr/daemons` in
the following manner:

::

   ...
   ospfd=yes
   ospfd_instances=1,5,6
   ...

The ``ospfd_instances`` variable controls which instances are started and what
their IDs are. In this example, after starting FRR you should see the following
processes:

.. code-block:: shell

   # ps -ef | grep "ospfd"
   frr      11816     1  0 17:30 ?        00:00:00 /usr/lib/frr/ospfd --daemon -A 127.0.0.1 -n 1
   frr      11822     1  0 17:30 ?        00:00:00 /usr/lib/frr/ospfd --daemon -A 127.0.0.1 -n 2
   frr      11828     1  0 17:30 ?        00:00:00 /usr/lib/frr/ospfd --daemon -A 127.0.0.1 -n 3


The instance number should be specified in the config when addressing a particular instance:

.. code-block:: frr

   router ospf 5
      ospf router-id 1.2.3.4
      area 0.0.0.0 authentication message-digest
      ...

.. _ospf-router:

Routers
-------

To start OSPF process you have to specify the OSPF router.

.. clicmd:: router ospf [{(1-65535)|vrf NAME}]


   Enable or disable the OSPF process.

   Multiple instances don't support `vrf NAME`.

.. clicmd:: ospf router-id A.B.C.D


   This sets the router-ID of the OSPF process. The router-ID may be an IP
   address of the router, but need not be - it can be any arbitrary 32bit
   number. However it MUST be unique within the entire OSPF domain to the OSPF
   speaker - bad things will happen if multiple OSPF speakers are configured
   with the same router-ID! If one is not specified then *ospfd* will obtain a
   router-ID automatically from *zebra*.

.. clicmd:: ospf abr-type TYPE


   `type` can be cisco|ibm|shortcut|standard. The "Cisco" and "IBM" types
   are equivalent.

   The OSPF standard for ABR behaviour does not allow an ABR to consider
   routes through non-backbone areas when its links to the backbone are
   down, even when there are other ABRs in attached non-backbone areas
   which still can reach the backbone - this restriction exists primarily
   to ensure routing-loops are avoided.

   With the "Cisco" or "IBM" ABR type, the default in this release of FRR, this
   restriction is lifted, allowing an ABR to consider summaries learned from
   other ABRs through non-backbone areas, and hence route via non-backbone
   areas as a last resort when, and only when, backbone links are down.

   Note that areas with fully-adjacent virtual-links are considered to be
   "transit capable" and can always be used to route backbone traffic, and
   hence are unaffected by this setting (:clicmd:`area A.B.C.D virtual-link A.B.C.D`).

   More information regarding the behaviour controlled by this command can
   be found in :rfc:`3509`, and :t:`draft-ietf-ospf-shortcut-abr-02.txt`.

   Quote: "Though the definition of the :abbr:`ABR (Area Border Router)`
   in the OSPF specification does not require a router with multiple
   attached areas to have a backbone connection, it is actually
   necessary to provide successful routing to the inter-area and
   external destinations. If this requirement is not met, all traffic
   destined for the areas not connected to such an ABR or out of the
   OSPF domain, is dropped. This document describes alternative ABR
   behaviors implemented in Cisco and IBM routers."

.. clicmd:: ospf rfc1583compatibility


   :rfc:`2328`, the successor to :rfc:`1583`, suggests according
   to section G.2 (changes) in section 16.4 a change to the path
   preference algorithm that prevents possible routing loops that were
   possible in the old version of OSPFv2. More specifically it demands
   that inter-area paths and intra-area backbone path are now of equal preference
   but still both preferred to external paths.

   This command should NOT be set normally.

.. clicmd:: log-adjacency-changes [detail]


   Configures ospfd to log changes in adjacency. With the optional
   detail argument, all changes in adjacency status are shown. Without detail,
   only changes to full or regressions are shown.

.. clicmd:: passive-interface default

   Make all interfaces that belong to this router passive by default. For the
   description of passive interface look at :clicmd:`ip ospf passive [A.B.C.D]`.
   Per-interface configuration takes precedence over the default value.

.. clicmd:: timers throttle spf (0-600000) (0-600000) (0-600000)

   This command sets the initial `delay`, the `initial-holdtime`
   and the `maximum-holdtime` between when SPF is calculated and the
   event which triggered the calculation. The times are specified in
   milliseconds and must be in the range of 0 to 600000 milliseconds.

   The `delay` specifies the minimum amount of time to delay SPF
   calculation (hence it affects how long SPF calculation is delayed after
   an event which occurs outside of the holdtime of any previous SPF
   calculation, and also serves as a minimum holdtime).

   Consecutive SPF calculations will always be separated by at least
   'hold-time' milliseconds. The hold-time is adaptive and initially is
   set to the `initial-holdtime` configured with the above command.
   Events which occur within the holdtime of the previous SPF calculation
   will cause the holdtime to be increased by `initial-holdtime`, bounded
   by the `maximum-holdtime` configured with this command. If the adaptive
   hold-time elapses without any SPF-triggering event occurring then
   the current holdtime is reset to the `initial-holdtime`. The current
   holdtime can be viewed with :clicmd:`show ip ospf`, where it is expressed as
   a multiplier of the `initial-holdtime`.

   .. code-block:: frr

      router ospf
      timers throttle spf 200 400 10000


   In this example, the `delay` is set to 200ms, the initial holdtime is set to
   400ms and the `maximum holdtime` to 10s. Hence there will always be at least
   200ms between an event which requires SPF calculation and the actual SPF
   calculation. Further consecutive SPF calculations will always be separated
   by between 400ms to 10s, the hold-time increasing by 400ms each time an
   SPF-triggering event occurs within the hold-time of the previous SPF
   calculation.

   This command supersedes the *timers spf* command in previous FRR
   releases.

.. clicmd:: timers throttle lsa all (0-5000)

   This command sets the minumum interval between originations of the
   same LSA or the `minimum LSA refresh interval`. The time is specified
   in milliseconds and the default is 5 seconds (5000 milliseconds) consistent
   with the architectual constant MinLSInterval specified in Appendix D of
   RFC 2328. When a self-originated LSA needs to be reoriginated, it may be
   delayed for up to this interval.

   .. code-block:: frr

      router ospf
       timers throttle lsa all 1000


   In this example, the `mininum LSA refresh interval` is set to 1000ms. This
   command reduces the delay between successive originations of a self-originated
   LSA from 5000 milliseconds to 1000 milliseconds.

.. clicmd:: timers lsa min-arrival (0-5000)

   This command sets the minumum interval between receptions of instances of
   the same LSA or the `minimum LSA arrival interval`. The time is specified in
   milliseconds and the default is 1 second (1000 milliseconds) consistent with
   the architectual constant MinLSArrival specified in Appendix D of RFC 2328. If a
   newer instance of the same LSA is received in less than this interval, it is
   ignored.

   .. code-block:: frr

      router ospf
       timers lsa min-arrival 50


   In this example, the `minimum LSA arrival interval` is set to 50ms. This
   command reduces the minimum interval required between instances of the same
   LSA from 1000 milliseconds to 50 milliseconds.

.. clicmd:: max-metric router-lsa [on-startup (5-86400)|on-shutdown (5-100)]

.. clicmd:: max-metric router-lsa administrative


   This enables :rfc:`3137` support, where the OSPF process describes its
   transit links in its router-LSA as having infinite distance so that other
   routers will avoid calculating transit paths through the router while still
   being able to reach networks through the router.

   This support may be enabled administratively (and indefinitely) or
   conditionally. Conditional enabling of max-metric router-lsas can be for a
   period of seconds after startup and/or for a period of seconds prior to
   shutdown.

   Enabling this for a period after startup allows OSPF to converge fully first
   without affecting any existing routes used by other routers, while still
   allowing any connected stub links and/or redistributed routes to be
   reachable. Enabling this for a period of time in advance of shutdown allows
   the router to gracefully excuse itself from the OSPF domain.

   Enabling this feature administratively allows for administrative
   intervention for whatever reason, for an indefinite period of time.  Note
   that if the configuration is written to file, this administrative form of
   the stub-router command will also be written to file. If *ospfd* is
   restarted later, the command will then take effect until manually
   deconfigured.

   Configured state of this feature as well as current status, such as the
   number of second remaining till on-startup or on-shutdown ends, can be
   viewed with the :clicmd:`show ip ospf` command.

.. clicmd:: auto-cost reference-bandwidth (1-4294967)


   This sets the reference
   bandwidth for cost calculations, where this bandwidth is considered
   equivalent to an OSPF cost of 1, specified in Mbits/s. The default is
   100Mbit/s (i.e. a link of bandwidth 100Mbit/s or higher will have a
   cost of 1. Cost of lower bandwidth links will be scaled with reference
   to this cost).

   This configuration setting MUST be consistent across all routers within the
   OSPF domain.

.. clicmd:: neighbor A.B.C.D [poll-interval (1-65535)] [priority (0-255)]


   Configures OSPF neighbors for non-broadcast multi-access (NBMA) networks
   and point-to-multipoint non-broadcast networks. The `poll-interval`
   specifies the rate for sending hello packets to neighbors that are not
   active. When the configured neighbor is discovered, hello packets will be
   sent at the rate of the hello-interval. The default `poll-interval` is 60
   seconds. The `priority` is used to for the Designated Router (DR) election
   on non-broadcast multi-access networks.

.. clicmd:: network A.B.C.D/M area A.B.C.D

.. clicmd:: network A.B.C.D/M area (0-4294967295)



   This command specifies the OSPF enabled interface(s). If the interface has
   an address from range 192.168.1.0/24 then the command below enables ospf
   on this interface so router can provide network information to the other
   ospf routers via this interface.

   .. code-block:: frr

      router ospf
      network 192.168.1.0/24 area 0.0.0.0

   Prefix length in interface must be equal or bigger (i.e. smaller network) than
   prefix length in network statement. For example statement above doesn't enable
   ospf on interface with address 192.168.1.1/23, but it does on interface with
   address 192.168.1.129/25.

   Note that the behavior when there is a peer address
   defined on an interface changed after release 0.99.7.
   Currently, if a peer prefix has been configured,
   then we test whether the prefix in the network command contains
   the destination prefix. Otherwise, we test whether the network command prefix
   contains the local address prefix of the interface.

   It is also possible to enable OSPF on a per interface/subnet basis
   using the interface command (:clicmd:`ip ospf area AREA [ADDR]`).
   However, mixing both network commands (:clicmd:`network`) and interface
   commands (:clicmd:`ip ospf`) on the same router is not supported.

.. clicmd:: proactive-arp


   This command enables or disables sending ARP requests to update neighbor
   table entries. It speeds up convergence for /32 networks on a P2P
   connection.

   This feature is enabled by default.

.. clicmd:: clear ip ospf [(1-65535)] process

   This command can be used to clear the ospf process data structures. This
   will clear the ospf neighborship as well and it will get re-established.
   This will clear the LSDB too. This will be helpful when there is a change
   in router-id and if user wants the router-id change to take effect, user can
   use this cli instead of restarting the ospfd daemon.

.. clicmd:: clear ip ospf [(1-65535)] neighbor

   This command can be used to clear the ospf neighbor data structures. This
   will clear the ospf neighborship and it will get re-established. This
   command can be used when the neighbor state get stuck at some state and
   this can be used to recover it from that state.

.. clicmd:: maximum-paths (1-64)

   Use this command to control the maximum number of equal cost paths to reach
   a specific destination. The upper limit may differ if you change the value
   of MULTIPATH_NUM during compilation. The default is MULTIPATH_NUM (64).

.. clicmd:: write-multiplier (1-100)

   Use this command to tune the amount of work done in the packet read and
   write threads before relinquishing control. The parameter is the number
   of packets to process before returning. The defult value of this parameter
   is 20.

.. clicmd:: socket buffer <send | recv | all> (1-4000000000)

   This command controls the ospf instance's socket buffer sizes. The
   'no' form resets one or both values to the default.

.. clicmd:: no socket-per-interface

   Ordinarily, ospfd uses a socket per interface for sending
   packets. This command disables those per-interface sockets, and
   causes ospfd to use a single socket per ospf instance for sending
   and receiving packets.

.. _ospf-area:

Areas
-----

.. clicmd:: area A.B.C.D range A.B.C.D/M [advertise [cost (0-16777215)]]

.. clicmd:: area (0-4294967295) range A.B.C.D/M [advertise [cost (0-16777215)]]



   Summarize intra area paths from specified area into one Type-3 summary-LSA
   announced to other areas. This command can be used only in ABR and ONLY
   router-LSAs (Type-1) and network-LSAs (Type-2) (i.e. LSAs with scope area) can
   be summarized. Type-5 AS-external-LSAs can't be summarized - their scope is AS.

   .. code-block:: frr

      router ospf
       network 192.168.1.0/24 area 0.0.0.0
       network 10.0.0.0/8 area 0.0.0.10
       area 0.0.0.10 range 10.0.0.0/8


   With configuration above one Type-3 Summary-LSA with routing info 10.0.0.0/8 is
   announced into backbone area if area 0.0.0.10 contains at least one intra-area
   network (i.e. described with router or network LSA) from this range.

.. clicmd:: area A.B.C.D range A.B.C.D/M not-advertise

.. clicmd:: area (0-4294967295) range A.B.C.D/M not-advertise


   Instead of summarizing intra area paths filter them - i.e. intra area paths from this
   range are not advertised into other areas.
   This command makes sense in ABR only.

.. clicmd:: area A.B.C.D range A.B.C.D/M {substitute A.B.C.D/M|cost (0-16777215)}

.. clicmd:: area (0-4294967295) range A.B.C.D/M {substitute A.B.C.D/M|cost (0-16777215)}


   Substitute summarized prefix with another prefix.

   .. code-block:: frr

      router ospf
       network 192.168.1.0/24 area 0.0.0.0
       network 10.0.0.0/8 area 0.0.0.10
       area 0.0.0.10 range 10.0.0.0/8 substitute 11.0.0.0/8


   One Type-3 summary-LSA with routing info 11.0.0.0/8 is announced into backbone area if
   area 0.0.0.10 contains at least one intra-area network (i.e. described with router-LSA or
   network-LSA) from range 10.0.0.0/8.

   By default, the metric of the summary route is calculated as the highest
   metric among the summarized routes. The `cost` option, however, can be used
   to set an explicit metric.

   This command makes sense in ABR only.

.. clicmd:: area A.B.C.D virtual-link A.B.C.D

.. clicmd:: area (0-4294967295) virtual-link A.B.C.D



.. clicmd:: area A.B.C.D shortcut

.. clicmd:: area (0-4294967295) shortcut



   Configure the area as Shortcut capable. See :rfc:`3509`. This requires
   that the 'abr-type' be set to 'shortcut'.

.. clicmd:: area A.B.C.D stub

.. clicmd:: area (0-4294967295) stub



   Configure the area to be a stub area. That is, an area where no router
   originates routes external to OSPF and hence an area where all external
   routes are via the ABR(s). Hence, ABRs for such an area do not need
   to pass AS-External LSAs (type-5s) or ASBR-Summary LSAs (type-4) into the
   area. They need only pass Network-Summary (type-3) LSAs into such an area,
   along with a default-route summary.

.. clicmd:: area A.B.C.D stub no-summary

.. clicmd:: area (0-4294967295) stub no-summary



    Prevents an *ospfd* ABR from injecting inter-area
    summaries into the specified stub area.

.. clicmd:: area A.B.C.D nssa

.. clicmd:: area (0-4294967295) nssa

    Configure the area to be a NSSA (Not-So-Stubby Area). This is an area that
    allows OSPF to import external routes into a stub area via a new LSA type
    (type 7). An NSSA autonomous system boundary router (ASBR) will generate this
    type of LSA. The area border router (ABR) translates the LSA type 7 into LSA
    type 5, which is propagated into the OSPF domain. NSSA areas are defined in
    RFC 3101.

.. clicmd:: area A.B.C.D nssa suppress-fa

.. clicmd:: area (0-4294967295) nssa suppress-fa

    Configure the router to set the forwarding address to 0.0.0.0 in all LSA type 5
    translated from LSA type 7. The router needs to be elected the translator of the
    area for this command to take effect. This feature causes routers that are
    configured not to advertise forwarding addresses into the backbone to direct
    forwarded traffic to the NSSA ABR translator.

.. clicmd:: area A.B.C.D nssa default-information-originate [metric-type (1-2)] [metric (0-16777214)]

.. clicmd:: area (0-4294967295) nssa default-information-originate [metric-type (1-2)] [metric (0-16777214)]

   NSSA ABRs and ASBRs can be configured with the `default-information-originate`
   option to originate a Type-7 default route into the NSSA area. In the case
   of NSSA ASBRs, the origination of the default route is conditioned to the
   existence of a default route in the RIB that wasn't learned via the OSPF
   protocol.

.. clicmd:: area A.B.C.D nssa range A.B.C.D/M [<not-advertise|cost (0-16777215)>]

.. clicmd:: area (0-4294967295) nssa range A.B.C.D/M [<not-advertise|cost (0-16777215)>]

    Summarize a group of external subnets into a single Type-7 LSA, which is
    then translated to a Type-5 LSA and avertised to the backbone.
    This command can only be used at the area boundary (NSSA ABR router).

    By default, the metric of the summary route is calculated as the highest
    metric among the summarized routes. The `cost` option, however, can be used
    to set an explicit metric.

    The `not-advertise` option, when present, prevents the summary route from
    being advertised, effectively filtering the summarized routes.

.. clicmd:: area A.B.C.D default-cost (0-16777215)


   Set the cost of default-summary LSAs announced to stubby areas.

.. clicmd:: area A.B.C.D export-list NAME

.. clicmd:: area (0-4294967295) export-list NAME



   Filter Type-3 summary-LSAs announced to other areas originated from intra-
   area paths from specified area.

   .. code-block:: frr

      router ospf
       network 192.168.1.0/24 area 0.0.0.0
       network 10.0.0.0/8 area 0.0.0.10
       area 0.0.0.10 export-list foo
      !
      access-list foo permit 10.10.0.0/16
      access-list foo deny any

   With example above any intra-area paths from area 0.0.0.10 and from range
   10.10.0.0/16 (for example 10.10.1.0/24 and 10.10.2.128/30) are announced into
   other areas as Type-3 summary-LSA's, but any others (for example 10.11.0.0/16
   or 10.128.30.16/30) aren't.

   This command is only relevant if the router is an ABR for the specified
   area.

.. clicmd:: area A.B.C.D import-list NAME

.. clicmd:: area (0-4294967295) import-list NAME



   Same as export-list, but it applies to paths announced into specified area
   as Type-3 summary-LSAs.

.. clicmd:: area A.B.C.D filter-list prefix NAME in

.. clicmd:: area A.B.C.D filter-list prefix NAME out

.. clicmd:: area (0-4294967295) filter-list prefix NAME in

.. clicmd:: area (0-4294967295) filter-list prefix NAME out





   Filtering Type-3 summary-LSAs to/from area using prefix lists. This command
   makes sense in ABR only.

.. clicmd:: area A.B.C.D authentication

.. clicmd:: area (0-4294967295) authentication



   Specify that simple password authentication should be used for the given
   area.

.. clicmd:: area A.B.C.D authentication message-digest

.. clicmd:: area (0-4294967295) authentication message-digest

   Specify that OSPF packets must be authenticated with MD5 HMACs within the
   given area. Keying material must also be configured on a per-interface basis
   (:clicmd:`ip ospf message-digest-key`).

   MD5 authentication may also be configured on a per-interface basis
   (:clicmd:`ip ospf authentication message-digest`). Such per-interface
   settings will override any per-area authentication setting.

.. _ospf-interface:

Interfaces
----------

.. clicmd:: ip ospf area AREA [ADDR]


   Enable OSPF on the interface, optionally restricted to just the IP address
   given by `ADDR`, putting it in the `AREA` area. If you have a lot of
   interfaces, and/or a lot of subnets, then enabling OSPF via this command
   instead of (:clicmd:`network A.B.C.D/M area A.B.C.D`) may result in a
   slight performance improvement.

   Notice that, mixing both network commands (:clicmd:`network`) and interface
   commands (:clicmd:`ip ospf`) on the same router is not supported.
   If (:clicmd:`ip ospf`) is present, (:clicmd:`network`) commands will fail.

.. clicmd:: ip ospf authentication-key AUTH_KEY


   Set OSPF authentication key to a simple password. After setting `AUTH_KEY`,
   all OSPF packets are authenticated. `AUTH_KEY` has length up to 8 chars.

   Simple text password authentication is insecure and deprecated in favour of
   MD5 HMAC authentication.

.. clicmd:: ip ospf authentication message-digest

   Specify that MD5 HMAC authentication must be used on this interface. MD5
   keying material must also be configured. Overrides any authentication
   enabled on a per-area basis
   (:clicmd:`area A.B.C.D authentication message-digest`)

   Note that OSPF MD5 authentication requires that time never go backwards
   (correct time is NOT important, only that it never goes backwards), even
   across resets, if ospfd is to be able to promptly reestablish adjacencies
   with its neighbors after restarts/reboots. The host should have system time
   be set at boot from an external or non-volatile source (e.g. battery backed
   clock, NTP, etc.) or else the system clock should be periodically saved to
   non-volatile storage and restored at boot if MD5 authentication is to be
   expected to work reliably.

.. clicmd:: ip ospf message-digest-key KEYID md5 KEY


   Set OSPF authentication key to a cryptographic password. The cryptographic
   algorithm is MD5.

   KEYID identifies secret key used to create the message digest. This ID is
   part of the protocol and must be consistent across routers on a link.

   KEY is the actual message digest key, of up to 16 chars (larger strings will
   be truncated), and is associated with the given KEYID.

.. clicmd:: ip ospf authentication key-chain KEYCHAIN

   Specify that HMAC cryptographic authentication must be used on this interface
   using a key chain. Overrides any authentication enabled on a per-area basis
   (:clicmd:`area A.B.C.D authentication message-digest`).

   ``KEYCHAIN``: Specifies the name of the key chain that contains the authentication
   key(s) and cryptographic algorithms to be used for OSPF authentication. The key chain
   is a logical container that holds one or more authentication keys,
   allowing for key rotation and management.

   Note that OSPF HMAC cryptographic authentication requires that time never go backwards
   (correct time is NOT important, only that it never goes backwards), even
   across resets, if ospfd is to be able to promptly reestablish adjacencies
   with its neighbors after restarts/reboots. The host should have system time
   be set at boot from an external or non-volatile source (e.g. battery backed
   clock, NTP, etc.) or else the system clock should be periodically saved to
   non-volatile storage and restored at boot if HMAC cryptographic authentication is to be
   expected to work reliably.

   Example:

   .. code:: sh

      r1(config)#key chain temp
      r1(config-keychain)#key 13
      r1(config-keychain-key)#key-string ospf
      r1(config-keychain-key)#cryptographic-algorithm hmac-sha-256
      r1(config)#int eth0
      r1(config-if)#ip ospf authentication key-chain temp
      r1(config-if)#ip ospf area 0

.. clicmd:: ip ospf cost (1-65535)


   Set link cost for the specified interface. The cost value is set to
   router-LSA's metric field and used for SPF calculation.

.. clicmd:: ip ospf dead-interval (1-65535)

.. clicmd:: ip ospf dead-interval minimal hello-multiplier (2-20)


   Set number of seconds for RouterDeadInterval timer value used for Wait Timer
   and Inactivity Timer. This value must be the same for all routers attached
   to a common network. The default value is 40 seconds.

   If 'minimal' is specified instead, then the dead-interval is set to 1 second
   and one must specify a hello-multiplier. The hello-multiplier specifies how
   many Hellos to send per second, from 2 (every 500ms) to 20 (every 50ms).
   Thus one can have 1s convergence time for OSPF. If this form is specified,
   then the hello-interval advertised in Hello packets is set to 0 and the
   hello-interval on received Hello packets is not checked, thus the
   hello-multiplier need NOT be the same across multiple routers on a common
   link.

.. clicmd:: ip ospf hello-interval (1-65535)


   Set number of seconds for HelloInterval timer value. Setting this value,
   Hello packet will be sent every timer value seconds on the specified interface.
   This value must be the same for all routers attached to a common network.
   The default value is 10 seconds.

   This command has no effect if
   :clicmd:`ip ospf dead-interval minimal hello-multiplier (2-20)` is also
   specified for the interface.

.. clicmd:: ip ospf graceful-restart hello-delay (1-1800)

   Set the length of time during which Grace-LSAs are sent at 1-second intervals
   while coming back up after an unplanned outage. During this time, no hello
   packets are sent.

   A higher hello delay will increase the chance that all neighbors are notified
   about the ongoing graceful restart before receiving a hello packet (which is
   crucial for the graceful restart to succeed). The hello delay shouldn't be set
   too high, however, otherwise the adjacencies might time out. As a best practice,
   it's recommended to set the hello delay and hello interval with the same values.
   The default value is 10 seconds.

.. clicmd:: ip ospf network (broadcast|non-broadcast|point-to-multipoint [delay-reflood|non-broadcast]|point-to-point [dmvpn])

   When configuring a point-to-point network on an interface and the interface
   has a /32 address associated with then OSPF will treat the interface
   as being `unnumbered`.  If you are doing this you *must* set the
   net.ipv4.conf.<interface name>.rp_filter value to 0.  In order for
   the ospf multicast packets to be delivered by the kernel.

   When used in a DMVPN network at a spoke, this OSPF will be configured in
   point-to-point, but the HUB will be a point-to-multipoint. To make this
   topology work, specify the optional 'dmvpn' parameter at the spoke.

   When the network is configured as point-to-multipoint and `non-broadcast`
   is specified, the network doesn't support broadcast or multicast delivery
   and neighbors cannot be discovered from OSPF hello received from the
   OSPFAllRouters (224.0.0.5). Rather, they must be explicitly configured
   using the :clicmd:`neighbor A.B.C.D` configuration command as they are
   on non-broadcast networks.

   When the network is configured as point-to-multipoint and `delay-reflood`
   is specified, LSAs received on the interface from neighbors on the
   interface will not be flooded back out on the interface immediately.
   Rather, they will be added to the neighbor's link state retransmission
   list and only sent to the neighbor if the neighbor doesn't acknowledge
   the LSA prior to the link state retransmission timer expiring.

   Set explicitly network type for specified interface.

.. clicmd:: ip ospf priority (0-255)


   Set RouterPriority integer value. The router with the highest priority will
   be more eligible to become Designated Router. Setting the value to 0, makes
   the router ineligible to become Designated Router. The default value is 1.

.. clicmd:: ip ospf retransmit-interval (1-65535)


   Set number of seconds for RxmtInterval timer value. This value is used when
   retransmitting Database Description and Link State Request packets. The
   default value is 5 seconds.

.. clicmd:: ip ospf retransmit-window (20-1000)


   Set number of milliseconds in the window for neighbor LSA retransmission.
   When a neighbor Link State (LS) retransmission timer expires, LSAs scheduled
   to be retransmitted within the number of milliseconds configured are
   retransmitted to the neighbor. Any expiring after the window will be
   retransmitted the next time the neighbor LS retransmission timer expires.
   The default is 50 milliseconds.

 .. clicmd:: ip ospf transmit-delay (1-65535) [A.B.C.D]


   Set number of seconds for InfTransDelay value. LSAs' age should be
   incremented by this value when transmitting. The default value is 1 second.

.. clicmd:: ip ospf passive [A.B.C.D]

   Do not speak OSPF on the interface, but do advertise the interface as a stub
   link in the router-:abbr:`LSA (Link State Advertisement)` for this router.
   This allows one to advertise addresses on such connected interfaces without
   having to originate AS-External/Type-5 LSAs (which have global flooding
   scope) - as would occur if connected addresses were redistributed into
   OSPF (:ref:`redistribute-routes-to-ospf`). This is the only way to
   advertise non-OSPF links into stub areas.

.. clicmd:: ip ospf prefix-suppression [A.B.C.D]

   Configure OSPF to not advertise the IPv4 prefix associated with the
   OSPF interface. The associated IPv4 prefix will be omitted from an OSPF
   router-LSA or advertised with a host mask in an OSPF network-LSA as
   specified in RFC 6860, "Hiding Transit-Only Networks in OSPF". If an
   optional IPv4 address is specified, the prefix suppression will apply
   to the OSPF interface associated with the specified interface address.

.. clicmd:: ip ospf neighbor-filter NAME [A.B.C.D]

   Configure an IP prefix-list to use to filter packets received from
   OSPF neighbors on the OSPF interface. The prefix-list should include rules
   to permit or deny OSPF neighbors by IP source address. This is useful for
   multi-access interfaces where adjacencies with only a subset of the
   reachable neighbors are desired. Applications include testing partially
   meshed topologies, OSPF Denial of Sevice (DoS) mitigation, and avoidance
   of adjacencies with OSPF neighbors not meeting traffic engineering criteria.

      Example:

.. code-block:: frr

   !
   ! Prefix-list to block neighbor with source address 10.1.0.2
   !
   ip prefix-list nbr-filter seq 10 deny 10.1.0.2/32
   ip prefix-list nbr-filter seq 200 permit any
   !
   ! Configure the neighbor filter prefix-list on interface eth0
   !
   interface eth0
    ip ospf neighbor-filter nbr-filter
   !

.. clicmd:: ip ospf area (A.B.C.D|(0-4294967295))


   Enable ospf on an interface and set associated area.

OSPF route-map
==============

Usage of *ospfd*'s route-map support.

.. clicmd:: set metric [+|-](0-4294967295)

   Set a metric for matched route when sending announcement. Use plus (+) sign
   to add a metric value to an existing metric. Use minus (-) sign to
   substract a metric value from an existing metric.

.. _redistribute-routes-to-ospf:

Redistribution
--------------

.. _ospf-redistribute:

.. clicmd:: redistribute <babel|bgp|connected|eigrp|isis|kernel|openfabric|ospf|rip|sharp|static|table> [metric-type (1-2)] [metric (0-16777214)] [route-map WORD]

   Redistribute routes of the specified protocol or kind into OSPF, with the
   metric type and metric set if specified, filtering the routes using the
   given route-map if specified.  Redistributed routes may also be filtered
   with distribute-lists, see
   :ref:`ospf distribute-list configuration <ospf-distribute-list>`.

   Redistributed routes are distributed as into OSPF as Type-5 External LSAs
   into links to areas that accept external routes, Type-7 External LSAs for
   NSSA areas and are not redistributed at all into Stub areas, where external
   routes are not permitted.

   Note that for connected routes, one may instead use the
   :clicmd:`ip ospf passive [A.B.C.D]` configuration.

.. clicmd:: default-information originate

.. clicmd:: default-information originate metric (0-16777214)

.. clicmd:: default-information originate metric (0-16777214) metric-type (1|2)

.. clicmd:: default-information originate metric (0-16777214) metric-type (1|2) route-map WORD

.. clicmd:: default-information originate always

.. clicmd:: default-information originate always metric (0-16777214)

.. clicmd:: default-information originate always metric (0-16777214) metric-type (1|2)

.. clicmd:: default-information originate always metric (0-16777214) metric-type (1|2) route-map WORD


   Originate an AS-External (type-5) LSA describing a default route into all
   external-routing capable areas, of the specified metric and metric type. If
   the 'always' keyword is given then the default is always advertised, even
   when there is no default present in the routing table.

.. _ospf-distribute-list:

.. clicmd:: distribute-list NAME out <kernel|connected|static|rip|isis|bgp|eigrp|nhrp|table|vnc|babel|openfabric>

   Apply the access-list filter, NAME, to redistributed routes of the given
   type before allowing the routes to be redistributed into OSPF
   (:ref:`ospf redistribution <ospf-redistribute>`).

.. clicmd:: default-metric (0-16777214)


.. clicmd:: distance (1-255)


.. clicmd:: distance ospf (intra-area|inter-area|external) (1-255)



Graceful Restart
================

.. clicmd:: graceful-restart [grace-period (1-1800)]


   Configure Graceful Restart (RFC 3623) restarting support.
   When enabled, the default grace period is 120 seconds.

   To perform a graceful shutdown, the "graceful-restart prepare ip ospf"
   EXEC-level command needs to be issued before restarting the ospfd daemon.

   When Graceful Restart is enabled and the ospfd daemon crashes or is killed
   abruptely (e.g. SIGKILL), it will attempt an unplanned Graceful Restart once
   it restarts.

.. clicmd:: graceful-restart helper enable [A.B.C.D]


   Configure Graceful Restart (RFC 3623) helper support.
   By default, helper support is disabled for all neighbors.
   This config enables/disables helper support on this router
   for all neighbors.
   To enable/disable helper support for a specific
   neighbor, the router-id (A.B.C.D) has to be specified.

.. clicmd:: graceful-restart helper strict-lsa-checking


   If 'strict-lsa-checking' is configured then the helper will
   abort the Graceful Restart when a LSA change occurs which
   affects the restarting router.
   By default 'strict-lsa-checking' is enabled"

.. clicmd:: graceful-restart helper supported-grace-time (10-1800)


   Supports as HELPER for configured grace period.

.. clicmd:: graceful-restart helper planned-only


   It helps to support as HELPER only for planned
   restarts. By default, it supports both planned and
   unplanned outages.


.. clicmd:: graceful-restart prepare ip ospf


   Initiate a graceful restart for all OSPF instances configured with the
   "graceful-restart" command. The ospfd daemon should be restarted during
   the instance-specific grace period, otherwise the graceful restart will fail.

   This is an EXEC-level command.


.. _showing-ospf-information:

Showing Information
===================

.. _show-ip-ospf:

.. clicmd:: show ip ospf [vrf <NAME|all>] [json]

   Show information on a variety of general OSPF and area state and
   configuration information.

.. clicmd:: show ip ospf interface [INTERFACE] [json]

   Show state and configuration of OSPF the specified interface, or all
   interfaces if no interface is given.

.. clicmd:: show ip ospf neighbor [json]

.. clicmd:: show ip ospf [vrf <NAME|all>] neighbor INTERFACE [json]

.. clicmd:: show ip ospf neighbor detail [json]

.. clicmd:: show ip ospf [vrf <NAME|all>] neighbor A.B.C.D [detail] [json]

.. clicmd:: show ip ospf [vrf <NAME|all>] neighbor INTERFACE detail [json]

   Display lsa information of LSDB.
   Json o/p of this command covers base route information
   i.e all LSAs except opaque lsa info.

.. clicmd:: show ip ospf [vrf <NAME|all>] database [self-originate] [json]

   Show the OSPF database summary.

.. clicmd:: show ip ospf [vrf <NAME|all>] database max-age [json]

   Show all MaxAge LSAs present in the OSPF link-state database.

.. clicmd:: show ip ospf [vrf <NAME|all>] database detail [LINK-STATE-ID] [adv-router A.B.C.D] [json]

.. clicmd:: show ip ospf [vrf <NAME|all>] database detail [LINK-STATE-ID] [self-originate] [json]

.. clicmd:: show ip ospf [vrf <NAME|all>] database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) [LINK-STATE-ID] [adv-router A.B.C.D] [json]

.. clicmd:: show ip ospf [vrf <NAME|all>] database (asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as) [LINK-STATE-ID] [self-originate] [json]

   Show detailed information about the OSPF link-state database.

.. clicmd:: show ip ospf route [detail] [json]

   Show the OSPF routing table, as determined by the most recent SPF
   calculation. When detail option is used, it shows more information
   to the CLI like advertising router ID for each route, etc.

.. clicmd:: show ip ospf [vrf <NAME|all>] border-routers [json]

   Show the list of ABR and ASBR border routers summary learnt via
   OSPFv2 Type-3 (Summary LSA) and Type-4 (Summary ASBR LSA).
   User can get that information as JSON format when ``json`` keyword
   at the end of cli is presented.

.. clicmd:: show ip ospf [{(1-65535)|vrf <NAME|all>}] graceful-restart helper [detail] [json]

   Displays the Graceful Restart Helper details including helper
   config changes.

.. _opaque-lsa:

Opaque LSA
==========

.. clicmd:: ospf opaque-lsa

.. clicmd:: capability opaque



   *ospfd* supports Opaque LSA (:rfc:`5250`) as partial support for
   MPLS Traffic Engineering LSAs. The opaque-lsa capability must be
   enabled in the configuration. An alternate command could be
   "mpls-te on" (:ref:`ospf-traffic-engineering`). Note that FRR
   offers only partial support for some of the routing protocol
   extensions that are used with MPLS-TE; it does not support a
   complete RSVP-TE solution.

.. clicmd:: ip ospf capability opaque [A.B.C.D]

   Enable or disable OSPF LSA database exchange and flooding on an interface.
   The default is that opaque capability is enabled as long as the opaque
   capability is enabled with the :clicmd:`capability opaque` command at the
   OSPF instance level (using the command above). Note that disabling opaque
   LSA support on an interface will impact the applications using opaque LSAs
   if the opaque LSAs are not received on other flooding paths by all the
   OSPF routers using those applications. For example, OSPF Graceful Restart
   uses opaque-link LSAs and disabling support on an interface will disable
   graceful restart signaling on that interface.

.. clicmd:: show ip ospf [vrf <NAME|all>] database (opaque-link|opaque-area|opaque-external)

.. clicmd:: show ip ospf [vrf <NAME|all>] database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID

.. clicmd:: show ip ospf [vrf <NAME|all>] database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID adv-router ADV-ROUTER

.. clicmd:: show ip ospf [vrf <NAME|all>] database (opaque-link|opaque-area|opaque-external) adv-router ADV-ROUTER

.. clicmd:: show ip ospf [vrf <NAME|all>] database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID self-originate

.. clicmd:: show ip ospf [vrf <NAME|all>] database (opaque-link|opaque-area|opaque-external) self-originate

   Show Opaque LSA from the database.

.. clicmd:: show ip ospf (1-65535) reachable-routers

.. clicmd:: show ip ospf [vrf <NAME|all>] reachable-routers

   Show routing table of reachable routers.

.. _ospf-traffic-engineering:

Traffic Engineering
===================

.. note::

   At this time, FRR offers partial support for some of the routing
   protocol extensions that can be used with MPLS-TE. FRR does not
   support a complete RSVP-TE solution currently.

.. clicmd:: mpls-te on


   Enable Traffic Engineering LSA flooding.

.. clicmd:: mpls-te router-address <A.B.C.D>

   Configure stable IP address for MPLS-TE. This IP address is then advertise
   in Opaque LSA Type-10 TLV=1 (TE) option 1 (Router-Address).

.. clicmd:: mpls-te inter-as area <area-id>|as


   Enable :rfc:`5392` support - Inter-AS TE v2 - to flood Traffic Engineering
   parameters of Inter-AS link.  2 modes are supported: AREA and AS; LSA are
   flood in AREA <area-id> with Opaque Type-10, respectively in AS with Opaque
   Type-11. In all case, Opaque-LSA TLV=6.

.. clicmd:: mpls-te export

   Export Traffic Engineering Data Base to other daemons through the ZAPI
   Opaque Link State messages.

.. clicmd:: show ip ospf mpls-te interface

.. clicmd:: show ip ospf mpls-te interface INTERFACE

   Show MPLS Traffic Engineering parameters for all or specified interface.

.. clicmd:: show ip ospf mpls-te router

   Show Traffic Engineering router parameters.

.. clicmd:: show ip ospf mpls-te database [verbose|json]

.. clicmd:: show ip ospf mpls-te database vertex [self-originate|adv-router ADV-ROUTER] [verbose|json]

.. clicmd:: show ip ospf mpls-te database edge [A.B.C.D] [verbose|json]

.. clicmd:: show ip ospf mpls-te database subnet [A.B.C.D/M] [verbose|json]

   Show Traffic Engineering Database

.. _router-information:

Router Information
==================

.. clicmd:: router-info [as | area]


   Enable Router Information (:rfc:`4970`) LSA advertisement with AS scope
   (default) or Area scope flooding when area is specified. Old syntax
   `router-info area <A.B.C.D>` is always supported but mark as deprecated
   as the area ID is no more necessary. Indeed, router information support
   multi-area and detect automatically the areas.

.. clicmd:: pce address <A.B.C.D>


.. clicmd:: pce domain as (0-65535)


.. clicmd:: pce neighbor as (0-65535)


.. clicmd:: pce flag BITPATTERN


.. clicmd:: pce scope BITPATTERN


   The commands are conform to :rfc:`5088` and allow OSPF router announce Path
   Computation Element (PCE) capabilities through the Router Information (RI)
   LSA. Router Information must be enable prior to this. The command set/unset
   respectively the PCE IP address, Autonomous System (AS) numbers of
   controlled domains, neighbor ASs, flag and scope. For flag and scope, please
   refer to :rfc`5088` for the BITPATTERN recognition. Multiple 'pce neighbor'
   command could be specified in order to specify all PCE neighbors.

.. clicmd:: show ip ospf router-info

   Show Router Capabilities flag.

.. clicmd:: show ip ospf router-info pce

   Show Router Capabilities PCE parameters.

Segment Routing
===============

This is an EXPERIMENTAL support of Segment Routing as per `RFC 8665` for MPLS
dataplane.

.. clicmd:: segment-routing on

   Enable Segment Routing. Even if this also activate routing information
   support, it is preferable to also activate routing information, and set
   accordingly the Area or AS flooding.

.. clicmd:: segment-routing global-block (16-1048575) (16-1048575) [local-block (16-1048575) (16-1048575)]

   Set the Segment Routing Global Block i.e. the label range used by MPLS to
   store label in the MPLS FIB for Prefix SID. Optionally also set the Local
   Block, i.e. the label range used for Adjacency SID. The negative version
   of the command always unsets both ranges.

.. clicmd:: segment-routing node-msd (1-16)

   Fix the Maximum Stack Depth supported by the router. The value depend of the
   MPLS dataplane. E.g. for Linux kernel, since version 4.13 it is 32.

.. clicmd:: segment-routing prefix A.B.C.D/M [index (0-65535)|no-php-flag|explicit-null]

   prefix with /32 corresponding to a loopback interface are currently
   supported. The 'no-php-flag' means NO Penultimate Hop Popping that allows SR
   node to request to its neighbor to not pop the label. The 'explicit-null' means that
   neighbor nodes must swap the incoming label by the MPLS Explicit Null label
   before delivering the packet.

.. clicmd:: show ip ospf database segment-routing <adv-router ADVROUTER|self-originate> [json]

   Show Segment Routing Data Base, all SR nodes, specific advertised router or
   self router. Optional JSON output can be obtained by appending 'json' to the
   end of the command.

External Route Summarisation
============================
This feature summarises originated external LSAs(Type-5 and Type-7).
Summary Route will be originated on-behalf of all matched external LSAs.

.. clicmd:: summary-address A.B.C.D/M [tag (1-4294967295)]

   This command enable/disables summarisation for the configured address
   range. Tag is the optional parameter. If tag configured Summary route
   will be originated with the configured tag.

.. clicmd:: summary-address A.B.C.D/M no-advertise

   This command to ensure not advertise the summary lsa for the matched
   external LSAs.

.. clicmd:: aggregation timer (5-1800)

   Configure aggregation delay timer interval. Summarisation starts only after
   this delay timer expiry. By default, delay interval is 5 seconds.


   The no form of the command resets the aggregation delay interval to default
   value.

.. clicmd:: show ip ospf [vrf <NAME|all>] summary-address [detail] [json]

   Show configuration for display all configured summary routes with
   matching external LSA information.

TI-LFA
======

Experimental support for Topology Independent LFA (Loop-Free Alternate), see
for example 'draft-bashandy-rtgwg-segment-routing-ti-lfa-05'. Note that
TI-LFA requires a proper Segment Routing configuration.

.. clicmd:: fast-reroute ti-lfa [node-protection]

   Configured on the router level. Activates TI-LFA for all interfaces.

   Note that so far only P2P interfaces are supported.

.. _debugging-ospf:

Debugging OSPF
==============

.. clicmd:: debug ospf [(1-65535)] bfd

   Enable or disable debugging for BFD events. This will show BFD integration
   library messages and OSPF BFD integration messages that are mostly state
   transitions and validation problems.

.. clicmd:: debug ospf [(1-65535)] client-api

   Show debug information for the OSPF opaque data client API.

.. clicmd:: debug ospf [(1-65535)] default-information

   Show debug information of default information

.. clicmd:: debug ospf [(1-65535)] packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]


   Dump Packet for debugging

.. clicmd:: debug ospf [(1-65535)] ism [status|events|timers]



   Show debug information of Interface State Machine

.. clicmd:: debug ospf [(1-65535)] nsm [status|events|timers]



   Show debug information of Network State Machine

.. clicmd:: debug ospf [(1-65535)] event


   Show debug information of OSPF event

.. clicmd:: debug ospf [(1-65535)] nssa


   Show debug information about Not So Stub Area

.. clicmd:: debug ospf [(1-65535)] ldp-sync

   Show debug information about LDP-Sync

.. clicmd:: debug ospf [(1-65535)] lsa [aggregate|flooding|generate|install|refresh]



   Show debug detail of Link State messages

.. clicmd:: debug ospf [(1-65535)] sr

   Show debug information about Segment Routing

.. clicmd:: debug ospf [(1-65535)] te


   Show debug information about Traffic Engineering LSA

.. clicmd:: debug ospf [(1-65535)] ti-lfa

   Show debug information about SR TI-LFA

.. clicmd:: debug ospf [(1-65535)] zebra [interface|redistribute]



   Show debug information of ZEBRA API

.. clicmd:: debug ospf [(1-65535)] graceful-restart


   Enable/disable debug information for OSPF Graceful Restart Helper

.. clicmd:: show debugging ospf



Sample Configuration
====================

A simple example, with MD5 authentication enabled:

.. code-block:: frr

   !
   interface bge0
    ip ospf authentication message-digest
    ip ospf message-digest-key 1 md5 ABCDEFGHIJK
   !
   router ospf
    network 192.168.0.0/16 area 0.0.0.1
    area 0.0.0.1 authentication message-digest


An :abbr:`ABR` router, with MD5 authentication and performing summarisation
of networks between the areas:

.. code-block:: frr

   !
   password ABCDEF
   log file /var/log/frr/ospfd.log
   service advanced-vty
   !
   interface eth0
    ip ospf authentication message-digest
    ip ospf message-digest-key 1 md5 ABCDEFGHIJK
   !
   interface ppp0
    ip ospf passive
   !
   interface br0
    ip ospf authentication message-digest
    ip ospf message-digest-key 2 md5 XYZ12345
   !
   router ospf
    ospf router-id 192.168.0.1
    redistribute connected
    network 192.168.0.0/24 area 0.0.0.0
    network 10.0.0.0/16 area 0.0.0.0
    network 192.168.1.0/24 area 0.0.0.1
    area 0.0.0.0 authentication message-digest
    area 0.0.0.0 range 10.0.0.0/16
    area 0.0.0.0 range 192.168.0.0/24
    area 0.0.0.1 authentication message-digest
    area 0.0.0.1 range 10.2.0.0/16
   !


A Traffic Engineering configuration, with Inter-ASv2 support.

First, the :file:`zebra.conf` part:

.. code-block:: frr

   interface eth0
    ip address 198.168.1.1/24
    link-params
     enable
     admin-grp 0xa1
     metric 100
     max-bw 1.25e+07
     max-rsv-bw 1.25e+06
     unrsv-bw 0 1.25e+06
     unrsv-bw 1 1.25e+06
     unrsv-bw 2 1.25e+06
     unrsv-bw 3 1.25e+06
     unrsv-bw 4 1.25e+06
     unrsv-bw 5 1.25e+06
     unrsv-bw 6 1.25e+06
     unrsv-bw 7 1.25e+06
   !
   interface eth1
    ip address 192.168.2.1/24
    link-params
     enable
     metric 10
     max-bw 1.25e+07
     max-rsv-bw 1.25e+06
     unrsv-bw 0 1.25e+06
     unrsv-bw 1 1.25e+06
     unrsv-bw 2 1.25e+06
     unrsv-bw 3 1.25e+06
     unrsv-bw 4 1.25e+06
     unrsv-bw 5 1.25e+06
     unrsv-bw 6 1.25e+06
     unrsv-bw 7 1.25e+06
     neighbor 192.168.2.2 as 65000
      hostname HOSTNAME
      password PASSWORD
      log file /var/log/zebra.log
      !
      interface eth0
       ip address 198.168.1.1/24
       link-params
        enable
        admin-grp 0xa1
        metric 100
        max-bw 1.25e+07
        max-rsv-bw 1.25e+06
        unrsv-bw 0 1.25e+06
        unrsv-bw 1 1.25e+06
        unrsv-bw 2 1.25e+06
        unrsv-bw 3 1.25e+06
        unrsv-bw 4 1.25e+06
        unrsv-bw 5 1.25e+06
        unrsv-bw 6 1.25e+06
        unrsv-bw 7 1.25e+06
      !
      interface eth1
       ip address 192.168.2.1/24
       link-params
        enable
        metric 10
        max-bw 1.25e+07
        max-rsv-bw 1.25e+06
        unrsv-bw 0 1.25e+06
        unrsv-bw 1 1.25e+06
        unrsv-bw 2 1.25e+06
        unrsv-bw 3 1.25e+06
        unrsv-bw 4 1.25e+06
        unrsv-bw 5 1.25e+06
        unrsv-bw 6 1.25e+06
        unrsv-bw 7 1.25e+06
        neighbor 192.168.2.2 as 65000

Then the :file:`ospfd.conf` itself:

.. code-block:: frr

   hostname HOSTNAME
   password PASSWORD
   log file /var/log/ospfd.log
   !
   !
   interface eth0
    ip ospf hello-interval 60
    ip ospf dead-interval 240
   !
   interface eth1
    ip ospf hello-interval 60
    ip ospf dead-interval 240
   !
   !
   router ospf
    ospf router-id 192.168.1.1
    network 192.168.0.0/16 area 1
    ospf opaque-lsa
    mpls-te
    mpls-te router-address 192.168.1.1
    mpls-te inter-as area 1
   !
   line vty

A router information example with PCE advertisement:

.. code-block:: frr

   !
   router ospf
    ospf router-id 192.168.1.1
    network 192.168.0.0/16 area 1
    capability opaque
    mpls-te
    mpls-te router-address 192.168.1.1
    router-info area 0.0.0.1
    pce address 192.168.1.1
    pce flag 0x80
    pce domain as 65400
    pce neighbor as 65500
    pce neighbor as 65200
    pce scope 0x80
   !
