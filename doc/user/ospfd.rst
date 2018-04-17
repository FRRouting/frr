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

Configuring ospfd
=================

There are no *ospfd* specific options. Common options can be specified
(:ref:`common-invocation-options`) to *ospfd*.  *ospfd* needs to acquire
interface information from *zebra* in order to function. Therefore *zebra* must
be running before invoking *ospfd*. Also, if *zebra* is restarted then *ospfd*
must be too.

Like other daemons, *ospfd* configuration is done in :abbr:`OSPF` specific
configuration file :file:`ospfd.conf`.

.. _ospf-router:

OSPF router
===========

To start OSPF process you have to specify the OSPF router. As of this
writing, *ospfd* does not support multiple OSPF processes.

.. index:: router ospf
.. clicmd:: router ospf

.. index:: no router ospf
.. clicmd:: no router ospf

   Enable or disable the OSPF process. *ospfd* does not yet
   support multiple OSPF processes. So you can not specify an OSPF process
   number.

.. index:: ospf router-id A.B.C.D
.. clicmd:: ospf router-id A.B.C.D

.. index:: no ospf router-id
.. clicmd:: no ospf router-id

   This sets the router-ID of the OSPF process. The
   router-ID may be an IP address of the router, but need not be - it can
   be any arbitrary 32bit number. However it MUST be unique within the
   entire OSPF domain to the OSPF speaker - bad things will happen if
   multiple OSPF speakers are configured with the same router-ID! If one
   is not specified then *ospfd* will obtain a router-ID
   automatically from *zebra*.

.. index:: ospf abr-type TYPE
.. clicmd:: ospf abr-type TYPE

.. index:: no ospf abr-type TYPE
.. clicmd:: no ospf abr-type TYPE

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

.. index:: ospf rfc1583compatibility
.. clicmd:: ospf rfc1583compatibility

.. index:: no ospf rfc1583compatibility
.. clicmd:: no ospf rfc1583compatibility

   :rfc:`2328`, the successor to :rfc:`1583`, suggests according
   to section G.2 (changes) in section 16.4 a change to the path
   preference algorithm that prevents possible routing loops that were
   possible in the old version of OSPFv2. More specifically it demands
   that inter-area paths and intra-area backbone path are now of equal preference
   but still both preferred to external paths.

   This command should NOT be set normally.

.. index:: log-adjacency-changes [detail]
.. clicmd:: log-adjacency-changes [detail]

.. index:: no log-adjacency-changes [detail]
.. clicmd:: no log-adjacency-changes [detail]

   Configures ospfd to log changes in adjacency. With the optional
   detail argument, all changes in adjacency status are shown. Without detail,
   only changes to full or regressions are shown.

.. index:: passive-interface INTERFACE
.. clicmd:: passive-interface INTERFACE

.. index:: no passive-interface INTERFACE
.. clicmd:: no passive-interface INTERFACE

   Do not speak OSPF interface on the
   given interface, but do advertise the interface as a stub link in the
   router-:abbr:`LSA (Link State Advertisement)` for this router. This
   allows one to advertise addresses on such connected interfaces without
   having to originate AS-External/Type-5 LSAs (which have global flooding
   scope) - as would occur if connected addresses were redistributed into
   OSPF (:ref:`redistribute-routes-to-ospf`). This is the only way to
   advertise non-OSPF links into stub areas.

.. index:: timers throttle spf DELAY INITIAL-HOLDTIME MAX-HOLDTIME
.. clicmd:: timers throttle spf DELAY INITIAL-HOLDTIME MAX-HOLDTIME

.. index:: no timers throttle spf
.. clicmd:: no timers throttle spf

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

   This command supercedes the *timers spf* command in previous FRR
   releases.

.. index:: max-metric router-lsa [on-startup|on-shutdown] (5-86400)
.. clicmd:: max-metric router-lsa [on-startup|on-shutdown] (5-86400)

.. index:: max-metric router-lsa administrative
.. clicmd:: max-metric router-lsa administrative

.. index:: no max-metric router-lsa [on-startup|on-shutdown|administrative]
.. clicmd:: no max-metric router-lsa [on-startup|on-shutdown|administrative]

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

.. index:: auto-cost reference-bandwidth (1-4294967)
.. clicmd:: auto-cost reference-bandwidth (1-4294967)

.. index:: no auto-cost reference-bandwidth
.. clicmd:: no auto-cost reference-bandwidth

   This sets the reference
   bandwidth for cost calculations, where this bandwidth is considered
   equivalent to an OSPF cost of 1, specified in Mbits/s. The default is
   100Mbit/s (i.e. a link of bandwidth 100Mbit/s or higher will have a
   cost of 1. Cost of lower bandwidth links will be scaled with reference
   to this cost).

   This configuration setting MUST be consistent across all routers within the
   OSPF domain.

.. index:: network A.B.C.D/M area A.B.C.D
.. clicmd:: network A.B.C.D/M area A.B.C.D

.. index:: network A.B.C.D/M area (0-4294967295)
.. clicmd:: network A.B.C.D/M area (0-4294967295)

.. index:: no network A.B.C.D/M area A.B.C.D
.. clicmd:: no network A.B.C.D/M area A.B.C.D

.. index:: no network A.B.C.D/M area (0-4294967295)
.. clicmd:: no network A.B.C.D/M area (0-4294967295)

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

   In some cases it may be more convenient to enable OSPF on a per
   interface/subnet basis (:clicmd:`ip ospf area AREA [ADDR]`).


.. _ospf-area:

OSPF area
=========

.. index:: area A.B.C.D range A.B.C.D/M
.. clicmd:: area A.B.C.D range A.B.C.D/M

.. index:: area (0-4294967295) range A.B.C.D/M
.. clicmd:: area (0-4294967295) range A.B.C.D/M

.. index:: no area A.B.C.D range A.B.C.D/M
.. clicmd:: no area A.B.C.D range A.B.C.D/M

.. index:: no area (0-4294967295) range A.B.C.D/M
.. clicmd:: no area (0-4294967295) range A.B.C.D/M

   Summarize intra area paths from specified area into one Type-3 summary-LSA
   announced to other areas. This command can be used only in ABR and ONLY
   router-LSAs (Type-1) and network-LSAs (Type-2) (i.e. LSAs with scope area) can
   be summarized. Type-5 AS-external-LSAs can't be summarized - their scope is AS.
   Summarizing Type-7 AS-external-LSAs isn't supported yet by FRR.

   .. code-block:: frr

      router ospf
       network 192.168.1.0/24 area 0.0.0.0
       network 10.0.0.0/8 area 0.0.0.10
       area 0.0.0.10 range 10.0.0.0/8


   With configuration above one Type-3 Summary-LSA with routing info 10.0.0.0/8 is
   announced into backbone area if area 0.0.0.10 contains at least one intra-area
   network (i.e. described with router or network LSA) from this range.

.. index:: area A.B.C.D range IPV4_PREFIX not-advertise
.. clicmd:: area A.B.C.D range IPV4_PREFIX not-advertise

.. index:: no area A.B.C.D range IPV4_PREFIX not-advertise
.. clicmd:: no area A.B.C.D range IPV4_PREFIX not-advertise

   Instead of summarizing intra area paths filter them - i.e. intra area paths from this
   range are not advertised into other areas.
   This command makes sense in ABR only.

.. index:: area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX
.. clicmd:: area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX

.. index:: no area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX
.. clicmd:: no area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX

   Substitute summarized prefix with another prefix.

   .. code-block:: frr

      router ospf
       network 192.168.1.0/24 area 0.0.0.0
       network 10.0.0.0/8 area 0.0.0.10
       area 0.0.0.10 range 10.0.0.0/8 substitute 11.0.0.0/8


   One Type-3 summary-LSA with routing info 11.0.0.0/8 is announced into backbone area if
   area 0.0.0.10 contains at least one intra-area network (i.e. described with router-LSA or
   network-LSA) from range 10.0.0.0/8.
   This command makes sense in ABR only.

.. index:: area A.B.C.D virtual-link A.B.C.D
.. clicmd:: area A.B.C.D virtual-link A.B.C.D

.. index:: area (0-4294967295) virtual-link A.B.C.D
.. clicmd:: area (0-4294967295) virtual-link A.B.C.D

.. index:: no area A.B.C.D virtual-link A.B.C.D
.. clicmd:: no area A.B.C.D virtual-link A.B.C.D

.. index:: no area (0-4294967295) virtual-link A.B.C.D
.. clicmd:: no area (0-4294967295) virtual-link A.B.C.D

.. index:: area A.B.C.D shortcut
.. clicmd:: area A.B.C.D shortcut

.. index:: area (0-4294967295) shortcut
.. clicmd:: area (0-4294967295) shortcut

.. index:: no area A.B.C.D shortcut
.. clicmd:: no area A.B.C.D shortcut

.. index:: no area (0-4294967295) shortcut
.. clicmd:: no area (0-4294967295) shortcut

   Configure the area as Shortcut capable. See :rfc:`3509`. This requires
   that the 'abr-type' be set to 'shortcut'.

.. index:: area A.B.C.D stub
.. clicmd:: area A.B.C.D stub

.. index:: area (0-4294967295) stub
.. clicmd:: area (0-4294967295) stub

.. index:: no area A.B.C.D stub
.. clicmd:: no area A.B.C.D stub

.. index:: no area (0-4294967295) stub
.. clicmd:: no area (0-4294967295) stub

   Configure the area to be a stub area. That is, an area where no router
   originates routes external to OSPF and hence an area where all external
   routes are via the ABR(s). Hence, ABRs for such an area do not need
   to pass AS-External LSAs (type-5s) or ASBR-Summary LSAs (type-4) into the
   area. They need only pass Network-Summary (type-3) LSAs into such an area,
   along with a default-route summary.

.. index:: area A.B.C.D stub no-summary
.. clicmd:: area A.B.C.D stub no-summary

.. index:: area (0-4294967295) stub no-summary
.. clicmd:: area (0-4294967295) stub no-summary

.. index:: no area A.B.C.D stub no-summary
.. clicmd:: no area A.B.C.D stub no-summary

.. index:: no area (0-4294967295) stub no-summary
.. clicmd:: no area (0-4294967295) stub no-summary

    Prevents an *ospfd* ABR from injecting inter-area
    summaries into the specified stub area.

.. index:: area A.B.C.D default-cost (0-16777215)
.. clicmd:: area A.B.C.D default-cost (0-16777215)

.. index:: no area A.B.C.D default-cost (0-16777215)
.. clicmd:: no area A.B.C.D default-cost (0-16777215)

   Set the cost of default-summary LSAs announced to stubby areas.

.. index:: area A.B.C.D export-list NAME
.. clicmd:: area A.B.C.D export-list NAME

.. index:: area (0-4294967295) export-list NAME
.. clicmd:: area (0-4294967295) export-list NAME

.. index:: no area A.B.C.D export-list NAME
.. clicmd:: no area A.B.C.D export-list NAME

.. index:: no area (0-4294967295) export-list NAME
.. clicmd:: no area (0-4294967295) export-list NAME

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

.. index:: area A.B.C.D import-list NAME
.. clicmd:: area A.B.C.D import-list NAME

.. index:: area (0-4294967295) import-list NAME
.. clicmd:: area (0-4294967295) import-list NAME

.. index:: no area A.B.C.D import-list NAME
.. clicmd:: no area A.B.C.D import-list NAME

.. index:: no area (0-4294967295) import-list NAME
.. clicmd:: no area (0-4294967295) import-list NAME

   Same as export-list, but it applies to paths announced into specified area
   as Type-3 summary-LSAs.

.. index:: area A.B.C.D filter-list prefix NAME in
.. clicmd:: area A.B.C.D filter-list prefix NAME in

.. index:: area A.B.C.D filter-list prefix NAME out
.. clicmd:: area A.B.C.D filter-list prefix NAME out

.. index:: area (0-4294967295) filter-list prefix NAME in
.. clicmd:: area (0-4294967295) filter-list prefix NAME in

.. index:: area (0-4294967295) filter-list prefix NAME out
.. clicmd:: area (0-4294967295) filter-list prefix NAME out

.. index:: no area A.B.C.D filter-list prefix NAME in
.. clicmd:: no area A.B.C.D filter-list prefix NAME in

.. index:: no area A.B.C.D filter-list prefix NAME out
.. clicmd:: no area A.B.C.D filter-list prefix NAME out

.. index:: no area (0-4294967295) filter-list prefix NAME in
.. clicmd:: no area (0-4294967295) filter-list prefix NAME in

.. index:: no area (0-4294967295) filter-list prefix NAME out
.. clicmd:: no area (0-4294967295) filter-list prefix NAME out

   Filtering Type-3 summary-LSAs to/from area using prefix lists. This command
   makes sense in ABR only.

.. index:: area A.B.C.D authentication
.. clicmd:: area A.B.C.D authentication

.. index:: area (0-4294967295) authentication
.. clicmd:: area (0-4294967295) authentication

.. index:: no area A.B.C.D authentication
.. clicmd:: no area A.B.C.D authentication

.. index:: no area (0-4294967295) authentication
.. clicmd:: no area (0-4294967295) authentication

   Specify that simple password authentication should be used for the given
   area.

.. index:: area A.B.C.D authentication message-digest
.. clicmd:: area A.B.C.D authentication message-digest

.. index:: area (0-4294967295) authentication message-digest
.. clicmd:: area (0-4294967295) authentication message-digest

   Specify that OSPF packets must be authenticated with MD5 HMACs within the
   given area. Keying material must also be configured on a per-interface basis
   (:clicmd:`ip ospf message-digest-key`).

   MD5 authentication may also be configured on a per-interface basis
   (:clicmd:`ip ospf authentication message-digest`). Such per-interface
   settings will override any per-area authentication setting.

.. _ospf-interface:

OSPF interface
==============

.. index:: ip ospf area AREA [ADDR]
.. clicmd:: ip ospf area AREA [ADDR]

.. index:: no ip ospf area [ADDR]
.. clicmd:: no ip ospf area [ADDR]

   Enable OSPF on the interface, optionally restricted to just the IP address
   given by `ADDR`, putting it in the `AREA` area. Per interface area settings
   take precedence to network commands
   (:clicmd:`network A.B.C.D/M area A.B.C.D`).

   If you have a lot of interfaces, and/or a lot of subnets, then enabling OSPF
   via this command may result in a slight performance improvement.

.. index:: ip ospf authentication-key AUTH_KEY
.. clicmd:: ip ospf authentication-key AUTH_KEY

.. index:: no ip ospf authentication-key
.. clicmd:: no ip ospf authentication-key

   Set OSPF authentication key to a simple password. After setting `AUTH_KEY`,
   all OSPF packets are authenticated. `AUTH_KEY` has length up to 8 chars.

   Simple text password authentication is insecure and deprecated in favour of
   MD5 HMAC authentication.

.. index:: ip ospf authentication message-digest
.. clicmd:: ip ospf authentication message-digest

   Specify that MD5 HMAC authentication must be used on this interface. MD5
   keying material must also be configured. Overrides any authentication
   enabled on a per-area basis
   (:clicmd:`area A.B.C.D authentication message-digest`)

   Note that OSPF MD5 authentication requires that time never go backwards
   (correct time is NOT important, only that it never goes backwards), even
   across resets, if ospfd is to be able to promptly reestablish adjacencies
   with its neighbours after restarts/reboots. The host should have system time
   be set at boot from an external or non-volatile source (e.g. battery backed
   clock, NTP, etc.) or else the system clock should be periodically saved to
   non-volatile storage and restored at boot if MD5 authentication is to be
   expected to work reliably.

.. index:: ip ospf message-digest-key KEYID md5 KEY
.. clicmd:: ip ospf message-digest-key KEYID md5 KEY

.. index:: no ip ospf message-digest-key
.. clicmd:: no ip ospf message-digest-key

   Set OSPF authentication key to a cryptographic password. The cryptographic
   algorithm is MD5.

   KEYID identifies secret key used to create the message digest. This ID is
   part of the protocol and must be consistent across routers on a link.

   KEY is the actual message digest key, of up to 16 chars (larger strings will
   be truncated), and is associated with the given KEYID.

.. index:: ip ospf cost (1-65535)
.. clicmd:: ip ospf cost (1-65535)

.. index:: no ip ospf cost
.. clicmd:: no ip ospf cost

   Set link cost for the specified interface. The cost value is set to
   router-LSA's metric field and used for SPF calculation.

.. index:: ip ospf dead-interval (1-65535)
.. clicmd:: ip ospf dead-interval (1-65535)

.. index:: ip ospf dead-interval minimal hello-multiplier (2-20)
.. clicmd:: ip ospf dead-interval minimal hello-multiplier (2-20)

.. index:: no ip ospf dead-interval
.. clicmd:: no ip ospf dead-interval

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

.. index:: ip ospf hello-interval (1-65535)
.. clicmd:: ip ospf hello-interval (1-65535)

.. index:: no ip ospf hello-interval
.. clicmd:: no ip ospf hello-interval

   Set number of seconds for HelloInterval timer value. Setting this value,
   Hello packet will be sent every timer value seconds on the specified interface.
   This value must be the same for all routers attached to a common network.
   The default value is 10 seconds.

   This command has no effect if
   :clicmd:`ip ospf dead-interval minimal hello-multiplier (2-20)` is also
   specified for the interface.

.. index:: ip ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)
.. clicmd:: ip ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)

.. index:: no ip ospf network
.. clicmd:: no ip ospf network

   Set explicitly network type for specified interface.

.. index:: ip ospf priority (0-255)
.. clicmd:: ip ospf priority (0-255)

.. index:: no ip ospf priority
.. clicmd:: no ip ospf priority

   Set RouterPriority integer value. The router with the highest priority will
   be more eligible to become Designated Router. Setting the value to 0, makes
   the router ineligible to become Designated Router. The default value is 1.

.. index:: ip ospf retransmit-interval (1-65535)
.. clicmd:: ip ospf retransmit-interval (1-65535)

.. index:: no ip ospf retransmit interval
.. clicmd:: no ip ospf retransmit interval

   Set number of seconds for RxmtInterval timer value. This value is used when
   retransmitting Database Description and Link State Request packets. The
   default value is 5 seconds.

.. index:: ip ospf transmit-delay
.. clicmd:: ip ospf transmit-delay

.. index:: no ip ospf transmit-delay
.. clicmd:: no ip ospf transmit-delay

   Set number of seconds for InfTransDelay value. LSAs' age should be
   incremented by this value when transmitting. The default value is 1 second.

.. index:: ip ospf area (A.B.C.D|(0-4294967295))
.. clicmd:: ip ospf area (A.B.C.D|(0-4294967295))

.. index:: no ip ospf area
.. clicmd:: no ip ospf area

   Enable ospf on an interface and set associated area.

.. _redistribute-routes-to-ospf:

Redistribute routes to OSPF
===========================

.. index:: redistribute (kernel|connected|static|rip|bgp)
.. clicmd:: redistribute (kernel|connected|static|rip|bgp)

.. index:: redistribute (kernel|connected|static|rip|bgp) ROUTE-MAP
.. clicmd:: redistribute (kernel|connected|static|rip|bgp) ROUTE-MAP

.. index:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2)
.. clicmd:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2)

.. index:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) route-map WORD
.. clicmd:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) route-map WORD

.. index:: redistribute (kernel|connected|static|rip|bgp) metric (0-16777214)
.. clicmd:: redistribute (kernel|connected|static|rip|bgp) metric (0-16777214)

.. index:: redistribute (kernel|connected|static|rip|bgp) metric (0-16777214) route-map WORD
.. clicmd:: redistribute (kernel|connected|static|rip|bgp) metric (0-16777214) route-map WORD

.. index:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric (0-16777214)
.. clicmd:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric (0-16777214)

.. index:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric (0-16777214) route-map WORD
.. clicmd:: redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric (0-16777214) route-map WORD

.. index:: no redistribute (kernel|connected|static|rip|bgp)
.. clicmd:: no redistribute (kernel|connected|static|rip|bgp)

.. _ospf-redistribute:

   Redistribute routes of the specified protocol or kind into OSPF, with the
   metric type and metric set if specified, filtering the routes using the
   given route-map if specified.  Redistributed routes may also be filtered
   with distribute-lists, see
   :ref:`ospf distribute-list configuration <ospf-distribute-list>`.

   Redistributed routes are distributed as into OSPF as Type-5 External LSAs
   into links to areas that accept external routes, Type-7 External LSAs for
   NSSA areas and are not redistributed at all into Stub areas, where external
   routes are not permitted.

   Note that for connected routes, one may instead use the `passive-interface`
   configuration.

.. seealso::

   clicmd:`passive-interface INTERFACE`.

.. index:: default-information originate
.. clicmd:: default-information originate

.. index:: default-information originate metric (0-16777214)
.. clicmd:: default-information originate metric (0-16777214)

.. index:: default-information originate metric (0-16777214) metric-type (1|2)
.. clicmd:: default-information originate metric (0-16777214) metric-type (1|2)

.. index:: default-information originate metric (0-16777214) metric-type (1|2) route-map WORD
.. clicmd:: default-information originate metric (0-16777214) metric-type (1|2) route-map WORD

.. index:: default-information originate always
.. clicmd:: default-information originate always

.. index:: default-information originate always metric (0-16777214)
.. clicmd:: default-information originate always metric (0-16777214)

.. index:: default-information originate always metric (0-16777214) metric-type (1|2)
.. clicmd:: default-information originate always metric (0-16777214) metric-type (1|2)

.. index:: default-information originate always metric (0-16777214) metric-type (1|2) route-map WORD
.. clicmd:: default-information originate always metric (0-16777214) metric-type (1|2) route-map WORD

.. index:: no default-information originate
.. clicmd:: no default-information originate

   Originate an AS-External (type-5) LSA describing a default route into all
   external-routing capable areas, of the specified metric and metric type. If
   the 'always' keyword is given then the default is always advertised, even
   when there is no default present in the routing table.

.. index:: distribute-list NAME out (kernel|connected|static|rip|ospf
.. clicmd:: distribute-list NAME out (kernel|connected|static|rip|ospf

.. index:: no distribute-list NAME out (kernel|connected|static|rip|ospf
.. clicmd:: no distribute-list NAME out (kernel|connected|static|rip|ospf

.. _ospf-distribute-list:

   Apply the access-list filter, NAME, to redistributed routes of the given
   type before allowing the routes to redistributed into OSPF
   (:ref:`ospf redistribution <ospf-redistribute>`).

.. index:: default-metric (0-16777214)
.. clicmd:: default-metric (0-16777214)

.. index:: no default-metric
.. clicmd:: no default-metric

.. index:: distance (1-255)
.. clicmd:: distance (1-255)

.. index:: no distance (1-255)
.. clicmd:: no distance (1-255)

.. index:: distance ospf (intra-area|inter-area|external) (1-255)
.. clicmd:: distance ospf (intra-area|inter-area|external) (1-255)

.. index:: no distance ospf
.. clicmd:: no distance ospf

.. index:: router zebra
.. clicmd:: router zebra

.. index:: no router zebra
.. clicmd:: no router zebra


.. _showing-ospf-information:

Showing OSPF information
========================

.. _show-ip-ospf:

.. index:: show ip ospf
.. clicmd:: show ip ospf

   Show information on a variety of general OSPF and area state and
   configuration information.

.. index:: show ip ospf interface [INTERFACE]
.. clicmd:: show ip ospf interface [INTERFACE]

   Show state and configuration of OSPF the specified interface, or all
   interfaces if no interface is given.

.. index:: show ip ospf neighbor
.. clicmd:: show ip ospf neighbor

.. index:: show ip ospf neighbor INTERFACE
.. clicmd:: show ip ospf neighbor INTERFACE

.. index:: show ip ospf neighbor detail
.. clicmd:: show ip ospf neighbor detail

.. index:: show ip ospf neighbor INTERFACE detail
.. clicmd:: show ip ospf neighbor INTERFACE detail

.. index:: show ip ospf database
.. clicmd:: show ip ospf database

.. index:: show ip ospf database (asbr-summary|external|network|router|summary)
.. clicmd:: show ip ospf database (asbr-summary|external|network|router|summary)

.. index:: show ip ospf database (asbr-summary|external|network|router|summary) LINK-STATE-ID
.. clicmd:: show ip ospf database (asbr-summary|external|network|router|summary) LINK-STATE-ID

.. index:: show ip ospf database (asbr-summary|external|network|router|summary) LINK-STATE-ID adv-router ADV-ROUTER
.. clicmd:: show ip ospf database (asbr-summary|external|network|router|summary) LINK-STATE-ID adv-router ADV-ROUTER

.. index:: show ip ospf database (asbr-summary|external|network|router|summary) adv-router ADV-ROUTER
.. clicmd:: show ip ospf database (asbr-summary|external|network|router|summary) adv-router ADV-ROUTER

.. index:: show ip ospf database (asbr-summary|external|network|router|summary) LINK-STATE-ID self-originate
.. clicmd:: show ip ospf database (asbr-summary|external|network|router|summary) LINK-STATE-ID self-originate

.. index:: show ip ospf database (asbr-summary|external|network|router|summary) self-originate
.. clicmd:: show ip ospf database (asbr-summary|external|network|router|summary) self-originate

.. index:: show ip ospf database max-age
.. clicmd:: show ip ospf database max-age

.. index:: show ip ospf database self-originate
.. clicmd:: show ip ospf database self-originate

.. index:: show ip ospf route
.. clicmd:: show ip ospf route

   Show the OSPF routing table, as determined by the most recent SPF
   calculation.

.. _opaque-lsa:

Opaque LSA
==========

.. index:: ospf opaque-lsa
.. clicmd:: ospf opaque-lsa

.. index:: capability opaque
.. clicmd:: capability opaque

.. index:: no ospf opaque-lsa
.. clicmd:: no ospf opaque-lsa

.. index:: no capability opaque
.. clicmd:: no capability opaque

   *ospfd* supports Opaque LSA (:rfc:`2370`) as fundamental for MPLS Traffic
   Engineering LSA. Prior to used MPLS TE, opaque-lsa must be enable in the
   configuration file. Alternate command could be "mpls-te on"
   (:ref:`ospf-traffic-engineering`).

.. index:: show ip ospf database (opaque-link|opaque-area|opaque-external)
.. clicmd:: show ip ospf database (opaque-link|opaque-area|opaque-external)

.. index:: show ip ospf database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID
.. clicmd:: show ip ospf database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID

.. index:: show ip ospf database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID adv-router ADV-ROUTER
.. clicmd:: show ip ospf database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID adv-router ADV-ROUTER

.. index:: show ip ospf database (opaque-link|opaque-area|opaque-external) adv-router ADV-ROUTER
.. clicmd:: show ip ospf database (opaque-link|opaque-area|opaque-external) adv-router ADV-ROUTER

.. index:: show ip ospf database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID self-originate
.. clicmd:: show ip ospf database (opaque-link|opaque-area|opaque-external) LINK-STATE-ID self-originate

.. index:: show ip ospf database (opaque-link|opaque-area|opaque-external) self-originate
.. clicmd:: show ip ospf database (opaque-link|opaque-area|opaque-external) self-originate

   Show Opaque LSA from the database.

.. _ospf-traffic-engineering:

Traffic Engineering
===================

.. index:: mpls-te on
.. clicmd:: mpls-te on

.. index:: no mpls-te
.. clicmd:: no mpls-te

   Enable Traffic Engineering LSA flooding.

.. index:: mpls-te router-address <A.B.C.D>
.. clicmd:: mpls-te router-address <A.B.C.D>

   Configure stable IP address for MPLS-TE. This IP address is then advertise
   in Opaque LSA Type-10 TLV=1 (TE) option 1 (Router-Address).

.. index:: mpls-te inter-as area <area-id>|as
.. clicmd:: mpls-te inter-as area <area-id>|as

.. index:: no mpls-te inter-as
.. clicmd:: no mpls-te inter-as

   Enable :rfc:`5392` support - Inter-AS TE v2 - to flood Traffic Engineering
   parameters of Inter-AS link.  2 modes are supported: AREA and AS; LSA are
   flood in AREA <area-id> with Opaque Type-10, respectively in AS with Opaque
   Type-11. In all case, Opaque-LSA TLV=6.

.. index:: show ip ospf mpls-te interface
.. clicmd:: show ip ospf mpls-te interface

.. index:: show ip ospf mpls-te interface INTERFACE
.. clicmd:: show ip ospf mpls-te interface INTERFACE

   Show MPLS Traffic Engineering parameters for all or specified interface.

.. index:: show ip ospf mpls-te router
.. clicmd:: show ip ospf mpls-te router

   Show Traffic Engineering router parameters.

.. _router-information:

Router Information
==================

.. index:: router-info [as | area <A.B.C.D>]
.. clicmd:: router-info [as | area <A.B.C.D>]

.. index:: no router-info
.. clicmd:: no router-info

   Enable Router Information (:rfc:`4970`) LSA advertisement with AS scope
   (default) or Area scope flooding when area is specified.

.. index:: pce address <A.B.C.D>
.. clicmd:: pce address <A.B.C.D>

.. index:: no pce address
.. clicmd:: no pce address

.. index:: pce domain as (0-65535)
.. clicmd:: pce domain as (0-65535)

.. index:: no pce domain as (0-65535)
.. clicmd:: no pce domain as (0-65535)

.. index:: pce neighbor as (0-65535)
.. clicmd:: pce neighbor as (0-65535)

.. index:: no pce neighbor as (0-65535)
.. clicmd:: no pce neighbor as (0-65535)

.. index:: pce flag BITPATTERN
.. clicmd:: pce flag BITPATTERN

.. index:: no pce flag
.. clicmd:: no pce flag

.. index:: pce scope BITPATTERN
.. clicmd:: pce scope BITPATTERN

.. index:: no pce scope
.. clicmd:: no pce scope

   The commands are conform to :rfc:`5088` and allow OSPF router announce Path
   Computation Element (PCE) capabilities through the Router Information (RI)
   LSA. Router Information must be enable prior to this. The command set/unset
   respectively the PCE IP address, Autonomous System (AS) numbers of
   controlled domains, neighbor ASs, flag and scope. For flag and scope, please
   refer to :rfc`5088` for the BITPATTERN recognition. Multiple 'pce neighbor'
   command could be specified in order to specify all PCE neighbours.

.. index:: show ip ospf router-info
.. clicmd:: show ip ospf router-info

   Show Router Capabilities flag.

.. index:: show ip ospf router-info pce
.. clicmd:: show ip ospf router-info pce

   Show Router Capabilities PCE parameters.

.. _debugging-ospf:

Segment Routing
===============

This is an EXPERIMENTAL support of Segment Routing as per draft
`draft-ietf-ospf-segment-routing-extensions-24.txt` for MPLS dataplane.

.. index:: [no] segment-routing on
.. clicmd:: [no] segment-routing on

   Enable Segment Routing. Even if this also activate routing information
   support, it is preferable to also activate routing information, and set
   accordingly the Area or AS flooding.

.. index:: [no] segment-routing global-block (0-1048575) (0-1048575)
.. clicmd:: [no] segment-routing global-block (0-1048575) (0-1048575)

   Fix the Segment Routing Global Block i.e. the label range used by MPLS to
   store label in the MPLS FIB.

.. index:: [no] segment-routing node-msd (1-16)
.. clicmd:: [no] segment-routing node-msd (1-16)

   Fix the Maximum Stack Depth supported by the router. The value depend of the
   MPLS dataplane. E.g. for Linux kernel, since version 4.13 it is 32.

.. index:: [no] segment-routing prefix A.B.C.D/M index (0-65535) [no-php-flag]
.. clicmd:: [no] segment-routing prefix A.B.C.D/M index (0-65535) [no-php-flag]

   Set the Segment Routing index for the specified prefix. Note that, only
   prefix with /32 corresponding to a loopback interface are currently
   supported. The 'no-php-flag' means NO Penultimate Hop Popping that allows SR
   node to request to its neighbor to not pop the label.

.. index:: show ip ospf database segment-routing <adv-router ADVROUTER|self-originate> [json]
.. clicmd:: show ip ospf database segment-routing <adv-router ADVROUTER|self-originate> [json]

   Show Segment Routing Data Base, all SR nodes, specific advertised router or
   self router. Optional JSON output can be obtained by appending 'json' to the
   end of the command.

Debugging OSPF
==============

.. index:: debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]
.. clicmd:: debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]

.. index:: no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]
.. clicmd:: no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]

   Dump Packet for debugging

.. index:: debug ospf ism
.. clicmd:: debug ospf ism

.. index:: debug ospf ism (status|events|timers)
.. clicmd:: debug ospf ism (status|events|timers)

.. index:: no debug ospf ism
.. clicmd:: no debug ospf ism

.. index:: no debug ospf ism (status|events|timers)
.. clicmd:: no debug ospf ism (status|events|timers)

   Show debug information of Interface State Machine

.. index:: debug ospf nsm
.. clicmd:: debug ospf nsm

.. index:: debug ospf nsm (status|events|timers)
.. clicmd:: debug ospf nsm (status|events|timers)

.. index:: no debug ospf nsm
.. clicmd:: no debug ospf nsm

.. index:: no debug ospf nsm (status|events|timers)
.. clicmd:: no debug ospf nsm (status|events|timers)

   Show debug information of Network State Machine

.. index:: debug ospf event
.. clicmd:: debug ospf event

.. index:: no debug ospf event
.. clicmd:: no debug ospf event

   Show debug information of OSPF event

.. index:: debug ospf nssa
.. clicmd:: debug ospf nssa

.. index:: no debug ospf nssa
.. clicmd:: no debug ospf nssa

   Show debug information about Not So Stub Area

.. index:: debug ospf lsa
.. clicmd:: debug ospf lsa

.. index:: debug ospf lsa (generate|flooding|refresh)
.. clicmd:: debug ospf lsa (generate|flooding|refresh)

.. index:: no debug ospf lsa
.. clicmd:: no debug ospf lsa

.. index:: no debug ospf lsa (generate|flooding|refresh)
.. clicmd:: no debug ospf lsa (generate|flooding|refresh)

   Show debug detail of Link State messages

.. index:: debug ospf te
.. clicmd:: debug ospf te

.. index:: no debug ospf te
.. clicmd:: no debug ospf te

   Show debug information about Traffic Engineering LSA

.. index:: debug ospf zebra
.. clicmd:: debug ospf zebra

.. index:: debug ospf zebra (interface|redistribute)
.. clicmd:: debug ospf zebra (interface|redistribute)

.. index:: no debug ospf zebra
.. clicmd:: no debug ospf zebra

.. index:: no debug ospf zebra (interface|redistribute)
.. clicmd:: no debug ospf zebra (interface|redistribute)

   Show debug information of ZEBRA API

.. index:: show debugging ospf
.. clicmd:: show debugging ospf


OSPF Configuration Examples
===========================

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
   !
   interface br0
    ip ospf authentication message-digest
    ip ospf message-digest-key 2 md5 XYZ12345
   !
   router ospf
    ospf router-id 192.168.0.1
    redistribute connected
    passive interface ppp0
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
