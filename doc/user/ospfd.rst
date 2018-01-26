.. _OSPFv2:

******
OSPFv2
******

@acronym{OSPF,Open Shortest Path First} version 2 is a routing protocol
which is described in @cite{RFC2328, OSPF Version 2}.  OSPF is an
@acronym{IGP,Interior Gateway Protocol}.  Compared with @acronym{RIP},
@acronym{OSPF} can provide scalable network support and faster
convergence times.  OSPF is widely used in large networks such as
@acronym{ISP,Internet Service Provider} backbone and enterprise
networks.

@include ospf_fundamentals.texi

.. _Configuring_ospfd:

Configuring ospfd
=================

There are no *ospfd* specific options.  Common options can be
specified (:ref:`Common_Invocation_Options`) to *ospfd*.
*ospfd* needs to acquire interface information from
*zebra* in order to function. Therefore *zebra* must be
running before invoking *ospfd*. Also, if *zebra* is
restarted then *ospfd* must be too.

Like other daemons, *ospfd* configuration is done in @acronym{OSPF}
specific configuration file :file:`ospfd.conf`.

.. _OSPF_router:

OSPF router
===========

To start OSPF process you have to specify the OSPF router.  As of this
writing, *ospfd* does not support multiple OSPF processes.

.. index:: Command {router ospf} {}

Command {router ospf} {}
.. index:: Command {no router ospf} {}

Command {no router ospf} {}
    Enable or disable the OSPF process.  *ospfd* does not yet
    support multiple OSPF processes.  So you can not specify an OSPF process
    number.

.. index:: {OSPF Command} {ospf router-id `a.b.c.d`} {}

{OSPF Command} {ospf router-id `a.b.c.d`} {}
.. index:: {OSPF Command} {no ospf router-id} {}

{OSPF Command} {no ospf router-id} {}
      .. _ospf_router-id:

      This sets the router-ID of the OSPF process. The
      router-ID may be an IP address of the router, but need not be - it can
      be any arbitrary 32bit number. However it MUST be unique within the
      entire OSPF domain to the OSPF speaker - bad things will happen if
      multiple OSPF speakers are configured with the same router-ID! If one
      is not specified then *ospfd* will obtain a router-ID
      automatically from *zebra*.

.. index:: {OSPF Command} {ospf abr-type `type`} {}

{OSPF Command} {ospf abr-type `type`} {}
.. index:: {OSPF Command} {no ospf abr-type `type`} {}

{OSPF Command} {no ospf abr-type `type`} {}
        `type` can be cisco|ibm|shortcut|standard. The "Cisco" and "IBM" types
        are equivalent.

        The OSPF standard for ABR behaviour does not allow an ABR to consider
        routes through non-backbone areas when its links to the backbone are
        down, even when there are other ABRs in attached non-backbone areas
        which still can reach the backbone - this restriction exists primarily
        to ensure routing-loops are avoided.

        With the "Cisco" or "IBM" ABR type, the default in this release of
        FRR, this restriction is lifted, allowing an ABR to consider
        summaries learnt from other ABRs through non-backbone areas, and hence
        route via non-backbone areas as a last resort when, and only when,
        backbone links are down.

        Note that areas with fully-adjacent virtual-links are considered to be
        "transit capable" and can always be used to route backbone traffic, and
        hence are unaffected by this setting (:ref:`OSPF_virtual-link`).

        More information regarding the behaviour controlled by this command can
        be found in @cite{RFC 3509, Alternative Implementations of OSPF Area
        Border Routers}, and @cite{draft-ietf-ospf-shortcut-abr-02.txt}.

        Quote: "Though the definition of the @acronym{ABR,Area Border Router}
        in the OSPF specification does not require a router with multiple
        attached areas to have a backbone connection, it is actually
        necessary to provide successful routing to the inter-area and
        external destinations. If this requirement is not met, all traffic
        destined for the areas not connected to such an ABR or out of the
        OSPF domain, is dropped.  This document describes alternative ABR
        behaviors implemented in Cisco and IBM routers."

.. index:: {OSPF Command} {ospf rfc1583compatibility} {}

{OSPF Command} {ospf rfc1583compatibility} {}
.. index:: {OSPF Command} {no ospf rfc1583compatibility} {}

{OSPF Command} {no ospf rfc1583compatibility} {}
          @cite{RFC2328}, the sucessor to @cite{RFC1583}, suggests according
          to section G.2 (changes) in section 16.4 a change to the path
          preference algorithm that prevents possible routing loops that were
          possible in the old version of OSPFv2. More specifically it demands
          that inter-area paths and intra-area backbone path are now of equal preference
          but still both preferred to external paths.

          This command should NOT be set normally.

.. index:: {OSPF Command} {log-adjacency-changes [detail]} {}

{OSPF Command} {log-adjacency-changes [detail]} {}
.. index:: {OSPF Command} {no log-adjacency-changes [detail]} {}

{OSPF Command} {no log-adjacency-changes [detail]} {}
            Configures ospfd to log changes in adjacency.  With the optional
            detail argument, all changes in adjacency status are shown.  Without detail,
            only changes to full or regressions are shown.

.. index:: {OSPF Command} {passive-interface `interface`} {}

{OSPF Command} {passive-interface `interface`} {}
.. index:: {OSPF Command} {no passive-interface `interface`} {}

{OSPF Command} {no passive-interface `interface`} {}
              .. _OSPF_passive-interface:

              Do not speak OSPF interface on the
              given interface, but do advertise the interface as a stub link in the
              router-@acronym{LSA,Link State Advertisement} for this router. This
              allows one to advertise addresses on such connected interfaces without
              having to originate AS-External/Type-5 LSAs (which have global flooding
              scope) - as would occur if connected addresses were redistributed into
              OSPF (:ref:`Redistribute_routes_to_OSPF`)@. This is the only way to
              advertise non-OSPF links into stub areas.

.. index:: {OSPF Command} {timers throttle spf `delay` `initial-holdtime` `max-holdtime`} {}

{OSPF Command} {timers throttle spf `delay` `initial-holdtime` `max-holdtime`} {}
.. index:: {OSPF Command} {no timers throttle spf} {}

{OSPF Command} {no timers throttle spf} {}
                This command sets the initial `delay`, the `initial-holdtime`
                and the `maximum-holdtime` between when SPF is calculated and the
                event which triggered the calculation. The times are specified in
                milliseconds and must be in the range of 0 to 600000 milliseconds.

                The `delay` specifies the minimum amount of time to delay SPF
                calculation (hence it affects how long SPF calculation is delayed after
                an event which occurs outside of the holdtime of any previous SPF
                calculation, and also serves as a minimum holdtime).

                Consecutive SPF calculations will always be seperated by at least
                'hold-time' milliseconds. The hold-time is adaptive and initially is
                set to the `initial-holdtime` configured with the above command.
                Events which occur within the holdtime of the previous SPF calculation
                will cause the holdtime to be increased by `initial-holdtime`, bounded
                by the `maximum-holdtime` configured with this command. If the adaptive
                hold-time elapses without any SPF-triggering event occuring then 
                the current holdtime is reset to the `initial-holdtime`. The current
                holdtime can be viewed with :ref:`show_ip_ospf`, where it is expressed as 
                a multiplier of the `initial-holdtime`.

::

                  router ospf
                   timers throttle spf 200 400 10000
                  

                In this example, the `delay` is set to 200ms, the @var{initial
                holdtime} is set to 400ms and the `maximum holdtime` to 10s. Hence
                there will always be at least 200ms between an event which requires SPF
                calculation and the actual SPF calculation. Further consecutive SPF
                calculations will always be seperated by between 400ms to 10s, the
                hold-time increasing by 400ms each time an SPF-triggering event occurs
                within the hold-time of the previous SPF calculation.

                This command supercedes the *timers spf* command in previous FRR
                releases.

.. index:: {OSPF Command} {max-metric router-lsa [on-startup|on-shutdown] <5-86400>} {}

{OSPF Command} {max-metric router-lsa [on-startup|on-shutdown] <5-86400>} {}
.. index:: {OSPF Command} {max-metric router-lsa administrative} {}

{OSPF Command} {max-metric router-lsa administrative} {}
.. index:: {OSPF Command} {no max-metric router-lsa [on-startup|on-shutdown|administrative]} {}

{OSPF Command} {no max-metric router-lsa [on-startup|on-shutdown|administrative]} {}
                    This enables @cite{RFC3137, OSPF Stub Router Advertisement} support,
                    where the OSPF process describes its transit links in its router-LSA as
                    having infinite distance so that other routers will avoid calculating
                    transit paths through the router while still being able to reach
                    networks through the router.

                    This support may be enabled administratively (and indefinitely) or
                    conditionally. Conditional enabling of max-metric router-lsas can be
                    for a period of seconds after startup and/or for a period of seconds
                    prior to shutdown. 

                    Enabling this for a period after startup allows OSPF to converge fully
                    first without affecting any existing routes used by other routers,
                    while still allowing any connected stub links and/or redistributed
                    routes to be reachable. Enabling this for a period of time in advance
                    of shutdown allows the router to gracefully excuse itself from the OSPF
                    domain. 

                    Enabling this feature administratively allows for administrative
                    intervention for whatever reason, for an indefinite period of time.
                    Note that if the configuration is written to file, this administrative
                    form of the stub-router command will also be written to file. If
                    *ospfd* is restarted later, the command will then take effect
                    until manually deconfigured.

                    Configured state of this feature as well as current status, such as the
                    number of second remaining till on-startup or on-shutdown ends, can be
                    viewed with the :ref:`show_ip_ospf` command.

.. index:: {OSPF Command} {auto-cost reference-bandwidth <1-4294967>} {}

{OSPF Command} {auto-cost reference-bandwidth <1-4294967>} {}
.. index:: {OSPF Command} {no auto-cost reference-bandwidth} {}

{OSPF Command} {no auto-cost reference-bandwidth} {}
                      .. _OSPF_auto-cost_reference-bandwidth:

                      This sets the reference
                      bandwidth for cost calculations, where this bandwidth is considered
                      equivalent to an OSPF cost of 1, specified in Mbits/s. The default is
                      100Mbit/s (i.e. a link of bandwidth 100Mbit/s or higher will have a
                      cost of 1. Cost of lower bandwidth links will be scaled with reference
                      to this cost).

                      This configuration setting MUST be consistent across all routers within the
                      OSPF domain.

.. index:: {OSPF Command} {network `a.b.c.d/m` area `a.b.c.d`} {}

{OSPF Command} {network `a.b.c.d/m` area `a.b.c.d`} {}
.. index:: {OSPF Command} {network `a.b.c.d/m` area `<0-4294967295>`} {}

{OSPF Command} {network `a.b.c.d/m` area `<0-4294967295>`} {}
.. index:: {OSPF Command} {no network `a.b.c.d/m` area `a.b.c.d`} {}

{OSPF Command} {no network `a.b.c.d/m` area `a.b.c.d`} {}
.. index:: {OSPF Command} {no network `a.b.c.d/m` area `<0-4294967295>`} {}

{OSPF Command} {no network `a.b.c.d/m` area `<0-4294967295>`} {}
                            .. _OSPF_network_command:

                            This command specifies the OSPF enabled interface(s).  If the interface has
                            an address from range 192.168.1.0/24 then the command below enables ospf
                            on this interface so router can provide network information to the other
                            ospf routers via this interface.

::

                              router ospf
                               network 192.168.1.0/24 area 0.0.0.0
                              

                            Prefix length in interface must be equal or bigger (ie. smaller network) than
                            prefix length in network statement. For example statement above doesn't enable
                            ospf on interface with address 192.168.1.1/23, but it does on interface with
                            address 192.168.1.129/25.

                            Note that the behavior when there is a peer address
                            defined on an interface changed after release 0.99.7.
                            Currently, if a peer prefix has been configured,
                            then we test whether the prefix in the network command contains
                            the destination prefix.  Otherwise, we test whether the network command prefix
                            contains the local address prefix of the interface. 

                            In some cases it may be more convenient to enable OSPF on a per
                            interface/subnet basis (:ref:`OSPF_ip_ospf_area_command`).


.. _OSPF_area:

OSPF area
=========

.. index:: {OSPF Command} {area `a.b.c.d` range `a.b.c.d/m`} {}

{OSPF Command} {area `a.b.c.d` range `a.b.c.d/m`} {}
.. index:: {OSPF Command} {area <0-4294967295> range `a.b.c.d/m`} {}

{OSPF Command} {area <0-4294967295> range `a.b.c.d/m`} {}
.. index:: {OSPF Command} {no area `a.b.c.d` range `a.b.c.d/m`} {}

{OSPF Command} {no area `a.b.c.d` range `a.b.c.d/m`} {}
.. index:: {OSPF Command} {no area <0-4294967295> range `a.b.c.d/m`} {}

{OSPF Command} {no area <0-4294967295> range `a.b.c.d/m`} {}
        Summarize intra area paths from specified area into one Type-3 summary-LSA
        announced to other areas. This command can be used only in ABR and ONLY
        router-LSAs (Type-1) and network-LSAs (Type-2) (ie. LSAs with scope area) can
        be summarized. Type-5 AS-external-LSAs can't be summarized - their scope is AS.
        Summarizing Type-7 AS-external-LSAs isn't supported yet by FRR.

::

          router ospf
           network 192.168.1.0/24 area 0.0.0.0
           network 10.0.0.0/8 area 0.0.0.10
           area 0.0.0.10 range 10.0.0.0/8
          

        With configuration above one Type-3 Summary-LSA with routing info 10.0.0.0/8 is
        announced into backbone area if area 0.0.0.10 contains at least one intra-area
        network (ie. described with router or network LSA) from this range.

.. index:: {OSPF Command} {area `a.b.c.d` range IPV4_PREFIX not-advertise} {}

{OSPF Command} {area `a.b.c.d` range IPV4_PREFIX not-advertise} {}
.. index:: {OSPF Command} {no area `a.b.c.d` range IPV4_PREFIX not-advertise} {}

{OSPF Command} {no area `a.b.c.d` range IPV4_PREFIX not-advertise} {}
          Instead of summarizing intra area paths filter them - ie. intra area paths from this
          range are not advertised into other areas.
          This command makes sense in ABR only.

.. index:: {OSPF Command} {area `a.b.c.d` range IPV4_PREFIX substitute IPV4_PREFIX} {}

{OSPF Command} {area `a.b.c.d` range IPV4_PREFIX substitute IPV4_PREFIX} {}
.. index:: {OSPF Command} {no area `a.b.c.d` range IPV4_PREFIX substitute IPV4_PREFIX} {}

{OSPF Command} {no area `a.b.c.d` range IPV4_PREFIX substitute IPV4_PREFIX} {}
            Substitute summarized prefix with another prefix.

::

              router ospf
               network 192.168.1.0/24 area 0.0.0.0
               network 10.0.0.0/8 area 0.0.0.10
               area 0.0.0.10 range 10.0.0.0/8 substitute 11.0.0.0/8
              

            One Type-3 summary-LSA with routing info 11.0.0.0/8 is announced into backbone area if
            area 0.0.0.10 contains at least one intra-area network (ie. described with router-LSA or
            network-LSA) from range 10.0.0.0/8.
            This command makes sense in ABR only.

.. index:: {OSPF Command} {area `a.b.c.d` virtual-link `a.b.c.d`} {}

{OSPF Command} {area `a.b.c.d` virtual-link `a.b.c.d`} {}
.. index:: {OSPF Command} {area <0-4294967295> virtual-link `a.b.c.d`} {}

{OSPF Command} {area <0-4294967295> virtual-link `a.b.c.d`} {}
.. index:: {OSPF Command} {no area `a.b.c.d` virtual-link `a.b.c.d`} {}

{OSPF Command} {no area `a.b.c.d` virtual-link `a.b.c.d`} {}
.. index:: {OSPF Command} {no area <0-4294967295> virtual-link `a.b.c.d`} {}

{OSPF Command} {no area <0-4294967295> virtual-link `a.b.c.d`} {}
                  .. _OSPF_virtual-link:

.. index:: {OSPF Command} {area `a.b.c.d` shortcut} {}

{OSPF Command} {area `a.b.c.d` shortcut} {}
.. index:: {OSPF Command} {area <0-4294967295> shortcut} {}

{OSPF Command} {area <0-4294967295> shortcut} {}
.. index:: {OSPF Command} {no area `a.b.c.d` shortcut} {}

{OSPF Command} {no area `a.b.c.d` shortcut} {}
.. index:: {OSPF Command} {no area <0-4294967295> shortcut} {}

{OSPF Command} {no area <0-4294967295> shortcut} {}
                        Configure the area as Shortcut capable. See @cite{RFC3509}. This requires
                        that the 'abr-type' be set to 'shortcut'.

.. index:: {OSPF Command} {area `a.b.c.d` stub} {}

{OSPF Command} {area `a.b.c.d` stub} {}
.. index:: {OSPF Command} {area <0-4294967295> stub} {}

{OSPF Command} {area <0-4294967295> stub} {}
.. index:: {OSPF Command} {no area `a.b.c.d` stub} {}

{OSPF Command} {no area `a.b.c.d` stub} {}
.. index:: {OSPF Command} {no area <0-4294967295> stub} {}

{OSPF Command} {no area <0-4294967295> stub} {}
                              Configure the area to be a stub area. That is, an area where no router
                              originates routes external to OSPF and hence an area where all external 
                              routes are via the ABR(s). Hence, ABRs for such an area do not need
                              to pass AS-External LSAs (type-5s) or ASBR-Summary LSAs (type-4) into the
                              area. They need only pass Network-Summary (type-3) LSAs into such an area,
                              along with a default-route summary.

.. index:: {OSPF Command} {area `a.b.c.d` stub no-summary} {}

{OSPF Command} {area `a.b.c.d` stub no-summary} {}
.. index:: {OSPF Command} {area <0-4294967295> stub no-summary} {}

{OSPF Command} {area <0-4294967295> stub no-summary} {}
.. index:: {OSPF Command} {no area `a.b.c.d` stub no-summary} {}

{OSPF Command} {no area `a.b.c.d` stub no-summary} {}
.. index:: {OSPF Command} {no area <0-4294967295> stub no-summary} {}

{OSPF Command} {no area <0-4294967295> stub no-summary} {}
                                    Prevents an *ospfd* ABR from injecting inter-area 
                                    summaries into the specified stub area.

.. index:: {OSPF Command} {area `a.b.c.d` default-cost <0-16777215>} {}

{OSPF Command} {area `a.b.c.d` default-cost <0-16777215>} {}
.. index:: {OSPF Command} {no area `a.b.c.d` default-cost <0-16777215>} {}

{OSPF Command} {no area `a.b.c.d` default-cost <0-16777215>} {}
                                      Set the cost of default-summary LSAs announced to stubby areas.

.. index:: {OSPF Command} {area `a.b.c.d` export-list NAME} {}

{OSPF Command} {area `a.b.c.d` export-list NAME} {}
.. index:: {OSPF Command} {area <0-4294967295> export-list NAME} {}

{OSPF Command} {area <0-4294967295> export-list NAME} {}
.. index:: {OSPF Command} {no area `a.b.c.d` export-list NAME} {}

{OSPF Command} {no area `a.b.c.d` export-list NAME} {}
.. index:: {OSPF Command} {no area <0-4294967295> export-list NAME} {}

{OSPF Command} {no area <0-4294967295> export-list NAME} {}
                                            Filter Type-3 summary-LSAs announced to other areas originated from intra-
                                            area paths from specified area.

::

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

.. index:: {OSPF Command} {area `a.b.c.d` import-list NAME} {}

{OSPF Command} {area `a.b.c.d` import-list NAME} {}
.. index:: {OSPF Command} {area <0-4294967295> import-list NAME} {}

{OSPF Command} {area <0-4294967295> import-list NAME} {}
.. index:: {OSPF Command} {no area `a.b.c.d` import-list NAME} {}

{OSPF Command} {no area `a.b.c.d` import-list NAME} {}
.. index:: {OSPF Command} {no area <0-4294967295> import-list NAME} {}

{OSPF Command} {no area <0-4294967295> import-list NAME} {}
                                                  Same as export-list, but it applies to paths announced into specified area as
                                                  Type-3 summary-LSAs.

.. index:: {OSPF Command} {area `a.b.c.d` filter-list prefix NAME in} {}

{OSPF Command} {area `a.b.c.d` filter-list prefix NAME in} {}
.. index:: {OSPF Command} {area `a.b.c.d` filter-list prefix NAME out} {}

{OSPF Command} {area `a.b.c.d` filter-list prefix NAME out} {}
.. index:: {OSPF Command} {area <0-4294967295> filter-list prefix NAME in} {}

{OSPF Command} {area <0-4294967295> filter-list prefix NAME in} {}
.. index:: {OSPF Command} {area <0-4294967295> filter-list prefix NAME out} {}

{OSPF Command} {area <0-4294967295> filter-list prefix NAME out} {}
.. index:: {OSPF Command} {no area `a.b.c.d` filter-list prefix NAME in} {}

{OSPF Command} {no area `a.b.c.d` filter-list prefix NAME in} {}
.. index:: {OSPF Command} {no area `a.b.c.d` filter-list prefix NAME out} {}

{OSPF Command} {no area `a.b.c.d` filter-list prefix NAME out} {}
.. index:: {OSPF Command} {no area <0-4294967295> filter-list prefix NAME in} {}

{OSPF Command} {no area <0-4294967295> filter-list prefix NAME in} {}
.. index:: {OSPF Command} {no area <0-4294967295> filter-list prefix NAME out} {}

{OSPF Command} {no area <0-4294967295> filter-list prefix NAME out} {}
                                                                Filtering Type-3 summary-LSAs to/from area using prefix lists. This command
                                                                makes sense in ABR only.

.. index:: {OSPF Command} {area `a.b.c.d` authentication} {}

{OSPF Command} {area `a.b.c.d` authentication} {}
.. index:: {OSPF Command} {area <0-4294967295> authentication} {}

{OSPF Command} {area <0-4294967295> authentication} {}
.. index:: {OSPF Command} {no area `a.b.c.d` authentication} {}

{OSPF Command} {no area `a.b.c.d` authentication} {}
.. index:: {OSPF Command} {no area <0-4294967295> authentication} {}

{OSPF Command} {no area <0-4294967295> authentication} {}
                                                                      Specify that simple password authentication should be used for the given
                                                                      area.

.. index:: {OSPF Command} {area `a.b.c.d` authentication message-digest} {}

{OSPF Command} {area `a.b.c.d` authentication message-digest} {}
.. index:: {OSPF Command} {area <0-4294967295> authentication message-digest} {}

{OSPF Command} {area <0-4294967295> authentication message-digest} {}
                                                                        .. _area_authentication_message-digest:

                                                                        Specify that OSPF packets
                                                                        must be authenticated with MD5 HMACs within the given area. Keying
                                                                        material must also be configured on a per-interface basis (:ref:`ip_ospf_message-digest-key`).

                                                                        MD5 authentication may also be configured on a per-interface basis
                                                                        (:ref:`ip_ospf_authentication_message-digest`). Such per-interface
                                                                        settings will override any per-area authentication setting.

.. _OSPF_interface:

OSPF interface
==============

.. index:: {Interface Command} {ip ospf area `AREA` [`ADDR`]} {} 

{Interface Command} {ip ospf area `AREA` [`ADDR`]} {}
.. index:: {Interface Command} {no ip ospf area [`ADDR`]} {}

{Interface Command} {no ip ospf area [`ADDR`]} {}
    .. _OSPF_ip_ospf_area_command:

    Enable OSPF on the interface, optionally restricted to just the IP address
    given by `ADDR`, putting it in the `AREA` area. Per interface area
    settings take precedence to network commands (:ref:`OSPF_network_command`).

    If you have a lot of interfaces, and/or a lot of subnets, then enabling OSPF
    via this command may result in a slight performance improvement.

.. index:: {Interface Command} {ip ospf authentication-key `AUTH_KEY`} {}

{Interface Command} {ip ospf authentication-key `AUTH_KEY`} {}
.. index:: {Interface Command} {no ip ospf authentication-key} {}

{Interface Command} {no ip ospf authentication-key} {}
      Set OSPF authentication key to a simple password.  After setting `AUTH_KEY`,
      all OSPF packets are authenticated. `AUTH_KEY` has length up to 8 chars.

      Simple text password authentication is insecure and deprecated in favour of
      MD5 HMAC authentication (:ref:`ip_ospf_authentication_message-digest`).

.. index:: {Interface Command} {ip ospf authentication message-digest} {}

{Interface Command} {ip ospf authentication message-digest} {}
      .. _ip_ospf_authentication_message-digest:

      Specify that MD5 HMAC
      authentication must be used on this interface. MD5 keying material must
      also be configured (:ref:`ip_ospf_message-digest-key`). Overrides any
      authentication enabled on a per-area basis (:ref:`area_authentication_message-digest`).

      Note that OSPF MD5 authentication requires that time never go backwards
      (correct time is NOT important, only that it never goes backwards), even
      across resets, if ospfd is to be able to promptly reestabish adjacencies
      with its neighbours after restarts/reboots. The host should have system
      time be set at boot from an external or non-volatile source (eg battery backed clock, NTP,
      etc.) or else the system clock should be periodically saved to non-volative
      storage and restored at boot if MD5 authentication is to be expected to work
      reliably.

.. index:: {Interface Command} {ip ospf message-digest-key KEYID md5 KEY} {}

{Interface Command} {ip ospf message-digest-key KEYID md5 KEY} {}
.. index:: {Interface Command} {no ip ospf message-digest-key} {}

{Interface Command} {no ip ospf message-digest-key} {}
        .. _ip_ospf_message-digest-key:

        Set OSPF authentication key to a
        cryptographic password.  The cryptographic algorithm is MD5.  

        KEYID identifies secret key used to create the message digest. This ID
        is part of the protocol and must be consistent across routers on a
        link.

        KEY is the actual message digest key, of up to 16 chars (larger strings
        will be truncated), and is associated with the given KEYID.

.. index:: {Interface Command} {ip ospf cost <1-65535>} {}

{Interface Command} {ip ospf cost <1-65535>} {}
.. index:: {Interface Command} {no ip ospf cost} {}

{Interface Command} {no ip ospf cost} {}
          Set link cost for the specified interface.  The cost value is set to router-LSA's
          metric field and used for SPF calculation.

.. index:: {Interface Command} {ip ospf dead-interval <1-65535>} {}

{Interface Command} {ip ospf dead-interval <1-65535>} {}
.. index:: {Interface Command} {ip ospf dead-interval minimal hello-multiplier <2-20>} {}

{Interface Command} {ip ospf dead-interval minimal hello-multiplier <2-20>} {}
.. index:: {Interface Command} {no ip ospf dead-interval} {}

{Interface Command} {no ip ospf dead-interval} {}
              .. _ip_ospf_dead-interval_minimal:

              Set number of seconds for
              RouterDeadInterval timer value used for Wait Timer and Inactivity
              Timer.  This value must be the same for all routers attached to a
              common network.  The default value is 40 seconds.

              If 'minimal' is specified instead, then the dead-interval is set to 1
              second and one must specify a hello-multiplier. The hello-multiplier
              specifies how many Hellos to send per second, from 2 (every 500ms) to
              20 (every 50ms). Thus one can have 1s convergence time for OSPF. If this form
              is specified, then the hello-interval advertised in Hello packets is set to
              0 and the hello-interval on received Hello packets is not checked, thus 
              the hello-multiplier need NOT be the same across multiple routers on a common
              link.

.. index:: {Interface Command} {ip ospf hello-interval <1-65535>} {}

{Interface Command} {ip ospf hello-interval <1-65535>} {}
.. index:: {Interface Command} {no ip ospf hello-interval} {}

{Interface Command} {no ip ospf hello-interval} {}
                Set number of seconds for HelloInterval timer value.  Setting this value,
                Hello packet will be sent every timer value seconds on the specified interface.
                This value must be the same for all routers attached to a common network.
                The default value is 10 seconds.

                This command has no effect if :ref:`ip_ospf_dead-interval_minimal` is also 
                specified for the interface.

.. index:: {Interface Command} {ip ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)} {}

{Interface Command} {ip ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)} {}
.. index:: {Interface Command} {no ip ospf network} {}

{Interface Command} {no ip ospf network} {}
                  Set explicitly network type for specifed interface.

.. index:: {Interface Command} {ip ospf priority <0-255>} {}

{Interface Command} {ip ospf priority <0-255>} {}
.. index:: {Interface Command} {no ip ospf priority} {}

{Interface Command} {no ip ospf priority} {}
                    Set RouterPriority integer value.  The router with the highest priority
                    will be more eligible to become Designated Router.  Setting the value
                    to 0, makes the router ineligible to become Designated Router. The
                    default value is 1.

.. index:: {Interface Command} {ip ospf retransmit-interval <1-65535>} {}

{Interface Command} {ip ospf retransmit-interval <1-65535>} {}
.. index:: {Interface Command} {no ip ospf retransmit interval} {}

{Interface Command} {no ip ospf retransmit interval} {}
                      Set number of seconds for RxmtInterval timer value.  This value is used
                      when retransmitting Database Description and Link State Request packets.
                      The default value is 5 seconds.

.. index:: {Interface Command} {ip ospf transmit-delay} {}

{Interface Command} {ip ospf transmit-delay} {}
.. index:: {Interface Command} {no ip ospf transmit-delay} {}

{Interface Command} {no ip ospf transmit-delay} {}
                        Set number of seconds for InfTransDelay value.  LSAs' age should be 
                        incremented by this value when transmitting.
                        The default value is 1 seconds.

.. index:: {Interface Command} {ip ospf area (A.B.C.D|<0-4294967295>)} {}

{Interface Command} {ip ospf area (A.B.C.D|<0-4294967295>)} {}
.. index:: {Interface Command} {no ip ospf area} {}

{Interface Command} {no ip ospf area} {}
                          Enable ospf on an interface and set associated area.

.. _Redistribute_routes_to_OSPF:

Redistribute routes to OSPF
===========================

.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp)} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp)} {}
.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp) `route-map`} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp) `route-map`} {}
.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2)} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2)} {}
.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) route-map `word`} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) route-map `word`} {}
.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric <0-16777214>} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric <0-16777214>} {}
.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric <0-16777214> route-map `word`} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric <0-16777214> route-map `word`} {}
.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214>} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214>} {}
.. index:: {OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214> route-map `word`} {}

{OSPF Command} {redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214> route-map `word`} {}
.. index:: {OSPF Command} {no redistribute (kernel|connected|static|rip|bgp)} {}

{OSPF Command} {no redistribute (kernel|connected|static|rip|bgp)} {}
                  .. _OSPF_redistribute:

                  Redistribute routes of the specified protocol
                  or kind into OSPF, with the metric type and metric set if specified,
                  filtering the routes using the given route-map if specified.
                  Redistributed routes may also be filtered with distribute-lists, see
                  :ref:`ospf_distribute-list`.

                  Redistributed routes are distributed as into OSPF as Type-5 External
                  LSAs into links to areas that accept external routes, Type-7 External LSAs
                  for NSSA areas and are not redistributed at all into Stub areas, where
                  external routes are not permitted.

                  Note that for connected routes, one may instead use
                  @dfn{passive-interface}, see :ref:`OSPF_passive-interface`.

.. index:: {OSPF Command} {default-information originate} {}

{OSPF Command} {default-information originate} {}
.. index:: {OSPF Command} {default-information originate metric <0-16777214>} {}

{OSPF Command} {default-information originate metric <0-16777214>} {}
.. index:: {OSPF Command} {default-information originate metric <0-16777214> metric-type (1|2)} {}

{OSPF Command} {default-information originate metric <0-16777214> metric-type (1|2)} {}
.. index:: {OSPF Command} {default-information originate metric <0-16777214> metric-type (1|2) route-map `word`} {}

{OSPF Command} {default-information originate metric <0-16777214> metric-type (1|2) route-map `word`} {}
.. index:: {OSPF Command} {default-information originate always} {}

{OSPF Command} {default-information originate always} {}
.. index:: {OSPF Command} {default-information originate always metric <0-16777214>} {}

{OSPF Command} {default-information originate always metric <0-16777214>} {}
.. index:: {OSPF Command} {default-information originate always metric <0-16777214> metric-type (1|2)} {}

{OSPF Command} {default-information originate always metric <0-16777214> metric-type (1|2)} {}
.. index:: {OSPF Command} {default-information originate always metric <0-16777214> metric-type (1|2) route-map `word`} {}

{OSPF Command} {default-information originate always metric <0-16777214> metric-type (1|2) route-map `word`} {}
.. index:: {OSPF Command} {no default-information originate} {}

{OSPF Command} {no default-information originate} {}
                                  Originate an AS-External (type-5) LSA describing a default route into
                                  all external-routing capable areas, of the specified metric and metric
                                  type. If the 'always' keyword is given then the default is always
                                  advertised, even when there is no default present in the routing table.

.. index:: {OSPF Command} {distribute-list NAME out (kernel|connected|static|rip|ospf} {}

{OSPF Command} {distribute-list NAME out (kernel|connected|static|rip|ospf} {}
.. index:: {OSPF Command} {no distribute-list NAME out (kernel|connected|static|rip|ospf} {}

{OSPF Command} {no distribute-list NAME out (kernel|connected|static|rip|ospf} {}
                                    .. _ospf_distribute-list:

                                    Apply the access-list filter, NAME, to
                                    redistributed routes of the given type before allowing the routes to
                                    redistributed into OSPF (:ref:`OSPF_redistribute`).

.. index:: {OSPF Command} {default-metric <0-16777214>} {}

{OSPF Command} {default-metric <0-16777214>} {}
.. index:: {OSPF Command} {no default-metric} {}

{OSPF Command} {no default-metric} {}
.. index:: {OSPF Command} {distance <1-255>} {}

{OSPF Command} {distance <1-255>} {}
.. index:: {OSPF Command} {no distance <1-255>} {}

{OSPF Command} {no distance <1-255>} {}
.. index:: {OSPF Command} {distance ospf (intra-area|inter-area|external) <1-255>} {}

{OSPF Command} {distance ospf (intra-area|inter-area|external) <1-255>} {}
.. index:: {OSPF Command} {no distance ospf} {}

{OSPF Command} {no distance ospf} {}
.. index:: {Command} {router zebra} {}

{Command} {router zebra} {}
.. index:: {Command} {no router zebra} {}

{Command} {no router zebra} {}

.. _Showing_OSPF_information:

Showing OSPF information
========================

.. index:: {Command} {show ip ospf} {}

{Command} {show ip ospf} {}
  .. _show_ip_ospf:

  Show information on a variety of general OSPF and
  area state and configuration information.

.. index:: {Command} {show ip ospf interface [INTERFACE]} {}

{Command} {show ip ospf interface [INTERFACE]} {}
  Show state and configuration of OSPF the specified interface, or all
  interfaces if no interface is given.

.. index:: {Command} {show ip ospf neighbor} {}

{Command} {show ip ospf neighbor} {}
.. index:: {Command} {show ip ospf neighbor INTERFACE} {}

{Command} {show ip ospf neighbor INTERFACE} {}
.. index:: {Command} {show ip ospf neighbor detail} {}

{Command} {show ip ospf neighbor detail} {}
.. index:: {Command} {show ip ospf neighbor INTERFACE detail} {}

{Command} {show ip ospf neighbor INTERFACE detail} {}
.. index:: {Command} {show ip ospf database} {}

{Command} {show ip ospf database} {}
.. index:: {Command} {show ip ospf database (asbr-summary|external|network|router|summary)} {}

{Command} {show ip ospf database (asbr-summary|external|network|router|summary)} {}
.. index:: {Command} {show ip ospf database (asbr-summary|external|network|router|summary) `link-state-id`} {}

{Command} {show ip ospf database (asbr-summary|external|network|router|summary) `link-state-id`} {}
.. index:: {Command} {show ip ospf database (asbr-summary|external|network|router|summary) `link-state-id` adv-router `adv-router`} {}

{Command} {show ip ospf database (asbr-summary|external|network|router|summary) `link-state-id` adv-router `adv-router`} {}
.. index:: {Command} {show ip ospf database (asbr-summary|external|network|router|summary) adv-router `adv-router`} {}

{Command} {show ip ospf database (asbr-summary|external|network|router|summary) adv-router `adv-router`} {}
.. index:: {Command} {show ip ospf database (asbr-summary|external|network|router|summary) `link-state-id` self-originate} {}

{Command} {show ip ospf database (asbr-summary|external|network|router|summary) `link-state-id` self-originate} {}
.. index:: {Command} {show ip ospf database (asbr-summary|external|network|router|summary) self-originate} {}

{Command} {show ip ospf database (asbr-summary|external|network|router|summary) self-originate} {}
.. index:: {Command} {show ip ospf database max-age} {}

{Command} {show ip ospf database max-age} {}
.. index:: {Command} {show ip ospf database self-originate} {}

{Command} {show ip ospf database self-originate} {}
.. index:: {Command} {show ip ospf route} {}

{Command} {show ip ospf route} {}
                  Show the OSPF routing table, as determined by the most recent SPF calculation.

.. _Opaque_LSA:

Opaque LSA
==========

.. index:: {OSPF Command} {ospf opaque-lsa} {}

{OSPF Command} {ospf opaque-lsa} {}
.. index:: {OSPF Command} {capability opaque} {}

{OSPF Command} {capability opaque} {}
.. index:: {OSPF Command} {no ospf opaque-lsa} {}

{OSPF Command} {no ospf opaque-lsa} {}
.. index:: {OSPF Command} {no capability opaque} {}

{OSPF Command} {no capability opaque} {}
        *ospfd* support Opaque LSA (RFC2370) as fondment for MPLS Traffic Engineering LSA. Prior to used MPLS TE, opaque-lsa must be enable in the configuration file. Alternate command could be "mpls-te on" (:ref:`OSPF_Traffic_Engineering`).

.. index:: {Command} {show ip ospf database (opaque-link|opaque-area|opaque-external)} {}

{Command} {show ip ospf database (opaque-link|opaque-area|opaque-external)} {}
.. index:: {Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) `link-state-id`} {}

{Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) `link-state-id`} {}
.. index:: {Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) `link-state-id` adv-router `adv-router`} {}

{Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) `link-state-id` adv-router `adv-router`} {}
.. index:: {Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) adv-router `adv-router`} {}

{Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) adv-router `adv-router`} {}
.. index:: {Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) `link-state-id` self-originate} {}

{Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) `link-state-id` self-originate} {}
.. index:: {Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) self-originate} {}

{Command} {show ip ospf database (opaque-link|opaque-area|opaque-external) self-originate} {}
                  Show Opaque LSA from the database.

.. _Traffic_Engineering:

Traffic Engineering
===================

.. index:: {OSPF Command} {mpls-te on} {}

{OSPF Command} {mpls-te on} {}
.. index:: {OSPF Command} {no mpls-te} {}

{OSPF Command} {no mpls-te} {}
    Enable Traffic Engineering LSA flooding.

.. index:: {OSPF Command} {mpls-te router-address <A.B.C.D>} {}

{OSPF Command} {mpls-te router-address <A.B.C.D>} {}
.. index:: {OSPF Command} {no mpls-te} {}

{OSPF Command} {no mpls-te} {}
      Configure stable IP address for MPLS-TE. This IP address is then advertise in Opaque LSA Type-10 TLV=1 (TE)
      option 1 (Router-Address).

.. index:: {OSPF Command} {mpls-te inter-as area <area-id>|as} {}

{OSPF Command} {mpls-te inter-as area <area-id>|as} {}
.. index:: {OSPF Command} {no mpls-te inter-as} {}

{OSPF Command} {no mpls-te inter-as} {}
        Enable RFC5392 suuport - Inter-AS TE v2 - to flood Traffic Engineering parameters of Inter-AS link.
        2 modes are supported: AREA and AS; LSA are flood in AREA <area-id> with Opaque Type-10,
        respectively in AS with Opaque Type-11. In all case, Opaque-LSA TLV=6.

.. index:: {Command} {show ip ospf mpls-te interface} {}

{Command} {show ip ospf mpls-te interface} {}
.. index:: {Command} {show ip ospf mpls-te interface `interface`} {}

{Command} {show ip ospf mpls-te interface `interface`} {}
          Show MPLS Traffic Engineering parameters for all or specified interface.

.. index:: {Command} {show ip ospf mpls-te router} {}

{Command} {show ip ospf mpls-te router} {}
          Show Traffic Engineering router parameters.

.. _Router_Information:

Router Information
==================

.. index:: {OSPF Command} {router-info [as | area <A.B.C.D>]} {}

{OSPF Command} {router-info [as | area <A.B.C.D>]} {}
.. index:: {OSPF Command} {no router-info} {}

{OSPF Command} {no router-info} {}
    Enable Router Information (RFC4970) LSA advertisement with AS scope (default) or Area scope flooding
    when area is specified.

.. index:: {OSPF Command} {pce address <A.B.C.D>} {}

{OSPF Command} {pce address <A.B.C.D>} {}
.. index:: {OSPF Command} {no pce address} {}

{OSPF Command} {no pce address} {}
.. index:: {OSPF Command} {pce domain as <0-65535>} {}

{OSPF Command} {pce domain as <0-65535>} {}
.. index:: {OSPF Command} {no pce domain as <0-65535>} {}

{OSPF Command} {no pce domain as <0-65535>} {}
.. index:: {OSPF Command} {pce neighbor as <0-65535>} {}

{OSPF Command} {pce neighbor as <0-65535>} {}
.. index:: {OSPF Command} {no pce neighbor as <0-65535>} {}

{OSPF Command} {no pce neighbor as <0-65535>} {}
.. index:: {OSPF Command} {pce flag BITPATTERN} {}

{OSPF Command} {pce flag BITPATTERN} {}
.. index:: {OSPF Command} {no pce flag} {}

{OSPF Command} {no pce flag} {}
.. index:: {OSPF Command} {pce scope BITPATTERN} {}

{OSPF Command} {pce scope BITPATTERN} {}
.. index:: {OSPF Command} {no pce scope} {}

{OSPF Command} {no pce scope} {}
                      The commands are conform to RFC 5088 and allow OSPF router announce Path Compuatation Elemenent (PCE) capabilities
                      through the Router Information (RI) LSA. Router Information must be enable prior to this. The command set/unset
                      respectively the PCE IP adress, Autonomous System (AS) numbers of controlled domains, neighbor ASs, flag and scope.
                      For flag and scope, please refer to RFC5088 for the BITPATTERN recognition. Multiple 'pce neighbor' command could
                      be specified in order to specify all PCE neighbours.

.. index:: {Command} {show ip ospf router-info} {}

{Command} {show ip ospf router-info} {}
                      Show Router Capabilities flag.
.. index:: {Command} {show ip ospf router-info pce} {}

{Command} {show ip ospf router-info pce} {}
                      Show Router Capabilities PCE parameters.

.. _Debugging_OSPF:

Debugging OSPF
==============

.. index:: {Command} {debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]} {}

{Command} {debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]} {}
.. index:: {Command} {no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]} {}

{Command} {no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) [detail]} {}
    Dump Packet for debugging

.. index:: {Command} {debug ospf ism} {}

{Command} {debug ospf ism} {}
.. index:: {Command} {debug ospf ism (status|events|timers)} {}

{Command} {debug ospf ism (status|events|timers)} {}
.. index:: {Command} {no debug ospf ism} {}

{Command} {no debug ospf ism} {}
.. index:: {Command} {no debug ospf ism (status|events|timers)} {}

{Command} {no debug ospf ism (status|events|timers)} {}
          Show debug information of Interface State Machine

.. index:: {Command} {debug ospf nsm} {}

{Command} {debug ospf nsm} {}
.. index:: {Command} {debug ospf nsm (status|events|timers)} {}

{Command} {debug ospf nsm (status|events|timers)} {}
.. index:: {Command} {no debug ospf nsm} {}

{Command} {no debug ospf nsm} {}
.. index:: {Command} {no debug ospf nsm (status|events|timers)} {}

{Command} {no debug ospf nsm (status|events|timers)} {}
                Show debug information of Network State Machine

.. index:: {Command} {debug ospf event} {}

{Command} {debug ospf event} {}
.. index:: {Command} {no debug ospf event} {}

{Command} {no debug ospf event} {}
                  Show debug information of OSPF event

.. index:: {Command} {debug ospf nssa} {}

{Command} {debug ospf nssa} {}
.. index:: {Command} {no debug ospf nssa} {}

{Command} {no debug ospf nssa} {}
                    Show debug information about Not So Stub Area

.. index:: {Command} {debug ospf lsa} {}

{Command} {debug ospf lsa} {}
.. index:: {Command} {debug ospf lsa (generate|flooding|refresh)} {}

{Command} {debug ospf lsa (generate|flooding|refresh)} {}
.. index:: {Command} {no debug ospf lsa} {}

{Command} {no debug ospf lsa} {}
.. index:: {Command} {no debug ospf lsa (generate|flooding|refresh)} {}

{Command} {no debug ospf lsa (generate|flooding|refresh)} {}
                          Show debug detail of Link State messages

.. index:: {Command} {debug ospf te} {}

{Command} {debug ospf te} {}
.. index:: {Command} {no debug ospf te} {}

{Command} {no debug ospf te} {}
                            Show debug information about Traffic Engineering LSA

.. index:: {Command} {debug ospf zebra} {}

{Command} {debug ospf zebra} {}
.. index:: {Command} {debug ospf zebra (interface|redistribute)} {}

{Command} {debug ospf zebra (interface|redistribute)} {}
.. index:: {Command} {no debug ospf zebra} {}

{Command} {no debug ospf zebra} {}
.. index:: {Command} {no debug ospf zebra (interface|redistribute)} {}

{Command} {no debug ospf zebra (interface|redistribute)} {}
                                  Show debug information of ZEBRA API

.. index:: {Command} {show debugging ospf} {}

{Command} {show debugging ospf} {}

OSPF Configuration Examples
===========================

A simple example, with MD5 authentication enabled:

::

  !
  interface bge0
   ip ospf authentication message-digest
   ip ospf message-digest-key 1 md5 ABCDEFGHIJK
  !
  router ospf
   network 192.168.0.0/16 area 0.0.0.1
   area 0.0.0.1 authentication message-digest
  

An @acronym{ABR} router, with MD5 authentication and performing summarisation
of networks between the areas:

::

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

- First, the 'zebra.conf' part:

::

  hostname HOSTNAME
  password PASSWORD
  log file /var/log/zebra.log
  !
  interface eth0
   ip address 198.168.1.1/24
   mpls-te on
   mpls-te link metric 10
   mpls-te link max-bw 1.25e+06
   mpls-te link max-rsv-bw 1.25e+06
   mpls-te link unrsv-bw 0 1.25e+06
   mpls-te link unrsv-bw 1 1.25e+06
   mpls-te link unrsv-bw 2 1.25e+06
   mpls-te link unrsv-bw 3 1.25e+06
   mpls-te link unrsv-bw 4 1.25e+06
   mpls-te link unrsv-bw 5 1.25e+06
   mpls-te link unrsv-bw 6 1.25e+06
   mpls-te link unrsv-bw 7 1.25e+06
   mpls-te link rsc-clsclr 0xab
  !
  interface eth1
   ip address 192.168.2.1/24
   mpls-te on
   mpls-te link metric 10
   mpls-te link max-bw 1.25e+06
   mpls-te link max-rsv-bw 1.25e+06
   mpls-te link unrsv-bw 0 1.25e+06
   mpls-te link unrsv-bw 1 1.25e+06
   mpls-te link unrsv-bw 2 1.25e+06
   mpls-te link unrsv-bw 3 1.25e+06
   mpls-te link unrsv-bw 4 1.25e+06
   mpls-te link unrsv-bw 5 1.25e+06
   mpls-te link unrsv-bw 6 1.25e+06
   mpls-te link unrsv-bw 7 1.25e+06
   mpls-te link rsc-clsclr 0xab
   mpls-te neighbor 192.168.2.2 as 65000
  

- Then the 'ospfd.conf' itself:

::

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
  

A router information example with PCE advsertisement:

::

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
  

