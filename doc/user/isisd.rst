.. _ISIS:

****
ISIS
****

:abbr:`ISIS (Intermediate System to Intermediate System)` is a routing protocol
which is described in @cite{ISO10589, RFC1195, RFC5308}.  ISIS is an
:abbr:`IGP (Interior Gateway Protocol)`.  Compared with :abbr:`RIP`,
:abbr:`ISIS` can provide scalable network support and faster
convergence times like :abbr:`OSPF`. ISIS is widely used in large networks such as
:abbr:`ISP (Internet Service Provider)` and carrier backbone networks.

.. _Configuring_isisd:

Configuring isisd
=================

There are no *isisd* specific options.  Common options can be
specified (:ref:`Common_Invocation_Options`) to *isisd*.
*isisd* needs to acquire interface information from
*zebra* in order to function. Therefore *zebra* must be
running before invoking *isisd*. Also, if *zebra* is
restarted then *isisd* must be too.

Like other daemons, *isisd* configuration is done in :abbr:`ISIS`
specific configuration file :file:`isisd.conf`.

.. _ISIS_router:

ISIS router
===========

To start ISIS process you have to specify the ISIS router. As of this
writing, *isisd* does not support multiple ISIS processes.

.. index:: Command {router isis WORD} {}

Command {router isis WORD} {}
.. index:: Command {no router isis WORD} {}

Command {no router isis WORD} {}
    .. _router_isis_WORD:

    Enable or disable the ISIS process by specifying the ISIS domain with 'WORD'.
    *isisd* does not yet support multiple ISIS processes but you must specify
    the name of ISIS process. The ISIS process name 'WORD' is then used for interface
    (see command :ref:`ip_router_isis_WORD`).

.. index:: {ISIS Command} {net XX.XXXX. ... .XXX.XX} {}

{ISIS Command} {net XX.XXXX. ... .XXX.XX} {}
.. index:: {ISIS Command} {no net XX.XXXX. ... .XXX.XX} {}

{ISIS Command} {no net XX.XXXX. ... .XXX.XX} {}
      Set/Unset network entity title (NET) provided in ISO format.

.. index:: {ISIS Command} {hostname dynamic} {}

{ISIS Command} {hostname dynamic} {}
.. index:: {ISIS Command} {no hostname dynamic} {}

{ISIS Command} {no hostname dynamic} {}
        Enable support for dynamic hostname.

.. index:: {ISIS Command} {area-password [clear | md5] <password>} {}

{ISIS Command} {area-password [clear | md5] <password>} {}
.. index:: {ISIS Command} {domain-password [clear | md5] <password>} {}

{ISIS Command} {domain-password [clear | md5] <password>} {}
.. index:: {ISIS Command} {no area-password} {}

{ISIS Command} {no area-password} {}
.. index:: {ISIS Command} {no domain-password} {}

{ISIS Command} {no domain-password} {}
              Configure the authentication password for an area, respectively a domain,
              as clear text or md5 one.

.. index:: {ISIS Command} {log-adjacency-changes} {}

{ISIS Command} {log-adjacency-changes} {}
.. index:: {ISIS Command} {no log-adjacency-changes} {}

{ISIS Command} {no log-adjacency-changes} {}
                Log changes in adjacency state.

.. index:: {ISIS Command} {metric-style [narrow | transition | wide]} {}

{ISIS Command} {metric-style [narrow | transition | wide]} {}
.. index:: {ISIS Command} {no metric-style} {}

{ISIS Command} {no metric-style} {}
                  .. _metric-style:

                  Set old-style (ISO 10589) or new-style packet formats:
                  - narrow      Use old style of TLVs with narrow metric
                  - transition  Send and accept both styles of TLVs during transition
                  - wide        Use new style of TLVs to carry wider metric

.. index:: {ISIS Command} {set-overload-bit} {}

{ISIS Command} {set-overload-bit} {}
.. index:: {ISIS Command} {no set-overload-bit} {}

{ISIS Command} {no set-overload-bit} {}
                    Set overload bit to avoid any transit traffic.

.. _ISIS_Timer:

ISIS Timer
==========

.. index:: {ISIS Command} {lsp-gen-interval (1-120)} {}

{ISIS Command} {lsp-gen-interval (1-120)} {}
.. index:: {ISIS Command} {lsp-gen-interval [level-1 | level-2] (1-120)} {}

{ISIS Command} {lsp-gen-interval [level-1 | level-2] (1-120)} {}
.. index:: {ISIS Command} {no lsp-gen-interval} {}

{ISIS Command} {no lsp-gen-interval} {}
.. index:: {ISIS Command} {no lsp-gen-interval [level-1 | level-2]} {}

{ISIS Command} {no lsp-gen-interval [level-1 | level-2]} {}
        Set minimum interval in seconds between regenerating same LSP,
        globally, for an area (level-1) or a domain (level-2).

.. index:: {ISIS Command} {lsp-refresh-interval (1-65235)} {}

{ISIS Command} {lsp-refresh-interval (1-65235)} {}
.. index:: {ISIS Command} {lsp-refresh-interval [level-1 | level-2] (1-65235)} {}

{ISIS Command} {lsp-refresh-interval [level-1 | level-2] (1-65235)} {}
.. index:: {ISIS Command} {no lsp-refresh-interval} {}

{ISIS Command} {no lsp-refresh-interval} {}
.. index:: {ISIS Command} {no lsp-refresh-interval [level-1 | level-2]} {}

{ISIS Command} {no lsp-refresh-interval [level-1 | level-2]} {}
              Set LSP refresh interval in seconds, globally, for an area (level-1) or a domain (level-2).

.. index:: {ISIS Command} {lsp-refresh-interval (1-65235)} {}

{ISIS Command} {lsp-refresh-interval (1-65235)} {}
.. index:: {ISIS Command} {lsp-refresh-interval [level-1 | level-2] (1-65235)} {}

{ISIS Command} {lsp-refresh-interval [level-1 | level-2] (1-65235)} {}
.. index:: {ISIS Command} {no lsp-refresh-interval} {}

{ISIS Command} {no lsp-refresh-interval} {}
.. index:: {ISIS Command} {no lsp-refresh-interval [level-1 | level-2]} {}

{ISIS Command} {no lsp-refresh-interval [level-1 | level-2]} {}
                    Set LSP refresh interval in seconds, globally, for an area (level-1) or a domain (level-2).

.. index:: {ISIS Command} {max-lsp-lifetime (360-65535)} {}

{ISIS Command} {max-lsp-lifetime (360-65535)} {}
.. index:: {ISIS Command} {max-lsp-lifetime [level-1 | level-2] (360-65535)} {}

{ISIS Command} {max-lsp-lifetime [level-1 | level-2] (360-65535)} {}
.. index:: {ISIS Command} {no max-lsp-lifetime} {}

{ISIS Command} {no max-lsp-lifetime} {}
.. index:: {ISIS Command} {no max-lsp-lifetime [level-1 | level-2]} {}

{ISIS Command} {no max-lsp-lifetime [level-1 | level-2]} {}
                          Set LSP maximum LSP lifetime in seconds, globally, for an area (level-1) or a domain (level-2).

.. index:: {ISIS Command} {spf-interval (1-120)} {}

{ISIS Command} {spf-interval (1-120)} {}
.. index:: {ISIS Command} {spf-interval [level-1 | level-2] (1-120)} {}

{ISIS Command} {spf-interval [level-1 | level-2] (1-120)} {}
.. index:: {ISIS Command} {no spf-interval} {}

{ISIS Command} {no spf-interval} {}
.. index:: {ISIS Command} {no spf-interval [level-1 | level-2]} {}

{ISIS Command} {no spf-interval [level-1 | level-2]} {}
                                Set minimum interval between consecutive SPF calculations in seconds.

.. _ISIS_region:

ISIS region
===========

.. index:: {ISIS Command} {is-type [level-1 | level-1-2 | level-2-only]} {}

{ISIS Command} {is-type [level-1 | level-1-2 | level-2-only]} {}
.. index:: {ISIS Command} {no is-type} {}

{ISIS Command} {no is-type} {}
    Define the ISIS router behavior:
    - level-1       Act as a station router only
    - level-1-2     Act as both a station router and an area router
    - level-2-only  Act as an area router only

.. _ISIS_interface:

ISIS interface
==============

.. index:: {Interface Command} {ip router isis WORD} {}

{Interface Command} {ip router isis WORD} {}
.. index:: {Interface Command} {no ip router isis WORD} {}

{Interface Command} {no ip router isis WORD} {}
    .. _ip_router_isis_WORD:

    Activate ISIS adjacency on this interface. Note that the name
    of ISIS instance must be the same as the one used to configure the ISIS process
    (see command :ref:`router_isis_WORD`).

.. index:: {Interface Command} {isis circuit-type [level-1 | level-1-2 | level-2]} {}

{Interface Command} {isis circuit-type [level-1 | level-1-2 | level-2]} {}
.. index:: {Interface Command} {no isis circuit-type} {}

{Interface Command} {no isis circuit-type} {}
      Configure circuit type for interface:
      - level-1       Level-1 only adjacencies are formed
      - level-1-2     Level-1-2 adjacencies are formed
      - level-2-only  Level-2 only adjacencies are formed

.. index:: {Interface Command} {isis csnp-interval (1-600)} {}

{Interface Command} {isis csnp-interval (1-600)} {}
.. index:: {Interface Command} {isis csnp-interval (1-600) [level-1 | level-2]} {}

{Interface Command} {isis csnp-interval (1-600) [level-1 | level-2]} {}
.. index:: {Interface Command} {no isis csnp-interval} {}

{Interface Command} {no isis csnp-interval} {}
.. index:: {Interface Command} {no isis csnp-interval [level-1 | level-2]} {}

{Interface Command} {no isis csnp-interval [level-1 | level-2]} {}
            Set CSNP interval in seconds globally, for an area (level-1) or a domain (level-2).

.. index:: {Interface Command} {isis hello padding} {}

{Interface Command} {isis hello padding} {}
            Add padding to IS-IS hello packets.

.. index:: {Interface Command} {isis hello-interval (1-600)} {}

{Interface Command} {isis hello-interval (1-600)} {}
.. index:: {Interface Command} {isis hello-interval (1-600) [level-1 | level-2]} {}

{Interface Command} {isis hello-interval (1-600) [level-1 | level-2]} {}
.. index:: {Interface Command} {no isis hello-interval} {}

{Interface Command} {no isis hello-interval} {}
.. index:: {Interface Command} {no isis hello-interval [level-1 | level-2]} {}

{Interface Command} {no isis hello-interval [level-1 | level-2]} {}
                  Set Hello interval in seconds globally, for an area (level-1) or a domain (level-2).

.. index:: {Interface Command} {isis hello-multiplier (2-100)} {}

{Interface Command} {isis hello-multiplier (2-100)} {}
.. index:: {Interface Command} {isis hello-multiplier (2-100) [level-1 | level-2]} {}

{Interface Command} {isis hello-multiplier (2-100) [level-1 | level-2]} {}
.. index:: {Interface Command} {no isis hello-multiplier} {}

{Interface Command} {no isis hello-multiplier} {}
.. index:: {Interface Command} {no isis hello-multiplier [level-1 | level-2]} {}

{Interface Command} {no isis hello-multiplier [level-1 | level-2]} {}
                        Set multiplier for Hello holding time globally, for an area (level-1) or a domain (level-2).

.. index:: {Interface Command} {isis metric [(0-255) | (0-16777215)]} {}

{Interface Command} {isis metric [(0-255) | (0-16777215)]} {}
.. index:: {Interface Command} {isis metric [(0-255) | (0-16777215)] [level-1 | level-2]} {}

{Interface Command} {isis metric [(0-255) | (0-16777215)] [level-1 | level-2]} {}
.. index:: {Interface Command} {no isis metric} {}

{Interface Command} {no isis metric} {}
.. index:: {Interface Command} {no isis metric [level-1 | level-2]} {}

{Interface Command} {no isis metric [level-1 | level-2]} {}
                              Set default metric value globally, for an area (level-1) or a domain (level-2).
                              Max value depend if metric support narrow or wide value (see command :ref:`metric-style`).

.. index:: {Interface Command} {isis network point-to-point} {}

{Interface Command} {isis network point-to-point} {}
.. index:: {Interface Command} {no isis network point-to-point} {}

{Interface Command} {no isis network point-to-point} {}
                                Set network type to 'Point-to-Point' (broadcast by default).

.. index:: {Interface Command} {isis passive} {}

{Interface Command} {isis passive} {}
.. index:: {Interface Command} {no isis passive} {}

{Interface Command} {no isis passive} {}
                                  Configure the passive mode for this interface.

.. index:: {Interface Command} {isis password [clear | md5] <password>} {}

{Interface Command} {isis password [clear | md5] <password>} {}
.. index:: {Interface Command} {no isis password} {}

{Interface Command} {no isis password} {}
                                    Configure the authentication password (clear or encoded text) for the interface.

.. index:: {Interface Command} {isis priority (0-127)} {}

{Interface Command} {isis priority (0-127)} {}
.. index:: {Interface Command} {isis priority (0-127) [level-1 | level-2]} {}

{Interface Command} {isis priority (0-127) [level-1 | level-2]} {}
.. index:: {Interface Command} {no isis priority} {}

{Interface Command} {no isis priority} {}
.. index:: {Interface Command} {no isis priority [level-1 | level-2]} {}

{Interface Command} {no isis priority [level-1 | level-2]} {}
                                          Set priority for Designated Router election, globally, for the area (level-1)
                                          or the domain (level-2).

.. index:: {Interface Command} {isis psnp-interval (1-120)} {}

{Interface Command} {isis psnp-interval (1-120)} {}
.. index:: {Interface Command} {isis psnp-interval (1-120) [level-1 | level-2]} {}

{Interface Command} {isis psnp-interval (1-120) [level-1 | level-2]} {}
.. index:: {Interface Command} {no isis psnp-interval} {}

{Interface Command} {no isis psnp-interval} {}
.. index:: {Interface Command} {no isis psnp-interval [level-1 | level-2]} {}

{Interface Command} {no isis psnp-interval [level-1 | level-2]} {}
                                                Set PSNP interval in seconds globally, for an area (level-1) or a domain (level-2).

.. _Showing_ISIS_information:

Showing ISIS information
========================

.. index:: {Command} {show isis summary} {}

{Command} {show isis summary} {}
  Show summary information about ISIS.

.. index:: {Command} {show isis hostname} {}

{Command} {show isis hostname} {}
  Show information about ISIS node.

.. index:: {Command} {show isis interface} {}

{Command} {show isis interface} {}
.. index:: {Command} {show isis interface detail} {}

{Command} {show isis interface detail} {}
.. index:: {Command} {show isis interface <interface name>} {}

{Command} {show isis interface <interface name>} {}
      Show state and configuration of ISIS specified interface, or all
      interfaces if no interface is given with or without details.

.. index:: {Command} {show isis neighbor} {}

{Command} {show isis neighbor} {}
.. index:: {Command} {show isis neighbor <System Id>} {}

{Command} {show isis neighbor <System Id>} {}
.. index:: {Command} {show isis neighbor detail} {}

{Command} {show isis neighbor detail} {}
          Show state and information of ISIS specified neighbor, or all
          neighbors if no system id is given with or without details.

.. index:: {Command} {show isis database} {}

{Command} {show isis database} {}
.. index:: {Command} {show isis database [detail]} {}

{Command} {show isis database [detail]} {}
.. index:: {Command} {show isis database <LSP id> [detail]} {}

{Command} {show isis database <LSP id> [detail]} {}
.. index:: {Command} {show isis database detail <LSP id>} {}

{Command} {show isis database detail <LSP id>} {}
                Show the ISIS database globally, for a specific LSP id without or with details.

.. index:: {Command} {show isis topology} {}

{Command} {show isis topology} {}
.. index:: {Command} {show isis topology [level-1|level-2]} {}

{Command} {show isis topology [level-1|level-2]} {}
                  Show topology IS-IS paths to Intermediate Systems, globally,
                  in area (level-1) or domain (level-2).

.. index:: {Command} {show ip route isis} {}

{Command} {show ip route isis} {}
                  Show the ISIS routing table, as determined by the most recent SPF calculation.

.. _Traffic_Engineering:

Traffic Engineering
===================

.. index:: {ISIS Command} {mpls-te on} {}

{ISIS Command} {mpls-te on} {}
.. index:: {ISIS Command} {no mpls-te} {}

{ISIS Command} {no mpls-te} {}
    Enable Traffic Engineering LSP flooding.

.. index:: {ISIS Command} {mpls-te router-address <A.B.C.D>} {}

{ISIS Command} {mpls-te router-address <A.B.C.D>} {}
.. index:: {ISIS Command} {no mpls-te router-address} {}

{ISIS Command} {no mpls-te router-address} {}
      Configure stable IP address for MPLS-TE.

.. index:: {Command} {show isis mpls-te interface} {}

{Command} {show isis mpls-te interface} {}
.. index:: {Command} {show isis mpls-te interface `interface`} {}

{Command} {show isis mpls-te interface `interface`} {}
        Show MPLS Traffic Engineering parameters for all or specified interface.

.. index:: {Command} {show isis mpls-te router} {}

{Command} {show isis mpls-te router} {}
        Show Traffic Engineering router parameters.

.. _Debugging_ISIS:

Debugging ISIS
==============

.. index:: {Command} {debug isis adj-packets} {}

{Command} {debug isis adj-packets} {}
.. index:: {Command} {no debug isis adj-packets} {}

{Command} {no debug isis adj-packets} {}
    IS-IS Adjacency related packets.

.. index:: {Command} {debug isis checksum-errors} {}

{Command} {debug isis checksum-errors} {}
.. index:: {Command} {no debug isis checksum-errors} {}

{Command} {no debug isis checksum-errors} {}
      IS-IS LSP checksum errors.

.. index:: {Command} {debug isis events} {}

{Command} {debug isis events} {}
.. index:: {Command} {no debug isis events} {}

{Command} {no debug isis events} {}
        IS-IS Events.

.. index:: {Command} {debug isis local-updates} {}

{Command} {debug isis local-updates} {}
.. index:: {Command} {no debug isis local-updates} {}

{Command} {no debug isis local-updates} {}
          IS-IS local update packets.

.. index:: {Command} {debug isis packet-dump} {}

{Command} {debug isis packet-dump} {}
.. index:: {Command} {no debug isis packet-dump} {}

{Command} {no debug isis packet-dump} {}
            IS-IS packet dump.

.. index:: {Command} {debug isis protocol-errors} {}

{Command} {debug isis protocol-errors} {}
.. index:: {Command} {no debug isis protocol-errors} {}

{Command} {no debug isis protocol-errors} {}
              IS-IS LSP protocol errors.

.. index:: {Command} {debug isis route-events} {}

{Command} {debug isis route-events} {}
.. index:: {Command} {no debug isis route-events} {}

{Command} {no debug isis route-events} {}
                IS-IS Route related events.

.. index:: {Command} {debug isis snp-packets} {}

{Command} {debug isis snp-packets} {}
.. index:: {Command} {no debug isis snp-packets} {}

{Command} {no debug isis snp-packets} {}
                  IS-IS CSNP/PSNP packets.

.. index:: {Command} {debug isis spf-events} {}

{Command} {debug isis spf-events} {}
.. index:: {Command} {debug isis spf-statistics} {}

{Command} {debug isis spf-statistics} {}
.. index:: {Command} {debug isis spf-triggers} {}

{Command} {debug isis spf-triggers} {}
.. index:: {Command} {no debug isis spf-events} {}

{Command} {no debug isis spf-events} {}
.. index:: {Command} {no debug isis spf-statistics} {}

{Command} {no debug isis spf-statistics} {}
.. index:: {Command} {no debug isis spf-triggers} {}

{Command} {no debug isis spf-triggers} {}
                            IS-IS Shortest Path First Events, Timing and Statistic Data
                            and triggering events.

.. index:: {Command} {debug isis update-packets} {}

{Command} {debug isis update-packets} {}
.. index:: {Command} {no debug isis update-packets} {}

{Command} {no debug isis update-packets} {}
                              Update related packets.

.. index:: {Command} {show debugging isis} {}

{Command} {show debugging isis} {}
                              Print which ISIS debug level is activate.

ISIS Configuration Examples
===========================

A simple example, with MD5 authentication enabled:

::

  !
  interface eth0
   ip router isis FOO
   isis network point-to-point
   isis circuit-type level-2-only
  !
  router isis FOO
  net 47.0023.0000.0000.0000.0000.0000.0000.1900.0004.00
   metric-style wide
   is-type level-2-only


A Traffic Engineering configuration, with Inter-ASv2 support.

- First, the 'zebra.conf' part:

::

  hostname HOSTNAME
  password PASSWORD
  log file /var/log/zebra.log
  !
  interface eth0
   ip address 10.2.2.2/24
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
   ip address 10.1.1.1/24
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
   mpls-te neighbor 10.1.1.2 as 65000


- Then the 'isisd.conf' itself:

::

  hostname HOSTNAME
  password PASSWORD
  log file /var/log/isisd.log
  !
  !
  interface eth0
   ip router isis FOO
  !
  interface eth1
   ip router isis FOO
  !
  !
  router isis FOO
   isis net 47.0023.0000.0000.0000.0000.0000.0000.1900.0004.00
    mpls-te on
    mpls-te router-address 10.1.1.1
  !
  line vty


