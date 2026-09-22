.. _prefix-origin-validation-using-rpki:

Prefix Origin Validation Using RPKI
===================================

Prefix Origin Validation allows BGP routers to verify if the origin AS of an IP
prefix is legitimate to announce this IP prefix. The required attestation
objects are stored in the Resource Public Key Infrastructure (:abbr:`RPKI`).
However, RPKI-enabled routers do not store cryptographic data itself but only
validation information. The validation of the cryptographic data (so called
Route Origin Authorization, or short :abbr:`ROA`, objects) will be performed by
trusted cache servers. The RPKI/RTR protocol defines a standard mechanism to
maintain the exchange of the prefix/origin AS mapping between the cache server
and routers. In combination with a  BGP Prefix Origin Validation scheme a
router is able to verify received BGP updates without suffering from
cryptographic complexity.

The RPKI/RTR protocol is defined in :rfc:`6810` and the validation scheme in
:rfc:`6811`. The current version of Prefix Origin Validation in FRR implements
both RFCs.

For a more detailed but still easy-to-read background, we suggest:

- [Securing-BGP]_
- [Resource-Certification]_

.. _features-of-the-current-implementation:

Features of the Current Implementation
--------------------------------------

In a nutshell, the current implementation provides the following features

- The BGP router can connect to one or more RPKI cache servers to receive
  validated prefix to origin AS mappings. Advanced failover can be implemented
  by server sockets with different preference values.
- If no connection to an RPKI cache server can be established after a
  pre-defined timeout, the router will process routes without prefix origin
  validation. It still will try to establish a connection to an RPKI cache
  server in the background.
- By default, enabling RPKI does not change best path selection. In particular,
  invalid prefixes will still be considered during best path selection.
  However, the router can be configured to ignore all invalid prefixes.
- Route maps can be configured to match a specific RPKI validation state. This
  allows the creation of local policies, which handle BGP routes based on the
  outcome of the Prefix Origin Validation.
- Updates from the RPKI cache servers are directly applied and path selection
  is updated accordingly. (Soft reconfiguration **must** be enabled for this
  to work).


.. _enabling-rpki:

Enabling RPKI
-------------

You must install ``frr-rpki-rtrlib`` additional package for RPKI support,
otherwise ``bgpd`` daemon won't startup.

.. clicmd:: rpki

   This command enables the RPKI configuration mode. Most commands that start
   with *rpki* can only be used in this mode.

   This command is available either in *configure node* for default *vrf* or
   in *vrf node* for specific *vrf*. When it is used in a telnet session,
   leaving of this mode cause rpki to be initialized.

   Executing this command alone does not activate prefix validation. You need
   to configure at least one reachable cache server. See section
   :ref:`configuring-rpki-rtr-cache-servers` for configuring a cache server.

Remember to add ``-M rpki`` to the variable ``bgpd_options`` in
:file:`/etc/frr/daemons` , like so::

   bgpd_options="   -A 127.0.0.1 -M rpki"

instead of the default setting::

   bgpd_options="   -A 127.0.0.1"

Otherwise you will encounter an error when trying to enter RPKI
configuration mode due to the ``rpki`` module not being loaded when the BGP
daemon is initialized.

Examples of the error::

   router(config)# debug rpki
   % [BGP] Unknown command: debug rpki

   router(config)# rpki
   % [BGP] Unknown command: rpki

   router(config-vrf)# rpki
   % [BGP] Unknown command: rpki

Note that the RPKI commands will be available in vtysh when running
``find rpki`` regardless of whether the module is loaded.

.. _configuring-rpki-rtr-cache-servers:

Configuring RPKI/RTR Cache Servers
----------------------------------

RPKI/RTR can be configured independently, either in configure node, or in *vrf*
sub context. If configured in configure node, the core *bgp* instance of default
*vrf* is impacted by the configuration.

Each RPKI/RTR context is mapped to a *vrf* and can be made up of a specific list
of cache-servers, and specific settings.

The following commands are available for independent of a specific cache server.

.. clicmd:: rpki polling_period (1-3600)

   Set the number of seconds the router waits until the router asks the cache
   again for updated data.

   The default value is 300 seconds.

.. clicmd:: rpki expire_interval (600-172800)

   Set the number of seconds the router waits until the router expires the cache.

   The default value is 7200 seconds.

.. clicmd:: rpki retry_interval (1-7200)

   Set the number of seconds the router waits until retrying to connect to the
   cache server.

   The default value is 600 seconds.

.. clicmd:: rpki cache tcp HOST PORT [source A.B.C.D] preference (1-255)

   Add a TCP cache server to the socket.

.. clicmd:: rpki cache ssh HOST PORT SSH_USERNAME SSH_PRIVKEY_PATH [KNOWN_HOSTS_PATH] [source A.B.C.D] preference (1-255)

   Add a SSH cache server to the socket.

   SSH_USERNAME
      SSH username to establish an SSH connection to the cache server.

   SSH_PRIVKEY_PATH
      Local path that includes the private key file of the router.

   KNOWN_HOSTS_PATH
      Local path that includes the known hosts file. The default value depends
      on the configuration of the operating system environment, usually
      :file:`~/.ssh/known_hosts`.

   source A.B.C.D
      Source address of the RPKI connection to access cache server.

.. _configuring-rpki-neighbors:

Configuring RPKI neighbors
--------------------------

.. clicmd:: neighbor PEER rpki strict

   Enable RPKI strict mode for the specified neighbor. If strict mode is enabled,
   the router will not establish a BGP session with the neighbor until the RPKI cache
   server is connected.

   Default: disabled.

.. _validating-bgp-updates:

Validating BGP Updates
----------------------

.. clicmd:: match rpki notfound|invalid|valid


    Create a clause for a route map to match prefixes with the specified RPKI
    state.

    In the following example, the router prefers valid routes over invalid
    prefixes because invalid routes have a lower local preference.

    .. code-block:: frr

       ! Allow for invalid routes in route selection process
       route bgp 65001
       !
       ! Set local preference of invalid prefixes to 10
       route-map rpki permit 10
        match rpki invalid
        set local-preference 10
       !
       ! Set local preference of valid prefixes to 500
       route-map rpki permit 500
        match rpki valid
        set local-preference 500

.. clicmd:: match rpki-extcommunity notfound|invalid|valid

   Create a clause for a route map to match prefixes with the specified RPKI
   state, that is derived from the Origin Validation State extended community
   attribute (OVS). OVS extended community is non-transitive and is exchanged
   only between iBGP peers.

.. _debugging:

Debugging
---------

.. clicmd:: debug rpki


   Enable or disable debugging output for RPKI.

.. _displaying-rpki:

Displaying RPKI
---------------

.. clicmd:: show rpki configuration [vrf NAME] [json]

   Display RPKI configuration state including timers values.

.. clicmd:: show rpki prefix <A.B.C.D/M|X:X::X:X/M> [ASN] [vrf NAME] [json]

   Display validated prefixes received from the cache servers filtered
   by the specified prefix.  The AS number space has been increased
   to allow the choice of using AS 0 because RFC-7607 specifically
   calls out the usage of 0 in a special case.

.. clicmd:: show rpki as-number ASN [vrf NAME] [json]

   Display validated prefixes received from the cache servers filtered
   by ASN.  The usage of AS 0 is allowed because RFC-76067 specifically
   calls out the usage of 0 in a special case.

.. clicmd:: show rpki prefix-table [vrf NAME] [json]

   Display all validated prefix to origin AS mappings/records which have been
   received from the cache servers and stored in the router. Based on this data,
   the router validates BGP Updates.

.. clicmd:: show rpki cache-server [vrf NAME] [json]

   Display all configured cache servers, whether active or not.

.. clicmd:: show rpki cache-connection [vrf NAME] [json]

   Display all cache connections, and show which is connected or not.

.. clicmd:: show bgp [vrf NAME] [afi] [safi] <A.B.C.D|A.B.C.D/M|X:X::X:X|X:X::X:X/M> rpki <valid|invalid|notfound>

   Display for the specified prefix or address the bgp paths that match the given rpki state.

.. clicmd:: show bgp [vrf NAME] [afi] [safi] rpki <valid|invalid|notfound>

   Display all prefixes that match the given rpki state.

RPKI Configuration Example
--------------------------

.. code-block:: frr

   hostname bgpd1
   password zebra
   ! log stdout
   debug bgp updates
   debug bgp keepalives
   debug rpki
   !
   vrf VRF1
    rpki
     rpki polling_period 1000
     rpki timeout 10
      ! SSH Example:
      rpki cache ssh example.com 22 rtr-ssh ./ssh_key/id_rsa preference 1
      ! TCP Example:
      rpki cache tcp rpki-validator.realmv6.org 8282 preference 2
      exit
    !
    exit-vrf
   !
   rpki
    rpki polling_period 1000
    rpki timeout 10
     ! SSH Example:
     rpki cache ssh example.com source 198.51.100.223 22 rtr-ssh ./ssh_key/id_rsa preference 1
     ! TCP Example:
     rpki cache tcp rpki-validator.realmv6.org 8282 preference 2
     exit
   !
   router bgp 65001
    bgp router-id 198.51.100.223
    neighbor 203.0.113.1 remote-as 65002
    neighbor 203.0.113.1 update-source 198.51.100.223
    address-family ipv4
     network 192.0.2.0/24
     neighbor 203.0.113.1 route-map rpki in
    exit-address-family
   !
    address-family ipv6
     neighbor 203.0.113.1 activate
     neighbor 203.0.113.1 route-map rpki in
    exit-address-family
   !
   router bgp 65001 vrf VRF1
    bgp router-id 198.51.100.223
    neighbor 203.0.113.1 remote-as 65002
    address-family ipv4
     network 192.0.2.0/24
     neighbor 203.0.113.1 route-map rpki in
    exit-address-family
   !
    address-family ipv6
     neighbor 203.0.113.1 activate
     neighbor 203.0.113.1 route-map rpki in
    exit-address-family
   !
   route-map rpki permit 10
    match rpki invalid
    set local-preference 10
   !
   route-map rpki permit 20
    match rpki notfound
    set local-preference 20
   !
   route-map rpki permit 30
    match rpki valid
    set local-preference 30
   !
   route-map rpki permit 40
   !

.. _aspa:

ASPA AS_PATH Verification
=========================

ASPA (Autonomous System Provider Authorization) verifies that every hop in a
received ``AS_PATH`` is consistent with the customer-to-provider relationships
published in the RPKI. ASPA records arrive over the same RTR sessions as ROAs
and require RTR protocol version 2, so no extra cache configuration is needed
beyond :ref:`configuring-rpki-rtr-cache-servers`.

ASPA support is a build-time capability: it is present only when FRR was built
against a version of librtr that provides ASPA. ``configure`` reports this as
``checking whether the RTR Library supports ASPA``. On a build without it,
``match aspa`` is still accepted by the parser but never matches.

Verification Direction
----------------------

ASPA defines two verification algorithms, and which one applies depends on the
business relationship with the neighbor the route was received from:

``upstream``
   For routes received from a customer, a lateral peer, or an RS-client. The
   whole ``AS_PATH`` must form a customer-to-provider chain.

``downstream``
   For routes received from a provider or a route server. The ``AS_PATH`` may
   rise to an apex and descend again, which is a strictly weaker test.

The same ``AS_PATH`` can therefore be invalid upstream and valid downstream.

FRR takes the direction from the route-map rather than deriving it from
:clicmd:`neighbor PEER local-role ROLE`. The two features are deliberately
independent: configuring ``local-role`` also enables RFC 9234 Only-To-Customer
route-leak handling and advertises the Role capability, which operators
adopting ASPA may not want. State the direction explicitly instead, and attach
the route-map to the matching session.

.. clicmd:: match aspa <upstream|downstream> <valid|invalid|unknown>

   Match the ASPA verification state of the route's ``AS_PATH``, evaluated in
   the given direction.

.. note::

   ASPA records arriving from a cache server only re-evaluate routes that were
   already received if the peer has ``soft-reconfiguration inbound`` enabled,
   because revalidation replays the Adj-RIB-In. The same requirement already
   applies to ROA updates.

.. clicmd:: show rpki aspa [ASNUM] [vrf NAME] [json]

   Display the validated ASPA records received from the cache servers, sorted
   by customer AS, optionally for a single customer AS only.

.. code-block:: frr

   router# show rpki aspa
   Customer ASN   Provider ASNs
   64500          64496, 64497
   64501          64496

The per-prefix detail view reports both directions, because outside a
route-map there is no direction to choose:

.. code-block:: frr

   router# show bgp ipv4 unicast 192.0.2.0/24
   BGP routing table entry for 192.0.2.0/24, version 4
   Paths: (1 available, best #1, table default)
     65001 65004
       10.0.0.1 from 10.0.0.1 (10.0.0.1)
         Origin IGP, valid, external, best (First path received), rpki validation-state: not found, aspa (upstream: invalid, downstream: valid)

ASPA Configuration Example
--------------------------

.. code-block:: frr

   router bgp 65001
    neighbor 192.0.2.1 remote-as 65002
    neighbor 203.0.113.1 remote-as 65100
    address-family ipv4 unicast
     neighbor 192.0.2.1 soft-reconfiguration inbound
     neighbor 192.0.2.1 route-map FROM-CUSTOMER in
     neighbor 203.0.113.1 soft-reconfiguration inbound
     neighbor 203.0.113.1 route-map FROM-TRANSIT in
    exit-address-family
   !
   rpki
    rpki cache tcp 10.0.0.10 3323 preference 1
   exit
   !
   ! A customer must send us a complete customer-to-provider chain.
   route-map FROM-CUSTOMER deny 10
    match aspa upstream invalid
   !
   route-map FROM-CUSTOMER permit 20
   !
   ! A transit provider may legitimately send valley paths, so the same
   ! AS_PATH is checked downstream instead.
   route-map FROM-TRANSIT permit 10
    match aspa downstream invalid
    set local-preference 50
   !
   route-map FROM-TRANSIT permit 20
   !

.. [Securing-BGP] Geoff Huston, Randy Bush: Securing BGP, In: The Internet Protocol Journal, Volume 14, No. 2, 2011. <https://www.cisco.com/c/dam/en_us/about/ac123/ac147/archived_issues/ipj_14-2/ipj_14-2.pdf>
.. [Resource-Certification] Geoff Huston: Resource Certification, In: The Internet Protocol Journal, Volume 12, No.1, 2009. <https://www.cisco.com/c/dam/en_us/about/ac123/ac147/archived_issues/ipj_12-1/ipj_12-1.pdf>
