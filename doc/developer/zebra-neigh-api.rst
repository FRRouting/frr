.. _zebra_neighbor_api:

Zebra Neighbor API
==================

Introduction
------------

The Zebra Neighbor API provides client daemons with the ability to track IPv4
and IPv6 neighbor (ARP/NDP) state changes from the Linux kernel. Zebra monitors
neighbor state changes via netlink and redistributes this information to
subscribed client daemons through ZAPI messages.

Architecture
------------

Communication Model
^^^^^^^^^^^^^^^^^^^

Zebra acts as a relay between the Linux kernel and client daemons. The architecture
follows a registration-based publish-subscribe model:

::

   ┌─────────────────────────────────────────────────────┐
   │              Linux Kernel (Netlink)                 │
   │         (Neighbor Discovery, ARP, ND)               │
   └────────────────────┬────────────────────────────────┘
                        │ RTM_NEWNEIGH/RTM_DELNEIGH
                        ↓
   ┌─────────────────────────────────────────────────────┐
   │                    Zebra                            │
   │  ┌──────────────────────────────────────────────┐  │
   │  │  Netlink Neighbor Event Handler              │  │
   │  └─────────────┬────────────────────────────────┘  │
   │                ↓                                    │
   │  ┌──────────────────────────────────────────────┐  │
   │  │  Client Registration Manager                 │  │
   │  │  (Tracks subscribed daemons per AFI)         │  │
   │  └─────────────┬────────────────────────────────┘  │
   └────────────────┼────────────────────────────────────┘
                    │ ZAPI Messages
                    │ (ZEBRA_NEIGH_ADDED/REMOVED)
                    ↓
   ┌────────────────────────────────────────────────────┐
   │          Client Daemons (via zclient)              │
   │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
   │  │ staticd  │  │   bgpd   │  │   ...    │        │
   │  │          │  │          │  │          │        │
   │  └──────────┘  └──────────┘  └──────────┘        │
   └────────────────────────────────────────────────────┘

Key Properties
^^^^^^^^^^^^^^

The neighbor API provides the following guarantees and properties:

- **Registration-Based**: Client daemons must explicitly subscribe to receive
  neighbor notifications via :c:func:`zclient_register_neigh()`

- **Per-AFI Subscriptions**: IPv4 (``AFI_IP``) and IPv6 (``AFI_IP6``) neighbors
  are tracked separately. Clients must register for each address family independently

- **VRF-Aware**: All neighbor operations are scoped to a specific VRF

- **Push + Pull Model**:

  - *Push*: Zebra automatically sends notifications when neighbor state changes
  - *Pull*: Clients can explicitly request current neighbors via
    :c:func:`zclient_neigh_get()`

- **Asynchronous**: Neighbor queries and responses are non-blocking

Message Flow
^^^^^^^^^^^^

The following diagram illustrates the typical message exchange between a client
daemon and zebra:

::

       Client Daemon                  Zebra               Linux Kernel
            |                           |                      |
            |    Register (AFI_IP6)     |                      |        \
            |-------------------------->|                      |         |
            |                           |                      |      Register
            |    Request Neighbors      |                      |       Phase
            |-------------------------->|                      |         |
            |                           |                      |        /
            |                           |                      |
            |  ZEBRA_NEIGH_ADDED (N1)   |  (from cache)        |        \
            |<--------------------------|                      |         |
            |  ZEBRA_NEIGH_ADDED (N2)   |                      |    Initial
            |<--------------------------|                      |      Sync
            |           ...             |                      |       Phase
            |  ZEBRA_NEIGH_ADDED (Nn)   |                      |         |
            |<--------------------------|                      |         |
            |                           |                      |        /
            :                           :                      :
            :                           :                      :
            |                           |  RTM_NEWNEIGH        |        \
            |                           |<---------------------|         |
            |  ZEBRA_NEIGH_ADDED        |                      |      Update
            |<--------------------------|                      |       Phase
            |                           |                      |         |
            |                           |  RTM_DELNEIGH        |         |
            |  ZEBRA_NEIGH_REMOVED      |<---------------------|         |
            |<--------------------------|                      |        /
            :                           :                      :
            |                           |                      |
            |    Unregister (AFI_IP6)   |                      |        \
            |-------------------------->|                      |    Unregister
            |                           |                      |       Phase
            |                           |  RTM_NEWNEIGH        |         |
            |                           |<---------------------|         |
            |                (no forward)                      |        /
            |                           |                      |

Registration API
----------------

.. c:function:: int zclient_register_neigh(struct zclient *zclient, vrf_id_t vrf_id, afi_t afi, bool reg)

   Register or unregister a client daemon to receive neighbor state change
   notifications from zebra.

   :param zclient: Pointer to the client's zclient structure
   :param vrf_id: VRF identifier (use ``VRF_DEFAULT`` for default VRF)
   :param afi: Address family - ``AFI_IP`` (IPv4) or ``AFI_IP6`` (IPv6)
   :param reg: ``true`` to register, ``false`` to unregister
   :return: 0 on success, negative value on error

   Usage example::

      // Register for IPv6 neighbor notifications
      int ret = zclient_register_neigh(zclient, VRF_DEFAULT, AFI_IP6, true);
      if (ret < 0) {
          zlog_err("Failed to register for IPv6 neighbor notifications");
          return;
      }

      // Unregister when done
      zclient_register_neigh(zclient, VRF_DEFAULT, AFI_IP6, false);

Query and Discovery APIs
------------------------

Neighbor Query API
^^^^^^^^^^^^^^^^^^

.. c:function:: void zclient_neigh_get(struct zclient *zclient, struct interface *ifp, afi_t afi)

   Query zebra for all neighbors on a specific interface and address family.
   This retrieves neighbor information from zebra's cache.

   :param zclient: Pointer to the client's zclient structure
   :param ifp: Pointer to the interface structure
   :param afi: Address family - ``AFI_IP`` or ``AFI_IP6``

   This function sends a request to zebra to retrieve all neighbors associated
   with the specified interface. Zebra responds with neighbor information from
   its cache via asynchronous ``ZEBRA_NEIGH_ADDED`` messages.

   Usage example::

      void get_neighbors_for_interface(struct interface *ifp)
      {
          zlog_debug("Querying IPv6 neighbors for interface %s",
                     ifp->name);

          // Query zebra's neighbor cache
          zclient_neigh_get(zclient, ifp, AFI_IP6);

          // Zebra will send ZEBRA_NEIGH_ADDED messages
          // for each neighbor in its cache
      }

Neighbor Discovery Request API
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. c:function:: void zclient_send_neigh_discovery_req(struct zclient *zclient, const struct interface *ifp, afi_t afi)

   Request zebra to send a Neighbor Discovery probe on the network interface.
   This triggers active neighbor verification at the network level.

   :param zclient: Pointer to the client's zclient structure
   :param ifp: Pointer to the interface structure
   :param afi: Address family - ``AFI_IP`` or ``AFI_IP6``

   This function asks zebra to transmit a Neighbor Discovery message (ICMPv6 NS
   for IPv6, ARP for IPv4) on the specified interface to actively probe for
   neighbors. If a neighbor responds:

   1. The kernel receives the response and updates its neighbor table
   2. The kernel notifies zebra via netlink
   3. Zebra forwards the notification to subscribed daemons via ``ZEBRA_NEIGH_ADDED``

   Usage example::

      void trigger_neighbor_discovery(struct interface *ifp)
      {
          zlog_debug("Triggering neighbor discovery on interface %s",
                     ifp->name);

          // Send ND probe on the network
          zclient_send_neigh_discovery_req(zclient, ifp, AFI_IP6);

          // If neighbors respond, kernel will notify zebra
          // and zebra will send ZEBRA_NEIGH_ADDED messages
      }

   .. note::

      - This sends actual network packets (ICMPv6 NS or ARP)
      - Responses come asynchronously via kernel → zebra → daemon
      - Multiple neighbors may respond to a single discovery request
      - No guarantee of response if no neighbors exist

Notification Messages
---------------------

Message Types
^^^^^^^^^^^^^

Zebra sends neighbor notifications via ZAPI messages. Client daemons must
register handlers for the following message types:

.. c:macro:: ZEBRA_NEIGH_ADDED

   Sent when a neighbor is added or its state changes. This includes:

   - New neighbor discovered by kernel
   - Existing neighbor state updated (e.g., STALE → REACHABLE)
   - Neighbor revalidated after probe

.. c:macro:: ZEBRA_NEIGH_REMOVED

   Sent when a neighbor is deleted or aged out from the kernel neighbor table.
