Operational Data, RPCs and Notifications
========================================

.. contents:: Table of contents
    :local:
    :backlinks: entry
    :depth: 1

Operational data
~~~~~~~~~~~~~~~~

Writing API-agnostic code for YANG-modeled operational data is
challenging. ConfD and Sysrepo, for instance, have completely different
APIs to fetch operational data. So how can we write API-agnostic
callbacks that can be used by both the ConfD and Sysrepo plugins, and
any other northbound client that might be written in the future?

As an additional requirement, the callbacks must be designed in a way
that makes in-place XPath filtering possible. As an example, a
management client might want to retrieve only a subset of a large YANG
list (e.g. a BGP table), and for optimal performance it should be
possible to filter out the unwanted elements locally in the managed
devices instead of returning all elements and performing the filtering
on the management application.

To meet all these requirements, the four callbacks below were introduced
in the northbound architecture:

.. code:: c

           /*
            * Operational data callback.
            *
            * The callback function should return the value of a specific leaf or
            * inform if a typeless value (presence containers or leafs of type
            * empty) exists or not.
            *
            * xpath
            *    YANG data path of the data we want to get
            *
            * list_entry
            *    pointer to list entry
            *
            * Returns:
            *    pointer to newly created yang_data structure, or NULL to indicate
            *    the absence of data
            */
           struct yang_data *(*get_elem)(const char *xpath, void *list_entry);

           /*
            * Operational data callback for YANG lists.
            *
            * The callback function should return the next entry in the list. The
            * 'list_entry' parameter will be NULL on the first invocation.
            *
            * list_entry
            *    pointer to a list entry
            *
            * Returns:
            *    pointer to the next entry in the list, or NULL to signal that the
            *    end of the list was reached
            */
           void *(*get_next)(void *list_entry);

           /*
            * Operational data callback for YANG lists.
            *
            * The callback function should fill the 'keys' parameter based on the
            * given list_entry.
            *
            * list_entry
            *    pointer to a list entry
            *
            * keys
            *    structure to be filled based on the attributes of the provided
            *    list entry
            *
            * Returns:
            *    NB_OK on success, NB_ERR otherwise
            */
           int (*get_keys)(void *list_entry, struct yang_list_keys *keys);

           /*
            * Operational data callback for YANG lists.
            *
            * The callback function should return a list entry based on the list
            * keys given as a parameter.
            *
            * keys
            *    structure containing the keys of the list entry
            *
            * Returns:
            *    a pointer to the list entry if found, or NULL if not found
            */
           void *(*lookup_entry)(struct yang_list_keys *keys);

These callbacks were designed to provide maximum flexibility, and borrow
a lot of ideas from the ConfD API. Each callback does one and only one
task, they are indivisible primitives that can be combined in several
different ways to iterate over operational data. The extra flexibility
certainly has a performance cost, but it’s the price to pay if we want
to expose FRR operational data using several different management
interfaces (e.g. NETCONF via either ConfD or Sysrepo+Netopeer2). In the
future it might be possible to introduce optional callbacks that do
things like returning multiple objects at once. They would provide
enhanced performance when iterating over large lists, but their use
would be limited by the northbound plugins that can be integrated with
them.

   NOTE: using the northbound callbacks as a base, the ConfD plugin can
   provide up to 100 objects between each round trip between FRR and the
   *confd* daemon. Preliminary tests showed FRR taking ~7 seconds
   (asynchronously, without blocking the main pthread) to return a RIP
   table containing 100k routes to a NETCONF client connected to *confd*
   (JSON was used as the encoding format). Work needs to be done to find
   the bottlenecks and optimize this operation.

The [[Plugins - Writing Your Own]] page explains how the northbound
plugins can fetch operational data using the aforementioned northbound
callbacks, and how in-place XPath filtering can be implemented.

Example
^^^^^^^

Now let’s move to an example to show how these callbacks are implemented
in practice. The following YANG container is part of the *ietf-rip*
module and contains operational data about RIP neighbors:

.. code:: yang

         container neighbors {
           description
             "Neighbor information.";
           list neighbor {
             key "address";
             description
               "A RIP neighbor.";
             leaf address {
               type inet:ipv4-address;
               description
                 "IP address that a RIP neighbor is using as its
                  source address.";
             }
             leaf last-update {
               type yang:date-and-time;
               description
                 "The time when the most recent RIP update was
                  received from this neighbor.";
             }
             leaf bad-packets-rcvd {
               type yang:counter32;
               description
                 "The number of RIP invalid packets received from
                  this neighbor which were subsequently discarded
                  for any reason (e.g. a version 0 packet, or an
                  unknown command type).";
             }
             leaf bad-routes-rcvd {
               type yang:counter32;
               description
                 "The number of routes received from this neighbor,
                  in valid RIP packets, which were ignored for any
                  reason (e.g. unknown address family, or invalid
                  metric).";
             }
           }
         }

We know that this is operational data because the ``neighbors``
container is within the ``state`` container, which has the
``config false;`` property (which is applied recursively).

As expected, the ``gen_northbound_callbacks`` tool also generates
skeleton callbacks for nodes that represent operational data:

.. code:: c

                   {
                           .xpath = "/frr-ripd:ripd/state/neighbors/neighbor",
                           .cbs.get_next = ripd_state_neighbors_neighbor_get_next,
                           .cbs.get_keys = ripd_state_neighbors_neighbor_get_keys,
                           .cbs.lookup_entry = ripd_state_neighbors_neighbor_lookup_entry,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/neighbors/neighbor/address",
                           .cbs.get_elem = ripd_state_neighbors_neighbor_address_get_elem,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/neighbors/neighbor/last-update",
                           .cbs.get_elem = ripd_state_neighbors_neighbor_last_update_get_elem,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/neighbors/neighbor/bad-packets-rcvd",
                           .cbs.get_elem = ripd_state_neighbors_neighbor_bad_packets_rcvd_get_elem,
                   },
                   {
                           .xpath = "/frr-ripd:ripd/state/neighbors/neighbor/bad-routes-rcvd",
                           .cbs.get_elem = ripd_state_neighbors_neighbor_bad_routes_rcvd_get_elem,
                   },

The ``/frr-ripd:ripd/state/neighbors/neighbor`` list within the
``neighbors`` container has three different callbacks that need to be
implemented. Let’s start with the first one, the ``get_next`` callback:

.. code:: c

   static void *ripd_state_neighbors_neighbor_get_next(void *list_entry)
   {
           struct listnode *node;

           if (list_entry == NULL)
                   node = listhead(peer_list);
           else
                   node = listnextnode((struct listnode *)list_entry);

           return node;
   }

Given a list entry, the job of this callback is to find the next element
from the list. When the ``list_entry`` parameter is NULL, then the first
element of the list should be returned.

*ripd* uses the ``rip_peer`` structure to represent RIP neighbors, and
the ``peer_list`` global variable (linked list) is used to store all RIP
neighbors.

In order to be able to iterate over the list of RIP neighbors, the
callback returns a ``listnode`` variable instead of a ``rip_peer``
variable. The ``listnextnode`` macro can then be used to find the next
element from the linked list.

Now the second callback, ``get_keys``:

.. code:: c

   static int ripd_state_neighbors_neighbor_get_keys(void *list_entry,
                                                     struct yang_list_keys *keys)
   {
           struct listnode *node = list_entry;
           struct rip_peer *peer = listgetdata(node);

           keys->num = 1;
           (void)inet_ntop(AF_INET, &peer->addr, keys->key[0].value,
                           sizeof(keys->key[0].value));

           return NB_OK;
   }

This one is easy. First, we obtain the RIP neighbor from the
``listnode`` structure. Then, we fill the ``keys`` parameter according
to the attributes of the RIP neighbor. In this case, the ``neighbor``
YANG list has only one key: the neighbor IP address. We then use the
``inet_ntop()`` function to transform this binary IP address into a
string (the lingua franca of the FRR northbound).

The last callback for the ``neighbor`` YANG list is the ``lookup_entry``
callback:

.. code:: c

   static void *
   ripd_state_neighbors_neighbor_lookup_entry(struct yang_list_keys *keys)
   {
           struct in_addr address;

           yang_str2ipv4(keys->key[0].value, &address);

           return rip_peer_lookup(&address);
   }

This callback is the counterpart of the ``get_keys`` callback: given an
array of list keys, the associated list entry should be returned. The
``yang_str2ipv4()`` function is used to convert the list key (an IP
address) from a string to an ``in_addr`` structure. Then the
``rip_peer_lookup()`` function is used to find the list entry.

Finally, each YANG leaf inside the ``neighbor`` list has its associated
``get_elem`` callback:

.. code:: c

   /*
    * XPath: /frr-ripd:ripd/state/neighbors/neighbor/address
    */
   static struct yang_data *
   ripd_state_neighbors_neighbor_address_get_elem(const char *xpath,
                                                  void *list_entry)
   {
           struct rip_peer *peer = list_entry;

           return yang_data_new_ipv4(xpath, &peer->addr);
   }

   /*
    * XPath: /frr-ripd:ripd/state/neighbors/neighbor/last-update
    */
   static struct yang_data *
   ripd_state_neighbors_neighbor_last_update_get_elem(const char *xpath,
                                                      void *list_entry)
   {
           /* TODO: yang:date-and-time is tricky */
           return NULL;
   }

   /*
    * XPath: /frr-ripd:ripd/state/neighbors/neighbor/bad-packets-rcvd
    */
   static struct yang_data *
   ripd_state_neighbors_neighbor_bad_packets_rcvd_get_elem(const char *xpath,
                                                           void *list_entry)
   {
           struct rip_peer *peer = list_entry;

           return yang_data_new_uint32(xpath, peer->recv_badpackets);
   }

   /*
    * XPath: /frr-ripd:ripd/state/neighbors/neighbor/bad-routes-rcvd
    */
   static struct yang_data *
   ripd_state_neighbors_neighbor_bad_routes_rcvd_get_elem(const char *xpath,
                                                          void *list_entry)
   {
           struct rip_peer *peer = list_entry;

           return yang_data_new_uint32(xpath, peer->recv_badroutes);
   }

These callbacks receive the list entry as parameter and return the
corresponding data using the ``yang_data_new_*()`` wrapper functions.
Not much to explain here.

Iterating over operational data without blocking the main pthread
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

One of the problems we have in FRR is that some “show” commands in the
CLI can take too long, potentially long enough to the point of
triggering some protocol timeouts and bringing sessions down.

To avoid this kind of problem, northbound clients are encouraged to do
one of the following:

* Create a separate pthread for handling requests to fetch operational data.

* Iterate over YANG lists and leaf-lists asynchronously, returning a maximum
  number of elements per time instead of returning all elements in one shot.

In order to handle both cases correctly, the ``get_next`` callbacks need
to use locks to prevent the YANG lists from being modified while they
are being iterated over. If that is not done, the list entry returned by
this callback can become a dangling pointer when used in another
callback.

Currently the ConfD and Sysrepo plugins run only in the main pthread.
The plan in the short-term is to introduce a separate pthread only for
handling operational data, and use the main pthread only for handling
configuration changes, RPCs and notifications.

RPCs and Actions
~~~~~~~~~~~~~~~~

The FRR northbound supports YANG RPCs and Actions through the ``rpc()``
callback, which is documented as follows in the *lib/northbound.h* file:

.. code:: c

           /*
            * RPC and action callback.
            *
            * Both 'input' and 'output' are lists of 'yang_data' structures. The
            * callback should fetch all the input parameters from the 'input' list,
            * and add output parameters to the 'output' list if necessary.
            *
            * xpath
            *    xpath of the YANG RPC or action
            *
            * input
            *    read-only list of input parameters
            *
            * output
            *    list of output parameters to be populated by the callback
            *
            * Returns:
            *    NB_OK on success, NB_ERR otherwise
            */
           int (*rpc)(const char *xpath, const struct list *input,
                      struct list *output);

Note that the same callback is used for both RPCs and actions, which are
essentially the same thing. In the case of YANG actions, the ``xpath``
parameter can be consulted to find the data node associated to the
operation.

As part of the northbound retrofitting process, it’s suggested to model
some EXEC-level commands using YANG so that their functionality is
exposed to other management interfaces other than the CLI. As an
example, if the ``clear bgp`` command is modeled using a YANG RPC, and a
corresponding ``rpc`` callback is written, then it should be possible to
clear BGP neighbors using NETCONF and RESTCONF with that RPC (the ConfD
and Sysrepo plugins have full support for YANG RPCs and actions).

Here’s an example of a very simple RPC modeled using YANG:

.. code:: yang

     rpc clear-rip-route {
       description
         "Clears RIP routes from the IP routing table and routes
          redistributed into the RIP protocol.";
     }

This RPC doesn’t have any input or output parameters. Below we can see
the implementation of the corresponding ``rpc`` callback, whose skeleton
was automatically generated by the ``gen_northbound_callbacks`` tool:

.. code:: c

   /*
    * XPath: /frr-ripd:clear-rip-route
    */
   static int clear_rip_route_rpc(const char *xpath, const struct list *input,
                                  struct list *output)
   {
           struct route_node *rp;
           struct rip_info *rinfo;
           struct list *list;
           struct listnode *listnode;

           /* Clear received RIP routes */
           for (rp = route_top(rip->table); rp; rp = route_next(rp)) {
                   list = rp->info;
                   if (list == NULL)
                           continue;

                   for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
                           if (!rip_route_rte(rinfo))
                                   continue;

                           if (CHECK_FLAG(rinfo->flags, RIP_RTF_FIB))
                                   rip_zebra_ipv4_delete(rp);
                           break;
                   }

                   if (rinfo) {
                           RIP_TIMER_OFF(rinfo->t_timeout);
                           RIP_TIMER_OFF(rinfo->t_garbage_collect);
                           listnode_delete(list, rinfo);
                           rip_info_free(rinfo);
                   }

                   if (list_isempty(list)) {
                           list_delete_and_null(&list);
                           rp->info = NULL;
                           route_unlock_node(rp);
                   }
           }

           return NB_OK;
   }

If the ``clear-rip-route`` RPC had any input parameters, they would be
available in the ``input`` list given as a parameter to the callback.
Similarly, the ``output`` list can be used to append output parameters
generated by the RPC, if any are defined in the YANG model.

The northbound clients (CLI and northbound plugins) have the
responsibility to create and delete the ``input`` and ``output`` lists.
However, in the cases where the RPC or action doesn’t have any input or
output parameters, the northbound client can pass NULL pointers to the
``rpc`` callback to avoid creating linked lists unnecessarily. We can
see this happening in the example below:

.. code:: c

   /*
    * XPath: /frr-ripd:clear-rip-route
    */
   DEFPY (clear_ip_rip,
          clear_ip_rip_cmd,
          "clear ip rip",
          CLEAR_STR
          IP_STR
          "Clear IP RIP database\n")
   {
           return nb_cli_rpc("/frr-ripd:clear-rip-route", NULL, NULL);
   }

``nb_cli_rpc()`` is a helper function that merely finds the appropriate
``rpc`` callback based on the XPath provided in the first argument, and
map the northbound error code from the ``rpc`` callback to a vty error
code (e.g. ``CMD_SUCCESS``, ``CMD_WARNING``). The second and third
arguments provided to the function refer to the ``input`` and ``output``
lists. In this case, both arguments are set to NULL since the YANG RPC
in question doesn’t have any input/output parameters.

Notifications
~~~~~~~~~~~~~

YANG notifations are sent using the ``nb_notification_send()`` function,
documented in the *lib/northbound.h* file as follows:

.. code:: c

   /*
    * Send a YANG notification. This is a no-op unless the 'nb_notification_send'
    * hook was registered by a northbound plugin.
    *
    * xpath
    *    xpath of the YANG notification
    *
    * arguments
    *    linked list containing the arguments that should be sent. This list is
    *    deleted after being used.
    *
    * Returns:
    *    NB_OK on success, NB_ERR otherwise
    */
   extern int nb_notification_send(const char *xpath, struct list *arguments);

The northbound doesn’t use callbacks for notifications because
notifications are generated locally and sent to the northbound clients.
This way, whenever a notification needs to be sent, it’s possible to
call the appropriate function directly instead of finding a callback
based on the XPath of the YANG notification.

As an example, the *ietf-rip* module contains the following
notification:

.. code:: yang

     notification authentication-failure {
       description
         "This notification is sent when the system
          receives a PDU with the wrong authentication
          information.";
       leaf interface-name {
         type string;
         description
           "Describes the name of the RIP interface.";
       }
     }

The following convenience function was implemented in *ripd* to send
*authentication-failure* YANG notifications:

.. code:: c

   /*
    * XPath: /frr-ripd:authentication-failure
    */
   void ripd_notif_send_auth_failure(const char *ifname)
   {
           const char *xpath = "/frr-ripd:authentication-failure";
           struct list *arguments;
           char xpath_arg[XPATH_MAXLEN];
           struct yang_data *data;

           arguments = yang_data_list_new();

           snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-name", xpath);
           data = yang_data_new_string(xpath_arg, ifname);
           listnode_add(arguments, data);

           nb_notification_send(xpath, arguments);
   }

Now sending the *authentication-failure* YANG notification should be as
simple as calling the above function and provide the appropriate
interface name. The notification will be processed by all northbound
plugins that subscribed a callback to the ``nb_notification_send`` hook.
The ConfD and Sysrepo plugins, for instance, use this hook to relay the
notifications to the *confd*/*sysrepod* daemons, which can generate
NETCONF notifications to subscribed clients. When no northbound plugin
is loaded, ``nb_notification_send()`` doesn’t do anything and the
notifications are ignored.
