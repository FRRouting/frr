********
Glossary
********

.. glossary::

   distance-vector
      A distance-vector routing protocol in data networks determines the best
      route for data packets based on distance. Distance-vector routing
      protocols measure the distance by the number of routers a packet has to
      pass. Some distance-vector protocols also take into account network
      latency and other factors that influence traffic on a given route. To
      determine the best route across a network, routers on which a
      distance-vector protocol is implemented exchange information with one
      another, usually routing tables plus hop counts for destination networks
      and possibly other traffic information. Distance-vector routing protocols
      also require that a router informs its neighbours of network topology
      changes periodically. [distance-vector-rp]_

   link-state
      Link-state algorithms (also known as shortest path first algorithms)
      flood routing information to all nodes in the internetwork. Each router,
      however, sends only the portion of the routing table that describes the
      state of its own links. In link-state algorithms, each router builds a
      picture of the entire network in its routing tables. Distance vector
      algorithms (also known as Bellman-Ford algorithms) call for each router
      to send all or some portion of its routing table, but only to its
      neighbors. In essence, link-state algorithms send small updates
      everywhere, while distance vector algorithms send larger updates only to
      neighboring routers. Distance vector algorithms know only about their
      neighbors. [link-state-rp]_

   Bellman-Ford
      The Bellman–Ford algorithm is an algorithm that computes shortest paths
      from a single source vertex to all of the other vertices in a weighted
      digraph. [bellman-ford]_


.. [distance-vector-rp] https://en.wikipedia.org/wiki/Distance-vector_routing_protocol
.. [link-state-rp] https://en.wikipedia.org/wiki/Link-state_routing_protocol
.. [bellman-ford] https://en.wikipedia.org/wiki/Bellman-Ford_algorithm
