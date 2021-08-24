ASCII Network diagrams
======================

topotato uses ASCII network diagrams to specify topologies and connections
for tests.  The :py:class:`topotato.parse.Topology` class represents these
topologies.

A somewhat degenerate example topology to illustrate most features available
in drawing network diagrams looks something like this:

.. code-block:: none

    [    ](eth0)------[ r2 ]
    [ r1 ]
    [    ](eth1)------[ r4 ]
    [    ]------------[    ]
       |                 |
       |                 |
    (eth2)               |
    [ r3 ]------------{ lan1 }----[ r5 ]
                      {      }----[    ]

As outlined by the class documentation, the following features are supported
in these network diagrams:

Box drawing

   The ASCII diagram is parsed for boxes aligned to each other.  Note that
   to be parsed correctly, the "box" must have the same horizontal size on
   each line.

   Tabs should not be used in network diagram drawings (as is regular Python
   coding style anyway.)

``[ host ]``

   Routers (or plain hosts) are created by drawing a box with ``[ ]`` outlines.
   The router's name must occur exactly once inside the box (it cannot be
   repeated.)  All four "edges" can be used to attach links, and multiple
   links can be attached on an edge.

``{ network }``

   Multi-access networks -- Ethernet links, really -- are created with ``{ }``
   outlines.  Like routers, the box can be extended and multiple links can be
   connected at each edge.

Direct links

   Direct links (still Ethernet) are created from links between routers without
   a ``{ network }`` inserted.  This does not do anything special to make the
   link "point-to-point", but the address generation code handles these links
   differently.

   .. note::

      A point-to-point link is not the same as a ``{ network }`` with 2
      connections.  The latter is intended to represent a full broadcast
      domain.

Parallel links

   To create multiple parallel links between two items, simply draw two lines.

Repeating hosts or networks

   Host and network boxes can be repeated for complex diagrams if more
   connections need to be made but can't easily be wedged into ASCII.  Simply
   repeating the same router/network name causes multiple "boxes" to be merged.

``( ifname )``

   Interface names can be overridden by placing ``( ifname )`` on the
   "connection point" from the router's box.

.. todo::

   Support for diagonal / crossover links, particularly for common
   ``| X |`` connections, would be useful.


Implementation
--------------

.. autoclass:: topotato.parse.Topology
   :exclude-members: BoxMerge
   :members:
