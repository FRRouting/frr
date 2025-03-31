.. _babel:

*****
Babel
*****

Babel is an interior gateway protocol that is suitable both for wired networks
and for wireless mesh networks.  Babel has been described as 'RIP on speed' --
it is based on the same principles as RIP, but includes a number of refinements
that make it react much faster to topology changes without ever counting to
infinity, and allow it to perform reliable link quality estimation on wireless
links.  Babel is a double-stack routing protocol, meaning that a single Babel
instance is able to perform routing for both IPv4 and IPv6.

FRR implements Babel as described in :rfc:`6126`.

.. _configuring-babeld:

Configuring babeld
==================

The *babeld* daemon can be invoked with any of the common
options (:ref:`common-invocation-options`).

The *zebra* daemon must be running before *babeld* is
invoked. Also, if *zebra* is restarted then *babeld*
must be too.

.. include:: config-include.rst

.. _babel-configuration:

Babel configuration
===================

.. clicmd:: router babel

   Enable or disable Babel routing.

.. clicmd:: babel diversity

   Enable or disable routing using radio frequency diversity.  This is
   highly recommended in networks with many wireless nodes.
   If you enable this, you will probably want to set `babel
   diversity-factor` and `babel channel` below.


.. clicmd:: babel diversity-factor (1-256)

   Sets the multiplicative factor used for diversity routing, in units of
   1/256; lower values cause diversity to play a more important role in
   route selection.  The default it 256, which means that diversity plays
   no role in route selection; you will probably want to set that to 128
   or less on nodes with multiple independent radios.

.. clicmd:: network IFNAME

   Enable or disable Babel on the given interface.


.. clicmd:: babel <wired|wireless>

   Specifies whether this interface is wireless, which disables a number
   of optimisations that are only correct on wired interfaces.
   Specifying `wireless` (the default) is always correct, but may
   cause slower convergence and extra routing traffic.

.. clicmd:: babel split-horizon

   Specifies whether to perform split-horizon on the interface.  Specifying
   ``no babel split-horizon`` is always correct, while ``babel
   split-horizon`` is an optimisation that should only be used on symmetric
   and transitive (wired) networks.  The default is ``babel split-horizon``
   on wired interfaces, and ``no babel split-horizon`` on wireless
   interfaces.  This flag is reset when the wired/wireless status of an
   interface is changed.


.. clicmd:: babel hello-interval (20-655340)

   Specifies the time in milliseconds between two scheduled hellos.  On
   wired links, Babel notices a link failure within two hello intervals;
   on wireless links, the link quality value is reestimated at every
   hello interval.  The default is 4000 ms.


.. clicmd:: babel update-interval (20-655340)

   Specifies the time in milliseconds between two scheduled updates.  Since
   Babel makes extensive use of triggered updates, this can be set to fairly
   high values on links with little packet loss.  The default is 20000 ms.


.. clicmd:: babel channel (1-254)
.. clicmd:: babel channel interfering
.. clicmd:: babel channel noninterfering

   Set the channel number that diversity routing uses for this interface (see
   `babel diversity` above).  Noninterfering interfaces are assumed to only
   interfere with themselves, interfering interfaces are assumed to interfere
   with all other channels except noninterfering channels, and interfaces with
   a channel number interfere with interfering interfaces and interfaces with
   the same channel number.  The default is ``babel channel interfering`` for
   wireless interfaces, and ``babel channel noninterfering`` for wired
   interfaces.  This is reset when the wired/wireless status of an interface is
   changed.


.. clicmd:: babel rxcost (1-65534)

   Specifies the base receive cost for this interface.  For wireless
   interfaces, it specifies the multiplier used for computing the ETX
   reception cost (default 256); for wired interfaces, it specifies the
   cost that will be advertised to neighbours.  This value is reset when
   the wired/wireless attribute of the interface is changed.

.. note::
   Do not use this command unless you know what you are doing; in most
   networks, acting directly on the cost using route maps is a better
   technique.


.. clicmd:: babel rtt-decay (1-256)

   This specifies the decay factor for the exponential moving average of
   RTT samples, in units of 1/256.  Higher values discard old samples
   faster.  The default is 42.


.. clicmd:: babel rtt-min (1-65535)

   This specifies the minimum RTT, in milliseconds, starting from which we
   increase the cost to a neighbour. The additional cost is linear in
   (rtt - rtt-min).  The default is 10 ms.


.. clicmd:: babel rtt-max (1-65535)

   This specifies the maximum RTT, in milliseconds, above which we don't
   increase the cost to a neighbour. The default is 120 ms.


.. clicmd:: babel max-rtt-penalty (0-65535)

   This specifies the maximum cost added to a neighbour because of RTT, i.e.
   when the RTT is higher or equal than rtt-max. The default is 150. Setting it
   to 0 effectively disables the use of a RTT-based cost.


.. clicmd:: babel enable-timestamps

   Enable or disable sending timestamps with each Hello and IHU message in
   order to compute RTT values.  The default is `no babel enable-timestamps`.


.. clicmd:: babel resend-delay (20-655340)

   Specifies the time in milliseconds after which an 'important' request or
   update will be resent.  The default is 2000 ms.  You probably don't want to
   tweak this value.


.. clicmd:: babel smoothing-half-life (0-65534)

   Specifies the time constant, in seconds, of the smoothing algorithm used for
   implementing hysteresis.  Larger values reduce route oscillation at the cost
   of very slightly increasing convergence time.  The value 0 disables
   hysteresis, and is suitable for wired networks.  The default is 4 s.

.. _babel-redistribution:

Babel redistribution
====================


.. clicmd:: redistribute <ipv4|ipv6> KIND

   Specify which kind of routes should be redistributed into Babel.

.. _show-babel-information:

Show Babel information
======================

These commands dump various parts of *babeld*'s internal state.


.. clicmd:: show babel route


.. clicmd:: show babel route A.B.C.D


.. clicmd:: show babel route X:X::X:X


.. clicmd:: show babel route A.B.C.D/M


.. clicmd:: show babel route X:X::X:X/M


.. clicmd:: show babel interface


.. clicmd:: show babel interface IFNAME


.. clicmd:: show babel neighbor


.. clicmd:: show babel parameters

Babel debugging commands
========================

   simple: debug babel KIND
   simple: no debug babel KIND

.. clicmd:: debug babel KIND

   Enable or disable debugging messages of a given kind. ``KIND`` can
   be one of:

   - ``common``
   - ``filter``
   - ``timeout``
   - ``interface``
   - ``route``
   - ``all``

.. note::
   If you have compiled with the ``NO_DEBUG`` flag, then these commands aren't
   available.


Babel sample configuration file
===============================

.. code-block:: frr

   debug babel common
   !debug babel kernel
   !debug babel filter
   !debug babel timeout
   !debug babel interface
   !debug babel route
   !debug babel all

   router babel
   ! network wlan0
   ! network eth0
   ! redistribute ipv4 kernel
   ! no redistribute ipv6 static

   ! The defaults are fine for a wireless interface

   !interface wlan0

   ! A few optimisation tweaks are optional but recommended on a wired interface
   ! Disable link quality estimation, enable split horizon processing, and
   ! increase the hello and update intervals.

   !interface eth0
   ! babel wired
   ! babel split-horizon
   ! babel hello-interval 12000
   ! babel update-interval 36000

   ! log file /var/log/frr/babeld.log
   log stdout

