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

Configuration of *babeld* is done in its configuration file
:file:`babeld.conf`.

.. _babel-configuration:

Babel configuration
===================

.. index::
   single: router babel
   single: no router babel

.. clicmd:: [no] router babel

   Enable or disable Babel routing.

.. index::
   single: babel resend-delay (20-655340)
   single: no babel resend-delay [(20-655340)]

.. clicmd:: [no] babel resend-delay (20-655340)

   Specifies the time after which important messages are resent when
   avoiding a black-hole. The default is 2000 ms.

.. index::
   single: babel diversity
   single: no babel diversity

.. clicmd:: [no] babel diversity

   Enable or disable routing using radio frequency diversity.  This is
   highly recommended in networks with many wireless nodes.
   If you enable this, you will probably want to set `babel
   diversity-factor` and `babel channel` below.

.. index:: babel diversity-factor (1-256)

.. clicmd:: babel diversity-factor (1-256)

   Sets the multiplicative factor used for diversity routing, in units of
   1/256; lower values cause diversity to play a more important role in
   route selection.  The default it 256, which means that diversity plays
   no role in route selection; you will probably want to set that to 128
   or less on nodes with multiple independent radios.

.. index::
   single: network IFNAME
   single: no network IFNAME

.. clicmd:: no network IFNAME

   Enable or disable Babel on the given interface.

.. index:: babel <wired|wireless>

.. clicmd:: babel <wired|wireless>

   Specifies whether this interface is wireless, which disables a number
   of optimisations that are only correct on wired interfaces.
   Specifying `wireless` (the default) is always correct, but may
   cause slower convergence and extra routing traffic.

.. index::
   single: babel split-horizon
   single: no babel split-horizon

.. clicmd:: [no] babel split-horizon

   Specifies whether to perform split-horizon on the interface.  Specifying
   ``no babel split-horizon`` is always correct, while ``babel
   split-horizon`` is an optimisation that should only be used on symmetric
   and transitive (wired) networks.  The default is ``babel split-horizon``
   on wired interfaces, and ``no babel split-horizon`` on wireless
   interfaces.  This flag is reset when the wired/wireless status of an
   interface is changed.

.. index:: babel hello-interval (20-655340)

.. clicmd:: babel hello-interval (20-655340)

   Specifies the time in milliseconds between two scheduled hellos.  On
   wired links, Babel notices a link failure within two hello intervals;
   on wireless links, the link quality value is reestimated at every
   hello interval.  The default is 4000 ms.

.. index:: babel update-interval (20-655340)

.. clicmd:: babel update-interval (20-655340)

   Specifies the time in milliseconds between two scheduled updates.  Since
   Babel makes extensive use of triggered updates, this can be set to fairly
   high values on links with little packet loss.  The default is 20000 ms.

.. index::
   single: babel channel (1-254)
   single: babel channel interfering
   single: babel channel noninterfering

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

.. index:: babel rxcost (1-65534)

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

.. index:: babel rtt-decay (1-256)

.. clicmd:: babel rtt-decay (1-256)

   This specifies the decay factor for the exponential moving average of
   RTT samples, in units of 1/256.  Higher values discard old samples
   faster.  The default is 42.

.. index:: babel rtt-min (1-65535)

.. clicmd:: babel rtt-min (1-65535)

   This specifies the minimum RTT, in milliseconds, starting from which we
   increase the cost to a neighbour. The additional cost is linear in
   (rtt - rtt-min).  The default is 100 ms.

.. index:: babel rtt-max (1-65535)

.. clicmd:: babel rtt-max (1-65535)

   This specifies the maximum RTT, in milliseconds, above which we don't
   increase the cost to a neighbour. The default is 120 ms.

.. index:: babel max-rtt-penalty (0-65535)

.. clicmd:: babel max-rtt-penalty (0-65535)

   This specifies the maximum cost added to a neighbour because of RTT, i.e.
   when the RTT is higher or equal than rtt-max.  The default is 0, which
   effectively disables the use of a RTT-based cost.

.. index::
   single: babel enable-timestamps
   single: no babel enable-timestamps

.. clicmd:: [no] babel enable-timestamps

   Enable or disable sending timestamps with each Hello and IHU message in
   order to compute RTT values.  The default is `no babel enable-timestamps`.

.. index:: babel resend-delay (20-655340)

.. clicmd:: babel resend-delay (20-655340)

   Specifies the time in milliseconds after which an 'important' request or
   update will be resent.  The default is 2000 ms.  You probably don't want to
   tweak this value.

.. index:: babel smoothing-half-life (0-65534)

.. clicmd:: babel smoothing-half-life (0-65534)

   Specifies the time constant, in seconds, of the smoothing algorithm used for
   implementing hysteresis.  Larger values reduce route oscillation at the cost
   of very slightly increasing convergence time.  The value 0 disables
   hysteresis, and is suitable for wired networks.  The default is 4 s.

.. _babel-redistribution:

Babel redistribution
====================

.. index::
   single: redistribute <ipv4|ipv6> KIND
   single: no redistribute <ipv4|ipv6> KIND

.. clicmd:: [no] redistribute <ipv4|ipv6> KIND

   Specify which kind of routes should be redistributed into Babel.

.. _show-babel-information:

Show Babel information
======================

These commands dump various parts of *babeld*'s internal state.

.. index:: show babel route

.. clicmd:: show babel route

.. index:: show babel route A.B.C.D

.. clicmd:: show babel route A.B.C.D

.. index:: show babel route X:X::X:X

.. clicmd:: show babel route X:X::X:X

.. index:: show babel route A.B.C.D/M

.. clicmd:: show babel route A.B.C.D/M

.. index:: show babel route X:X::X:X/M

.. clicmd:: show babel route X:X::X:X/M

.. index:: show babel interface

.. clicmd:: show babel interface

.. index:: show babel interface IFNAME

.. clicmd:: show babel interface IFNAME

.. index:: show babel neighbor

.. clicmd:: show babel neighbor

.. index:: show babel parameters

.. clicmd:: show babel parameters

Babel debugging commands
========================

.. index::
   simple: debug babel KIND
   simple: no debug babel KIND

.. clicmd:: [no] debug babel KIND

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
