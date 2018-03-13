.. Copyright 2018 6WIND S.A.

=====
Usage
=====

Starting |CP-ROUTING|
=====================

``zebra``
---------

**Description**

The ``zebra`` daemon:

- aggregates routes calculated using supported routing
  protocols, and,

- synchronizes them with the routes in the Linux kernel.

The routing protocols are handled by their respective daemons, which must also
be started.

**Synopsis**

.. code-block:: console

   zebra [-d] [-f conf_file] [-n]

**Parameters**

.. program:: zebra

.. option:: -d

   Detach from the terminal and run as a background daemon.

.. option:: -f conf_file

   Specify an initial configuration file.

.. option:: -n

   Add VRF namespace backend support

.. seealso::

   For more information about |frr| daemons startup, see the `online
   documentation`__.

__ https://frrouting.org/user-guide/


Configuration
=============

You must create a configuration file before starting the daemon. When the daemon
is started, you can alter the running configuration interactively by passing
commands to ``zebra`` via its CLI.

The CLI syntax and the configuration file syntax are quite similar.

Accessing the CLI for runtime configuration
-------------------------------------------

If needed, you can access each daemon's CLI for runtime configuration either:

- remotely via Telnet:

  .. code-block:: console

     $ telnet localhost <daemon_port>
     $ enable

- or, using the ``vtysh`` program, that allows configuring ``zebra`` and all other
  routing protocols:

   .. code-block:: console

      $ vtysh

  .. seealso::

     For more information about the CLI modes, see the `online documentation`__.

__ https://frrouting.org/user-guide/Virtual-Terminal-Interfaces.html#Virtual-Terminal-Interface

   .. note::

       You can also configure ``zebra`` and all other protocols through the
       ``telnet localhost 2601`` socket.

