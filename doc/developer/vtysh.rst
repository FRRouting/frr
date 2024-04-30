.. _vtysh:

*****
VTYSH
*****

.. seealso:: :ref:`command-line-interface`

.. _vtysh-architecture:

Architecture
============

VTYSH is a shell for FRR daemons. It amalgamates all the CLI commands defined
in each of the daemons and presents them to the user in a single shell, which
saves the user from having to telnet to each of the daemons and use their
individual shells.  The amalgamation is achieved by
:ref:`extracting <vtysh-command-extraction>` commands from daemons and
injecting them into VTYSH at build time.

At runtime, VTYSH maintains an instance of a CLI mode tree just like each
daemon. However, the mode tree in VTYSH contains (almost) all commands from
every daemon in the same tree, whereas individual daemons have trees that only
contain commands relevant to themselves. VTYSH also uses the library CLI
facilities to maintain the user's current position in the tree (the current
node). Note that this position must be synchronized with all daemons; if a
daemon receives a command that causes it to change its current node, VTYSH must
also change its node. Since the extraction script does not understand the
handler code of commands, but only their definitions, this and other behaviors
must be manually programmed into VTYSH for every case where the internal state
of VTYSH must change in response to a command. Details on how this is done are
discussed in the :ref:`vtysh-special-defuns` section.

VTYSH also handles writing and applying the integrated configuration file,
:file:`/etc/frr/frr.conf`. Since it has knowledge of the entire command space
of FRR, it can intelligently distribute configuration commands only to the
daemons that understand them. Similarly, when writing the configuration file it
takes care of combining multiple instances of configuration blocks and
simplifying the output. This is discussed in :ref:`vtysh-configuration`.

.. _vtysh-command-extraction:

Command Extraction
------------------

To build ``vtysh``, the :file:`python/xref2vtysh.py` script scans through the
:file:`frr.xref` file created earlier in the build process.  This file contains
a list of all ``DEFUN`` and ``install_element`` sites in the code, generated
directly from the binaries (and therefore matching exactly what is really
available.)

This list is collated and transformed into ``DEFSH`` (and ``install_element``)
statements, output to ``vtysh_cmd.c``. Each ``DEFSH``
contains the name of the command plus ``_vtysh``, as well as a flag that
indicates which daemons the command was found in. When the command is executed
in VTYSH, this flag is inspected to determine which daemons to send the command
to. This way, commands are only sent to the daemons that know about them,
avoiding spurious errors from daemons that don't have the command defined.

The extraction script contains lots of hardcoded knowledge about what sources
to look at and what flags to use for certain commands.

.. note::

   The ``vtysh_scan`` Makefile variable and ``#ifndef VTYSH_EXTRACT_PL``
   checks in source files are no longer used.  Remove them when rebasing older
   changes.

.. _vtysh-special-defuns:

Special DEFUNs
--------------

In addition to the vanilla ``DEFUN`` macro for defining CLI commands, there are
several VTYSH-specific ``DEFUN`` variants that each serve different purposes.

``DEFSH``
   Used almost exclusively by generated VTYSH code. This macro defines a
   ``cmd_element`` with no handler function; the command, when executed, is
   simply forwarded to the daemons indicated in the daemon flag.

``DEFUN_NOSH``
   Used by daemons. Has the same expansion as a ``DEFUN``, but ``xref2vtysh.py``
   will skip these definitions when extracting commands. This is typically used
   when VTYSH must take some special action upon receiving the command, and the
   programmer therefore needs to write VTYSH's copy of the command manually
   instead of using the generated version.

``DEFUNSH``
   The same as ``DEFUN``, but with an argument that allows specifying the
   ``->daemon`` field of the generated ``cmd_element``. This is used by VTYSH
   to determine which daemons to send the command to.

``DEFUNSH_ATTR``
   A version of ``DEFUNSH`` that allows setting the ``->attr`` field of the
   generated ``cmd_element``. Not used in practice.

.. _vtysh-configuration:

Configuration Management
------------------------

When integrated configuration is used, VTYSH manages writing, reading and
applying the FRR configuration file. VTYSH can be made to read and apply an
integrated configuration to all running daemons by launching it with ``-f
<file>``. It sends the appropriate configuration lines to the relevant daemons
in the same way that commands entered by the user on VTYSH's shell prompt are
processed.

Configuration writing is more complicated. VTYSH makes a best-effort attempt to
combine and simplify the configuration as much as possible. A working example
is best to explain this behavior.

Example
^^^^^^^

Suppose we have just *staticd* and *zebra* running on the system, and use VTYSH
to apply the following configuration snippet:

.. code-block:: frr

   !
   vrf blue
    ip protocol static route-map ExampleRoutemap
    ip route 192.168.0.0/24 192.168.0.1
    exit-vrf
   !

Note that *staticd* defines static route commands and *zebra* defines ``ip
protocol`` commands. Therefore if we ask only *zebra* for its configuration, we
get the following::

   (config)# do sh running-config zebra
   Building configuration...

   ...
   !
   vrf blue
    ip protocol static route-map ExampleRoutemap
    exit-vrf
   !
   ...

Note that the static route doesn't show up there. Similarly, if we ask
*staticd* for its configuration, we get::

   (config)# do sh running-config staticd

   ...
   !
   vrf blue
    ip route 192.168.0.0/24 192.168.0.1
    exit-vrf
   !
   ...

But when we display the configuration with VTYSH, we see::

   ubuntu-bionic(config)# do sh running-config

   ...
   !
   vrf blue
    ip protocol static route-map ExampleRoutemap
    ip route 192.168.0.0/24 192.168.0.1
    exit-vrf
   !
   ...

This is because VTYSH asks each daemon for its currently running configuration,
and combines equivalent blocks together. In the above example, it combined the
``vrf blue`` blocks from both *zebra* and *staticd* together into one. This is
done in :file:`vtysh_config.c`.

Protocol
========

VTYSH communicates with FRR daemons by way of domain socket. Each daemon
creates its own socket, typically in :file:`/var/run/frr/<daemon>.vty`. The
protocol is very simple. In the VTYSH to daemon direction, messages are simply
NUL-terminated strings, whose content are CLI commands. Here is a typical
message from VTYSH to a daemon:

::

   Request

   00000000: 646f 2077 7269 7465 2074 6572 6d69 6e61  do write termina
   00000010: 6c0a 00                                  l..


The response format has some more data in it. First is a NUL-terminated string
containing the plaintext response, which is just the output of the command that
was sent in the request. This is displayed to the user. The plaintext response
is followed by 3 null marker bytes, followed by a 1-byte status code that
indicates whether the command was successful or not.

::

   Response

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Plaintext Response                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Marker (0x00)                 |  Status Code  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


The first ``0x00`` byte in the marker also serves to terminate the plaintext
response.
