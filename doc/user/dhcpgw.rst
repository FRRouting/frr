.. _dhcpgw:

******
DHCPGW
******

:abbr:`DHCPGW` is a daemon that handles the installation and deletion of static
routes via dhcp gateway. It is thin layer over `staticd` that watches changes
of DHCP gateway and deletes/installs routes using `staticd`.

.. _starting-dhcpgw:

Starting DHCPGW
===============

.. program:: dhcpgwd

:abbr:`DHCPGW` supports all the common FRR daemon start options which are
documented elsewhere.

.. include:: config-include.rst

.. _setup-dhcpgw:

Setting DHCPGW up
=================

To work properly hook must be installed in used DHCP client. Sample hooks
are provided for `udhcpc`, `dhcpcd` and `dhclient` as `sample-*-hook`.
Hook should call `update-dhcp-gw INTERFACE [down|up IP]` whenever DHCP gateway state
or IP is changed.

The `update-dhcp-gw` must have write access to dhcpgw state directory.
If `systemd-tmpfiles` is used, configuration file `/usr/lib/tmpfiles.d/frr.conf`
takes care of that. Otherwise you can create directory with frr user
as owner, make frr user owner of `update-dhcp-gw` and set setuid for `update-dhcp-gw`.

If standard paths are used, it can be done like this:

.. code-block:: bash

   sudo mkdir /run/frr/dhcpgw-state
   sudo chown frr:frr /run/frr/dhcpgw-state
   sudo chmod u+s /usr/lib/frr/update-dhcp-gw


.. _dhcpgw-commands:

DHCPGW Commands
=====================

DHCPGW handles static routes that should use DHCP gateway as nexthop.

It mimics `static` command with GATEWAY replaced with `dhcp-gateway`:

.. clicmd:: ip route NETWORK dhcp-gateway IFNAME [DISTANCE] [onlink] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

   See description of all options in :ref:`static-route-commands`.

.. clicmd:: dhcpgw update IFNAME

   Reread status and IP of DHCP gateway for interface IFNAME and update routes that use DHCP gateway for this interface.

.. clicmd:: show dhcpgw route

   Show all interfaces that are used in dhcpgw routes and their status.
