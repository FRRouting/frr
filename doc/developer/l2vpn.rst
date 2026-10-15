.. _l2vpn-library:

*************
L2VPN Library
*************

Overview
========

An L2VPN instance, as described in :rfc:`4664` (L2VPN components), is
configured in FRR with the ``l2vpn NAME type vpls`` node. It groups the
attachment circuits (member interfaces, optionally attached to a bridge
interface) and the pseudowires that connect the instance to the remote
PEs.

Until now, the L2VPN instances were owned by ``ldpd``: their data
structures, their CLI and their running-config were part of the LDP code,
and the only way to signal the pseudowires was LDP (:rfc:`4447`,
:rfc:`4762`).

The L2VPN library extracts the definition of an L2VPN instance from
``ldpd``, and makes it a daemon independent object of ``libfrr``:

- the ``frr-l2vpn`` YANG module describes the instance (type, pseudowire
  type, MTU, bridge interface, member interfaces, member pseudowires with
  their remote endpoint, pseudowire ID, control word and status TLV
  settings);
- the northbound callbacks build the configured instances in the
  ``l2vpn_tree_config`` tree (``struct l2vpn``, ``struct l2vpn_if``,
  ``struct l2vpn_pw``, see :file:`lib/l2vpn.h`);
- the CLI and the running-config are produced from the YANG data
  (:file:`lib/l2vpn_cli.c`, :file:`lib/l2vpn_northbound.c`), and the CLI
  module is also loaded by ``mgmtd``.

The goal is that the same L2VPN instance definition can be used by any
daemon that provides a pseudowire control plane, instead of being tied to
LDP. LDP is the first, and today the only, user of the library. Another
signaling protocol for the same instances, for instance BGP based
auto-discovery and signaling of VPLS and VPWS (:rfc:`4761`,
:rfc:`6074`), would reuse the configured instances and only implement its
own signaling.

This work does not change BGP EVPN: EVPN instances keep their own
configuration in ``bgpd``.

Daemon Integration
==================

A daemon using the library calls ``l2vpn_init()`` at startup, then
registers its callbacks with ``l2vpn_register_hook()``:

``add_hook(name)``
   An L2VPN instance has been created, or one of its attributes (pseudowire
   type, MTU, bridge interface) or member interfaces has been set.

``del_hook(name)``
   An L2VPN instance has been deleted, or one of its attributes or member
   interfaces has been removed.

``event_hook(pw)``
   A member pseudowire, or one of its attributes, has changed.

``iface_ok_for_l2vpn(ifname)``
   Called by the northbound validation before an interface becomes a
   member interface or a pseudowire interface. The daemon returns true when
   it already uses the interface for itself, in which case the
   configuration is rejected. For instance, ``ldpd`` returns true for an
   interface where LDP is enabled.

The library only holds the configuration. The daemon keeps its own
runtime copy of the instances, with its protocol state. In ``ldpd``, each
hook applies the configuration again (``ldp_config_apply()``): the
instances of ``l2vpn_tree_config`` are sent to the LDP processes and
merged into their own trees, and the LDP copies are freed with
``ldp_l2vpn_del()``.
