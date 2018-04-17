.. _vty-shell:

*********
VTY shell
*********

.. program:: configure

*vtysh* provides a combined frontend to all FRR daemons in a single combined
session. It is enabled by default at build time, but can be disabled through
the :option:`--disable-vtysh` option to the configure script.

*vtysh* has a configuration file, :file:`vtysh.conf`. The location of that
file cannot be changed from |INSTALL_PREFIX_ETC| since it contains options
controlling authentication behavior. This file will also not be written by
configuration-save commands, it is intended to be updated manually by an
administrator with an external editor.

.. warning::

   This also means the ``hostname`` and ``banner motd`` commands (which both do
   have effect for vtysh) need to be manually updated in :file:`vtysh.conf`.


Permissions and setup requirements
==================================

*vtysh* connects to running daemons through Unix sockets located in
|INSTALL_PREFIX_STATE|. Running vtysh thus requires access to that directory,
plus membership in the |INSTALL_VTY_GROUP| group (which is the group that the
daemons will change ownership of their sockets to).

To restrict access to FRR configuration, make sure no unauthorized users are
members of the |INSTALL_VTY_GROUP| group.

.. warning::

   VTYSH implements a CLI option ``-u, --user`` that disallows entering the
   characters "en" on the command line, which ideally restricts access to
   configuration commands. However, VTYSH was never designed to be a privilege
   broker and is not built using secure coding practices. No guarantees of
   security are provided for this option and under no circumstances should this
   option be used to provide any semblance of security or read-only access to
   FRR.

PAM support (experimental)
--------------------------

vtysh has working (but rather useless) PAM support. It will perform an
"authenticate" PAM call using |PACKAGE_NAME| as service name. No other
(accounting, session, password change) calls will be performed by vtysh.

Users using vtysh still need to have appropriate access to the daemons' VTY
sockets, usually by being member of the |INSTALL_VTY_GROUP| group. If they
have this membership, PAM support is useless since they can connect to daemons
and issue commands using some other tool. Alternatively, the *vtysh* binary
could be made SGID (set group ID) to the |INSTALL_VTY_GROUP| group.

.. warning::

   No security guarantees are made for this configuration.


.. index:: username USERNAME nopassword
.. clicmd:: username USERNAME nopassword

  If PAM support is enabled at build-time, this command allows disabling the
  use of PAM on a per-user basis. If vtysh finds that an user is trying to
  use vtysh and a "nopassword" entry is found, no calls to PAM will be made
  at all.


.. _integrated-configuration-mode:

Integrated configuration mode
=============================

Integrated configuration mode uses a single configuration file,
:file:`frr.conf`, for all daemons. This replaces the individual files like
:file:`zebra.conf` or :file:`bgpd.conf`.

:file:`frr.conf` is located in |INSTALL_PREFIX_ETC|. All daemons check for the
existence of this file at startup, and if it exists will not load their
individual configuration files. Instead, ``vtysh -b`` must be invoked to
process :file:`frr.conf` and apply its settings to the individual daemons.

.. warning::

   *vtysh -b* must also be executed after restarting any daemon.


Configuration saving, file ownership and permissions
----------------------------------------------------

The :file:`frr.conf` file is not written by any of the daemons; instead *vtysh*
contains the necessary logic to collect configuration from all of the daemons,
combine it and write it out.

.. warning::

   Daemons must be running for *vtysh* to be able to collect their
   configuration. Any configuration from non-running daemons is permanently
   lost after doing a configuration save.

Since the *vtysh* command may be running as ordinary user on the system,
configuration writes will be tried through *watchfrr*, using the ``write
integrated`` command internally. Since *watchfrr* is running as superuser,
*vtysh* is able to ensure correct ownership and permissions on
:file:`frr.conf`.

If *watchfrr* is not running or the configuration write fails, *vtysh* will
attempt to directly write to the file. This is likely to fail if running as
unprivileged user; alternatively it may leave the file with incorrect owner or
permissions.

Writing the configuration can be triggered directly by invoking *vtysh -w*.
This may be useful for scripting. Note this command should be run as either the
superuser or the FRR user.

We recommend you do not mix the use of the two types of files. Further, it is
better not to use the integrated :file:`frr.conf` file, as any syntax error in
it can lead to /all/ of your daemons being unable to start up. Per daemon files
are more robust as impact of errors in configuration are limited to the daemon
in whose file the error is made.

.. index:: service integrated-vtysh-config
.. clicmd:: service integrated-vtysh-config

.. index:: no service integrated-vtysh-config
.. clicmd:: no service integrated-vtysh-config

   Control whether integrated :file:`frr.conf` file is written when
   'write file' is issued.

   These commands need to be placed in :file:`vtysh.conf` to have any effect.
   Note that since :file:`vtysh.conf` is not written by FRR itself, they
   therefore need to be manually placed in that file.

   This command has 3 states:


   service integrated-vtysh-config
      *vtysh* will always write :file:`frr.conf`.


   no service integrated-vtysh-config
      *vtysh* will never write :file:`frr.conf`; instead it will ask
      daemons to write their individual configuration files.

   Neither option present (default)
      *vtysh* will check whether :file:`frr.conf` exists. If it does,
      configuration writes will update that file. Otherwise, writes are performed
      through the individual daemons.

   This command is primarily intended for packaging/distribution purposes, to
   preset one of the two operating modes and ensure consistent operation across
   installations.

.. index:: write integrated
.. clicmd:: write integrated

   Unconditionally (regardless of ``service integrated-vtysh-config`` setting)
   write out integrated :file:`frr.conf` file through *watchfrr*. If *watchfrr*
   is not running, this command is unavailable.

.. warning::

   Configuration changes made while some daemon is not running will be
   invisible to that daemon. The daemon will start up with its saved
   configuration (either in its individual configuration file, or in
   :file:`frr.conf`).  This is particularly troublesome for route-maps and
   prefix lists, which would otherwise be synchronized between daemons.

