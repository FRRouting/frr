HELP AND VERSION
----------------

.. option:: -h, --help

   Print a short description of the daemon's command line options.

.. option:: -v, --version

   Print version and build information for the daemon.

Both of these options inhibit normal operation and will immediately exit.

PROCESS CONTROL
---------------
These options control background operation:

.. option:: -d, --daemon

   Launches the process in background/daemon mode, forking and detaching from the terminal.

  The parent process will delay its exit until the daemon/child has finished its initialization and has entered its main loop. This is important for zebra startup because the other daemons will attempt to connect to zebra. A return from zebra -d guarantees its readiness to accept these connections.

.. option:: -t, --terminal

   Opens an interactive VTY session on the terminal, allowing for both state and configuration operations.  Note that the terminal starts operating after startup has completed and the configuration file has been loaded.

   The process will exit when end of file is detected on the terminal.  It is possible to daemonize a process started with -t (but without -d) by sending SIGQUIT to the process (normally mapped to a ^\ keypress.)


The combination of :option:`--daemon` and :option:`--terminal` will delay the daemon from going into background until the terminal session ends (by end of file.)

If the process receives SIGINT (e.g. a ^C keypress) in this mode, it will exit instead of daemonizing.

It is safe to suspend (SIGTSTP / ^Z) the terminal session opened by the previous two options;  this will only stop the terminal but not the protocol daemon itself (which runs in a separate second process.)

CONFIGURATION AND PATHS
-----------------------
The following options control configuration and file system locations for frr processes:

.. option:: -f, --config_file config-file

   Specify a configuration file to be used instead of the default /etc/frr/<daemon>.conf file.

   Note that the daemon will attempt to write to this file if the write file command is issued on its VTY interface or through vtysh.

.. option:: -C, --dryrun

   Load the configuration file and check its validity, then exit.

.. option:: -i, --pid_file pid-file

   Output a pid file to a location other than the default /var/run/frr/<daemon>.pid.

.. option:: -z, --socket zclient-path

   Override the path of the ZAPI socket used to communicate between zebra and the various protocol daemons. The default is /var/run/frr/zserv.api.  The value of this option must be the same across all daemons.

.. option:: -N, --pathspace pathspace

   Insert pathspace into all default paths, changing the defaults to:

   /etc/frr/pathspace/<daemon>.conf
   /var/run/frr/pathspace/<daemon>.pid
   /var/run/frr/pathspace/<daemon>.vty
   /var/run/frr/pathspace/zserv.api

   ´.´ and ´/´ characters will not be accepted in pathspace, but the empty string will be accepted.

   Note that this only changes the respective defaults, it has no effect on the respective path if the -f, -i, -z or --vty_socket options are used.

   The purpose of this option is to easily group all file system related bits together for running multiple fully-separate "logical routers" on a system, particularly with Linux network namespaces.  Groups of daemons running with distinct pathspace values will be completely unaware of each other and not interact in any way.

   This option does not do any system setup (like network namespaces.) This must be done by the user, for example by running:

   ip netns exec namespace <daemon> -N namespace


PROCESS CREDENTIALS
-------------------
.. option:: -u, --user user

   (default: frr)

.. option:: -g, --group group

   (default: frr)

   Change the user/group which the daemon will switch to.

.. option:: -S, --skip_runas

   Skip setting the process effective user and group.


Note that there is an additional group, frrvty, which controls group ownership of the VTY sockets.  The name of this group cannot currently be changed, and user must be a member of this group.


VTY SETUP
---------
These following options control the daemon's VTY (interactive command line) interface.  The interface is available over TCP, using the telnet protocol, as well as through the vtysh frontend.

.. option:: -A, --vty_addr vty-addr

   Specify an IP/IPv6 address to bind the TCP VTY interface to.  It is generally recommended to specify ::1 or 127.0.0.1.  For reasons of backwards compatibility, the default is to listen on all interfaces.

.. option:: -P, --vty_port vty-port

   Override the daemon's default TCP VTY port (each daemon has a different default value upwards of 2600, listed below.)  Specifying 0 disables the TCP VTY interface.

   Default ports are:::

      zebra           2601
      ripd            2602
      ripngd          2603
      ospfd           2604
      bgpd            2605
      ospf6d          2606
      isisd           2608
      babeld          2609
      nhrpd           2610
      pimd            2611
      ldpd            2612
      eigrpd          2613
      pbrd            2615

   Port 2607 is used for ospfd's Opaque LSA API, while port 2600 is used for the (insecure) TCP-ZEBRA interface.

.. option:: --vty_socket vty-path

   Overrides the directory used for the <daemon>.vty sockets.  vtysh connects to these sockets in order to access each daemon's VTY.
   Default: /var/run/frr[/<pathspace>]

   NB: Unlike the other options, this option specifies a directory, not a full path.

   This option is primarily used by the SNAP packaging system, its semantics may change.  It should not be neccessary in most other scenarios.

MODULE LOADING
--------------
frr supports optional dynamically loadable modules, although these can only be loaded at startup.  The set of available modules may vary across distributions and packages, and modules may be available for installation as separate packages.

.. option:: -M, --module module[:options]

   Load a module named module, optionally passing options to it.

   If there is a ´/´ character in module, the value is assumed to be a pathname to a module.

   If there is no ´/´ character, the module directory (see next option) is searched first for a module named "<daemon>_<module>.so", then for "<module>.so".  This allows for a module to exist in variations appropriate for particular daemons, e.g. zebra_snmp and bgp_snmp, with the correct one selected by -M snmp.

   The meaning of options is specific to the module being loaded.  Most modules currently ignore it.

   Modules are loaded in the order as listed on the command line.  This is not generally relevant.

.. option:: --moduledir module-path

   Look for modules in the module-path directory instead of the default /usr/lib/frr/modules.  (This path is not affected by the -N option.)

The list of loaded modules can be inspected at runtime with the show modules VTY command.

