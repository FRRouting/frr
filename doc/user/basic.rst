.. _basic-commands:

**************
Basic commands
**************

There are five routing daemons in use, and there is one manager daemon.
These daemons may be located on separate machines from the manager
daemon. Each of these daemons will listen on a particular port for
incoming VTY connections. The routing daemons are:

- *ripd*
- *ripngd*
- *ospfd*
- *ospf6d*
- *bgpd*
- *zebra*

The following sections discuss commands common to all the routing
daemons.

.. _config-commands:

Config Commands
===============

.. index:: Configuration files for running the software

.. index:: Files for running configurations

.. index:: Modifying the herd's behavior

.. index:: Getting the herd running

In a config file, you can write the debugging options, a vty's password,
routing daemon configurations, a log file name, and so forth. This
information forms the initial command set for a routing beast as it is
starting.

Config files are generally found in |INSTALL_PREFIX_ETC|.

Each of the daemons has its own config file. The daemon name plus ``.conf`` is
the default config file name. For example, zebra's default config file name is
:file:`zebra.conf`. You can specify a config file using the :option:`-f` or
:option:`--config_file` options when starting the daemon.

.. _basic-config-commands:

Basic Config Commands
---------------------

.. index:: hostname HOSTNAME

.. clicmd:: hostname HOSTNAME

   Set hostname of the router.

.. index::
   single: no password PASSWORD
   single: password PASSWORD

.. clicmd:: [no] password PASSWORD

   Set password for vty interface. The ``no`` form of the command deletes the
   password. If there is no password, a vty won't accept connections.

.. index::
   single: no enable password PASSWORD
   single: enable password PASSWORD

.. clicmd:: [no] enable password PASSWORD

   Set enable password. The ``no`` form of the command deletes the enable
   password.

.. index::
   single: no log trap [LEVEL]
   single: log trap LEVEL

.. clicmd:: [no] log trap LEVEL

   These commands are deprecated and are present only for historical
   compatibility. The log trap command sets the current logging level for all
   enabled logging destinations, and it sets the default for all future logging
   commands that do not specify a level. The normal default logging level is
   debugging. The ``no`` form of the command resets the default level for future
   logging commands to debugging, but it does not change the logging level of
   existing logging destinations.

.. index::
   single: no log stdout [LEVEL]
   single: log stdout [LEVEL]

.. clicmd:: [no] log stdout LEVEL

   Enable logging output to stdout. If the optional second argument specifying
   the logging level is not present, the default logging level (typically
   debugging, but can be changed using the deprecated ``log trap`` command) will
   be used. The ``no`` form of the command disables logging to stdout. The
   ``LEVEL`` argument must have one of these values: emergencies, alerts,
   critical, errors, warnings, notifications, informational, or debugging. Note
   that the existing code logs its most important messages with severity
   ``errors``.

.. index::
   single: no log file [FILENAME [LEVEL]]
   single: log file FILENAME [LEVEL]

.. clicmd:: [no] log file [FILENAME [LEVEL]]

   If you want to log into a file, please specify ``filename`` as
   in this example: ::

     log file /var/log/frr/bgpd.log informational

   If the optional second argument specifying the logging level is not present,
   the default logging level (typically debugging, but can be changed using the
   deprecated ``log trap`` command) will be used. The ``no`` form of the command
   disables logging to a file. *Note:* if you do not configure any file logging,
   and a daemon crashes due to a signal or an assertion failure, it will attempt
   to save the crash information in a file named /var/tmp/frr.<daemon
   name>.crashlog. For security reasons, this will not happen if the file exists
   already, so it is important to delete the file after reporting the crash
   information.

.. index::
   single: no log syslog [LEVEL]
   single: log syslog [LEVEL]

.. clicmd:: [no] log syslog [LEVEL]

   Enable logging output to syslog. If the optional second argument specifying
   the logging level is not present, the default logging level (typically
   debugging, but can be changed using the deprecated ``log trap`` command) will
   be used. The ``no`` form of the command disables logging to syslog.

.. index::
   single: no log monitor [LEVEL]
   single: log monitor [LEVEL]

.. clicmd:: [no] log monitor [LEVEL]

   Enable logging output to vty terminals that have enabled logging using the
   ``terminal monitor`` command. By default, monitor logging is enabled at the
   debugging level, but this command (or the deprecated ``log trap`` command) can
   be used to change the monitor logging level. If the optional second argument
   specifying the logging level is not present, the default logging level
   (typically debugging, but can be changed using the deprecated ``log trap``
   command) will be used. The ``no`` form of the command disables logging to
   terminal monitors.

.. index::
   single: no log facility [FACILITY]
   single: log facility [FACILITY]

.. clicmd:: [no] log facility [FACILITY]

   This command changes the facility used in syslog messages. The default
   facility is ``daemon``. The ``no`` form of the command resets
   the facility to the default ``daemon`` facility.

.. index::
   single: no log record-priority
   single: log record-priority

.. clicmd:: [no] log record-priority

   To include the severity in all messages logged to a file, to stdout, or to
   a terminal monitor (i.e. anything except syslog),
   use the ``log record-priority`` global configuration command.
   To disable this option, use the ``no`` form of the command. By default,
   the severity level is not included in logged messages. Note: some
   versions of syslogd (including Solaris) can be configured to include
   the facility and level in the messages emitted.

.. index::
   single: log timestamp precision (0-6)
   single: [no] log timestamp precision (0-6)

.. clicmd:: [no] log timestamp precision [(0-6)]

   This command sets the precision of log message timestamps to the given number
   of digits after the decimal point. Currently, the value must be in the range
   0 to 6 (i.e. the maximum precision is microseconds). To restore the default
   behavior (1-second accuracy), use the ``no`` form of the command, or set the
   precision explicitly to 0.

::

     log timestamp precision 3

   In this example, the precision is set to provide timestamps with
   millisecond accuracy.

.. index:: log commands

.. clicmd:: log commands

   This command enables the logging of all commands typed by a user to
   all enabled log destinations. The note that logging includes full
   command lines, including passwords. Once set, command logging can only
   be turned off by restarting the daemon.

.. index:: service password-encryption

.. clicmd:: service password-encryption

   Encrypt password.

.. index:: service advanced-vty

.. clicmd:: service advanced-vty

   Enable advanced mode VTY.

.. index:: service terminal-length (0-512)

.. clicmd:: service terminal-length (0-512)

   Set system wide line configuration. This configuration command applies
   to all VTY interfaces.

.. index:: line vty

.. clicmd:: line vty

   Enter vty configuration mode.

.. index:: banner motd default

.. clicmd:: banner motd default

   Set default motd string.

.. index:: no banner motd

.. clicmd:: no banner motd

   No motd banner string will be printed.

.. index:: exec-timeout MINUTE [SECOND]

.. clicmd:: exec-timeout MINUTE [SECOND]

   Set VTY connection timeout value. When only one argument is specified
   it is used for timeout value in minutes. Optional second argument is
   used for timeout value in seconds. Default timeout value is 10 minutes.
   When timeout value is zero, it means no timeout.

.. index:: no exec-timeout

.. clicmd:: no exec-timeout

   Do not perform timeout at all. This command is as same as *exec-timeout 0 0*.

.. index:: access-class ACCESS-LIST

.. clicmd:: access-class ACCESS-LIST

   Restrict vty connections with an access list.

.. _sample-config-file:

Sample Config File
------------------

Below is a sample configuration file for the zebra daemon.

.. code-block:: frr

   !
   ! Zebra configuration file
   !
   hostname Router
   password zebra
   enable password zebra
   !
   log stdout
   !
   !


'!' and '#' are comment characters. If the first character of the word
is one of the comment characters then from the rest of the line forward
will be ignored as a comment.

.. code-block:: frr

   password zebra!password

If a comment character is not the first character of the word, it's a
normal character. So in the above example '!' will not be regarded as a
comment and the password is set to 'zebra!password'.

.. _terminal-mode-commands:

Terminal Mode Commands
======================

.. index:: write terminal

.. clicmd:: write terminal

   Displays the current configuration to the vty interface.

.. index:: write file

.. clicmd:: write file

   Write current configuration to configuration file.

.. index:: configure terminal

.. clicmd:: configure terminal

   Change to configuration mode. This command is the first step to
   configuration.

.. index:: terminal length (0-512)

.. clicmd:: terminal length (0-512)

   Set terminal display length to ``(0-512)``. If length is 0, no
   display control is performed.

.. index:: who

.. clicmd:: who

   Show a list of currently connected vty sessions.

.. index:: list

.. clicmd:: list

   List all available commands.

.. index:: show version

.. clicmd:: show version

   Show the current version of |PACKAGE_NAME| and its build host information.

.. index:: show logging

.. clicmd:: show logging

   Shows the current configuration of the logging system. This includes
   the status of all logging destinations.

.. index:: logmsg LEVEL MESSAGE

.. clicmd:: logmsg LEVEL MESSAGE

   Send a message to all logging destinations that are enabled for messages
   of the given severity.

.. _common-invocation-options:

Common Invocation Options
=========================

These options apply to all |PACKAGE_NAME| daemons.


.. option:: -d, --daemon

   Run in daemon mode.

.. option:: -f, --config_file <file>

   Set configuration file name.

.. option:: -h, --help

   Display this help and exit.

.. option:: -i, --pid_file <file>

   Upon startup the process identifier of the daemon is written to a file,
   typically in :file:`/var/run`. This file can be used by the init system
   to implement commands such as ``.../init.d/zebra status``,
   ``.../init.d/zebra restart`` or ``.../init.d/zebra stop``.

   The file name is an run-time option rather than a configure-time option
   so that multiple routing daemons can be run simultaneously. This is
   useful when using |PACKAGE_NAME| to implement a routing looking glass. One
   machine can be used to collect differing routing views from differing
   points in the network.

.. option:: -A, --vty_addr <address>

   Set the VTY local address to bind to. If set, the VTY socket will only
   be bound to this address.

.. option:: -P, --vty_port <port>

   Set the VTY TCP port number. If set to 0 then the TCP VTY sockets will not
   be opened.

.. option:: -u <user>

   Set the user and group to run as.

.. option:: -v, --version

   Print program version.

.. _loadable-module-support:

Loadable Module Support
=======================

FRR supports loading extension modules at startup. Loading, reloading or
unloading modules at runtime is not supported (yet). To load a module, use
the following command line option at daemon startup:


.. option:: -M, --module <module:options>

   Load the specified module, optionally passing options to it. If the module
   name contains a slash (/), it is assumed to be a full pathname to a file to
   be loaded. If it does not contain a slash, the |INSTALL_PREFIX_MODULES|
   directory is searched for a module of the given name; first with the daemon
   name prepended (e.g. ``zebra_mod`` for ``mod``), then without the daemon
   name prepended.

   This option is available on all daemons, though some daemons may not have
   any modules available to be loaded.

The SNMP Module
---------------

If SNMP is enabled during compile-time and installed as part of the package,
the ``snmp`` module can be loaded for the *zebra*, *bgpd*, *ospfd*, *ospf6d*
and *ripd* daemons.

The module ignores any options passed to it. Refer to :ref:`snmp-support`
for information on its usage.

The FPM Module
--------------

If FPM is enabled during compile-time and installed as part of the package, the
``fpm`` module can be loaded for the *zebra* daemon. This provides the
Forwarding Plane Manager ("FPM") API.

The module expects its argument to be either ``Netlink`` or ``protobuf``,
specifying the encapsulation to use. ``Netlink`` is the default, and
``protobuf`` may not be available if the module was built without protobuf
support. Refer to :ref:`zebra-fib-push-interface` for more information.

The Script WRAP Module
----------------------

If Wrap Script is enabled during compile-time and installed as part of the
package, the ``wrap_script`` module can be loaded for the *Zebra* daemon. This
provides the *Zebra* Script Wrapper interface to be available for handling
underlying firewall elements. Specifically, if the system where FRR is is Linux,
default firewall used is `Linux netfilters`. Note that the interface terminology
is tightly linked with `Linux netfilters` main objects, that is to say `iptables`
and `ipset`. But we will see that that module can configure or monitor other
similar objects.
Instead of using ioctl() operations, this wrap interface permits using either
underlying shell commands ( from where the FRR is based on) or custom scripts. This
can be done by using a vty command to configure which execution path to call for
`iptables` or `ipset` object. The vty commands can directly configure the native
Linux netfilter tools. Or the vty commands can reference external shell script that
will be called. This second case may be used for non Linux systems, or for users
that do not want to use netfilters, but want to use an other set of tools like `eBPF`
or `NFTables`.
The wrap script module proposes configuration APIs to create `ipset` and `iptables`
objects. Monitoring APIs will first return a json like format based on the output
of the 2 underlying objects. Here too, the format analysed is tightly linked with
the Linux format of `ipset` and `iptables`. However, even if the tools used are not
based on `Netfilter`, it will still be possible to use a strict to return json format
output similar to `ipset` and `iptables`.

.. _virtual-terminal-interfaces:

Virtual Terminal Interfaces
===========================

VTY -- Virtual Terminal [aka TeletYpe] Interface is a command line
interface (CLI) for user interaction with the routing daemon.

.. _vty-overview:

VTY Overview
------------

VTY stands for Virtual TeletYpe interface. It means you can connect to
the daemon via the telnet protocol.

To enable a VTY interface, you have to setup a VTY password. If there
is no VTY password, one cannot connect to the VTY interface at all.

::

   % telnet localhost 2601
   Trying 127.0.0.1...
   Connected to localhost.
   Escape character is '^]'.

   Hello, this is |PACKAGE_NAME| (version |PACKAGE_VERSION|)
   |COPYRIGHT_STR|

   User Access Verification

   Password: XXXXX
   Router> ?
     enable .  .  .  Turn on privileged commands
     exit   .  .  .  Exit current mode and down to previous mode
     help   .  .  .  Description of the interactive help system
     list   .  .  .  Print command list
     show   .  .  .  Show system inform

     wh. . .  Display who is on a vty
   Router> enable
   Password: XXXXX
   Router# configure terminal
   Router(config)# interface eth0
   Router(config-if)# ip address 10.0.0.1/8
   Router(config-if)# ^Z
   Router#


:kbd:`?` and the ``find`` command are very useful for looking up commands.

.. _vty-modes:

VTY Modes
---------

There are three basic VTY modes:

There are commands that may be restricted to specific VTY modes.

.. _vty-view-mode:

VTY View Mode
^^^^^^^^^^^^^

This mode is for read-only access to the CLI. One may exit the mode by
leaving the system, or by entering `enable` mode.

.. _vty-enable-mode:

VTY Enable Mode
^^^^^^^^^^^^^^^

This mode is for read-write access to the CLI. One may exit the mode by
leaving the system, or by escaping to view mode.

.. _vty-other-modes:

VTY Other Modes
^^^^^^^^^^^^^^^

This page is for describing other modes.

.. _vty-cli-commands:

VTY CLI Commands
----------------

Commands that you may use at the command-line are described in the following
three subsubsections.

.. _cli-movement-commands:

CLI Movement Commands
^^^^^^^^^^^^^^^^^^^^^

These commands are used for moving the CLI cursor. The :kbd:`C` character
means press the Control Key.

:kbd:`C-f` / :kbd:`LEFT`
   Move forward one character.

:kbd:`C-b` / :kbd:`RIGHT`
   Move backward one character.

:kbd:`M-f`
   Move forward one word.

:kbd:`M-b`
   Move backward one word.

:kbd:`C-a`
   Move to the beginning of the line.

:kbd:`C-e`
   Move to the end of the line.


.. _cli-editing-commands:

CLI Editing Commands
^^^^^^^^^^^^^^^^^^^^

These commands are used for editing text on a line. The :kbd:`C`
character means press the Control Key.


:kbd:`C-h` / :kbd:`DEL`
   Delete the character before point.


:kbd:`C-d`
   Delete the character after point.


:kbd:`M-d`
   Forward kill word.


:kbd:`C-w`
   Backward kill word.


:kbd:`C-k`
   Kill to the end of the line.


:kbd:`C-u`
   Kill line from the beginning, erasing input.


:kbd:`C-t`
   Transpose character.


CLI Advanced Commands
^^^^^^^^^^^^^^^^^^^^^

There are several additional CLI commands for command line completions,
insta-help, and VTY session management.


:kbd:`C-c`
   Interrupt current input and moves to the next line.


:kbd:`C-z`
   End current configuration session and move to top node.


:kbd:`C-n` / :kbd:`DOWN`
   Move down to next line in the history buffer.


:kbd:`C-p` / :kbd:`UP`
   Move up to previous line in the history buffer.


:kbd:`TAB`
   Use command line completion by typing :kbd:`TAB`.


:kbd:`?`
   You can use command line help by typing ``help`` at the beginning of the
   line.  Typing :kbd:`?` at any point in the line will show possible
   completions.

