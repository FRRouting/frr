.. _basic-commands:

**************
Basic Commands
**************

The following sections discuss commands common to all the routing daemons.

.. _config-commands:

Config Commands
===============

.. index:: Configuration files for running the software

.. index:: Files for running configurations

.. index:: Modifying the herd's behavior

.. index:: Getting the herd running

In a config file, you can write the debugging options, a vty's password,
routing daemon configurations, a log file name, and so forth. This information
forms the initial command set for a routing beast as it is starting.

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
   debugging. The ``no`` form of the command resets the default level for
   future logging commands to debugging, but it does not change the logging
   level of existing logging destinations.

.. index::
   single: no log stdout [LEVEL]
   single: log stdout [LEVEL]

.. clicmd:: [no] log stdout LEVEL

   Enable logging output to stdout. If the optional second argument specifying
   the logging level is not present, the default logging level (typically
   debugging) will be used. The ``no`` form of the command disables logging to
   stdout. The ``LEVEL`` argument must have one of these values: emergencies,
   alerts, critical, errors, warnings, notifications, informational, or
   debugging. Note that the existing code logs its most important messages with
   severity ``errors``.

.. index::
   single: no log file [FILENAME [LEVEL]]
   single: log file FILENAME [LEVEL]

.. clicmd:: [no] log file [FILENAME [LEVEL]]

   If you want to log into a file, please specify ``filename`` as
   in this example:

   ::

      log file /var/log/frr/bgpd.log informational

   If the optional second argument specifying the logging level is not present,
   the default logging level (typically debugging, but can be changed using the
   deprecated ``log trap`` command) will be used. The ``no`` form of the command
   disables logging to a file.

   .. note::

      If you do not configure any file logging, and a daemon crashes due to a
      signal or an assertion failure, it will attempt to save the crash
      information in a file named :file:`/var/tmp/frr.<daemon name>.crashlog`.
      For security reasons, this will not happen if the file exists already, so
      it is important to delete the file after reporting the crash information.

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
   debugging level, but this command (or the deprecated ``log trap`` command)
   can be used to change the monitor logging level. If the optional second
   argument specifying the logging level is not present, the default logging
   level (typically debugging) will be used. The ``no`` form of the command
   disables logging to terminal monitors.

.. index::
   single: no log facility [FACILITY]
   single: log facility [FACILITY]

.. clicmd:: [no] log facility [FACILITY]

   This command changes the facility used in syslog messages. The default
   facility is ``daemon``. The ``no`` form of the command resets the facility
   to the default ``daemon`` facility.

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

   This command sets the precision of log message timestamps to the given
   number of digits after the decimal point. Currently, the value must be in
   the range 0 to 6 (i.e. the maximum precision is microseconds). To restore
   the default behavior (1-second accuracy), use the ``no`` form of the
   command, or set the precision explicitly to 0.

   ::

      log timestamp precision 3

   In this example, the precision is set to provide timestamps with
   millisecond accuracy.

.. index:: [no] log commands
.. clicmd:: [no] log commands

   This command enables the logging of all commands typed by a user to all
   enabled log destinations. The note that logging includes full command lines,
   including passwords. If the daemon startup option `--command-log-always`
   is used to start the daemon then this command is turned on by default
   and cannot be turned off and the [no] form of the command is dissallowed.

.. index::
   single: no log-filter WORD [DAEMON]
   single: log-filter WORD [DAEMON]

.. clicmd:: [no] log-filter WORD [DAEMON]

   This command forces logs to be filtered on a specific string. A log message
   will only be printed if it matches on one of the filters in the log-filter
   table. Can be daemon independent.

   .. note::

      Log filters help when you need to turn on debugs that cause significant
      load on the system (enabling certain debugs can bring FRR to a halt).
      Log filters prevent this but you should still expect a small performance
      hit due to filtering each of all those logs.

.. index:: log-filter clear [DAEMON]
.. clicmd:: log-filter clear [DAEMON]

   This command clears all current filters in the log-filter table. Can be
   daemon independent.

.. index:: service password-encryption
.. clicmd:: service password-encryption

   Encrypt password.

.. index:: service advanced-vty
.. clicmd:: service advanced-vty

   Enable advanced mode VTY.

.. index:: service terminal-length (0-512)
.. clicmd:: service terminal-length (0-512)

   Set system wide line configuration. This configuration command applies to
   all VTY interfaces.

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

   Do not perform timeout at all. This command is as same as
   ``exec-timeout 0 0``.

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


``!`` and ``#`` are comment characters. If the first character of the word is
one of the comment characters then from the rest of the line forward will be
ignored as a comment.

.. code-block:: frr

   password zebra!password

If a comment character is not the first character of the word, it's a normal
character. So in the above example ``!`` will not be regarded as a comment and
the password is set to ``zebra!password``.

.. _terminal-mode-commands:

Terminal Mode Commands
======================

.. index:: write terminal
.. clicmd:: write terminal

   Displays the current configuration to the vty interface.

.. index:: write file
.. clicmd:: write file

   Write current configuration to configuration file.

.. index:: configure [terminal]
.. clicmd:: configure [terminal]

   Change to configuration mode. This command is the first step to
   configuration.

.. index:: terminal length (0-512)
.. clicmd:: terminal length (0-512)

   Set terminal display length to ``(0-512)``. If length is 0, no display
   control is performed.

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

   Shows the current configuration of the logging system. This includes the
   status of all logging destinations.

.. index:: show log-filter
.. clicmd:: show log-filter

   Shows the current log filters applied to each daemon.

.. index:: show memory
.. clicmd:: show memory

   Show information on how much memory is used for which specific things in
   |PACKAGE_NAME|.  Output may vary depending on system capabilities but will
   generally look something like this:

   ::

      frr# show memory
      System allocator statistics:
        Total heap allocated:  1584 KiB
        Holding block headers: 0 bytes
        Used small blocks:     0 bytes
        Used ordinary blocks:  1484 KiB
        Free small blocks:     2096 bytes
        Free ordinary blocks:  100 KiB
        Ordinary blocks:       2
        Small blocks:          60
        Holding blocks:        0
      (see system documentation for 'mallinfo' for meaning)
      --- qmem libfrr ---
      Buffer                        :          3      24                  72
      Buffer data                   :          1    4120                4120
      Host config                   :          3  (variably sized)        72
      Command Tokens                :       3427      72              247160
      Command Token Text            :       2555  (variably sized)     83720
      Command Token Help            :       2555  (variably sized)     61720
      Command Argument              :          2  (variably sized)        48
      Command Argument Name         :        641  (variably sized)     15672
      [...]
      --- qmem Label Manager ---
      --- qmem zebra ---
      ZEBRA VRF                     :          1     912                 920
      Route Entry                   :         11      80                 968
      Static route                  :          1     192                 200
      RIB destination               :          8      48                 448
      RIB table info                :          4      16                  96
      Nexthop tracking object       :          1     200                 200
      Zebra Name Space              :          1     312                 312
      --- qmem Table Manager ---

   To understand system allocator statistics, refer to your system's
   :manpage:`mallinfo(3)` man page.

   Below these statistics, statistics on individual memory allocation types
   in |PACKAGE_NAME| (so-called `MTYPEs`) is printed:

   * the first column of numbers is the current count of allocations made for
     the type (the number decreases when items are freed.)
   * the second column is the size of each item.  This is only available if
     allocations on a type are always made with the same size.
   * the third column is the total amount of memory allocated for the
     particular type, including padding applied by malloc.  This means that
     the number may be larger than the first column multiplied by the second.
     Overhead incurred by malloc's bookkeeping is not included in this, and
     the column may be missing if system support is not available.

   When executing this command from ``vtysh``, each of the daemons' memory
   usage is printed sequentially.

.. index:: logmsg LEVEL MESSAGE
.. clicmd:: logmsg LEVEL MESSAGE

   Send a message to all logging destinations that are enabled for messages of
   the given severity.

.. index:: find COMMAND...
.. clicmd:: find COMMAND...

   This command performs a simple substring search across all defined commands
   in all modes. As an example, suppose you're in enable mode and can't
   remember where the command to turn OSPF segment routing on is:

   ::

      frr# find segment-routing on
        (ospf)  segment-routing on

   The CLI mode is displayed next to each command. In this example,
   :clicmd:`segment-routing on` is under the `router ospf` mode.

   Similarly, suppose you want a listing of all commands that contain "l2vpn":

   ::

      frr# find l2vpn
        (view)  show [ip] bgp l2vpn evpn [json]
        (view)  show [ip] bgp l2vpn evpn all <A.B.C.D|A.B.C.D/M> [json]
        (view)  show [ip] bgp l2vpn evpn all neighbors A.B.C.D advertised-routes [json]
        (view)  show [ip] bgp l2vpn evpn all neighbors A.B.C.D routes [json]
        (view)  show [ip] bgp l2vpn evpn all overlay
        ...

.. _common-show-commands:

.. index:: show thread cpu
.. clicmd:: show thread cpu [r|w|t|e|x]

   This command displays system run statistics for all the different event
   types. If no options is specified all different run types are displayed
   together.  Additionally you can ask to look at (r)ead, (w)rite, (t)imer,
   (e)vent and e(x)ecute thread event types.  If you have compiled with
   disable-cpu-time then this command will not show up.

.. index:: show thread poll
.. clicmd:: show thread poll

   This command displays FRR's poll data.  It allows a glimpse into how
   we are setting each individual fd for the poll command at that point
   in time.

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

   The file name is an run-time option rather than a configure-time option so
   that multiple routing daemons can be run simultaneously. This is useful when
   using |PACKAGE_NAME| to implement a routing looking glass. One machine can
   be used to collect differing routing views from differing points in the
   network.

.. option:: -A, --vty_addr <address>

   Set the VTY local address to bind to. If set, the VTY socket will only be
   bound to this address.

.. option:: -P, --vty_port <port>

   Set the VTY TCP port number. If set to 0 then the TCP VTY sockets will not
   be opened.

.. option:: -u <user>

   Set the user and group to run as.

.. option:: -N <namespace>

   Set the namespace that the daemon will run in.  A "/<namespace>" will
   be added to all files that use the statedir.  If you have "/var/run/frr"
   as the default statedir then it will become "/var/run/frr/<namespace>".

.. option:: -v, --version

   Print program version.

.. option:: --command-log-always

   Cause the daemon to always log commands entered to the specified log file.
   This also makes the `no log commands` command dissallowed.  Enabling this
   is suggested if you have need to track what the operator is doing on
   this router.

.. option:: --log <stdout|syslog|file:/path/to/log/file>

   When initializing the daemon, setup the log to go to either stdout,
   syslog or to a file.  These values will be displayed as part of
   a show run.  Additionally they can be overridden at runtime if
   desired via the normal log commands.

.. option:: --log-level <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>

   When initializing the daemon, allow the specification of a default
   log level at startup from one of the specified levels.

.. option:: --tcli

   Enable the transactional CLI mode.

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
the ``snmp`` module can be loaded for the *Zebra*, *bgpd*, *ospfd*, *ospf6d*
and *ripd* daemons.

The module ignores any options passed to it. Refer to :ref:`snmp-support` for
information on its usage.


The FPM Module
--------------

If FPM is enabled during compile-time and installed as part of the package, the
``fpm`` module can be loaded for the *zebra* daemon. This provides the
Forwarding Plane Manager ("FPM") API.

The module expects its argument to be either ``Netlink`` or ``protobuf``,
specifying the encapsulation to use. ``Netlink`` is the default, and
``protobuf`` may not be available if the module was built without protobuf
support. Refer to :ref:`zebra-fib-push-interface` for more information.


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

Pipe Actions
^^^^^^^^^^^^

VTY supports optional modifiers at the end of commands that perform
postprocessing on command output or modify the action of commands. These do not
show up in the :kbd:`?` or :kbd:`TAB` suggestion lists.

``... | include REGEX``
   Filters the output of the preceding command, including only lines which
   match the POSIX Extended Regular Expression ``REGEX``. Do not put the regex
   in quotes.

   Examples:

   ::

      frr# show ip bgp sum json | include remoteAs
            "remoteAs":0,
            "remoteAs":455,
            "remoteAs":99,

   ::

      frr# show run | include neigh.*[0-9]{2}\.0\.[2-4]\.[0-9]*
       neighbor 10.0.2.106 remote-as 99
       neighbor 10.0.2.107 remote-as 99
       neighbor 10.0.2.108 remote-as 99
       neighbor 10.0.2.109 remote-as 99
       neighbor 10.0.2.110 remote-as 99
       neighbor 10.0.3.111 remote-as 111

