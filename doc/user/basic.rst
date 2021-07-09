.. _basic-commands:

**************
Basic Commands
**************

The following sections discuss commands common to all the routing daemons.

.. _config-commands:

Config Commands
===============





In a config file, you can write the debugging options, a vty's password,
routing daemon configurations, a log file name, and so forth. This information
forms the initial command set for a routing beast as it is starting.

Config files are generally found in |INSTALL_PREFIX_ETC|.

Config Methods
--------------

There are two ways of configuring FRR.

Traditionally each of the daemons had its own config file. The daemon name plus
``.conf`` was the default config file name. For example, zebra's default config
file was :file:`zebra.conf`. This method is deprecated.

Because of the amount of config files this creates, and the tendency of one
daemon to rely on others for certain functionality, most deployments now use
"integrated" configuration. In this setup all configuration goes into a single
file, typically :file:`/etc/frr/frr.conf`. When starting up FRR using an init
script or systemd, ``vtysh`` is invoked to read the config file and send the
appropriate portions to only the daemons interested in them. Running
configuration updates are persisted back to this single file using ``vtysh``.
This is the recommended method. To use this method, add the following line to
:file:`/etc/frr/vtysh.conf`:

.. code-block:: frr

   service integrated-vtysh-config

If you installed from source or used a package, this is probably already
present.

If desired, you can specify a config file using the :option:`-f` or
:option:`--config_file` options when starting a daemon.


.. _basic-config-commands:

Basic Config Commands
---------------------

.. clicmd:: hostname HOSTNAME

   Set hostname of the router.

.. clicmd:: password PASSWORD

   Set password for vty interface. The ``no`` form of the command deletes the
   password. If there is no password, a vty won't accept connections.

.. clicmd:: enable password PASSWORD

   Set enable password. The ``no`` form of the command deletes the enable
   password.

.. clicmd:: log trap LEVEL

   These commands are deprecated and are present only for historical
   compatibility. The log trap command sets the current logging level for all
   enabled logging destinations, and it sets the default for all future logging
   commands that do not specify a level. The normal default logging level is
   debugging. The ``no`` form of the command resets the default level for
   future logging commands to debugging, but it does not change the logging
   level of existing logging destinations.


.. clicmd:: log stdout LEVEL

   Enable logging output to stdout. If the optional second argument specifying
   the logging level is not present, the default logging level (typically
   debugging) will be used. The ``no`` form of the command disables logging to
   stdout. The ``LEVEL`` argument must have one of these values: emergencies,
   alerts, critical, errors, warnings, notifications, informational, or
   debugging. Note that the existing code logs its most important messages with
   severity ``errors``.

   .. warning::

      FRRouting uses the ``writev()`` system call to write log messages.  This
      call is supposed to be atomic, but in reality this does not hold for
      pipes or terminals, only regular files.  This means that in rare cases,
      concurrent log messages from distinct threads may get jumbled in
      terminal output.  Use a log file and ``tail -f`` if this rare chance is
      inacceptable to your setup.

.. clicmd:: log file [FILENAME [LEVEL]]

   If you want to log into a file, please specify ``filename`` as
   in this example:

   ::

      log file /var/log/frr/bgpd.log informational

   If the optional second argument specifying the logging level is not present,
   the default logging level (typically debugging, but can be changed using the
   deprecated ``log trap`` command) will be used. The ``no`` form of the command
   disables logging to a file.

.. clicmd:: log syslog [LEVEL]

   Enable logging output to syslog. If the optional second argument specifying
   the logging level is not present, the default logging level (typically
   debugging, but can be changed using the deprecated ``log trap`` command) will
   be used. The ``no`` form of the command disables logging to syslog.

.. clicmd:: log monitor [LEVEL]

   Enable logging output to vty terminals that have enabled logging using the
   ``terminal monitor`` command. By default, monitor logging is enabled at the
   debugging level, but this command (or the deprecated ``log trap`` command)
   can be used to change the monitor logging level. If the optional second
   argument specifying the logging level is not present, the default logging
   level (typically debugging) will be used. The ``no`` form of the command
   disables logging to terminal monitors.

.. clicmd:: log facility [FACILITY]

   This command changes the facility used in syslog messages. The default
   facility is ``daemon``. The ``no`` form of the command resets the facility
   to the default ``daemon`` facility.

.. clicmd:: log record-priority

   To include the severity in all messages logged to a file, to stdout, or to
   a terminal monitor (i.e. anything except syslog),
   use the ``log record-priority`` global configuration command.
   To disable this option, use the ``no`` form of the command. By default,
   the severity level is not included in logged messages. Note: some
   versions of syslogd can be configured to include the facility and
   level in the messages emitted.

.. clicmd:: log timestamp precision [(0-6)]

   This command sets the precision of log message timestamps to the given
   number of digits after the decimal point. Currently, the value must be in
   the range 0 to 6 (i.e. the maximum precision is microseconds). To restore
   the default behavior (1-second accuracy), use the ``no`` form of the
   command, or set the precision explicitly to 0.

   ::

      log timestamp precision 3

   In this example, the precision is set to provide timestamps with
   millisecond accuracy.

.. clicmd:: log commands

   This command enables the logging of all commands typed by a user to all
   enabled log destinations. The note that logging includes full command lines,
   including passwords. If the daemon startup option `--command-log-always`
   is used to start the daemon then this command is turned on by default
   and cannot be turned off and the [no] form of the command is dissallowed.

.. clicmd:: log-filter WORD [DAEMON]

   This command forces logs to be filtered on a specific string. A log message
   will only be printed if it matches on one of the filters in the log-filter
   table. Can be daemon independent.

   .. note::

      Log filters help when you need to turn on debugs that cause significant
      load on the system (enabling certain debugs can bring FRR to a halt).
      Log filters prevent this but you should still expect a small performance
      hit due to filtering each of all those logs.

.. clicmd:: log-filter clear [DAEMON]

   This command clears all current filters in the log-filter table. Can be
   daemon independent.


.. clicmd:: log immediate-mode

   Use unbuffered output for log and debug messages; normally there is
   some internal buffering.

.. clicmd:: service password-encryption

   Encrypt password.

.. clicmd:: service advanced-vty

   Enable advanced mode VTY.

.. clicmd:: service terminal-length (0-512)

   Set system wide line configuration. This configuration command applies to
   all VTY interfaces.

.. clicmd:: line vty

   Enter vty configuration mode.

.. clicmd:: banner motd default

   Set default motd string.

.. clicmd:: banner motd file FILE

   Set motd string from file. The file must be in directory specified
   under ``--sysconfdir``.

.. clicmd:: banner motd line LINE

   Set motd string from an input.

.. clicmd:: exec-timeout MINUTE [SECOND]

   Set VTY connection timeout value. When only one argument is specified
   it is used for timeout value in minutes. Optional second argument is
   used for timeout value in seconds. Default timeout value is 10 minutes.
   When timeout value is zero, it means no timeout.

   Not setting this, or setting the values to 0 0, means a timeout will not be
   enabled.

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
   frr version 6.0
   frr defaults traditional
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


Configuration versioning, profiles and upgrade behavior
-------------------------------------------------------

All |PACKAGE_NAME| daemons share a mechanism to specify a configuration profile
and version for loading and saving configuration.  Specific configuration
settings take different default values depending on the selected profile and
version.

While the profile can be selected by user configuration and will remain over
upgrades, |PACKAGE_NAME| will always write configurations using its current
version.  This means that, after upgrading, a ``write file`` may write out a
slightly different configuration than what was read in.

Since the previous configuration is loaded with its version's defaults, but
the new configuration is written with the new defaults, any default that
changed between versions will result in an appropriate configuration entry
being written out.  **FRRouting configuration is sticky, staying consistent
over upgrades.**  Changed defaults will only affect new configuration.

Note that the loaded version persists into interactive configuration
sessions.  Commands executed in an interactive configuration session are
no different from configuration loaded at startup.  This means that when,
say, you configure a new BGP peer, the defaults used for configuration
are the ones selected by the last ``frr version`` command.

.. warning::

   Saving the configuration does not bump the daemons forward to use the new
   version for their defaults, but restarting them will, since they will then
   apply the new ``frr version`` command that was written out.  Manually
   execute the ``frr version`` command in ``show running-config`` to avoid
   this intermediate state.

This is visible in ``show running-config``:

.. code-block:: frr

   Current configuration:
   !
   ! loaded from 6.0
   frr version 6.1-dev
   frr defaults traditional
   !

If you save and then restart with this configuration, the old defaults will
no longer apply.  Similarly, you could execute ``frr version 6.1-dev``, causing
the new defaults to apply and the ``loaded from 6.0`` comment to disappear.


Profiles
^^^^^^^^

|PACKAGE_NAME| provides configuration profiles to adapt its default settings
to various usage scenarios.  Currently, the following profiles are
implemented:

* ``traditional`` - reflects defaults adhering mostly to IETF standards or
  common practices in wide-area internet routing.
* ``datacenter`` - reflects a single administrative domain with intradomain
  links using aggressive timers.

Your distribution/installation may pre-set a profile through the ``-F`` command
line option on all daemons.  All daemons must be configured for the same
profile.  The value specified on the command line is only a pre-set and any
``frr defaults`` statement in the configuration will take precedence.

.. note::

   The profile must be the same across all daemons.  Mismatches may result
   in undefined behavior.

You can freely switch between profiles without causing any interruption or
configuration changes.  All settings remain at their previous values, and
``show running-configuration`` output will have new output listing the previous
default values as explicit configuration.  New configuration, e.g. adding a
BGP peer, will use the new defaults.  To apply the new defaults for existing
configuration, the previously-invisible old defaults that are now shown must
be removed from the configuration.


Upgrade practices for interactive configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you configure |PACKAGE_NAME| interactively and use the configuration
writing functionality to make changes persistent, the following
recommendations apply in regards to upgrades:

1. Skipping major versions should generally work but is still inadvisable.
   To avoid unneeded issue, upgrade one major version at a time and write
   out the configuration after each update.

2. After installing a new |PACKAGE_NAME| version, check the configuration
   for differences against your old configuration.  If any defaults changed
   that affect your setup, lines may appear or disappear.  If a new line
   appears, it was previously the default (or not supported) and is now
   neccessary to retain previous behavior.  If a line disappears, it
   previously wasn't the default, but now is, so it is no longer necessary.

3. Check the log files for deprecation warnings by using ``grep -i deprecat``.

4. After completing each upgrade, save the configuration and either restart
   |PACKAGE_NAME| or execute ``frr version <CURRENT>`` to ensure defaults of
   the new version are fully applied.


Upgrade practices for autogenerated configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When using |PACKAGE_NAME| with generated configurations (e.g. Ansible,
Puppet, etc.), upgrade considerations differ somewhat:

1. Always write out a ``frr version`` statement in the configurations you
   generate.  This ensures that defaults are applied consistently.

2. Try to not run more distinct versions of |PACKAGE_NAME| than necessary.
   Each version may need to be checked individually.  If running a mix of
   older and newer installations, use the oldest version for the
   ``frr version`` statement.

3. When rolling out upgrades, generate a configuration as usual with the old
   version identifier and load it.  Check for any differences or deprecation
   warnings.  If there are differences in the configuration, propagate these
   back to the configuration generator to minimize relying on actual default
   values.

4. After the last installation of an old version is removed, change the
   configuration generation to a newer ``frr version`` as appropriate.  Perform
   the same checks as when rolling out upgrades.


.. _terminal-mode-commands:

Terminal Mode Commands
======================

.. clicmd:: write terminal

   Displays the current configuration to the vty interface.

.. clicmd:: write file

   Write current configuration to configuration file.

.. clicmd:: configure [terminal]

   Change to configuration mode. This command is the first step to
   configuration.

.. clicmd:: terminal length (0-512)

   Set terminal display length to ``(0-512)``. If length is 0, no display
   control is performed.

.. clicmd:: who

   Show a list of currently connected vty sessions.

.. clicmd:: list

   List all available commands.

.. clicmd:: show version

   Show the current version of |PACKAGE_NAME| and its build host information.

.. clicmd:: show logging

   Shows the current configuration of the logging system. This includes the
   status of all logging destinations.

.. clicmd:: show log-filter

   Shows the current log filters applied to each daemon.

.. clicmd:: show memory [DAEMON]

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
   usage is printed sequentially. You can specify the daemon's name to print
   only its memory usage.

.. clicmd:: show history

   Dump the vtysh cli history.

.. clicmd:: logmsg LEVEL MESSAGE

   Send a message to all logging destinations that are enabled for messages of
   the given severity.

.. clicmd:: find REGEX...

   This command performs a regex search across all defined commands in all
   modes. As an example, suppose you're in enable mode and can't remember where
   the command to turn OSPF segment routing on is:

   ::

      frr# find segment-routing on
        (ospf)  segment-routing on
        (isis)  segment-routing on


   The CLI mode is displayed next to each command. In this example,
   :clicmd:`segment-routing on` is under the `router ospf` mode.

   Similarly, suppose you want a listing of all commands that contain "l2vpn"
   and "neighbor":

   ::

      frr# find l2vpn.*neighbor
        (view)  show [ip] bgp l2vpn evpn neighbors <A.B.C.D|X:X::X:X|WORD> advertised-routes [json]
        (view)  show [ip] bgp l2vpn evpn neighbors <A.B.C.D|X:X::X:X|WORD> routes [json]
        (view)  show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN neighbors <A.B.C.D|X:X::X:X|WORD> advertised-routes [json]
        (view)  show [ip] bgp l2vpn evpn rd ASN:NN_OR_IP-ADDRESS:NN neighbors <A.B.C.D|X:X::X:X|WORD> routes [json]
        ...


   Note that when entering spaces as part of a regex specification, repeated
   spaces will be compressed into a single space for matching purposes. This is
   a consequence of spaces being used to delimit CLI tokens. If you need to
   match more than one space, use the ``\s`` escape.

   POSIX Extended Regular Expressions are supported.


.. _common-show-commands:

.. clicmd:: show thread cpu [r|w|t|e|x]

   This command displays system run statistics for all the different event
   types. If no options is specified all different run types are displayed
   together.  Additionally you can ask to look at (r)ead, (w)rite, (t)imer,
   (e)vent and e(x)ecute thread event types.  If you have compiled with
   disable-cpu-time then this command will not show up.

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

.. option:: --limit-fds <number>

   Limit the number of file descriptors that will be used internally
   by the FRR daemons. By default, the daemons use the system ulimit
   value.

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

