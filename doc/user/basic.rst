.. _Basic_commands:

**************
Basic commands
**************

There are five routing daemons in use, and there is one manager daemon.
These daemons may be located on separate machines from the manager
daemon.  Each of these daemons will listen on a particular port for
incoming VTY connections.  The routing daemons are:

* *ripd*, *ripngd*, *ospfd*, *ospf6d*, *bgpd*
* *zebra*

The following sections discuss commands common to all the routing
daemons.

.. _Config_Commands:

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

Config files are generally found in:

* :file:`@value{INSTALL_PREFIX_ETC}`/\*.conf

Each of the daemons has its own
config file.  For example, zebra's default config file name is:

* :file:`@value{INSTALL_PREFIX_ETC`/zebra.conf}

The daemon name plus :file:`.conf` is the default config file name. You
can specify a config file using the @kbd{-f} or @kbd{--config-file}
options when starting the daemon.

.. _Basic_Config_Commands:

Basic Config Commands
---------------------

.. index:: Command {hostname `hostname`} {}

Command {hostname `hostname`} {}
  Set hostname of the router.

.. index:: Command {password `password`} {}

Command {password `password`} {}
  Set password for vty interface.  If there is no password, a vty won't
  accept connections.

.. index:: Command {enable password `password`} {}

Command {enable password `password`} {}
  Set enable password.

.. index:: Command {log trap `level`} {}

Command {log trap `level`} {}
.. index:: Command {no log trap} {}

Command {no log trap} {}
    These commands are deprecated and are present only for historical compatibility.
    The log trap command sets the current logging level for all enabled
    logging destinations, and it sets the default for all future logging commands
    that do not specify a level.  The normal default
    logging level is debugging.  The `no` form of the command resets
    the default level for future logging commands to debugging, but it does
    not change the logging level of existing logging destinations.

.. index:: Command {log stdout} {}

Command {log stdout} {}
.. index:: Command {log stdout `level`} {}

Command {log stdout `level`} {}
.. index:: Command {no log stdout} {}

Command {no log stdout} {}
        Enable logging output to stdout. 
        If the optional second argument specifying the
        logging level is not present, the default logging level (typically debugging,
        but can be changed using the deprecated `log trap` command) will be used.
        The `no` form of the command disables logging to stdout.
        The `level` argument must have one of these values: 
        emergencies, alerts, critical, errors, warnings, notifications, informational, or debugging.  Note that the existing code logs its most important messages
        with severity `errors`.

.. index:: Command {log file `filename`} {}

Command {log file `filename`} {}
.. index:: Command {log file `filename` `level`} {}

Command {log file `filename` `level`} {}
.. index:: Command {no log file} {}

Command {no log file} {}
            If you want to log into a file, please specify `filename` as
            in this example::

              log file /var/log/frr/bgpd.log informational
              
            If the optional second argument specifying the
            logging level is not present, the default logging level (typically debugging,
            but can be changed using the deprecated `log trap` command) will be used.
            The `no` form of the command disables logging to a file.

            Note: if you do not configure any file logging, and a daemon crashes due
            to a signal or an assertion failure, it will attempt to save the crash
            information in a file named /var/tmp/frr.<daemon name>.crashlog.
            For security reasons, this will not happen if the file exists already, so
            it is important to delete the file after reporting the crash information.

.. index:: Command {log syslog} {}

Command {log syslog} {}
.. index:: Command {log syslog `level`} {}

Command {log syslog `level`} {}
.. index:: Command {no log syslog} {}

Command {no log syslog} {}
                Enable logging output to syslog.
                If the optional second argument specifying the
                logging level is not present, the default logging level (typically debugging,
                but can be changed using the deprecated `log trap` command) will be used.
                The `no` form of the command disables logging to syslog.

.. index:: Command {log monitor} {}

Command {log monitor} {}
.. index:: Command {log monitor `level`} {}

Command {log monitor `level`} {}
.. index:: Command {no log monitor} {}

Command {no log monitor} {}
                    Enable logging output to vty terminals that have enabled logging
                    using the `terminal monitor` command.
                    By default, monitor logging is enabled at the debugging level, but this
                    command (or the deprecated `log trap` command) can be used to change 
                    the monitor logging level.
                    If the optional second argument specifying the
                    logging level is not present, the default logging level (typically debugging,
                    but can be changed using the deprecated `log trap` command) will be used.
                    The `no` form of the command disables logging to terminal monitors.

.. index:: Command {log facility `facility`} {}

Command {log facility `facility`} {}
.. index:: Command {no log facility} {}

Command {no log facility} {}
                      This command changes the facility used in syslog messages.  The default
                      facility is `daemon`.  The `no` form of the command resets
                      the facility to the default `daemon` facility.

.. index:: Command {log record-priority} {}

Command {log record-priority} {}
.. index:: Command {no log record-priority} {}

Command {no log record-priority} {}
                        To include the severity in all messages logged to a file, to stdout, or to
                        a terminal monitor (i.e. anything except syslog),
                        use the `log record-priority` global configuration command.
                        To disable this option, use the `no` form of the command.  By default,
                        the severity level is not included in logged messages.  Note: some
                        versions of syslogd (including Solaris) can be configured to include
                        the facility and level in the messages emitted.

.. index:: Command {log timestamp precision `<0-6>`} {}

Command {log timestamp precision `<0-6>`} {}
.. index:: Command {no log timestamp precision} {}

Command {no log timestamp precision} {}
                          This command sets the precision of log message timestamps to the
                          given number of digits after the decimal point.  Currently,
                          the value must be in the range 0 to 6 (i.e. the maximum precision
                          is microseconds).
                          To restore the default behavior (1-second accuracy), use the
                          `no` form of the command, or set the precision explicitly to 0.

::

                            @group
                            log timestamp precision 3
                            @end group
                            

                          In this example, the precision is set to provide timestamps with
                          millisecond accuracy.

.. index:: Command {log commands} {}

Command {log commands} {}
                          This command enables the logging of all commands typed by a user to
                          all enabled log destinations.  The note that logging includes full
                          command lines, including passwords.  Once set, command logging can only
                          be turned off by restarting the daemon.

.. index:: Command {service password-encryption} {}

Command {service password-encryption} {}
                          Encrypt password.

.. index:: Command {service advanced-vty} {}

Command {service advanced-vty} {}
                          Enable advanced mode VTY.

.. index:: Command {service terminal-length `<0-512>`} {}

Command {service terminal-length `<0-512>`} {}
                          Set system wide line configuration.  This configuration command applies
                          to all VTY interfaces.

.. index:: Command {line vty} {}

Command {line vty} {}
                          Enter vty configuration mode.

.. index:: Command {banner motd default} {}

Command {banner motd default} {}
                          Set default motd string.

.. index:: Command {no banner motd} {}

Command {no banner motd} {}
                          No motd banner string will be printed.

.. index:: {Line Command} {exec-timeout `minute`} {}

{Line Command} {exec-timeout `minute`} {}
.. index:: {Line Command} {exec-timeout `minute` `second`} {}

{Line Command} {exec-timeout `minute` `second`} {}
                            Set VTY connection timeout value.  When only one argument is specified
                            it is used for timeout value in minutes.  Optional second argument is
                            used for timeout value in seconds. Default timeout value is 10 minutes.
                            When timeout value is zero, it means no timeout.

.. index:: {Line Command} {no exec-timeout} {}

{Line Command} {no exec-timeout} {}
                            Do not perform timeout at all.  This command is as same as
                            *exec-timeout 0 0*.

.. index:: {Line Command} {access-class `access-list`} {}

{Line Command} {access-class `access-list`} {}
                            Restrict vty connections with an access list.

.. _Sample_Config_File:

Sample Config File
------------------

Below is a sample configuration file for the zebra daemon.

::

  @group
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
  @end group
  

'!' and '#' are comment characters.  If the first character of the word
is one of the comment characters then from the rest of the line forward
will be ignored as a comment.

::

  password zebra!password
  

If a comment character is not the first character of the word, it's a
normal character. So in the above example '!' will not be regarded as a
comment and the password is set to 'zebra!password'.

.. _Terminal_Mode_Commands:

Terminal Mode Commands
======================

.. index:: Command {write terminal} {}

Command {write terminal} {}
  Displays the current configuration to the vty interface.

.. index:: Command {write file} {}

Command {write file} {}
  Write current configuration to configuration file.

.. index:: Command {configure terminal} {}

Command {configure terminal} {}
  Change to configuration mode.  This command is the first step to
  configuration.

.. index:: Command {terminal length `<0-512>`} {}

Command {terminal length `<0-512>`} {}
  Set terminal display length to `<0-512>`.  If length is 0, no
  display control is performed.

.. index:: Command {who} {}

Command {who} {}
  Show a list of currently connected vty sessions.

.. index:: Command {list} {}

Command {list} {}
  List all available commands.

.. index:: Command {show version} {}

Command {show version} {}
  Show the current version of @value{PACKAGE_NAME} and its build host information.

.. index:: Command {show logging} {}

Command {show logging} {}
  Shows the current configuration of the logging system.  This includes
  the status of all logging destinations.

.. index:: Command {logmsg `level` `message`} {}

Command {logmsg `level` `message`} {}
  Send a message to all logging destinations that are enabled for messages
  of the given severity.

.. _Common_Invocation_Options:

Common Invocation Options
=========================

These options apply to all @value{PACKAGE_NAME} daemons.



*-d*

*--daemon*
  Runs in daemon mode.


*-f `file`*

*--config_file=`file`*
  Set configuration file name.


*-h*

*--help*
  Display this help and exit.


*-i `file`*

*--pid_file=`file`*
  Upon startup the process identifier of the daemon is written to a file,
  typically in :file:`/var/run`.  This file can be used by the init system
  to implement commands such as *.../init.d/zebra status*,
  *.../init.d/zebra restart* or @command{.../init.d/zebra
  stop}.

  The file name is an run-time option rather than a configure-time option
  so that multiple routing daemons can be run simultaneously.  This is
  useful when using @value{PACKAGE_NAME} to implement a routing looking glass.  One
  machine can be used to collect differing routing views from differing
  points in the network.


*-A `address`*

*--vty_addr=`address`*
  Set the VTY local address to bind to. If set, the VTY socket will only
  be bound to this address. 


*-P `port`*

*--vty_port=`port`*
  Set the VTY TCP port number. If set to 0 then the TCP VTY sockets will not
  be opened.


*-u `user`*

*--vty_addr=`user`*
  Set the user and group to run as.


*-v*

*--version*
  Print program version.


.. _Loadable_Module_Support:

Loadable Module Support
=======================

FRR supports loading extension modules at startup.  Loading, reloading or
unloading modules at runtime is not supported (yet).  To load a module, use
the following command line option at daemon startup:



*-M `module:options`*

*--module `module:options`*
  Load the specified module, optionally passing options to it.  If the module
  name contains a slash (/), it is assumed to be a full pathname to a file to
  be loaded.  If it does not contain a slash, the
  `@value{INSTALL_PREFIX_MODULES`} directory is searched for a module of
  the given name; first with the daemon name prepended (e.g. `zebra_mod`
  for `mod`), then without the daemon name prepended.

  This option is available on all daemons, though some daemons may not have
  any modules available to be loaded.

The SNMP Module
---------------

If SNMP is enabled during compile-time and installed as part of the package,
the `snmp` module can be loaded for the *zebra*,
*bgpd*, *ospfd*, *ospf6d* and *ripd* daemons.

The module ignores any options passed to it.  Refer to :ref:`SNMP_Support`
for information on its usage.

The FPM Module
--------------

If FPM is enabled during compile-time and installed as part of the package,
the `fpm` module can be loaded for the *zebra* daemon.  This
provides the Forwarding Plane Manager ("FPM") API.

The module expects its argument to be either `netlink` or
`protobuf`, specifying the encapsulation to use.  `netlink` is the
default, and `protobuf` may not be available if the module was built
without protobuf support.  Refer to :ref:`zebra_FIB_push_interface` for more
information.

.. _Virtual_Terminal_Interfaces:

Virtual Terminal Interfaces
===========================

VTY -- Virtual Terminal [aka TeletYpe] Interface is a command line
interface (CLI) for user interaction with the routing daemon.

.. _VTY_Overview:

VTY Overview
------------

VTY stands for Virtual TeletYpe interface.  It means you can connect to
the daemon via the telnet protocol.

To enable a VTY interface, you have to setup a VTY password.  If there
is no VTY password, one cannot connect to the VTY interface at all.

::

  @group
  % telnet localhost 2601
  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.

  Hello, this is @value{PACKAGE_NAME} (version @value{PACKAGE_VERSION})
  @value{COPYRIGHT_STR}

  User Access Verification

  Password: XXXXX
  Router> ?
    enable            Turn on privileged commands
    exit              Exit current mode and down to previous mode
    help              Description of the interactive help system
    list              Print command list
    show              Show running system information
    who               Display who is on a vty
  Router> enable
  Password: XXXXX
  Router# configure terminal
  Router(config)# interface eth0
  Router(config-if)# ip address 10.0.0.1/8
  Router(config-if)# ^Z
  Router#
  @end group
  

'?' is very useful for looking up commands.

.. _VTY_Modes:

VTY Modes
---------

There are three basic VTY modes:

There are commands that may be restricted to specific VTY modes.

.. _VTY_View_Mode:

VTY View Mode
^^^^^^^^^^^^^

This mode is for read-only access to the CLI. One may exit the mode by
leaving the system, or by entering `enable` mode.

.. _VTY_Enable_Mode:

VTY Enable Mode
^^^^^^^^^^^^^^^

This mode is for read-write access to the CLI. One may exit the mode by
leaving the system, or by escaping to view mode.

.. _VTY_Other_Modes:

VTY Other Modes
^^^^^^^^^^^^^^^

This page is for describing other modes.

.. _VTY_CLI_Commands:

VTY CLI Commands
----------------

Commands that you may use at the command-line are described in the following
three subsubsections.

.. _CLI_Movement_Commands:

CLI Movement Commands
^^^^^^^^^^^^^^^^^^^^^

These commands are used for moving the CLI cursor. The :kbd:`C` character
means press the Control Key.



*C-f*

*:kbd:`RIGHT`*
  @kindex C-f
  @kindex :kbd:`RIGHT`
  Move forward one character.


*C-b*

*:kbd:`LEFT`*
  @kindex C-b
  @kindex :kbd:`LEFT`
  Move backward one character.


*M-f*
  @kindex M-f
  Move forward one word.


*M-b*
  @kindex M-b
  Move backward one word.


*C-a*
  @kindex C-a
  Move to the beginning of the line.


*C-e*
  @kindex C-e
  Move to the end of the line.


.. _CLI_Editing_Commands:

CLI Editing Commands
^^^^^^^^^^^^^^^^^^^^

These commands are used for editing text on a line. The :kbd:`C`
character means press the Control Key.



*C-h*

*:kbd:`DEL`*
  @kindex C-h
  @kindex :kbd:`DEL`
  Delete the character before point.


*C-d*
  @kindex C-d
  Delete the character after point.


*M-d*
  @kindex M-d
  Forward kill word.


*C-w*
  @kindex C-w
  Backward kill word.


*C-k*
  @kindex C-k
  Kill to the end of the line.


*C-u*
  @kindex C-u
  Kill line from the beginning, erasing input.


*C-t*
  @kindex C-t
  Transpose character.


CLI Advanced Commands
^^^^^^^^^^^^^^^^^^^^^

There are several additional CLI commands for command line completions,
insta-help, and VTY session management.



*C-c*
  @kindex C-c
  Interrupt current input and moves to the next line.


*C-z*
  @kindex C-z
  End current configuration session and move to top node.


*C-n*

*:kbd:`DOWN`*
  @kindex C-n
  @kindex :kbd:`DOWN`
  Move down to next line in the history buffer.


*C-p*

*:kbd:`UP`*
  @kindex C-p
  @kindex :kbd:`UP`
  Move up to previous line in the history buffer.


*TAB*
  @kindex :kbd:`TAB`
  Use command line completion by typing :kbd:`TAB`.


*?*
  @kindex :kbd:`?`
  You can use command line help by typing `help` at the beginning of
  the line.  Typing @kbd{?} at any point in the line will show possible
  completions.


