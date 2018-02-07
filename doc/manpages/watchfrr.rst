********
WATCHFRR
********

.. include:: defines.rst
.. |DAEMON| replace:: watchfrr

SYNOPSIS
========
|DAEMON| |synopsis-options-hv|

|DAEMON| [option...] <daemon>...


DESCRIPTION
===========
|DAEMON| is a watchdog program that monitors the status of supplied frr daemons and tries to restart them in case they become unresponsive or shut down.

To determine whether a daemon is running, it tries to connect to the daemon's VTY UNIX stream socket, and send echo commands to ensure the daemon responds. When the daemon crashes, EOF is received from the socket, so that |DAEMON| can react immediately.

In order to avoid restarting the daemons in quick succession, you can supply the -m and -M options to set the minimum and maximum delay between the restart commands. The minimum restart delay is recalculated each time a restart is attempted.  If the time since the last restart attempt exceeds twice the value of -M, the restart delay is set to the value of -m, otherwise the interval is doubled (but capped at the value of -M).

OPTIONS
=======
The following 3 options specify scripts that |DAEMON| uses to perform start/stop/restart actions. These options are mandatory unless the --dry option is used:

.. option:: -s command, --start-command command

  Supply a Bourne shell command to start a single daemon. The command string should contain the '%s' placeholder to be sub‐ stituted with the daemon name.

.. option:: -k command, --kill-command command

   Supply a Bourne shell command to stop a single daemon. The command string should contain the '%s' placeholder to be substituted with the daemon name.

.. option:: -r command, --restart command

   Supply a Bourne shell command to restart a single daemon. The command string should contain the '%s' placeholder to be substituted with the daemon name.

Other options:

.. option:: --dry

   Run |DAEMON| in "dry-run" mode, only monitoring the specified daemons but not performing any start/stop/restart actions.

.. option:: -d, --daemon

   Run in daemon mode. When supplied, error messages are sent to Syslog instead of standard output (stdout).

.. option:: -S <directory>, --statedir <directory>

   Set the VTY socket directory (the default value is "/var/run/frr").

.. option:: -l <level>, --loglevel <level>

   Set the logging level (the default value is "6"). The value should range from 0 (LOG_EMERG) to 7 (LOG_DEBUG), but higher number can be supplied if extra debugging messages are required.

.. option:: --min-restart-interval <number>

   Set the minimum number of seconds to wait between invocations of the daemon restart commands (the default value is "60").

.. option:: --max-restart-interval <number>

   Set the maximum number of seconds to wait between invocations of the daemon restart commands (the default value is "600").

.. option:: -i <number>, --interval <number>

   Set the status polling interval in seconds (the default value is "5").

.. option:: -t <number>, --timeout <number>

   Set the unresponsiveness timeout in seconds (the default value is "10").

.. option:: -T <number>, --restart-timeout <number>

   Set the restart (kill) timeout in seconds (the default value is "20"). If any background jobs are still running after this period has elapsed, they will be killed.

.. option:: -p <filename>, --pid-file <filename>

   Set the process identifier filename (the default value is "/var/run/frr/|DAEMON|.pid").

.. option:: -b <string>, --blank-string <string>

   When the supplied string is found in any of the command line option arguments (i.e., -r, -s, or -k), replace it with a space.

   This is an ugly hack to circumvent problems with passing the command line arguments containing embedded spaces.

.. option:: -v, --version

   Display the version information and exit.

.. option:: -h, --help

   Display the usage information and exit.

PREVIOUS OPTIONS
================
Prior versions of |DAEMON| supported some additional options that no longer exist:::

   -a, -A, -e, -R, -z

The ``-a``, ``-A`` and ``-R`` options were used to select alternate monitoring modes that offered different patterns of restarting daemons. The "correct" mode (phased restart) is now the default. The -e and -z options used to disable some monitoring aspects, |DAEMON| now always has all monitoring features enabled.

Removing these options should result in correct operation, if it does not please file a bug report.

FILES
=====

|INSTALL_PREFIX_SBIN|/|DAEMON|
   The default location of the |DAEMON| binary.

|INSTALL_PREFIX_ETC|/|DAEMON|.conf
   The default location of the |DAEMON| config file.

$(PWD)/|DAEMON|.log
   If the |DAEMON| process is configured to output logs to a file, then you
   will find this file in the directory where you started |DAEMON|.

.. include:: epilogue.rst

