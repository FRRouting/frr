.. _ext-log-target:

***********************
Extended Logging Target
***********************

After creating one or more extended logging targets with the
:clicmd:`log extended EXTLOGNAME` command, the target(s) must be configured
for the desired logging output.

Each extended log target supports emitting log messages in one of the following
formats:

- ``rfc5424`` - :rfc:`5424` - modern syslog with ISO 8601 timestamps, time zone and
  structured data (key/value pairs) support
- ``rfc3164`` - :rfc:`3164` - legacy BSD syslog, timestamps with 1 second granularity
- ``local-syslog`` - same as :rfc:`3164`, but without the hostname field
- ``journald`` - systemd's `native journald protocol <https://systemd.io/JOURNAL_NATIVE_PROTOCOL/>`_.
  This protocol also supports structured data (key/value pairs).

Destinations
------------

The output location is configured with the following subcommands:

.. clicmd:: destination none

   Disable the target while retaining its remaining configuration.

.. clicmd:: destination syslog [supports-rfc5424]

   Send log messages to the system's standard log destination
   (``/dev/log``).  This does not use the C library's ``syslog()`` function,
   instead writing directly to ``/dev/log``.

   On NetBSD and FreeBSD, the RFC5424 format is automatically used when
   the OS version is recent enough (5.0 for NetBSD, 12.0 for FreeBSD).
   Unfortunately, support for this format cannot be autodetected otherwise,
   and particularly on Linux systems must be enabled manually.

.. clicmd:: destination journald

   Send log messages to systemd's journald.

.. clicmd:: destination <stdout|stderr|fd <(0-63)|envvar WORD>> \
                [format FORMAT]

   Send log messages to one of the daemon's file descriptors.  The
   ``fd (0-63)`` and ``fd envvar WORD`` variants are intended to work with
   the shell's ``command 3>something`` and bash's
   ``command {ENVVAR}>something`` I/O redirection specifiers.

   Only file descriptors open at a daemon's startup time can be used for
   this;  accidental misuse of a file descriptor that has been opened by
   FRR itself is prevented.

   Using FIFOs with this option will work but is unsupported and can cause
   daemons to hang or crash depending on reader behavior.

   Format defaults to RFC5424 if none is specified.

   .. note::

      When starting FRR daemons from custom shell scripts, make sure not
      to leak / leave extraneous file descriptors open.  FRR daemons do not
      close these.

.. clicmd:: destination file PATH \
                [create [{user WORD|group WORD|mode PERMS}]|no-create] \
                [format FORMAT]

   Log to a regular file.  File permissions can be specified when FRR creates
   the file itself.

   Format defaults to RFC5424 if none is specified.

   .. note::

      FRR will never change permissions or ownership on an existing log file.
      In many cases, FRR will also not have permissions to set user and group
      arbitrarily.

.. clicmd:: destination unix PATH [format FORMAT]

   Connect to a UNIX domain socket and send log messages there.  This will
   autodetect ``SOCK_STREAM``, ``SOCK_SEQPACKET`` and ``SOCK_DGRAM`` and
   adjust behavior appropriately.

Options
-------

.. clicmd:: priority PRIORITY

   Select minimum priority of messages to send to this target.  Defaults to
   `debugging`.

.. clicmd:: facility FACILITY

   Select syslog facility for messages on this target.  Defaults to `daemon`.
   The :clicmd:`log facility [FACILITY]` command does not affect extended
   targets.

.. clicmd:: timestamp precision (0-9)

   Set desired number of sub-second timestamp digits.  This only has an effect
   for RFC5424 and journald format targets;  the RFC3164 and local-syslogd
   formats do not support any sub-second digits.

.. clicmd:: timestamp local-time

   Use the local system timezone for timestamps rather than UTC (the default.)

   RFC5424 and journald formats include zone information (``Z`` or ``+-NN:NN``
   suffix in ISO8601).  RFC3164 and local-syslogd offer no way of identifying
   the time zone used, care must be taken that this option and the receiver
   are configured identically, or the timestamp is replaced at the receiver.

   .. note::

      FRR includes a timestamp in journald messages, but journald always
      provides its own timestamp.

.. clicmd:: structured-data <code-location|version|unique-id|error-category|format-args>

   Select additional key/value data to be included for the RFC5424 and journald
   formats.  Refer to the next section for details.

   ``unique-id`` and ``error-category`` are enabled by default.

   .. warning::

      Log messages can grow in size significantly when enabling additional
      data.


Structured data
---------------

When using the RFC5424 or journald formats, FRR can provide additional metadata
for log messages as key/value pairs.  The following information can be added
in this way:

+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| Switch             | 5424 group         | 5424 item(s) | journald field   | Contents                                    |
+====================+====================+==============+==================+=============================================+
| always active      | ``location@50145`` | ``tid``      | ``TID``          | Thread ID                                   |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| always active      | ``location@50145`` | ``instance`` | ``FRR_INSTANCE`` | Multi-instance number                       |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| ``unique-id``      | ``location@50145`` | ``id``       | ``FRR_ID``       | ``XXXXX-XXXXX`` unique message identifier   |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| ``error-category`` | ``location@50145`` | ``ec``       | ``FRR_EC``       | Integer error category number               |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| ``code-location``  | ``location@50145`` | ``file``     | ``CODE_FILE``    | Source code file name                       |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| ``code-location``  | ``location@50145`` | ``line``     | ``CODE_LINE``    | Source code line number                     |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| ``code-location``  | ``location@50145`` | ``func``     | ``CODE_FUNC``    | Source code function name                   |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| ``format-args``    | ``args@50145``     | ``argN``     | ``FRR_ARGn``     | Message printf format arguments (n = 1..16) |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+
| ``version``        | ``origin``         | multiple     | n/a              | FRR version information (IETF format)       |
+--------------------+--------------------+--------------+------------------+---------------------------------------------+

The information added by ``version`` is
``[origin enterpriseId="50145" software="FRRouting" swVersion="..."]``
and is the same for all log messages.  (Hence makes little sense to include in
most scenarios.)  50145 is the FRRouting IANA Enterprise Number.

Crashlogs / backtraces do not include any additional information since it
cannot safely be retrieved from a crash handler.  However, all of the above
destinations will deliver crashlogs.


Restart and Reconfiguration caveats
-----------------------------------

FRR uses "add-delete" semantics when reconfiguring log targets of any type
(including both extended targets mentioned here as well as the global
:clicmd:`log stdout LEVEL` and :clicmd:`log syslog [LEVEL]` variants.)  This
means that when changing logging configuration, log messages from threads
executing in parallel may be duplicated for a brief window of time.

For the ``unix``, ``syslog`` and ``journald`` extended destinations, messages
can be lost when the receiver is restarted without the use of socket
activation (i.e. keeping the receiver socket open.)  FRR does not buffer
log messages for later delivery, meaning anything logged while the receiver
is unavailable is lost.  Since systemd provides socket activation for
journald, no messages will be lost on the ``journald`` target.
