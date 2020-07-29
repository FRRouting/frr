.. _frr-reload:


The frr-reload.py script
========================

The ``frr-reload.py`` script attempts to update the configuration of running
daemons. It takes as argument the path of the configuration file that we want
to apply. The script will attempt to retrieve the running configuration from
daemons, calculate the delta between that config and the intended one, and
execute the required sequence of vtysh commands to enforce the changes.

Options
-------

There are several options that control the behavior of ``frr-reload``:

* ``--input INPUT``: uses the specified input file as the running configuration
  instead of retrieving it from a ``show running-config`` in vtysh
* ``--reload``: applies the configuration delta to the daemons. Either this or
  ``--test`` MUST be specified.
* ``--test``: only outputs the configuration delta, without enforcing it.
  Either this or ``--reload`` MUST be specified.
* ``--debug``: enable debug messages
* ``--stdout``: print output to stdout
* ``--bindir BINDIR``: path to the vtysh executable
* ``--confdir CONFDIR``: path to the existing daemon config files
* ``--rundir RUNDIR``: path to a folder to be used to write the temporary files
  needed by the script to do its job. The script should have write access to it
* ``--daemon DAEMON``: by default ``frr-reload.py`` assumes that we are using
  integrated config and attempting to update the configuration for all daemons.
  If this is not the case, e.g. each daemon has its individual config file,
  then the delta can only be computed on a per-daemon basis. This option allows
  the user to specify the daemon for which the config is intended. DAEMON
  should be one of the keywords allowed in vtysh as an option for ``show
  running-config``.
* ``--vty_socket VTY_SOCKET``: the socket to be used by vtysh to connect to the
  running daemons.
* ``--overwrite``: overwrite the existing daemon config file with the new
  config after the delta has been applied. The file name will be ``frr.conf``
  for integrate config, or ``DAEMON.conf`` when using per-daemon config files.
