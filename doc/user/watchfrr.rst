.. _watchfrr:

********
WATCHFRR
********

:abbr:`WATCHFRR` is a daemon that handles failed daemon processes and
intelligently restarts them as needed.

Starting WATCHFRR
=================

WATCHFRR is started as per normal systemd startup and typically does not
require end users management.

WATCHFRR commands
=================

.. clicmd:: show watchfrr

   Give status information about the state of the different daemons being
   watched by WATCHFRR

.. clicmd:: watchfrr ignore DAEMON

   Tell WATCHFRR to ignore a particular DAEMON if it goes unresponsive.
   This is particularly useful when you are a developer and need to debug
   a working system, without watchfrr pulling the rug out from under you.
