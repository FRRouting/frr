***
FRR
***

.. include:: defines.rst

SYNOPSIS
========
frr [ start ]

frr [ stop ]

frr [ reload ]

frr [ restart ]

frr [ status ]


DESCRIPTION
===========
frr is a systemd interaction script for the FRRouting routing engine.

OPTIONS
=======
Options available for the frr command:

start
   Start enabled FRR daemons

stop
   Stop enabled FRR daemons

reload
   Reload modified configuration files

restart
   Stop all running daemons and then restart them

status
   Status of all the daemon

.. include:: epilogue.rst

