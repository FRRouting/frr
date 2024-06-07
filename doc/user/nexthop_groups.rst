.. _nexthop-groups:

Nexthop Groups
==============

Nexthop groups are a way to encapsulate ECMP information together.  It's a
listing of ECMP nexthops used to forward packets.

.. clicmd:: nexthop-group NAME

   Create a nexthop-group with an associated NAME.  This will put you into a
   sub-mode where you can specify individual nexthops.  To exit this mode type
   exit or end as per normal conventions for leaving a sub-mode.

.. clicmd:: nexthop [A.B.C.D|X:X::X:XX] [interface [onlink]] [nexthop-vrf NAME] [label LABELS] [color (1-4294967295)]

   Create a v4 or v6 nexthop.  All normal rules for creating nexthops that you
   are used to are allowed here.  The syntax was intentionally kept the same as
   creating nexthops as you would for static routes.

.. clicmd:: resilient buckets (1-256) idle-timer (1-4294967295) unbalanced-timer (1-4294967295)

   Create a resilient Nexthop Group with the specified number of buckets, and
   associated timers.  Instead of using the normal kernel hashing methodology
   this specifies that X buckets will be created for the nexthop group and
   when a nexthop is lost the buckets forwarding that particular nexthop
   will be automatically re-assigned.  This cli command must be the first
   command entered currently.  Additionally this command only works with linux 5.19
   kernels or newer.

.. clicmd:: allow-recursion

   By default, a nexthop group is only marked as active when its nexthop is
   directly connected. The ``allow-recursion`` option allows zebra to resolve the
   nexthop using other types of routes.

.. clicmd:: child-group NAME

   Append a child nexthop group in the current nexthop group. The protocol daemon
   using it will ensure that the child group is configured at the protocol level,
   and installed at zebra level, before installing the parent nexthop group.
   This option is very useful to consider nexthop groups having multiple paths.
