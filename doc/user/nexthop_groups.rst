.. _nexthop-groups:

Nexthop Groups
==============

Nexthop groups are a way to encapsulate ECMP information together.  It's a
listing of ECMP nexthops used to forward packets.

.. clicmd:: nexthop-group NAME

   Create a nexthop-group with an associated NAME.  This will put you into a
   sub-mode where you can specify individual nexthops.  To exit this mode type
   exit or end as per normal conventions for leaving a sub-mode.

.. clicmd:: nexthop [A.B.C.D|X:X::X:XX] [interface [onlink]] [nexthop-vrf NAME] [label LABELS]

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

   Allow a next-hop to be resolved at zebra level. Instead of beig considered valid,
   the next-hop is checked against route reachability at zebra level. This permits
   sending an incomplete next-hop to zebra, whereas it was not authorised before.

.. clicmd:: force-nexthop-config

   Allow a Nexthop Group to be configured in ZEBRA, even if the nexthop has neither
   an interface configured and no `allow-recursion` set.

.. clicmd:: ibgp

   Allow a Nexthop Group to be considered as an IBGP nexthop. When used in ZEBRA,
   if `allow-recursion` is not used, some debug information is given.
