.. _nexthop-groups:

Nexthop Groups
==============

Nexthop groups are a way to encapsulate ECMP information together.  It's a
listing of ECMP nexthops used to forward packets.

.. clicmd:: nexthop-group NAME

   Create a nexthop-group with an associated NAME.  This will put you into a
   sub-mode where you can specify individual nexthops.  To exit this mode type
   exit or end as per normal conventions for leaving a sub-mode.

.. clicmd:: backup-group NAME

   Specify a group name containing backup nexthops for this nexthop group.

.. clicmd:: nexthop [A.B.C.D|X:X::X:X] [INTERFACE [onlink]] [nexthop-vrf NAME] [label LABELS] [vni VNI] [weight WEIGHT] [backup-idx INDEXES]

   Create a v4 or v6 nexthop.  All normal rules for creating nexthops that you
   are used to are allowed here.  The syntax was intentionally kept the same as
   creating nexthops as you would for static routes.

   **Parameters:**

   * **A.B.C.D|X:X::X:X**: IPv4 or IPv6 address (optional)
   * **INTERFACE**: Interface to use (optional)
   * **onlink**: Treat nexthop as directly attached to the interface (optional)
   * **nexthop-vrf NAME**: Specify VRF for the nexthop (optional)
   * **label LABELS**: Specify MPLS label(s) for this nexthop (optional)
     - Labels must be in the range 16-1048575
     - Multiple labels can be specified separated by '/'
     - Reserved labels (0-15) cannot be used
     - Maximum of 16 labels allowed
   * **vni VNI**: Specify VNI for this nexthop (optional)
     - VNI must be in the range 1-16777215
   * **weight WEIGHT**: Weight for ECMP load balancing (optional)
     - Weight must be in the range 1-4294967295
   * **backup-idx INDEXES**: Specify backup nexthop indexes (optional)
     - Indexes must be in the range 0-254
     - Multiple indexes can be specified separated by ','

.. clicmd:: resilient buckets (1-256) idle-timer (1-4294967295) unbalanced-timer (1-4294967295)

   Create a resilient Nexthop Group with the specified number of buckets, and
   associated timers.  Instead of using the normal kernel hashing methodology
   this specifies that X buckets will be created for the nexthop group and
   when a nexthop is lost the buckets forwarding that particular nexthop
   will be automatically re-assigned.  This cli command must be the first
   command entered currently.  Additionally this command only works with linux 5.19
   kernels or newer.

   **Parameters:**

   * **buckets**: Number of buckets in the hash (1-256)
   * **idle-timer**: Idle timer in seconds (1-4294967295)
   * **unbalanced-timer**: Unbalanced timer in seconds (1-4294967295)
