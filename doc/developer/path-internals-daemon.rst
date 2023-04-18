PATHD Internals
===============

Architecture
------------

Overview
........

The pathd deamon manages the segment routing policies, it owns the data
structures representing them and can load modules that manipulate them like the
PCEP module. Its responsibility is to select a candidate path for each
configured policy and to install it into Zebra.

Zebra
.....

Zebra manages policies that are active or pending to be activated due to the
next hop not being available yet. In zebra, policy data structures and APIs are
defined in `zebra_srte.[hc]`.

The responsibilities of Zebra are:

 - Store the policies' segment list.
 - Install the policies when their next-hop is available.
 - Notify other daemons of the status of the policies.

Adding and removing policies is done using the commands `ZEBRA_SR_POLICY_SET`
and `ZEBRA_SR_POLICY_DELETE` as parameter of the function `zebra_send_sr_policy`
all defined in `zclient.[hc]`.

If the first segment of the policy is an unknown label, it is kept until
notified by the mpls hooks `zebra_mpls_label_created`, and then it is installed.

To get notified when a policy status changes, a client can implement the
`sr_policy_notify_status` callback defined in `zclient.[hc]`.

For encoding/decoding the various data structures used to comunicate with zebra,
the following functions are available from `zclient.[hc]`:
`zapi_sr_policy_encode`, `zapi_sr_policy_decode` and
`zapi_sr_policy_notify_status_decode`.


Pathd
.....


The pathd daemon manages all the possible candidate paths for the segment
routing policies and selects the best one following the
`segment routing policy draft <https://tools.ietf.org/html/draft-ietf-spring-segment-routing-policy-06#section-2.9>`_.
It also supports loadable modules for handling dynamic candidate paths and the
creation of new policies and candidate paths at runtime.

The responsibilities of the pathd base daemon, not including any optional
modules, are:

 - Store the policies and all the possible candidate paths for them.
 - Select the best candidate path for each policy and send it to Zebra.
 - Provide VTYSH configuration to set up policies and candidate paths.
 - Provide a Northbound API to manipulate **configured** policies and candidate paths.
 - Handle loadable modules for extending the functionality.
 - Provide an API to the loadable module to manipulate policies and candidate paths.


Threading Model
---------------

The daemon runs completely inside the main thread using FRR event model, there
is no threading involved.


Source Code
-----------

Internal Data Structures
........................

The main data structures for policies and candidate paths are defined in
`pathd.h` and implemented in `pathd.c`.

When modifying these structures, either directly or through the functions
exported by `pathd.h`, nothing should be deleted/freed right away. The deletion
or modification flags must be set and when all the changes are done, the
function `srte_apply_changes` must be called. When called, a new candidate path
may be elected and sent to Zebra, and all the structures flagged as deleted
will be freed. In addition, a hook will be called so dynamic modules can perform
any required action when the elected candidate path changes.


Northbound API
..............

The northbound API is defined in `path_nb.[ch]` and implemented in
`path_nb_config.c` for configuration data and `path_nb_state.c` for operational
data.


Command Line Client
...................

The command-line client (VTYSH) is implemented in `path_cli.c`.


Interface with Zebra
....................

All the functions interfacing with Zebra are defined and implemented in
`path_zebra.[hc]`.


Loadable Module API
...................

For the time being, the API the loadable module uses is defined by `pathd.h`,
but in the future, it should be moved to a dedicated include file.
