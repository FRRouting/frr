OSPF Neighor Retransmission List
================================

Overview
--------

OSPF neighbor link-state retransmission lists are implemented using
both a sparse Link State Database (LSDB) and a doubly-linked list.
Rather than previous per-neighbor periodic timer, a per-neighbor
timer is set to the expiration time of the next scheduled LSA
retransmission.

Sparse Link State Database (LSDB)
---------------------------------

When an explicit or implied acknowledgment is recieved from a
neighbor in 2-way state or higher, the acknowledge LSA must be
removed from the neighbor's link state retransmission list. In order
to do this efficiently, a sparse LSDB is utilized. LSDB entries also
include a pointer to the corresponding list entry so that it may be
efficiently removed from the doubly-linked list.

The sparse LSDB is implemented using the OSPF functions is
ospf_lsdb.[c,h]. OSPF LSDBs are implemented as an array of route
tables (lib/table.[c,h]). What is unique of the LS Retransmission
list LSDB is that each entry also has a pointer into the doubly-linked
list to facilitate fast deletions.

Doubly-Linked List
------------------

In addition to the sparse LSDB, LSAs on a neighbor LS retransmission
list are also maintained in a linked-list order chronologically
with the LSA scheduled for the next retransmission at the head of
the list.

The doubly-link list is implemented using the dlist macros in
lib/typesafe.h.

LSA LS Retransmission List Addition
------------------------------------

When an LSA is added to a neighbor retransmission list, it is
added to both the sparse LSDB and the doubly-linked list with a pointer
in the LSDB route-table node to the list entry. The LSA is added to
the tail of the list with the expiration time set to the current time
with the retransmission interval added. If the neighbor retransmission
timer is not set, it is set to expire at the time of the newly added
LSA.

LSA LS Retransmission List Deletion
-----------------------------------

When an LSA is deleted from a neighbor retransmission list, it is
deleted from eboth the sparse LSDB and the doubly-linked list with the
pointer the LSDB route-table node used to efficiently delete the entry
from the list. If the LSA at the head of the list was removed, then
the neighbor retransmission timer is reset to the expiration of the
LSA at the head of the list or canceled if the list is empty.

Neighbor LS Retransmission List Expiration
------------------------------------------

When the neighbor retransmission timer expires, the LSA at the top of
list and any in a configured window (e.g., 50 milliseconds) are
retransmitted. The LSAs that have been retransmitted are removed from
the list and readded to the tail of the list with a new expiration time
which is retransmit-interval seconds in the future.

