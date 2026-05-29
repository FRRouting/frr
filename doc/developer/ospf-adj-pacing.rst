.. _ospf-adj-pacing:

****************
Adjacency Pacing
****************

OSPF adjacency pacing implements :rfc:`4222` recommendation 5 as a
per-interface gate on adjacency formation. The goal is to avoid starting too
many database exchanges at once on a bandwidth constrained interface.

Overview
========

Adjacency pacing is tracked in ``struct ospf_adj_pacing`` in
``ospfd/ospf_interface.h``. Each OSPF interface keeps:

- the pacing mode: disabled, static, or dynamic
- the current number of adjacencies in progress
- a first-come, first-served queue of neighbors waiting for a slot
- dynamic state such as the current limit and watermarks

An adjacency is considered in progress while the neighbor state is
``ExStart``, ``Exchange``, or ``Loading``.

Static Mode
===========

Static mode uses a fixed per-interface limit configured with:

.. code-block:: frr

   interface eth0
    ip ospf adjacency-pacing static 4

When the number of in-progress adjacencies reaches the configured limit, any
new neighbor that would otherwise advance into adjacency formation is placed on
the interface queue. Queued neighbors are retried in FIFO order when a slot
opens.

Dynamic Mode
============

Dynamic mode adapts the limit according to retransmission pressure on the
interface:

.. code-block:: frr

   interface eth0
    ip ospf adjacency-pacing dynamic
    ip ospf adjacency-pacing dynamic thresholds 100 2

In dynamic mode, the current limit still applies to the number of simultaneous
adjacencies allowed on the interface. The implementation computes ``U(t)`` as
the total number of unacknowledged LSAs across neighbors on the interface, and
uses the configured ``H`` and ``L`` values only as high-water and low-water
thresholds for that unacknowledged-LSA total. The current adjacency limit is
then adjusted using hysteresis:

- if ``U(t) > H``, reduce the current limit by the configured factor, down to 1
- if ``U(t) < L``, increase the current limit by 1, up to the configured maximum
- if ``L <= U(t) <= H``, keep the current limit unchanged

Current defaults from ``ospfd/ospf_interface.h`` are:

- initial dynamic limit: 1 (simultaneous adjacency)
- maximum dynamic limit: 50 (simultaneous adjacencies)
- decrease factor: 2
- adjustment interval: 1000 ms
- high-water mark: 100 (unacknowledged LSAs)
- low-water mark: 2 (unacknowledged LSAs)

Code Paths
==========

The main control flow lives in ``ospfd/ospf_nsm.c``:

- ``ospf_adj_pacing_allow()`` decides whether a new adjacency may proceed
- ``ospf_adj_pacing_enqueue()`` and ``ospf_adj_pacing_dequeue()`` manage the
  per-interface wait queue
- ``ospf_adj_pacing_kick()`` restarts queued neighbors when slots become
  available
- ``ospf_adj_dyn_adjust()`` and ``ospf_adj_dyn_adjust_timer()`` update the
  dynamic limit

Neighbor state changes update the in-progress count. When a neighbor leaves the
forming states, the count is decremented and the queue is serviced again.

Unacknowledged LSA Tracking
============================

``U(t)`` is computed by summing ``ls_rxmt_unacked`` across all neighbors on the
interface. This counter is incremented in ``ospf_count_sent_lsa()`` when an LSU
packet is written, and decremented in the LS Acknowledge receive path when the
matching retransmit entry is removed.

On a broadcast segment the DR floods each LSA once as a multicast, but every
neighbor is individually tracked — so ``U(t)`` reflects the total ACK
obligation across all neighbors, not just the number of distinct LSAs on the
wire. This gives a realistic measure of retransmission pressure regardless of
network type.

Operational Notes
=================

- Adjacency pacing is interface scoped, not process scoped.
- Disabling pacing clears the current mode and runtime state on existing OSPF
  interfaces.
- Dynamic thresholds must satisfy ``low < high``.
