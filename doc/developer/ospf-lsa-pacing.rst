.. _ospf-lsa-pacing:

**********
LSA Pacing
**********

OSPF LSA pacing implements :rfc:`4222` recommendation 4 as a per-neighbor,
per-interface gate on LS Update transmission. The goal is to prevent a router
from flooding its neighbors with back-to-back LS Updates during large topology
changes, which can overwhelm receive buffers and trigger retransmission storms.

Overview
========

LSA pacing is tracked per-neighbor in ``struct ospf_neighbor``
(``ospfd/ospf_neighbor.h``) and configured per-interface via
``struct ospf_if_params`` (``ospfd/ospf_interface.h``). Each OSPF interface
caches the effective parameters in ``struct ospf_interface`` so per-packet
hot paths avoid repeated parameter lookups.

When LSA pacing is enabled on an interface:

- Outbound LSAs destined for a neighbor are placed on a per-neighbor send
  queue (``nbr->r4_send_queue``) rather than being written immediately.
- A per-neighbor timer (``nbr->t_r4_send``) drains the queue at the
  configured rate, sending at most ``rec4_max_lsas`` LSAs per LS Update.
- The inter-packet gap (``nbr->lsu_gap_ms``) is adjusted adaptively using
  a multiplicative-increase/multiplicative-decrease (MIMD) algorithm based
  on the unacknowledged LSA count for that neighbor.

Data Structures
===============

``struct ospf_if_params``
   Holds the user-configured LSA pacing parameters for an interface:

   - ``gap_pacing_enable`` — boolean, set by ``ip ospf lsa-pacing``
   - ``gap_initial_ms`` — starting inter-LSU gap (default 20 ms)
   - ``gap_min_ms`` — floor for gap adaptation (default 20 ms)
   - ``gap_max_ms`` — ceiling for gap adaptation (default 1000 ms)
   - ``gap_factor`` — multiplicative adjustment factor F (default 2)
   - ``gap_adjust_int_ms`` — minimum time T between adjustments (default 1000 ms)
   - ``gap_high_water`` — unacked-LSA count H above which the gap grows (default 100)
   - ``gap_low_water`` — unacked-LSA count L below which the gap shrinks (default 2)
   - ``gap_max_lsas`` — LSAs packed per LS Update during paced sends (default 1)

``struct ospf_interface``
   Caches derived effective values (prefixed ``rec4_``) computed by
   ``ospf_rec4_recompute_effective()`` in ``ospfd/ospf_interface.c``:

   - ``rec4_gap_pacing`` — effective enable flag
   - ``rec4_gap_initial_ms``, ``rec4_gap_min_ms``, ``rec4_gap_max_ms``
   - ``rec4_gap_factor``, ``rec4_gap_adjust_int_ms``
   - ``rec4_high_water``, ``rec4_low_water``, ``rec4_max_lsas``

``struct ospf_neighbor``
   Holds per-neighbor runtime pacing state:

   - ``r4_send_queue`` — list of ``struct ospf_lsa *`` waiting to be sent
   - ``t_r4_send`` — FRR event timer for the paced send callback
   - ``lsu_gap_ms`` — current adaptive inter-LSU gap for this neighbor
   - ``next_send_ms`` — absolute timestamp (ms) when the next send is allowed
   - ``ls_rxmt_unacked`` — running count of unacknowledged LSAs sent to this
     neighbor; used as the ``U`` signal in the MIMD algorithm

MIMD Gap Adjustment
===================

``pace_maybe_adjust_gap()`` in ``ospfd/ospf_packet.c`` implements the
adaptive algorithm. It is called after each paced send and when an LS
Acknowledge is received. The algorithm uses the per-neighbor unacknowledged
LSA count ``U = nbr->ls_rxmt_unacked`` and the configured factor ``F``:

.. code-block:: text

   if U > H:   G = min(G × F, Gmax)   # multiplicative decrease: gap grows, send rate slows
   if U == 0:  G = Gmin               # immediate reset to minimum gap
   if U <= L:  G = max(G ÷ F, Gmin)   # multiplicative increase: gap shrinks, send rate rises
   L < U <= H: no change

The gap is never modified more frequently than once per ``T`` milliseconds
(``rec4_gap_adjust_int_ms``), preventing oscillation during transient bursts.

Defaults from ``ospfd/ospf_interface.h``:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Parameter
     - Default
     - Description
   * - Initial gap (G\ :sub:`init`)
     - 20 ms
     - Starting inter-LSU gap when an adjacency becomes Full
   * - Minimum gap (G\ :sub:`min`)
     - 20 ms
     - Floor: gap will not shrink below this value
   * - Maximum gap (G\ :sub:`max`)
     - 1000 ms
     - Ceiling: gap will not grow above this value
   * - Factor (F)
     - 2
     - Multiplicative adjustment factor for both directions
   * - Adjust interval (T)
     - 1000 ms
     - Minimum time between consecutive gap changes
   * - High-water (H)
     - 100
     - Unacked LSAs above which gap grows (rate slows)
   * - Low-water (L)
     - 2
     - Unacked LSAs below which gap shrinks (rate rises)
   * - Max LSAs per update
     - 1
     - LSAs packed into one paced LS Update

Code Paths
==========

The main control flow lives in ``ospfd/ospf_packet.c``:

- ``ospf_r4_nbr_init()`` — allocates ``r4_send_queue`` for a neighbor and sets
  ``lsu_gap_ms`` from the interface initial-gap.
- ``ospf_r4_nbr_cancel()`` — cancels the send timer and empties the queue;
  called on neighbor state regression.
- ``ospf_r4_nbr_enqueue()`` — appends an LSA to the neighbor's send queue and
  arms the send timer if not already scheduled.
- ``ospf_r4_nbr_arm_timer()`` — schedules ``ospf_r4_nbr_send_timer`` to fire at
  ``nbr->next_send_ms``. No-ops if the timer is already armed or the queue is
  empty.
- ``ospf_r4_nbr_send_timer()`` — timer callback that dequeues and sends one
  batch of LSAs (up to ``rec4_max_lsas``), then re-arms itself for the next
  send window.

``ospf_r4_nbr_send_timer()`` handles two conditions before sending:

1. **Gap not yet elapsed**: if ``nbr->next_send_ms > now``, reschedule for the
   remaining time rather than sending early.
2. **Interface write-queue busy**: if ``oi->on_write_q`` is set (the interface
   is currently being drained by ``ospf_write``), retry after 1 ms to yield the
   event loop without disrupting the pacing schedule.

Flood Integration
=================

``ospfd/ospf_flood.c`` integrates LSA pacing at two points:

- **Retransmit list population** (``ospf_flood_through_interface()``): when
  ``rec4_gap_pacing`` is set, the function skips adding the LSA to the normal
  retransmit list and instead sets ``retx_flag = 1`` to indicate the interface
  needs flooding. The LSA is enqueued per-neighbor via ``ospf_r4_nbr_enqueue()``
  in the subsequent neighbor-walk block.
- **Per-neighbor flood dispatch**: a neighbor-walk loop calls
  ``ospf_r4_nbr_enqueue()`` for each eligible neighbor in ``Exchange`` state
  or above, replacing the normal immediate-write path.

Broadcast Network Behavior
==========================

On a normal broadcast or NBMA interface, the DR/BDR floods each LSA once as a
single multicast packet to ``AllSPFRouters``; individual neighbors never get
a separate copy. When ``rec4_gap_pacing`` is enabled, this changes: pacing is
tracked per-neighbor (``nbr->r4_send_queue``, ``nbr->lsu_gap_ms``), so the
flood path in ``ospf_flood_through_interface()`` walks the interface's
neighbor table and calls ``ospf_r4_nbr_enqueue()`` once per eligible neighbor,
and ``ospf_ls_upd_queue_send()`` addresses the resulting packet directly to
that neighbor's unicast address (``ospf_packet.c``, destination selection
falls through to ``addr.s_addr`` rather than ``OSPF_ALLSPFROUTERS`` once
pacing is active).

This means enabling LSA pacing on a broadcast interface trades the normal
single-multicast flood for ``N`` independently paced unicast streams, one per
adjacent neighbor, each gated by its own gap and MIMD state. This is
intentional: per-neighbor pacing requires per-neighbor delivery, since
neighbors can have different unacked-LSA counts and therefore different
gaps. The tradeoff is more packets on the wire under pacing, in exchange for
gating each neighbor's flood rate independently of the others.

Unacknowledged LSA Tracking
============================

``U(t)`` is tracked per-neighbor via ``nbr->ls_rxmt_unacked``:

- Incremented by ``ospf_count_sent_lsa()`` when an LS Update is written for
  that neighbor.
- Decremented in the LS Acknowledge receive path when the matching retransmit
  list entry is removed.

Interaction with R5 Adjacency Pacing
=====================================

R4 LSA pacing and :ref:`ospf-adj-pacing` (R5) are completely independent
features. They share no data and neither's enable condition gates the other:

- Both react to the same network events (retransmit timer, LS Acknowledge) but
  in separate ``if`` blocks that check their own enable flags.
- R4 uses ``rec4_*`` fields on ``struct ospf_interface`` and per-neighbor queue
  state. R5 uses ``adj_pacing`` on ``struct ospf_interface``.
- Either feature can be enabled independently per-interface without affecting
  the other.
- This independence holds on broadcast segments as well: a topotest exercises
  both features together on a 5-router broadcast LAN (one DR, one BDR, three
  DROthers), with adjacency flapping and external-LSA injection under both
  unconstrained and bandwidth-constrained links, confirming neither feature's
  pacing decisions interfere with the other's.

Operational Notes
=================

- LSA pacing is interface-scoped, not process-scoped.
- Disabling pacing (``no ip ospf lsa-pacing``) clears ``gap_pacing_enable``
  and re-evaluates effective parameters on all OSPF interfaces using that
  interface's configuration.
- ``initial-gap`` is clamped to ``[min-gap, max-gap]`` silently if
  ``min-gap``/``max-gap`` are changed after ``initial-gap`` is set.
- ``low-watermark`` must be strictly less than ``high-watermark``.
