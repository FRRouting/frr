.. _zebra-system-manager:

*******************************
Zebra System Manager Interface
*******************************

Overview
========

This document proposes a new zebra subsystem that coordinates with a
system manager (SM) to exchange platform-level signals needed by a
network operating system (NOS). The subsystem is modeled on the zebra
dataplane framework and follows the same threading and event-driven
patterns used in zebra today.

Primary motivations:

- Provide a structured, race-free channel for warm/fast boot signaling.
- Coordinate global port reset phases (start/end for "all ports").
- Report readiness milestones (for example: all graceful-restart routes
  installed).

Goals
=====

- Separate SM I/O from the zebra main pthread to keep zebra responsive.
- Enforce thread-safe communication via context objects and queues.
- Allow clean, ordered shutdown and restart behavior.
- Make it easy to add new SM message types without modifying unrelated
  zebra subsystems.

Non-Goals
=========

- Define the external SM wire protocol or persistence semantics.
- Replace existing zapi/mgmtd interactions.
- Provide platform-specific device control logic in zebra.

Relevant Existing Patterns
==========================

Zebra already uses a dedicated pthread with an event loop in two places:

- Dataplane thread creation and event scheduling.
\n```7978:8024:zebra/zebra_dplane.c
void zebra_dplane_start(void)
{
    /* Start dataplane pthread */
    zdplane_info.dg_pthread = frr_pthread_new(&pattr, "Zebra dplane thread",
                          "zebra_dplane");
    zdplane_info.dg_master = zdplane_info.dg_pthread->master;
    zdplane_info.dg_run = true;
    event_add_event(zdplane_info.dg_master, dplane_thread_loop, NULL, 0,
            &zdplane_info.dg_t_update);
    /* ... */
    frr_pthread_run(zdplane_info.dg_pthread, NULL);
}
```

- Opaque module thread creation and event scheduling.
\n```141:165:zebra/zebra_opaque.c
void zebra_opaque_start(void)
{
    /* Start pthread */
    zo_info.pthread = frr_pthread_new(&pattr, "Zebra Opaque thread",
                      "zebra_opaque");
    zo_info.master = zo_info.pthread->master;
    atomic_store_explicit(&zo_info.run, 1, memory_order_relaxed);
    event_add_event(zo_info.master, process_messages, NULL, 0,
            &zo_info.t_msgs);
    frr_pthread_run(zo_info.pthread, NULL);
}
```

The dataplane also uses context objects and queues to carry work between
threads and providers. The SM design should copy that model:

\n```430:533:zebra/zebra_dplane.c
struct zebra_dplane_ctx {
    /* ... */
    union {
        /* per-op payloads */
        enum zebra_dplane_startup_notifications spot;
        /* ... */
    } u;
    struct zebra_dplane_info zd_ns_info;
    struct dplane_ctx_list_item zd_entries;
};
/* provider queues, globals, and mutex in the same module */
```

High-Level Architecture
=======================

Threads and Event Loops
-----------------------

- Zebra main pthread remains the owner of zebra core state.
- A new SM pthread is created with its own event loop (master).
- All interactions between zebra main and SM thread are via "SM context"
  objects enqueued on thread-safe queues (no direct data sharing).

Context Model
-------------

Define a new context object similar to ``struct zebra_dplane_ctx``:

- ``struct zebra_sysmgr_ctx`` holds:
  - Operation enum (``enum sysmgr_op_e``).
  - Status/result code (``enum zebra_sysmgr_result``).
  - Optional correlation ID and timestamps.
  - Union payload for op-specific data (warm boot, port reset, GR state,
    generic key/value).
  - Embedded list link for queueing.

Queues and Ownership
--------------------

Two queues are required:

- **Inbound to SM thread**: requests and notifications from zebra core.
- **Outbound to zebra main**: results and async notifications from SM.

Ownership rules:

- The producer allocates and initializes a context.
- The consumer frees or recycles after processing.
- No shared mutable state outside the context itself.

Use a mutex and list-head per queue, similar to dplane. Optionally, wrap
queue operations in helper APIs (alloc/enqueue/dequeue/list-append).

Transport/Provider Interface
----------------------------

The SM thread should own external I/O to the system manager. To keep the
design flexible, introduce an internal provider interface:

- ``struct zebra_sysmgr_provider`` with callbacks:
  - ``start``: open socket/IPC, register reads, perform handshake.
  - ``process``: handle a batch of inbound SM contexts.
  - ``read``: process incoming messages from SM, convert to contexts.
  - ``stop``: close resources.

The first implementation can be a Unix-domain socket transport. The
interface allows future support for other SM backends without changing
the zebra main thread.

Message Taxonomy
----------------

Proposed operations (initial set, extensible):

- ``SM_OP_WARMBOOT_BEGIN`` / ``SM_OP_WARMBOOT_END``
- ``SM_OP_FASTBOOT_BEGIN`` / ``SM_OP_FASTBOOT_END``
- ``SM_OP_PORT_RESET_BEGIN`` / ``SM_OP_PORT_RESET_END``
- ``SM_OP_GR_ROUTES_INSTALLED``
- ``SM_OP_QUERY_STATE`` / ``SM_OP_STATE_REPLY``
- ``SM_OP_GENERIC_NOTIFY`` (TLV-style for platform-specific signals)

Processing Model
----------------

SM thread event loop:

1. Dequeue a bounded number of inbound contexts (similar to the dplane
   per-cycle limit) to avoid starvation.
2. Send outbound messages to the system manager using provider callbacks.
3. Read incoming SM messages, convert to contexts, enqueue to zebra main.
4. Reschedule itself via ``event_add_event`` to continue processing.

Zebra main thread:

- Enqueue requests using a public API (``zebra_sysmgr_enqueue``).
- Receive SM notifications via a zebra-event callback that drains the
  outbound queue (similar to rib dplane result processing).
\n```5102:5112:zebra/zebra_rib.c
static int rib_dplane_results(struct dplane_ctx_list_head *ctxlist)
{
    frr_with_mutex (&dplane_mutex) {
        dplane_ctx_list_append(&rib_dplane_q, ctxlist);
    }
    event_add_event(zrouter.master, rib_process_dplane_results, NULL, 0,
            &t_dplane);
    return 0;
}
```

Lifecycle and Shutdown
----------------------

The SM subsystem follows the same lifecycle as dplane/opaque:

- ``zebra_sysmgr_init()``: initialize queues, mutexes, defaults.
- ``zebra_sysmgr_start()``: create and run pthread after fork.
- ``zebra_sysmgr_stop()``: stop pthread during shutdown.
- ``zebra_sysmgr_finish()``: free resources during zebra finalization.

During shutdown, zebra should:

- Stop the SM thread before closing any resources that the provider uses.
- Drain and free queued contexts to avoid leaks.
- Optionally notify SM of shutdown or "warm boot end" as a final step.

Diagnostics and Limits
----------------------

Include counters and limits similar to dplane:

- Max queued contexts (backpressure).
- Per-cycle dequeue limit.
- Counters for inbound/outbound messages and errors.

Expose these through debug logs and, if needed, a show command later.

Example Flows
=============

Warm Boot
---------

1. System manager sends ``SM_OP_WARMBOOT_BEGIN`` to SM thread.
2. SM thread translates to context and enqueues to zebra main.
3. Zebra sets internal state and suppresses disruptive actions.
4. Zebra later sends ``SM_OP_WARMBOOT_END`` when ready.

Port Reset Phase
----------------

1. System manager triggers "port reset start".
2. Zebra defers per-interface events until "port reset end" arrives.
3. Zebra then processes accumulated interface changes.

Graceful Restart Routes Installed
---------------------------------

1. Zebra determines GR routes installed (existing logic).
2. Zebra enqueues ``SM_OP_GR_ROUTES_INSTALLED`` to SM thread.
3. SM thread sends a notification to the system manager.

Implementation Steps
====================

1. **Add new module skeleton**
   - Create ``zebra/zebra_sysmgr.[ch]`` and add to build system.
   - Add init/start/stop/finish entry points.

2. **Define context and queues**
   - Add ``struct zebra_sysmgr_ctx`` with op, status, payload union.
   - Implement alloc/free/reset and queue helpers (list + mutex).

3. **Add SM pthread and event loop**
   - Create ``frr_pthread`` and event master.
   - Implement ``sysmgr_thread_loop`` with bounded dequeue and reschedule.

4. **Results callback into zebra main**
   - Implement a results enqueue function (patterned on dplane results).
   - Add event handler to drain SM-to-zebra queue in main thread.

5. **Transport/provider interface**
   - Define a provider API and add the first provider (Unix socket).
   - The provider converts wire messages to contexts and back.

6. **Wire zebra lifecycle**
   - Call ``zebra_sysmgr_init`` during zebra init.
   - Call ``zebra_sysmgr_start`` after fork.
   - Call ``zebra_sysmgr_stop`` and ``zebra_sysmgr_finish`` during shutdown.

7. **Implement first signals**
   - Add enums and payload structs for warm/fast boot and port reset.
   - Add "GR routes installed" notification path.

8. **Add observability**
   - Add debug logs and counters for enqueue/dequeue and errors.
   - Optional VTY/show command later if needed.

9. **Add tests**
   - Unit tests for queueing and lifecycle.
   - Integration tests for SM protocol if a mock is available.

Open Questions
==============

- What is the preferred external SM transport (UNIX socket, gRPC, or mgmtd)?
- Do we need persistence of SM state across zebra restart?
- Are any signals latency-sensitive enough to require priority queues?
