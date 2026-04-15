// SPDX-License-Identifier: GPL-2.0-or-later
/* Tracing for staticd
 *
 * Copyright (C) 2026  NVIDIA Corporation
 * Sougata Barik
 */

#if !defined(_STATIC_TRACE_H_) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _STATIC_TRACE_H_

#include "lib/trace.h"

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_static

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "staticd/static_trace.h"

#include <lttng/tracepoint.h>

/* clang-format off */

/*
 * Matches static_next_hop_bfd_change DEBUG: session status / path_down.
 * state/previous_state: enum bfd_session_state values (BSS_*).
 */
TRACEPOINT_EVENT(
	frr_static,
	static_bfd_session_change,
	TP_ARGS(uintptr_t, sn, uint32_t, state, uint32_t, previous_state,
		uint8_t, path_down),
	TP_FIELDS(
		ctf_integer(uintptr_t, nexthop, sn)
		ctf_integer(uint32_t, state, state)
		ctf_integer(uint32_t, previous_state, previous_state)
		ctf_integer(uint8_t, path_down, path_down)
	)
)

TRACEPOINT_LOGLEVEL(frr_static, static_bfd_session_change, TRACE_INFO)

/*
 * Hold-down timer cancelled. reason: 0=admin_down, 1=bfd_up, 2=rearm, 3=monitor_off
 */
TRACEPOINT_EVENT(
	frr_static,
	static_bfd_holddown_cancel,
	TP_ARGS(uintptr_t, sn, uint8_t, reason),
	TP_FIELDS(
		ctf_integer(uintptr_t, nexthop, sn)
		ctf_integer(uint8_t, reason, reason)
	)
)

TRACEPOINT_LOGLEVEL(frr_static, static_bfd_holddown_cancel, TRACE_INFO)

/*
 * Hold-down timer armed after Admin Down -> Down. rearm: 1 if a prior timer was replaced.
 */
TRACEPOINT_EVENT(
	frr_static,
	static_bfd_holddown_arm,
	TP_ARGS(uintptr_t, sn, uint32_t, seconds, uint8_t, rearm),
	TP_FIELDS(
		ctf_integer(uintptr_t, nexthop, sn)
		ctf_integer(uint32_t, seconds, seconds)
		ctf_integer(uint8_t, rearm, rearm)
	)
)

TRACEPOINT_LOGLEVEL(frr_static, static_bfd_holddown_arm, TRACE_INFO)

/*
 * Hold-down timer fired. outcome: 0=withdraw route, 1=ignore (BFD admin-down).
 */
TRACEPOINT_EVENT(
	frr_static,
	static_bfd_holddown_expire,
	TP_ARGS(uintptr_t, sn, uint8_t, outcome),
	TP_FIELDS(
		ctf_integer(uintptr_t, nexthop, sn)
		ctf_integer(uint8_t, outcome, outcome)
	)
)

TRACEPOINT_LOGLEVEL(frr_static, static_bfd_holddown_expire, TRACE_INFO)

/* Peer down: remove from RIB (non-hold-down path). */
TRACEPOINT_EVENT(
	frr_static,
	static_bfd_down_remove_rib,
	TP_ARGS(uintptr_t, sn),
	TP_FIELDS(
		ctf_integer(uintptr_t, nexthop, sn)
	)
)

TRACEPOINT_LOGLEVEL(frr_static, static_bfd_down_remove_rib, TRACE_INFO)

/*
 * Peer up. action: 0=route already installed, 1=add to RIB.
 */
TRACEPOINT_EVENT(
	frr_static,
	static_bfd_up_rib,
	TP_ARGS(uintptr_t, sn, uint8_t, action),
	TP_FIELDS(
		ctf_integer(uintptr_t, nexthop, sn)
		ctf_integer(uint8_t, action, action)
	)
)

TRACEPOINT_LOGLEVEL(frr_static, static_bfd_up_rib, TRACE_INFO)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _STATIC_TRACE_H_ */
