/* Tracing for BGP
 *
 * Copyright (C) 2020  NVIDIA Corporation
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#if !defined(_BGP_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _BGP_TRACE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_bgp

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "bgpd/bgp_trace.h"

#include <lttng/tracepoint.h>

#include "bgpd/bgpd.h"
#include "lib/stream.h"

/* clang-format off */

TRACEPOINT_EVENT_CLASS(
	frr_bgp,
	packet_process,
	TP_ARGS(struct peer *, peer, bgp_size_t, size),
	TP_FIELDS(
		ctf_string(peer, peer->host ? peer->host : "(unknown peer)")
	)
)

#define PKT_PROCESS_TRACEPOINT_INSTANCE(name)                                  \
	TRACEPOINT_EVENT_INSTANCE(                                             \
		frr_bgp, packet_process, name,                                 \
		TP_ARGS(struct peer *, peer, bgp_size_t, size))                \
	TRACEPOINT_LOGLEVEL(frr_bgp, name, TRACE_INFO)

PKT_PROCESS_TRACEPOINT_INSTANCE(open_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(keepalive_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(update_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(notification_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(capability_process)
PKT_PROCESS_TRACEPOINT_INSTANCE(refresh_process)

TRACEPOINT_EVENT(
	frr_bgp,
	packet_read,
	TP_ARGS(struct peer *, peer, struct stream *, pkt),
	TP_FIELDS(
		ctf_string(peer, peer->host ? peer->host : "(unknown peer)")
		ctf_integer(size_t, size, STREAM_READABLE(pkt))
		ctf_sequence_hex(uint8_t, packet, pkt->data, size_t, STREAM_READABLE(pkt))
	)
)


#include <lttng/tracepoint-event.h>

#else /* HAVE_LTTNG */

#define tracepoint(...)
#define tracef(...)
#define tracelog(...)
#define tracepoint_enabled(...) true

#endif /* HAVE_LTTNG */

#endif /* _BGP_TRACE_H */
