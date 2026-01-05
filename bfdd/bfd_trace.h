// SPDX-License-Identifier: GPL-2.0-or-later
/* BFD LTTng tracepoints
 *
 * Copyright (C) 2024  NVIDIA Corporation
 * Based on BGP tracing implementation
 */

#if !defined(_BFD_TRACE_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _BFD_TRACE_H

#include "lib/trace.h"

#if defined(HAVE_LTTNG) || defined(HAVE_BFD_LTTNG)

#if !defined(HAVE_LTTNG)
#undef frrtrace
#undef frrtrace_enabled
#undef frrtracelog
#define frrtrace(nargs, provider, name, ...)                                   \
	tracepoint(provider, name, ##__VA_ARGS__)
#define frrtrace_enabled(...) tracepoint_enabled(__VA_ARGS__)
#define frrtracelog(...) tracelog(__VA_ARGS__)
#endif

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_bfd

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "bfdd/bfd_trace.h"

#include <lttng/tracepoint.h>
#include "bfdd/bfd.h"
#include "lib/stream.h"

/* clang-format off */

/*
 * BFD state change tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	state_change,
	TP_ARGS(struct bfd_session *, bs, uint8_t, old_state, uint8_t, new_state, uint8_t, diag),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint32_t, remote_discr, bs ? bs->discrs.remote_discr : 0)
		ctf_integer(uint8_t, family, bs ? bs->key.family : 0)
		ctf_array(uint8_t, local_addr, bs ? (uint8_t *)&bs->key.local : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, peer_addr, bs ? (uint8_t *)&bs->key.peer : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, vrf_id, (bs && bs->vrf) ? bs->vrf->vrf_id : VRF_UNKNOWN)
		ctf_integer(uint32_t, ifindex, (bs && bs->ifp) ? bs->ifp->ifindex : 0)
		ctf_integer(bool, mhop, bs ? CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH) : false)
		ctf_string(vrfname, (bs && bs->key.vrfname[0]) ? bs->key.vrfname : "")
		ctf_string(ifname, (bs && bs->key.ifname[0]) ? bs->key.ifname : "")
		ctf_integer(uint8_t, old_state, old_state)
		ctf_integer(uint8_t, new_state, new_state)
		ctf_integer(uint8_t, diag, diag)
	)
)

/*
 * BFD session lifecycle tracepoint
 * is_create: true=create, false=delete
 */
TRACEPOINT_EVENT(
	frr_bfd,
	session_lifecycle,
	TP_ARGS(bool, is_create, struct bfd_session *, bs),
	TP_FIELDS(
		ctf_integer(bool, is_create, is_create)
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint8_t, family, bs ? bs->key.family : 0)
		ctf_integer(bool, mhop, bs ? bs->key.mhop : 0)
		ctf_array(uint8_t, local_addr, bs ? (uint8_t *)&bs->key.local : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, peer_addr, bs ? (uint8_t *)&bs->key.peer : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, (bs && bs->ifp) ? bs->ifp->ifindex : 0)
		ctf_integer(uint32_t, vrf_id, (bs && bs->vrf) ? bs->vrf->vrf_id : VRF_UNKNOWN)
		ctf_integer(uint32_t, desired_min_tx_ms, bs ? bs->timers.desired_min_tx / 1000 : 0)
		ctf_integer(uint32_t, required_min_rx_ms, bs ? bs->timers.required_min_rx / 1000 : 0)
		ctf_integer(uint8_t, detect_mult, bs ? bs->detect_mult : 0)
	)
)

/*
 * BFD session enable/disable tracepoint
 * is_enable: true=enable, false=disable
 */
TRACEPOINT_EVENT(
	frr_bfd,
	session_enable_event,
	TP_ARGS(bool, is_enable, struct bfd_session *, bs),
	TP_FIELDS(
		ctf_integer(bool, is_enable, is_enable)
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint8_t, family, bs ? bs->key.family : 0)
		ctf_array(uint8_t, local_addr, bs ? (uint8_t *)&bs->key.local : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, peer_addr, bs ? (uint8_t *)&bs->key.peer : (uint8_t[16]) {0}, 16)
		ctf_integer(uint8_t, state, bs ? bs->ses_state : 0)
		ctf_integer(bool, passive, bs ? CHECK_FLAG(bs->flags, BFD_SESS_FLAG_PASSIVE) : 0)
	)
)

/*
 * BFD authentication event tracepoint
 * is_success: true=success, false=failure
 * Includes packet context info (mhop, peer, local, ifindex, vrfid)
 */
TRACEPOINT_EVENT(
	frr_bfd,
	auth_event,
	TP_ARGS(bool, is_success, struct bfd_session *, bs, uint8_t, auth_type,
		bool, is_mhop, struct sockaddr_any *, peer, struct sockaddr_any *, local,
		ifindex_t, ifindex, vrf_id_t, vrfid),
	TP_FIELDS(
		ctf_integer(bool, is_success, is_success)
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint8_t, auth_type, auth_type)
		ctf_integer(bool, mhop, is_mhop)
		ctf_integer(uint8_t, family, peer ? peer->sa_sin.sin_family : 0)
		ctf_array(uint8_t, peer_addr, peer ? (uint8_t *)&peer->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, local_addr, local ? (uint8_t *)&local->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrfid)
	)
)

/*
 * BFD profile application tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	profile_apply,
	TP_ARGS(struct bfd_session *, bs, const char *, profname),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_string(profile_name, profname ? profname : "")
	)
)

/*
 * BFD session label update tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	session_label_update,
	TP_ARGS(struct bfd_session *, bs, const char *, label),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_string(label, label ? label : "")
	)
)

/*
 * BFD control notification tracepoint
 * Includes full session details for debugging
 */
TRACEPOINT_EVENT(
	frr_bfd,
	control_notify,
	TP_ARGS(struct bfd_session *, bs, uint8_t, notify_state),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint32_t, remote_discr, bs ? bs->discrs.remote_discr : 0)
		ctf_integer(uint8_t, notify_state, notify_state)
		ctf_integer(uint8_t, family, bs ? bs->key.family : 0)
		ctf_array(uint8_t, local_addr, bs ? (uint8_t *)&bs->key.local : (uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)
		ctf_array(uint8_t, peer_addr, bs ? (uint8_t *)&bs->key.peer : (uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)
		ctf_integer(bool, mhop, bs ? bs->key.mhop : false)
		ctf_string(vrfname, bs && bs->key.vrfname[0] ? bs->key.vrfname : "default")
		ctf_string(ifname, bs && bs->key.ifname[0] ? bs->key.ifname : "")
	)
)

/*
 * BFD packet validation error tracepoint
 * error_code: 1=PACKET_TOO_SMALL, 2=INVALID_TTL, 3=BAD_VERSION, 4=ZERO_DETECT_MULT,
 *             5=INVALID_LENGTH, 6=MULTIPOINT_SET, 7=ZERO_DISCRIMINATOR, 8=WRONG_VRF
 * error_value: actual value that caused the error (e.g., actual TTL, version, size)
 * expected_value: expected value (e.g., expected TTL=255, expected version=1)
 * Includes packet context info (mhop, peer, local)
 */
TRACEPOINT_EVENT(
	frr_bfd,
	packet_validation_error,
	TP_ARGS(uint8_t, error_code, bool, is_mhop, struct sockaddr_any *, peer,
		struct sockaddr_any *, local, ifindex_t, ifindex, vrf_id_t, vrfid,
		uint32_t, error_value, uint32_t, expected_value),
	TP_FIELDS(
		ctf_integer(uint8_t, error_code, error_code)
		ctf_integer(bool, mhop, is_mhop)
		ctf_integer(uint8_t, family, peer ? peer->sa_sin.sin_family : 0)
		ctf_array(uint8_t, peer_addr, peer ? (uint8_t *)&peer->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, local_addr, local ? (uint8_t *)&local->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrfid)
		ctf_integer(uint32_t, error_value, error_value)
		ctf_integer(uint32_t, expected_value, expected_value)
	)
)

/*
 * BFD control plane session not found tracepoint
 * Includes packet context info (mhop, peer, local)
 */
TRACEPOINT_EVENT(
	frr_bfd,
	packet_session_not_found,
	TP_ARGS(bool, is_mhop, struct sockaddr_any *, peer, struct sockaddr_any *, local,
		ifindex_t, ifindex, vrf_id_t, vrfid, uint32_t, remote_discr),
	TP_FIELDS(
		ctf_integer(bool, mhop, is_mhop)
		ctf_integer(uint8_t, family, peer ? peer->sa_sin.sin_family : 0)
		ctf_array(uint8_t, peer_addr, peer ? (uint8_t *)&peer->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, local_addr, local ? (uint8_t *)&local->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrfid)
		ctf_integer(uint32_t, remote_discr, remote_discr)
	)
)

/*
 * BFD remote discriminator change tracepoint
 * Includes packet context info (mhop, peer, local, ifindex, vrfid)
 */
TRACEPOINT_EVENT(
	frr_bfd,
	remote_discriminator_change,
	TP_ARGS(struct bfd_session *, bs, uint32_t, old_discr, uint32_t, new_discr,
		bool, is_mhop, struct sockaddr_any *, peer, struct sockaddr_any *, local,
		ifindex_t, ifindex, vrf_id_t, vrfid),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint32_t, old_remote_discr, old_discr)
		ctf_integer(uint32_t, new_remote_discr, new_discr)
		ctf_integer(bool, mhop, is_mhop)
		ctf_integer(uint8_t, family, peer ? peer->sa_sin.sin_family : 0)
		ctf_array(uint8_t, peer_addr, peer ? (uint8_t *)&peer->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, local_addr, local ? (uint8_t *)&local->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrfid)
	)
)

/*
 * BFD packet remote discriminator zero tracepoint
 * Traced when remote_discr is zero but session is not DOWN/ADM_DOWN
 */
TRACEPOINT_EVENT(
	frr_bfd,
	packet_remote_discr_zero,
	TP_ARGS(bool, is_mhop, struct sockaddr_any *, peer, struct sockaddr_any *, local,
		ifindex_t, ifindex, vrf_id_t, vrfid, uint8_t, session_state),
	TP_FIELDS(
		ctf_integer(bool, mhop, is_mhop)
		ctf_integer(uint8_t, family, peer ? peer->sa_sin.sin_family : 0)
		ctf_array(uint8_t, peer_addr, peer ? (uint8_t *)&peer->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, local_addr, local ? (uint8_t *)&local->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrfid)
		ctf_integer(uint8_t, session_state, session_state)
	)
)

/*
 * BFD packet TTL exceeded tracepoint (multihop only)
 * Traced when packet TTL is less than session's mh_ttl
 */
TRACEPOINT_EVENT(
	frr_bfd,
	packet_ttl_exceeded,
	TP_ARGS(bool, is_mhop, struct sockaddr_any *, peer, struct sockaddr_any *, local,
		ifindex_t, ifindex, vrf_id_t, vrfid, uint8_t, actual_ttl, uint8_t, expected_ttl),
	TP_FIELDS(
		ctf_integer(bool, mhop, is_mhop)
		ctf_integer(uint8_t, family, peer ? peer->sa_sin.sin_family : 0)
		ctf_array(uint8_t, peer_addr, peer ? (uint8_t *)&peer->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, local_addr, local ? (uint8_t *)&local->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrfid)
		ctf_integer(uint8_t, actual_ttl, actual_ttl)
		ctf_integer(uint8_t, expected_min_ttl, expected_ttl)
	)
)

/*
 * BFD echo packet error tracepoint
 * error_type: 1=PACKET_TOO_SMALL, 2=ZERO_DISCRIMINATOR
 */
TRACEPOINT_EVENT(
	frr_bfd,
	echo_packet_error,
	TP_ARGS(uint8_t, error_type, struct sockaddr_any *, peer, struct sockaddr_any *, local,
		ifindex_t, ifindex, vrf_id_t, vrfid, ssize_t, pkt_len),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(uint8_t, family, peer ? peer->sa_sin.sin_family : 0)
		ctf_array(uint8_t, peer_addr, peer ? (uint8_t *)&peer->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, local_addr, local ? (uint8_t *)&local->sa_sin.sin_addr : (uint8_t[16]) {0}, 16)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrfid)
		ctf_integer(int64_t, pkt_len, pkt_len)
	)
)

/*
 * BFD timer negotiation tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	timer_negotiation,
	TP_ARGS(struct bfd_session *, bs, uint32_t, xmt_TO, uint32_t, required_min_rx, uint64_t, detect_TO, uint64_t, echo_xmt_TO, uint64_t, echo_detect_TO),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint32_t, xmt_TO_ms, xmt_TO / 1000)
		ctf_integer(uint32_t, required_min_rx_ms, required_min_rx / 1000)
		ctf_integer(uint64_t, detect_TO_ms, detect_TO / 1000)
		ctf_integer(uint64_t, echo_xmt_TO_ms, echo_xmt_TO / 1000)
		ctf_integer(uint64_t, echo_detect_TO_ms, echo_detect_TO / 1000)
	)
)

/*
 * BFD control client event tracepoint
 * is_connect: true=connect, false=disconnect
 */
TRACEPOINT_EVENT(
	frr_bfd,
	control_client_event,
	TP_ARGS(bool, is_connect, int, socket_fd),
	TP_FIELDS(
		ctf_integer(bool, is_connect, is_connect)
		ctf_integer(int, client_fd, socket_fd)
	)
)

/*
 * BFD echo mode change tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	echo_mode_change,
	TP_ARGS(struct bfd_session *, bs, bool, enabled),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(bool, echo_enabled, enabled)
	)
)

/*
 * BFD data plane session not found tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	dplane_session_not_found,
	TP_ARGS(uint32_t, local_discr),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, local_discr)
	)
)

/*
 * BFD data plane add/delete session tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	dplane_session_update,
	TP_ARGS(bool, is_add, uint32_t, lid, uint32_t, flags, uint8_t, detect_mult, uint8_t, ttl),
	TP_FIELDS(
		ctf_integer(bool, is_add, is_add)
		ctf_integer(uint32_t, local_discr, lid)
		ctf_integer(uint32_t, flags, flags)
		ctf_integer(uint8_t, detect_mult, detect_mult)
		ctf_integer(uint8_t, ttl, ttl)
	)
)

/*
 * BFD data plane echo request/reply tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	dplane_echo,
	TP_ARGS(bool, is_request, uint64_t, dp_time, uint64_t, bfdd_time),
	TP_FIELDS(
		ctf_integer(bool, is_request, is_request)
		ctf_integer(uint64_t, dp_time, dp_time)
		ctf_integer(uint64_t, bfdd_time, bfdd_time)
	)
)

/*
 * BFD data plane socket error tracepoint
 * Covers initialization (socket, bind, listen) and connection (accept, connect) errors
 * op_code: 1=socket, 2=bind, 3=listen, 4=accept, 5=connect, 6=setsockopt_reuseaddr
 */
TRACEPOINT_EVENT(
	frr_bfd,
	dplane_init_error,
	TP_ARGS(uint8_t, op_code, int, error_code),
	TP_FIELDS(
		ctf_integer(uint8_t, op_code, op_code)
		ctf_integer(int, errno_val, error_code)
	)
)

/*
 * BFD VRF lifecycle tracepoint
 * action: 1=create, 2=delete, 3=enable, 4=disable
 */
TRACEPOINT_EVENT(
	frr_bfd,
	vrf_lifecycle,
	TP_ARGS(uint8_t, action, vrf_id_t, vrf_id),
	TP_FIELDS(
		ctf_integer(uint8_t, action, action)
		ctf_integer(uint32_t, vrf_id, vrf_id)
	)
)

/*
 * BFD Zebra interface event tracepoint
 * action: 1=add, 2=delete, 3=up, 4=down
 */
TRACEPOINT_EVENT(
	frr_bfd,
	zebra_interface_event,
	TP_ARGS(uint8_t, action, ifindex_t, ifindex, vrf_id_t, vrf_id,
		const char *, ifname, const char *, vrfname),
	TP_FIELDS(
		ctf_integer(uint8_t, action, action)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrf_id)
		ctf_string(ifname, ifname ? ifname : "")
		ctf_string(vrfname, vrfname ? vrfname : "")
	)
)

/*
 * BFD Zebra address event tracepoint
 * action: 1=add, 2=delete
 */
TRACEPOINT_EVENT(
	frr_bfd,
	zebra_address_event,
	TP_ARGS(uint8_t, action, uint8_t, family, ifindex_t, ifindex, vrf_id_t, vrf_id,
		uint8_t *, addr, uint8_t, prefixlen),
	TP_FIELDS(
		ctf_integer(uint8_t, action, action)
		ctf_integer(uint8_t, family, family)
		ctf_integer(uint32_t, ifindex, ifindex)
		ctf_integer(uint32_t, vrf_id, vrf_id)
		ctf_array(uint8_t, addr, addr, 16)
		ctf_integer(uint8_t, prefixlen, prefixlen)
	)
)

/*
 * BFD control protocol error tracepoint
 * error_type: 1=small_message, 2=invalid_length, 3=bad_version, 4=unhandled_message
 */
TRACEPOINT_EVENT(
	frr_bfd,
	control_protocol_error,
	TP_ARGS(uint8_t, error_type, int, client_fd, uint32_t, value),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(int, client_fd, client_fd)
		ctf_integer(uint32_t, value, value)
	)
)

/*
 * BFD PTM session event tracepoint
 * action: 1=add, 2=delete
 * For session operations with full session info
 */
TRACEPOINT_EVENT(
	frr_bfd,
	ptm_session_event,
	TP_ARGS(uint8_t, action, uint32_t, local_discr, uint8_t, diag,
		uint8_t, family, uint8_t *, local_addr, uint8_t *, peer_addr, uint64_t, refcount),
	TP_FIELDS(
		ctf_integer(uint8_t, action, action)
		ctf_integer(uint32_t, local_discr, local_discr)
		ctf_integer(uint8_t, diag, diag)
		ctf_integer(uint8_t, family, family)
		ctf_array(uint8_t, local_addr, local_addr, 16)
		ctf_array(uint8_t, peer_addr, peer_addr, 16)
		ctf_integer(uint64_t, refcount, refcount)
	)
)

/*
 * BFD PTM client event tracepoint
 * action: 1=register, 2=deregister
 * For client operations
 */
TRACEPOINT_EVENT(
	frr_bfd,
	ptm_client_event,
	TP_ARGS(uint8_t, action, uint32_t, pid),
	TP_FIELDS(
		ctf_integer(uint8_t, action, action)
		ctf_integer(uint32_t, pid, pid)
	)
)

/*
 * BFD packet send error tracepoint
 * error_type: 1=send_failure, 2=partial_send
 * Includes full session details (addresses, interface, socket)
 */
TRACEPOINT_EVENT(
	frr_bfd,
	packet_send_error,
	TP_ARGS(uint8_t, error_type, struct bfd_session *, bs, int, sd,
		ssize_t, bytes_sent, size_t, expected, int, error_code),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(uint32_t, local_discr, bs ? bs->discrs.my_discr : 0)
		ctf_integer(uint32_t, remote_discr, bs ? bs->discrs.remote_discr : 0)
		ctf_integer(uint8_t, family, bs ? bs->key.family : 0)
		ctf_array(uint8_t, local_addr, bs ? (uint8_t *)&bs->key.local : (uint8_t[16]) {0}, 16)
		ctf_array(uint8_t, peer_addr, bs ? (uint8_t *)&bs->key.peer : (uint8_t[16]) {0}, 16)
		ctf_integer(bool, mhop, bs ? CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH) : false)
		ctf_integer(uint32_t, ifindex, (bs && bs->ifp) ? bs->ifp->ifindex : 0)
		ctf_integer(uint32_t, vrf_id, (bs && bs->vrf) ? bs->vrf->vrf_id : VRF_UNKNOWN)
		ctf_string(vrfname, (bs && bs->key.vrfname[0]) ? bs->key.vrfname : "")
		ctf_string(ifname, (bs && bs->key.ifname[0]) ? bs->key.ifname : "")
		ctf_integer(int, socket_fd, sd)
		ctf_integer(int64_t, bytes_sent, bytes_sent)
		ctf_integer(uint64_t, expected_bytes, expected)
		ctf_integer(int, errno_val, error_code)
	)
)

/*
 * BFD statistics error tracepoint
 * error_type: 1=counters_update_failed
 */
TRACEPOINT_EVENT(
	frr_bfd,
	stats_error,
	TP_ARGS(uint8_t, error_type, uint32_t, local_discr, int, error_code),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(uint32_t, local_discr, local_discr)
		ctf_integer(int, error_code, error_code)
	)
)

/*
 * BFD VRF not found tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	vrf_not_found,
	TP_ARGS(const char *, vrf_name),
	TP_FIELDS(
		ctf_string(vrf_name, vrf_name ? vrf_name : "")
	)
)

/*
 * BFD interface not found tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	interface_not_found,
	TP_ARGS(const char *, ifname, uint32_t, vrf_id),
	TP_FIELDS(
		ctf_string(ifname, ifname ? ifname : "")
		ctf_integer(uint32_t, vrf_id, vrf_id)
	)
)

/*
 * BFD refcount error tracepoint
 */
TRACEPOINT_EVENT(
	frr_bfd,
	refcount_error,
	TP_ARGS(uint64_t, refcount),
	TP_FIELDS(
		ctf_integer(uint64_t, refcount, refcount)
	)
)

/*
 * BFD socket operation error tracepoint
 * error_type: 1=SOCKET_CREATE_FAILED, 2=BIND_FAILED, 3=LISTEN_FAILED,
 *             4=RECV_FAILED, 5=CLOSE_FAILED
 * socket_type: 1=control, 2=ipv4_shop, 3=ipv4_mhop, 4=ipv6_shop, 5=ipv6_mhop, 6=echo
 */
TRACEPOINT_EVENT(
	frr_bfd,
	socket_error,
	TP_ARGS(uint8_t, error_type, uint8_t, socket_type, int, error_code),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(uint8_t, socket_type, socket_type)
		ctf_integer(int, errno_val, error_code)
	)
)

/*
 * BFD config error tracepoint
 * error_type: 1=UNSUPPORTED_PEER_TYPE
 */
TRACEPOINT_EVENT(
	frr_bfd,
	config_error,
	TP_ARGS(uint8_t, error_type, uint32_t, value),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(uint32_t, value, value)
	)
)

/*
 * BFD dataplane client error tracepoint
 * error_type: 1=BAD_VERSION
 */
TRACEPOINT_EVENT(
	frr_bfd,
	dplane_client_error,
	TP_ARGS(uint8_t, error_type, int, version),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(int, version, version)
	)
)

/*
 * BFD PTM config refcount error tracepoint
 * Traced when a CLI-configured session has refcount=0 (indicates a bug)
 */
TRACEPOINT_EVENT(
	frr_bfd,
	ptm_config_refcount_error,
	TP_ARGS(uint32_t, local_discr, uint8_t, family, uint8_t *, local_addr, uint8_t *, peer_addr),
	TP_FIELDS(
		ctf_integer(uint32_t, local_discr, local_discr)
		ctf_integer(uint8_t, family, family)
		ctf_array(uint8_t, local_addr, local_addr, 16)
		ctf_array(uint8_t, peer_addr, peer_addr, 16)
	)
)

/*
 * BFD PTM adapter error tracepoint
 * error_type: 1=IFNAME_TOO_BIG, 2=VRF_ID_NOT_FOUND,
 *             3=CLIENT_REGISTER_FAILED, 4=CLIENT_DEREGISTER_FAILED, 5=REPLAY_CMD_NOT_FOUND,
 *             6=SESSION_CREATE_FAILED, 7=SESSION_NOT_FOUND, 8=CLIENT_NOT_FOUND, 9=INVALID_MSG_TYPE
 */
TRACEPOINT_EVENT(
	frr_bfd,
	ptm_error,
	TP_ARGS(uint8_t, error_type, uint32_t, value),
	TP_FIELDS(
		ctf_integer(uint8_t, error_type, error_type)
		ctf_integer(uint32_t, value, value)
	)
)


TRACEPOINT_LOGLEVEL(frr_bfd, state_change, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, session_lifecycle, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, session_enable_event, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, auth_event, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, profile_apply, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, session_label_update, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, control_notify, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, packet_validation_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, packet_session_not_found, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, remote_discriminator_change, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, packet_remote_discr_zero, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, packet_ttl_exceeded, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, echo_packet_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, timer_negotiation, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, control_client_event, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, echo_mode_change, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, dplane_session_not_found, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, dplane_session_update, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, dplane_echo, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(frr_bfd, dplane_init_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, vrf_lifecycle, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, zebra_interface_event, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, zebra_address_event, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, control_protocol_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, ptm_session_event, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, ptm_client_event, TRACE_INFO)
TRACEPOINT_LOGLEVEL(frr_bfd, packet_send_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, stats_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, vrf_not_found, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, interface_not_found, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, refcount_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, ptm_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, ptm_config_refcount_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, socket_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, config_error, TRACE_WARNING)
TRACEPOINT_LOGLEVEL(frr_bfd, dplane_client_error, TRACE_WARNING)

/* clang-format on */

#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* _BFD_TRACE_H */
