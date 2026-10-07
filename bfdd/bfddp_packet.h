// SPDX-License-Identifier: MIT
/*
 * BFD Data Plane protocol messages header.
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael F. Zalamena
 */

/**
 * \file bfddp_packet.h
 */
#ifndef BFD_DP_PACKET_H
#define BFD_DP_PACKET_H

#include <netinet/in.h>

#include <stdint.h>

/*
 * Protocol definitions.
 */

/**
 * BFD protocol version as defined in RFC5880 Section 4.1 Generic BFD Control
 * Packet Format.
 */
#define BFD_PROTOCOL_VERSION 1

/** Default data plane port. */
#define BFD_DATA_PLANE_DEFAULT_PORT 50700

/** BFD single hop UDP port, as defined in RFC 5881 Section 4. Encapsulation. */
#define BFD_SINGLE_HOP_PORT 3784

/** BFD multi hop UDP port, as defined in RFC 5883 Section 5. Encapsulation. */
#define BFD_MULTI_HOP_PORT 4784

/** Default slow start multiplier. */
#define SLOWSTART_DMULT 3
/** Default slow start transmission speed. */
#define SLOWSTART_TX 1000000u
/** Default slow start receive speed. */
#define SLOWSTART_RX 1000000u
/** Default slow start echo receive speed. */
#define SLOWSTART_ERX 0u

/*
 * BFD single hop source UDP ports. As defined in RFC 5881 Section 4.
 * Encapsulation.
 */
#define BFD_SOURCE_PORT_BEGIN 49152
#define BFD_SOURCE_PORT_END 65535

/** BFD data plane protocol version. */
#define BFD_DP_VERSION 1

/**
 * Longest authentication key `DP_SESSION_AUTH` will carry.
 *
 * One HMAC block, so any key a digest defined by RFC 5880 Section 6.7 can
 * use without first being hashed down fits. The RFC bounds the keys
 * themselves far lower: 16 bytes for a simple password and 20 for keyed
 * SHA1.
 */
#define BFDDP_AUTH_KEY_MAX 64

/**
 * Most keys a single `DP_SESSION_AUTH` message will carry.
 *
 * A bound on the message rather than on what a key chain may hold. A
 * rollover needs the outgoing key and whatever is still valid for accept,
 * which is a handful, so this is already generous. It is kept small
 * enough that `struct bfddp_message` stays cheap to put on the stack,
 * since every message type shares that size.
 */
#define BFDDP_AUTH_KEY_COUNT_MAX 16

/** BFD data plane message types. */
enum bfddp_message_type {
	/** Ask for BFD daemon or data plane for echo packet. */
	ECHO_REQUEST = 0,
	/** Answer a ECHO_REQUEST packet. */
	ECHO_REPLY = 1,
	/** Add or update BFD peer session. */
	DP_ADD_SESSION = 2,
	/** Delete BFD peer session. */
	DP_DELETE_SESSION = 3,
	/** Tell BFD daemon state changed: timer expired or session down. */
	BFD_STATE_CHANGE = 4,

	/** Ask for BFD session counters. */
	DP_REQUEST_SESSION_COUNTERS = 5,
	/** Tell BFD daemon about counters values. */
	BFD_SESSION_COUNTERS = 6,

	/** Send a session's authentication keys. */
	DP_SESSION_AUTH = 7,
};

/**
 * `ECHO_REQUEST`/`ECHO_REPLY` data payload.
 *
 * Data plane might use whatever precision it wants for `dp_time`
 * field, however if you want to be able to tell the delay between
 * data plane packet send and BFD daemon packet processing you should
 * use `gettimeofday()` and have the data plane clock synchronized with
 * BFD daemon (not a problem if data plane runs in the same system).
 *
 * Normally data plane will only check the time stamp it sent to determine
 * the whole packet trip time.
 */
struct bfddp_echo {
	/** Filled by data plane. */
	uint64_t dp_time;
	/** Filled by BFD daemon. */
	uint64_t bfdd_time;
};


/** BFD session flags. */
enum bfddp_session_flag {
	/** Set when using multi hop. */
	SESSION_MULTIHOP = (1 << 0),
	/** Set when using demand mode. */
	SESSION_DEMAND = (1 << 1),
	/** Set when using cbit (Control Plane Independent). */
	SESSION_CBIT = (1 << 2),
	/** Set when using echo mode. */
	SESSION_ECHO = (1 << 3),
	/** Set when using IPv6. */
	SESSION_IPV6 = (1 << 4),
	/** Set when using passive mode. */
	SESSION_PASSIVE = (1 << 5),
	/** Set when session is administrative down. */
	SESSION_SHUTDOWN = (1 << 6),
	/**
	 * Set when the session is configured to authenticate.
	 *
	 * The keys arrive separately. \see DP_SESSION_AUTH. A data plane
	 * that cannot authenticate must refuse a session carrying this flag
	 * rather than run it in the clear, because the peer will be
	 * authenticating and `show bfd peer` reports the session as
	 * authenticated either way.
	 *
	 * There is no capability exchange in this protocol, so the daemon
	 * cannot tell whether the data plane honours any of this. A data
	 * plane written against an earlier version ignores both the flag and
	 * the keys, and such a session runs unauthenticated, which is what
	 * happens today for want of anywhere to carry a key at all.
	 */
	SESSION_AUTH = (1 << 7),
};

/**
 * `DP_ADD_SESSION`/`DP_DELETE_SESSION` data payload.
 *
 * `lid` is unique in BFD daemon so it might be used as key for data
 * structures lookup.
 */
struct bfddp_session {
	/** Important session flags. \see bfddp_session_flag. */
	uint32_t flags;
	/**
	 * Session source address.
	 *
	 * Check `flags` field for `SESSION_IPV6` before using as IPv6.
	 */
	struct in6_addr src;
	/**
	 * Session destination address.
	 *
	 * Check `flags` field for `SESSION_IPV6` before using as IPv6.
	 */
	struct in6_addr dst;

	/** Local discriminator. */
	uint32_t lid;
	/**
	 * Minimum desired transmission interval (in microseconds) without
	 * jitter.
	 */
	uint32_t min_tx;
	/**
	 * Required minimum receive interval rate (in microseconds) without
	 * jitter.
	 */
	uint32_t min_rx;
	/**
	 * Echo transmission interval (in microseconds) without jitter.
	 *
	 * This is the negotiated value: the larger of the local desired
	 * interval and the peer's advertised Required Min Echo RX (see
	 * RFC 5880 Section 6.8.9). The BFD daemon performs the
	 * negotiation, since only it processes control packets.
	 */
	uint32_t min_echo_tx;
	/**
	 * Required minimum echo receive interval rate (in microseconds)
	 * without jitter.
	 */
	uint32_t min_echo_rx;
	/** Amount of milliseconds to wait before starting the session */
	uint32_t hold_time;

	/** Minimum TTL. */
	uint8_t ttl;
	/** Detection multiplier. */
	uint8_t detect_mult;
	/** Reserved / zeroed. */
	uint16_t zero;

	/** Interface index (set to `0` when unavailable). */
	uint32_t ifindex;
	/** Interface name (empty when unavailable). */
	char ifname[64];

	/*
	 * Authentication keys are not carried here. They change on their own
	 * schedule rather than with the session, and there may be several.
	 * \see DP_SESSION_AUTH.
	 */
};

/** BFD packet state values as defined in RFC 5880, Section 4.1. */
enum bfd_state_value {
	/** Session is administratively down. */
	STATE_ADMINDOWN = 0,
	/** Session is down or went down. */
	STATE_DOWN = 1,
	/** Session is initializing. */
	STATE_INIT = 2,
	/** Session is up. */
	STATE_UP = 3,
};

/** BFD diagnostic field values as defined in RFC 5880, Section 4.1. */
enum bfd_diagnostic_value {
	/** Nothing was diagnosed. */
	DIAG_NOTHING = 0,
	/** Control detection time expired. */
	DIAG_CONTROL_EXPIRED = 1,
	/** Echo function failed. */
	DIAG_ECHO_FAILED = 2,
	/** Neighbor signaled down. */
	DIAG_DOWN = 3,
	/** Forwarding plane reset. */
	DIAG_FP_RESET = 4,
	/** Path down. */
	DIAG_PATH_DOWN = 5,
	/** Concatenated path down. */
	DIAG_CONCAT_PATH_DOWN = 6,
	/** Administratively down. */
	DIAG_ADMIN_DOWN = 7,
	/** Reverse concatenated path down. */
	DIAG_REV_CONCAT_PATH_DOWN = 8,
};

/** BFD remote state flags. */
enum bfd_remote_flags {
	/** Control Plane Independent bit. */
	RBIT_CPI = (1 << 0),
	/** Demand mode bit. */
	RBIT_DEMAND = (1 << 1),
	/** Multipoint bit. */
	RBIT_MP = (1 << 2),
};

/**
 * `BFD_STATE_CHANGE` data payload.
 */
struct bfddp_state_change {
	/** Local discriminator. */
	uint32_t lid;
	/** Remote discriminator. */
	uint32_t rid;
	/** Remote configurations/bits set. \see bfd_remote_flags. */
	uint32_t remote_flags;
	/** Remote minimum desired transmission interval. */
	uint32_t desired_tx;
	/** Remote minimum receive interval. */
	uint32_t required_rx;
	/** Remote minimum echo receive interval. */
	uint32_t required_echo_rx;
	/** Local session state as determined by the data plane.
	 * This is NOT the remote peer state; the data plane has already
	 * evaluated the BFD state machine and reports the resulting
	 * local state.  \see bfd_state_values.
	 */
	uint8_t state;
	/** Remote diagnostics (if any) */
	uint8_t diagnostics;
	/** Remote detection multiplier. */
	uint8_t detection_multiplier;
};

/**
 * BFD control packet state bits definition.
 */
enum bfddp_control_state_bits {
	/** Used to request connection establishment signal. */
	STATE_POLL_BIT = (1 << 5),
	/** Finalizes the connection establishment signal. */
	STATE_FINAL_BIT = (1 << 4),
	/** Signalizes that forward plane doesn't depend on control plane. */
	STATE_CPI_BIT = (1 << 3),
	/** Signalizes the use of authentication. */
	STATE_AUTH_BIT = (1 << 2),
	/** Signalizes that peer is using demand mode. */
	STATE_DEMAND_BIT = (1 << 1),
	/** Used in RFC 8562 implementation. */
	STATE_MULTI_BIT = (1 << 0),
};

/**
 * BFD control packet.
 *
 * As defined in 'RFC 5880 Section 4.1 Generic BFD Control Packet Format'.
 */
struct bfddp_control_packet {
	/** (3 bits version << 5) | (5 bits diag). */
	uint8_t version_diag;
	/**
	 * (2 bits state << 6) | (6 bits flags)
	 *
	 * \see bfd_state_value, bfddp_control_state_bits.
	 */
	uint8_t state_bits;
	/** Detection multiplier. */
	uint8_t detection_multiplier;
	/** Packet length in bytes. */
	uint8_t length;
	/** Our discriminator. */
	uint32_t local_id;
	/** Remote system discriminator. */
	uint32_t remote_id;
	/** Desired minimum send interval in microseconds. */
	uint32_t desired_tx;
	/** Desired minimum receive interval in microseconds. */
	uint32_t required_rx;
	/** Desired minimum echo receive interval in microseconds. */
	uint32_t required_echo_rx;
};

/**
 * Period during which a key may be used.
 *
 * Seconds since the Unix epoch. A `start` of zero means the key has always
 * been valid, and an `end` of `-1` means it never expires. Both sentinels
 * come from the BFD daemon's key chain and a data plane must honour them,
 * since a key configured without lifetimes carries them.
 */
struct bfddp_key_lifetime {
	/** First second the key may be used, or zero for no start. */
	int64_t start;
	/** Last second the key may be used, or `-1` for no expiry. */
	int64_t end;
};

/**
 * One authentication key belonging to a session.
 *
 * The data plane decides which key to use and when, so the lifetimes
 * travel with the key. Transmit with the key whose `send` period contains
 * the current time, and verify a received packet with the key whose
 * `key_id` matches the Auth Key ID field, provided its `accept` period
 * contains the current time.
 *
 * The two periods overlap on purpose during a rollover: a key stops being
 * used to transmit before it stops being accepted, so packets already in
 * flight still verify.
 */
struct bfddp_auth_key {
	/** Authentication type, as in RFC 5880 Section 4.1. */
	uint8_t type;
	/** Authentication Key ID, as in RFC 5880 Section 4.2. */
	uint8_t key_id;
	/** Length of `key`, in bytes. */
	uint8_t key_len;
	/**
	 * Reserved / zeroed.
	 *
	 * Sized so the lifetimes below start on an eight byte boundary
	 * without the compiler inserting padding of its own.
	 */
	uint8_t zero[5];

	/** When this key may be used to transmit. */
	struct bfddp_key_lifetime send;
	/** When this key may be used to verify a received packet. */
	struct bfddp_key_lifetime accept;

	/** Key material, zero padded. */
	char key[BFDDP_AUTH_KEY_MAX];
};

/**
 * `DP_SESSION_AUTH` data payload.
 *
 * `key_count` `struct bfddp_auth_key` follow this header, so the message
 * is variable length and `bfddp_message_header.length` is what bounds it.
 *
 * Sent whenever the session's keys change, which is a configuration event
 * rather than a rollover: a rollover is the data plane noticing that a
 * lifetime has passed. A message carrying no keys means the session has
 * none left and must not be authenticated.
 */
struct bfddp_session_auth {
	/** Session local discriminator. */
	uint32_t lid;
	/** Number of entries of `keys` that are present. */
	uint16_t key_count;
	/** Reserved / zeroed. */
	uint16_t zero;
	/**
	 * The keys themselves.
	 *
	 * Only the first `key_count` entries are sent, so the message on the
	 * wire is shorter than this structure and
	 * `bfddp_message_header.length` is what says how much of it is
	 * there. The array is declared at its full size so that a receiver
	 * may copy a message into `struct bfddp_message` and read it in
	 * place, which is how the rest of this protocol is handled.
	 */
	struct bfddp_auth_key keys[BFDDP_AUTH_KEY_COUNT_MAX];
};

/**
 * The protocol wire message header structure.
 */
struct bfddp_message_header {
	/** Protocol version format. \see BFD_DP_VERSION. */
	uint8_t version;
	/** Reserved / zero field. */
	uint8_t zero;
	/** Message contents type. \see bfddp_message_type. */
	uint16_t type;
	/**
	 * Message identification (to pair request/response).
	 *
	 * The ID `0` is reserved for asynchronous messages (e.g. unrequested
	 * messages).
	 */
	uint16_t id;
	/** Message length. */
	uint16_t length;
};

/**
 * Data plane session counters request.
 *
 * Message type: `DP_REQUEST_SESSION_COUNTERS`.
 */
struct bfddp_request_counters {
	/** Session local discriminator. */
	uint32_t lid;
};

/**
 * BFD session counters reply.
 *
 * Message type: `BFD_SESSION_COUNTERS`.
 */
struct bfddp_session_counters {
	/** Session local discriminator. */
	uint32_t lid;

	/** Control packet bytes input. */
	uint64_t control_input_bytes;
	/** Control packets input. */
	uint64_t control_input_packets;
	/** Control packet bytes output. */
	uint64_t control_output_bytes;
	/** Control packets output. */
	uint64_t control_output_packets;

	/** Echo packet bytes input. */
	uint64_t echo_input_bytes;
	/** Echo packets input. */
	uint64_t echo_input_packets;
	/** Echo packet bytes output. */
	uint64_t echo_output_bytes;
	/** Echo packets output. */
	uint64_t echo_output_packets;
};

/**
 * The protocol wire messages structure.
 */
struct bfddp_message {
	/** Message header. \see bfddp_message_header. */
	struct bfddp_message_header header;

	/** Message payload. \see bfddp_message_type. */
	union {
		struct bfddp_echo echo;
		struct bfddp_session session;
		struct bfddp_state_change state;
		struct bfddp_control_packet control;
		struct bfddp_request_counters counters_req;
		struct bfddp_session_counters session_counters;
		struct bfddp_session_auth session_auth;
	} data;
};

#endif /* BFD_DP_PACKET_H */
