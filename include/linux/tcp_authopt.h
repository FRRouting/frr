/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Copy of TCP Authentication Option Linux ABI
 * This contains only the relevant subset of include/uapi/linux/tcp.h
 */
#ifndef __LINUX_TCP_AUTHOPT_H
#define __LINUX_TCP_AUTHOPT_H

#include <linux/socket.h>

#define TCP_AUTHOPT		38	/* TCP Authentication Option (RFC5925) */
#define TCP_AUTHOPT_KEY		39	/* TCP Authentication Option Key (RFC5925) */

/**
 * enum tcp_authopt_flag - flags for `tcp_authopt.flags`
 */
enum tcp_authopt_flag {
	/**
	 * @TCP_AUTHOPT_FLAG_LOCK_KEYID: keyid controlled by sockopt
	 *
	 * If this is set `tcp_authopt.local_send_id` is used to determined sending
	 * key. Otherwise a key with send_id == recv_rnextkeyid is preferred.
	 */
	TCP_AUTHOPT_FLAG_LOCK_KEYID = (1 << 0),
	/**
	 * @TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID: Override rnextkeyid from userspace
	 *
	 * If this is set then `tcp_authopt.send_rnextkeyid` is sent on outbound
	 * packets. Other the recv_id of the current sending key is sent.
	 */
	TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID = (1 << 1),
	/**
	 * @TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED:
	 *	Configure behavior of segments with TCP-AO coming from hosts for which no
	 *	key is configured. The default recommended by RFC is to silently accept
	 *	such connections.
	 */
	TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED = (1 << 2),
};

/**
 * struct tcp_authopt - Per-socket options related to TCP Authentication Option
 */
struct tcp_authopt {
	/** @flags: Combination of &enum tcp_authopt_flag */
	__u32	flags;
	/**
	 * @send_keyid: `tcp_authopt_key.send_id` of preferred send key
	 *
	 * This is only used if `TCP_AUTHOPT_FLAG_LOCK_KEYID` is set.
	 */
	__u8	send_keyid;
	/**
	 * @send_rnextkeyid: The rnextkeyid to send in packets
	 *
	 * This is controlled by the user iff TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID is
	 * set. Otherwise rnextkeyid is the recv_id of the current key.
	 */
	__u8	send_rnextkeyid;
	/** @recv_keyid: A recently-received keyid value. Only for getsockopt. */
	__u8	recv_keyid;
	/** @recv_rnextkeyid: A recently-received rnextkeyid value. Only for getsockopt. */
	__u8	recv_rnextkeyid;
};

/**
 * enum tcp_authopt_key_flag - flags for `tcp_authopt.flags`
 *
 * @TCP_AUTHOPT_KEY_DEL: Delete the key by local_id and ignore all other fields.
 * @TCP_AUTHOPT_KEY_EXCLUDE_OPTS: Exclude TCP options from signature.
 * @TCP_AUTHOPT_KEY_ADDR_BIND: Key only valid for `tcp_authopt.addr`
 */
enum tcp_authopt_key_flag {
	TCP_AUTHOPT_KEY_DEL = (1 << 0),
	TCP_AUTHOPT_KEY_EXCLUDE_OPTS = (1 << 1),
	TCP_AUTHOPT_KEY_ADDR_BIND = (1 << 2),
};

/**
 * enum tcp_authopt_alg - Algorithms for TCP Authentication Option
 */
enum tcp_authopt_alg {
	TCP_AUTHOPT_ALG_HMAC_SHA_1_96 = 1,
	TCP_AUTHOPT_ALG_AES_128_CMAC_96 = 2,
};

/* for TCP_AUTHOPT_KEY socket option */
#define TCP_AUTHOPT_MAXKEYLEN	80

/**
 * struct tcp_authopt_key - TCP Authentication KEY
 *
 * Key are identified by the combination of:
 * - send_id
 * - recv_id
 * - addr (iff TCP_AUTHOPT_KEY_ADDR_BIND)
 *
 * RFC5925 requires that key ids must not overlap for the same TCP connection.
 * This is not enforced by linux.
 */
struct tcp_authopt_key {
	/** @flags: Combination of &enum tcp_authopt_key_flag */
	__u32	flags;
	/** @send_id: keyid value for send */
	__u8	send_id;
	/** @recv_id: keyid value for receive */
	__u8	recv_id;
	/** @alg: One of &enum tcp_authopt_alg */
	__u8	alg;
	/** @keylen: Length of the key buffer */
	__u8	keylen;
	/** @key: Secret key */
	__u8	key[TCP_AUTHOPT_MAXKEYLEN];
	/**
	 * @addr: Key is only valid for this address
	 *
	 * Ignored unless TCP_AUTHOPT_KEY_ADDR_BIND flag is set
	 */
	struct __kernel_sockaddr_storage addr;
};

#endif
