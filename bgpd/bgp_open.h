// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP open message handling
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_OPEN_H
#define _QUAGGA_BGP_OPEN_H

/* Standard header for capability TLV */
struct capability_header {
	uint8_t code;
	uint8_t length;
};

/* Generic MP capability data */
struct capability_mp_data {
	uint16_t afi; /* iana_afi_t */
	uint8_t reserved;
	uint8_t safi; /* iana_safi_t */
};

struct graceful_restart_af {
	uint16_t afi;
	uint8_t safi;
	uint8_t flag;
};

/*
 * +--------------------------------------------------+
 * | Address Family Identifier (16 bits)              |
 * +--------------------------------------------------+
 * | Subsequent Address Family Identifier (8 bits)    |
 * +--------------------------------------------------+
 * | Flags for Address Family (8 bits)                |
 * +--------------------------------------------------+
 * | Long-lived Stale Time (24 bits)                  |
 * +--------------------------------------------------+
 */
#define BGP_CAP_LLGR_MIN_PACKET_LEN 7

/* Capability Code */
#define CAPABILITY_CODE_MP              1 /* Multiprotocol Extensions */
#define CAPABILITY_CODE_REFRESH         2 /* Route Refresh Capability */
#define CAPABILITY_CODE_ORF             3 /* Cooperative Route Filtering Capability */
#define CAPABILITY_CODE_RESTART        64 /* Graceful Restart Capability */
#define CAPABILITY_CODE_AS4            65 /* 4-octet AS number Capability */
#define CAPABILITY_CODE_DYNAMIC        67 /* Dynamic Capability */
#define CAPABILITY_CODE_ADDPATH        69 /* Addpath Capability */
#define CAPABILITY_CODE_ENHANCED_RR    70 /* Enhanced Route Refresh capability */
#define CAPABILITY_CODE_LLGR           71 /* Long-lived Graceful Restart */
#define CAPABILITY_CODE_FQDN           73 /* Advertise hostname capability */
#define CAPABILITY_CODE_SOFT_VERSION   75 /* Software Version capability */
#define CAPABILITY_CODE_ENHE            5 /* Extended Next Hop Encoding */
#define CAPABILITY_CODE_EXT_MESSAGE     6 /* Extended Message Support */
#define CAPABILITY_CODE_ROLE            9 /* Role Capability */
#define CAPABILITY_CODE_PATHS_LIMIT    76 /* Paths Limit Capability */

/* Capability Length */
#define CAPABILITY_CODE_MP_LEN          4
#define CAPABILITY_CODE_REFRESH_LEN     0
#define CAPABILITY_CODE_DYNAMIC_LEN     0
#define CAPABILITY_CODE_RESTART_LEN     2 /* Receiving only case */
#define CAPABILITY_CODE_AS4_LEN         4
#define CAPABILITY_CODE_ADDPATH_LEN     4
#define CAPABILITY_CODE_PATHS_LIMIT_LEN 5
#define CAPABILITY_CODE_ENHE_LEN        6 /* NRLI AFI = 2, SAFI = 2, Nexthop AFI = 2 */
#define CAPABILITY_CODE_MIN_FQDN_LEN    2
#define CAPABILITY_CODE_ENHANCED_LEN    0
#define CAPABILITY_CODE_LLGR_LEN        0
#define CAPABILITY_CODE_ORF_LEN         5
#define CAPABILITY_CODE_EXT_MESSAGE_LEN 0 /* Extended Message Support */
#define CAPABILITY_CODE_ROLE_LEN        1
#define CAPABILITY_CODE_SOFT_VERSION_LEN 1

/* Cooperative Route Filtering Capability.  */

/* ORF Type */
#define ORF_TYPE_RESERVED               0
#define ORF_TYPE_PREFIX                64

/* ORF Mode */
#define ORF_MODE_RECEIVE                1
#define ORF_MODE_SEND                   2
#define ORF_MODE_BOTH                   3

/* Capability Message Action.  */
#define CAPABILITY_ACTION_SET           0
#define CAPABILITY_ACTION_UNSET         1

/* Graceful Restart */
#define GRACEFUL_RESTART_R_BIT 0x8000
#define GRACEFUL_RESTART_N_BIT 0x4000
#define GRACEFUL_RESTART_F_BIT 0x80

/* Long-lived Graceful Restart */
#define LLGR_F_BIT 0x80

/* Optional Parameters */
#define BGP_OPEN_NON_EXT_OPT_LEN 255		      /* Non-Ext OP Len. */
#define BGP_OPEN_NON_EXT_OPT_TYPE_EXTENDED_LENGTH 255 /* Non-Ext OP Type */
#define BGP_OPEN_EXT_OPT_PARAMS_CAPABLE(peer)                                  \
	(CHECK_FLAG(peer->flags, PEER_FLAG_EXTENDED_OPT_PARAMS)                \
	 || CHECK_FLAG(peer->sflags, PEER_STATUS_EXT_OPT_PARAMS_LENGTH))

extern int bgp_open_option_parse(struct peer *peer, uint16_t length,
				 int *mp_capability);
extern uint16_t bgp_open_capability(struct stream *s, struct peer *peer,
				    bool ext_opt_params);
extern void bgp_capability_vty_out(struct vty *vty, struct peer *peer,
				   bool use_json, json_object *json_neigh);
extern as_t peek_for_as4_capability(struct peer *peer, uint16_t length);
extern const struct message capcode_str[];
extern const struct message orf_type_str[];
extern const struct message orf_mode_str[];
extern const size_t cap_minsizes[];
extern const size_t cap_modsizes[];

#endif /* _QUAGGA_BGP_OPEN_H */
