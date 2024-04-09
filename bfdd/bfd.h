// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * bfd.h: implements the BFD protocol.
 */

#ifndef _BFD_H_
#define _BFD_H_

#include <netinet/in.h>

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>

#include "lib/hash.h"
#include "lib/libfrr.h"
#include "lib/qobj.h"
#include "lib/queue.h"
#include "lib/vrf.h"

#include "bfdctl.h"

#ifdef BFD_DEBUG
#define BFDD_JSON_CONV_OPTIONS (JSON_C_TO_STRING_PRETTY)
#else
#define BFDD_JSON_CONV_OPTIONS (0)
#endif

DECLARE_MGROUP(BFDD);
DECLARE_MTYPE(BFDD_CONTROL);
DECLARE_MTYPE(BFDD_NOTIFICATION);

#define BFDD_SOCK_NAME "%s/bfdd.sock", frr_runstatedir

/* bfd Authentication Type. */
#define BFD_AUTH_NULL 0
#define BFD_AUTH_SIMPLE 1
#define BFD_AUTH_CRYPTOGRAPHIC 2

struct bfd_timers {
	uint32_t desired_min_tx;
	uint32_t required_min_rx;
	uint32_t required_min_echo;
};

struct bfd_discrs {
	uint32_t my_discr;
	uint32_t remote_discr;
};

/*
 * Format of control packet.  From section 4)
 */
struct bfd_pkt {
	union {
		uint32_t byteFields;
		struct {
			uint8_t diag;
			uint8_t flags;
			uint8_t detect_mult;
			uint8_t len;
		};
	};
	struct bfd_discrs discrs;
	struct bfd_timers timers;
};

/*
 * Format of authentification.
 */
struct bfd_auth {
	uint8_t type;
	uint8_t length;
};


/*
 * Format of Echo packet.
 */
struct bfd_echo_pkt {
	union {
		uint32_t byteFields;
		struct {
			uint8_t ver;
			uint8_t len;
			uint16_t reserved;
		};
	};
	uint32_t my_discr;
	uint64_t time_sent_sec;
	uint64_t time_sent_usec;
};


/* Macros for manipulating control packets */
#define BFD_VERMASK 0x07
#define BFD_DIAGMASK 0x1F
#define BFD_GETVER(diag) ((diag >> 5) & BFD_VERMASK)
#define BFD_SETVER(diag, val) ((diag) |= (val & BFD_VERMASK) << 5)
#define BFD_VERSION 1
#define BFD_PBIT 0x20
#define BFD_FBIT 0x10
#define BFD_CBIT 0x08
#define BFD_ABIT 0x04
#define BFD_DEMANDBIT 0x02
#define BFD_SETDEMANDBIT(flags, val)                                           \
	{                                                                      \
		if ((val))                                                     \
			flags |= BFD_DEMANDBIT;                                \
	}
#define BFD_SETPBIT(flags, val)                                                \
	{                                                                      \
		if ((val))                                                     \
			flags |= BFD_PBIT;                                     \
	}
#define BFD_GETPBIT(flags) (flags & BFD_PBIT)
#define BFD_SETFBIT(flags, val)                                                \
	{                                                                      \
		if ((val))                                                     \
			flags |= BFD_FBIT;                                     \
	}
#define BFD_GETFBIT(flags) (flags & BFD_FBIT)
#define BFD_SETSTATE(flags, val)                                               \
	{                                                                      \
		if ((val))                                                     \
			flags |= (val & 0x3) << 6;                             \
	}
#define BFD_GETSTATE(flags) ((flags >> 6) & 0x3)
#define BFD_SETCBIT(flags, val)                                                \
	{                                                                      \
		if ((val))                                                     \
			flags |= val;                                          \
	}
#define BFD_GETCBIT(flags) (flags & BFD_FBIT)
#define BFD_ECHO_VERSION 1
#define BFD_ECHO_PKT_LEN sizeof(struct bfd_echo_pkt)

enum bfd_diagnosticis {
	BD_OK = 0,
	/* Control Detection Time Expired. */
	BD_CONTROL_EXPIRED = 1,
	/* Echo Function Failed. */
	BD_ECHO_FAILED = 2,
	/* Neighbor Signaled Session Down. */
	BD_NEIGHBOR_DOWN = 3,
	/* Forwarding Plane Reset. */
	BD_FORWARDING_RESET = 4,
	/* Path Down. */
	BD_PATH_DOWN = 5,
	/* Concatenated Path Down. */
	BD_CONCATPATH_DOWN = 6,
	/* Administratively Down. */
	BD_ADMIN_DOWN = 7,
	/* Reverse Concatenated Path Down. */
	BD_REVCONCATPATH_DOWN = 8,
	/* 9..31: reserved. */
};

/* BFD session flags */
enum bfd_session_flags {
	BFD_SESS_FLAG_NONE = 0,
	BFD_SESS_FLAG_ECHO = 1 << 0,	/* BFD Echo functionality */
	BFD_SESS_FLAG_ECHO_ACTIVE = 1 << 1, /* BFD Echo Packets are being sent
					     * actively
					     */
	BFD_SESS_FLAG_MH = 1 << 2,	  /* BFD Multi-hop session */
	BFD_SESS_FLAG_IPV6 = 1 << 4,	/* BFD IPv6 session */
	BFD_SESS_FLAG_SEND_EVT_ACTIVE = 1 << 5, /* send event timer active */
	BFD_SESS_FLAG_SEND_EVT_IGNORE = 1 << 6, /* ignore send event when timer
						 * expires
						 */
	BFD_SESS_FLAG_SHUTDOWN = 1 << 7,	/* disable BGP peer function */
	BFD_SESS_FLAG_CONFIG = 1 << 8, /* Session configured with bfd NB API */
	BFD_SESS_FLAG_CBIT = 1 << 9,   /* CBIT is set */
	BFD_SESS_FLAG_PASSIVE = 1 << 10, /* Passive mode */
	BFD_SESS_FLAG_MAC_SET = 1 << 11, /* MAC of peer known */
};

/*
 * BFD session hash key.
 *
 * This structure must not have any padding bytes because their value is
 * unspecified after the struct assignment. Even when all fields of two keys
 * are the same, if the padding bytes are different, then the calculated hash
 * value is different, and the hash lookup will fail.
 *
 * Currently, the structure fields are correctly aligned, and the "packed"
 * attribute is added as a precaution. "family" and "mhop" fields are two-bytes
 * to eliminate unaligned memory access to "peer" and "local".
 */
struct bfd_key {
	uint16_t family;
	uint16_t mhop;
	struct in6_addr peer;
	struct in6_addr local;
	char ifname[IFNAMSIZ];
	char vrfname[VRF_NAMSIZ];
} __attribute__((packed));

struct bfd_session_stats {
	uint64_t rx_ctrl_pkt;
	uint64_t tx_ctrl_pkt;
	uint64_t rx_echo_pkt;
	uint64_t tx_echo_pkt;
	uint64_t session_up;
	uint64_t session_down;
	uint64_t znotification;
};

/**
 * BFD session profile to override default configurations.
 */
struct bfd_profile {
	/** Profile name. */
	char name[64];

	/** Session detection multiplier. */
	uint8_t detection_multiplier;
	/** Desired transmission interval (in microseconds). */
	uint32_t min_tx;
	/** Minimum required receive interval (in microseconds). */
	uint32_t min_rx;
	/** Administrative state. */
	bool admin_shutdown;
	/** Passive mode. */
	bool passive;
	/** Minimum expected TTL value. */
	uint8_t minimum_ttl;

	/** Echo mode (only applies to single hop). */
	bool echo_mode;
	/** Desired echo transmission interval (in microseconds). */
	uint32_t min_echo_tx;
	/** Minimum required echo receive interval (in microseconds). */
	uint32_t min_echo_rx;

	/** Profile list entry. */
	TAILQ_ENTRY(bfd_profile) entry;
};

/** Profile list type. */
TAILQ_HEAD(bfdproflist, bfd_profile);

/* bfd_session shortcut label forwarding. */
struct peer_label;

struct bfd_config_timers {
	uint32_t desired_min_tx;
	uint32_t required_min_rx;
	uint32_t desired_min_echo_tx;
	uint32_t required_min_echo_rx;
};

#define BFD_RTT_SAMPLE 8

/*
 * Session state information
 */
struct bfd_session {

	/* protocol state per RFC 5880*/
	uint8_t ses_state;
	struct bfd_discrs discrs;
	uint8_t local_diag;
	uint8_t demand_mode;
	uint8_t detect_mult;
	uint8_t remote_detect_mult;
	uint8_t mh_ttl;
	uint8_t remote_cbit;

	/** BFD profile name. */
	char *profile_name;
	/** BFD pre configured profile. */
	struct bfd_profile *profile;
	/** BFD peer configuration (without profile). */
	struct bfd_profile peer_profile;

	/* Timers */
	struct bfd_config_timers timers;
	struct bfd_timers cur_timers;
	uint64_t detect_TO;
	struct event *echo_recvtimer_ev;
	struct event *recvtimer_ev;
	uint64_t xmt_TO;
	uint64_t echo_xmt_TO;
	struct event *xmttimer_ev;
	struct event *echo_xmttimer_ev;
	uint64_t echo_detect_TO;

	/* software object state */
	uint8_t polling;

	/* This and the localDiscr are the keys to state info */
	struct bfd_key key;
	struct peer_label *pl;

	struct bfd_dplane_ctx *bdc;
	struct sockaddr_any local_address;
	uint8_t peer_hw_addr[ETH_ALEN];
	struct interface *ifp;
	struct vrf *vrf;

	int sock;

	/* BFD session flags */
	enum bfd_session_flags flags;

	struct bfd_session_stats stats;

	struct timeval uptime;   /* last up time */
	struct timeval downtime; /* last down time */

	/* Remote peer data (for debugging mostly) */
	uint8_t remote_diag;
	struct bfd_timers remote_timers;

	uint64_t refcount; /* number of pointers referencing this. */

	uint8_t rtt_valid;	    /* number of valid samples */
	uint8_t rtt_index;	    /* last index added */
	uint64_t rtt[BFD_RTT_SAMPLE]; /* RRT in usec for echo to be looped */
};

struct peer_label {
	TAILQ_ENTRY(peer_label) pl_entry;

	struct bfd_session *pl_bs;
	char pl_label[MAXNAMELEN];
};
TAILQ_HEAD(pllist, peer_label);

struct bfd_diag_str_list {
	const char *str;
	int type;
};

struct bfd_state_str_list {
	const char *str;
	int type;
};

struct bfd_session_observer {
	struct bfd_session *bso_bs;
	char bso_entryname[MAXNAMELEN];
	struct prefix bso_addr;

	TAILQ_ENTRY(bfd_session_observer) bso_entry;
};
TAILQ_HEAD(obslist, bfd_session_observer);


/* States defined per 4.1 */
#define PTM_BFD_ADM_DOWN 0
#define PTM_BFD_DOWN 1
#define PTM_BFD_INIT 2
#define PTM_BFD_UP 3


/* Various constants */
/* Retrieved from ptm_timer.h from Cumulus PTM sources. */
#define BFD_DEF_DEMAND 0
#define BFD_DEFDETECTMULT 3
#define BFD_DEFDESIREDMINTX (300 * 1000) /* microseconds. */
#define BFD_DEFREQUIREDMINRX (300 * 1000) /* microseconds. */
#define BFD_DEF_DES_MIN_ECHO_TX (50 * 1000) /* microseconds. */
#define BFD_DEF_REQ_MIN_ECHO_RX (50 * 1000) /* microseconds. */
#define BFD_DEF_SLOWTX (1000 * 1000) /* microseconds. */
/** Minimum multi hop TTL. */
#define BFD_DEF_MHOP_TTL 254
#define BFD_PKT_LEN 24 /* Length of control packet */
#define BFD_TTL_VAL 255
#define BFD_RCV_TTL_VAL 1
#define BFD_TOS_VAL 0xC0
#define BFD_PKT_INFO_VAL 1
#define BFD_IPV6_PKT_INFO_VAL 1
#define BFD_IPV6_ONLY_VAL 1
#define BFD_SRCPORTINIT 49152
#define BFD_SRCPORTMAX 65535
#define BFD_DEFDESTPORT 3784
#define BFD_DEF_ECHO_PORT 3785
#define BFD_DEF_MHOP_DEST_PORT 4784

/*
 * control.c
 *
 * Daemon control code to speak with local consumers.
 */

/* See 'bfdctrl.h' for client protocol definitions. */

struct bfd_control_buffer {
	size_t bcb_left;
	size_t bcb_pos;
	union {
		struct bfd_control_msg *bcb_bcm;
		uint8_t *bcb_buf;
	};
};

struct bfd_control_queue {
	TAILQ_ENTRY(bfd_control_queue) bcq_entry;

	struct bfd_control_buffer bcq_bcb;
};
TAILQ_HEAD(bcqueue, bfd_control_queue);

struct bfd_notify_peer {
	TAILQ_ENTRY(bfd_notify_peer) bnp_entry;

	struct bfd_session *bnp_bs;
};
TAILQ_HEAD(bnplist, bfd_notify_peer);

struct bfd_control_socket {
	TAILQ_ENTRY(bfd_control_socket) bcs_entry;

	int bcs_sd;
	struct event *bcs_ev;
	struct event *bcs_outev;
	struct bcqueue bcs_bcqueue;

	/* Notification data */
	uint64_t bcs_notify;
	struct bnplist bcs_bnplist;

	enum bc_msg_version bcs_version;
	enum bc_msg_type bcs_type;

	/* Message buffering */
	struct bfd_control_buffer bcs_bin;
	struct bfd_control_buffer *bcs_bout;
};
TAILQ_HEAD(bcslist, bfd_control_socket);

int control_init(const char *path);
void control_shutdown(void);
int control_notify(struct bfd_session *bs, uint8_t notify_state);
int control_notify_config(const char *op, struct bfd_session *bs);
void control_accept(struct event *t);


/*
 * bfdd.c
 *
 * Daemon specific code.
 */
struct bfd_vrf_global {
	int bg_shop;
	int bg_mhop;
	int bg_shop6;
	int bg_mhop6;
	int bg_echo;
	int bg_echov6;
	struct vrf *vrf;

	struct event *bg_ev[6];
};

/* Forward declaration of data plane context struct. */
struct bfd_dplane_ctx;
TAILQ_HEAD(dplane_queue, bfd_dplane_ctx);

struct bfd_global {
	int bg_csock;
	struct event *bg_csockev;
	struct bcslist bg_bcslist;

	struct pllist bg_pllist;

	struct obslist bg_obslist;

	struct zebra_privs_t bfdd_privs;

	/**
	 * Daemon is exit()ing? Use this to avoid actions that expect a
	 * running system or to avoid unnecessary operations when quitting.
	 */
	bool bg_shutdown;

	/* Distributed BFD items. */
	bool bg_use_dplane;
	int bg_dplane_sock;
	struct event *bg_dplane_sockev;
	struct dplane_queue bg_dplaneq;

	/* Debug options. */
	/* Show distributed BFD debug messages. */
	bool debug_dplane;
	/* Show all peer state changes events. */
	bool debug_peer_event;
	/*
	 * Show zebra message exchanges:
	 * - Interface add/delete.
	 * - Local address add/delete.
	 * - VRF add/delete.
	 */
	bool debug_zebra;
	/*
	 * Show network level debug information:
	 * - Echo packets without session.
	 * - Unavailable peer sessions.
	 * - Network system call failures.
	 */
	bool debug_network;
};

extern struct bfd_global bglobal;
extern const struct bfd_diag_str_list diag_list[];
extern const struct bfd_state_str_list state_list[];

void socket_close(int *s);


/*
 * config.c
 *
 * Contains the code related with loading/reloading configuration.
 */
int parse_config(const char *fname);
int config_request_add(const char *jsonstr);
int config_request_del(const char *jsonstr);
char *config_response(const char *status, const char *error);
char *config_notify(struct bfd_session *bs);
char *config_notify_config(const char *op, struct bfd_session *bs);

typedef int (*bpc_handle)(struct bfd_peer_cfg *, void *arg);
int config_notify_request(struct bfd_control_socket *bcs, const char *jsonstr,
			  bpc_handle bh);

struct peer_label *pl_new(const char *label, struct bfd_session *bs);
struct peer_label *pl_find(const char *label);
void pl_free(struct peer_label *pl);


/*
 * logging - alias to zebra log
 */
#define zlog_fatal(msg, ...)                                                   \
	do {                                                                   \
		zlog_err(msg, ##__VA_ARGS__);                                  \
		assert(!msg);                                                  \
		abort();                                                       \
	} while (0)


/*
 * bfd_packet.c
 *
 * Contains the code related with receiving/seding, packing/unpacking BFD data.
 */
int bp_set_ttlv6(int sd, uint8_t value);
int bp_set_ttl(int sd, uint8_t value);
int bp_set_tosv6(int sd, uint8_t value);
int bp_set_tos(int sd, uint8_t value);
int bp_bind_dev(int sd, const char *dev);

int bp_udp_shop(const struct vrf *vrf);
int bp_udp_mhop(const struct vrf *vrf);
int bp_udp6_shop(const struct vrf *vrf);
int bp_udp6_mhop(const struct vrf *vrf);
int bp_peer_socket(const struct bfd_session *bs);
int bp_peer_socketv6(const struct bfd_session *bs);
int bp_echo_socket(const struct vrf *vrf);
int bp_echov6_socket(const struct vrf *vrf);

void ptm_bfd_snd(struct bfd_session *bfd, int fbit);
void ptm_bfd_echo_snd(struct bfd_session *bfd);
void ptm_bfd_echo_fp_snd(struct bfd_session *bfd);

void bfd_recv_cb(struct event *t);


/*
 * event.c
 *
 * Contains the code related with event loop.
 */
typedef void (*bfd_ev_cb)(struct event *t);

void bfd_recvtimer_update(struct bfd_session *bs);
void bfd_echo_recvtimer_update(struct bfd_session *bs);
void bfd_xmttimer_update(struct bfd_session *bs, uint64_t jitter);
void bfd_echo_xmttimer_update(struct bfd_session *bs, uint64_t jitter);

void bfd_xmttimer_delete(struct bfd_session *bs);
void bfd_echo_xmttimer_delete(struct bfd_session *bs);
void bfd_recvtimer_delete(struct bfd_session *bs);
void bfd_echo_recvtimer_delete(struct bfd_session *bs);

void bfd_recvtimer_assign(struct bfd_session *bs, bfd_ev_cb cb, int sd);
void bfd_echo_recvtimer_assign(struct bfd_session *bs, bfd_ev_cb cb, int sd);
void bfd_xmttimer_assign(struct bfd_session *bs, bfd_ev_cb cb);
void bfd_echo_xmttimer_assign(struct bfd_session *bs, bfd_ev_cb cb);


/*
 * bfd.c
 *
 * BFD protocol specific code.
 */
int bfd_session_enable(struct bfd_session *bs);
void bfd_session_disable(struct bfd_session *bs);
struct bfd_session *ptm_bfd_sess_new(struct bfd_peer_cfg *bpc);
int ptm_bfd_sess_del(struct bfd_peer_cfg *bpc);
void ptm_bfd_sess_dn(struct bfd_session *bfd, uint8_t diag);
void ptm_bfd_sess_up(struct bfd_session *bfd);
void ptm_bfd_echo_stop(struct bfd_session *bfd);
void ptm_bfd_echo_start(struct bfd_session *bfd);
void ptm_bfd_xmt_TO(struct bfd_session *bfd, int fbit);
void ptm_bfd_start_xmt_timer(struct bfd_session *bfd, bool is_echo);
struct bfd_session *ptm_bfd_sess_find(struct bfd_pkt *cp,
				      struct sockaddr_any *peer,
				      struct sockaddr_any *local,
				      struct interface *ifp,
				      vrf_id_t vrfid,
				      bool is_mhop);

struct bfd_session *bs_peer_find(struct bfd_peer_cfg *bpc);
int bfd_session_update_label(struct bfd_session *bs, const char *nlabel);
void bfd_set_polling(struct bfd_session *bs);
void bs_state_handler(struct bfd_session *bs, int nstate);
void bs_echo_timer_handler(struct bfd_session *bs);
void bs_final_handler(struct bfd_session *bs);
void bs_set_slow_timers(struct bfd_session *bs);
const char *satostr(const struct sockaddr_any *sa);
const char *diag2str(uint8_t diag);
int strtosa(const char *addr, struct sockaddr_any *sa);
void integer2timestr(uint64_t time, char *buf, size_t buflen);
const char *bs_to_string(const struct bfd_session *bs);

int bs_observer_add(struct bfd_session *bs);
void bs_observer_del(struct bfd_session_observer *bso);

void bs_to_bpc(struct bfd_session *bs, struct bfd_peer_cfg *bpc);

void gen_bfd_key(struct bfd_key *key, struct sockaddr_any *peer,
		 struct sockaddr_any *local, bool mhop, const char *ifname,
		 const char *vrfname);
struct bfd_session *bfd_session_new(void);
struct bfd_session *bs_registrate(struct bfd_session *bs);
void bfd_session_free(struct bfd_session *bs);
const struct bfd_session *bfd_session_next(const struct bfd_session *bs,
					   bool mhop);
void bfd_sessions_remove_manual(void);
void bfd_profiles_remove(void);
void bfd_rtt_init(struct bfd_session *bfd);

/**
 * Set the BFD session echo state.
 *
 * \param bs the BFD session.
 * \param echo the echo operational state.
 */
void bfd_set_echo(struct bfd_session *bs, bool echo);

/**
 * Set the BFD session functional state.
 *
 * \param bs the BFD session.
 * \param shutdown the operational value.
 */
void bfd_set_shutdown(struct bfd_session *bs, bool shutdown);

/**
 * Set the BFD session passive mode.
 *
 * \param bs the BFD session.
 * \param passive the passive mode.
 */
void bfd_set_passive_mode(struct bfd_session *bs, bool passive);

/**
 * Picks the BFD session configuration from the appropriated source:
 * if using the default peer configuration prefer profile (if it exists),
 * otherwise use session.
 *
 * \param bs the BFD session.
 */
void bfd_session_apply(struct bfd_session *bs);

/* BFD hash data structures interface */
void bfd_initialize(void);
void bfd_shutdown(void);
void bfd_vrf_init(void);
void bfd_vrf_terminate(void);
struct bfd_vrf_global *bfd_vrf_look_by_session(struct bfd_session *bfd);
struct bfd_session *bfd_id_lookup(uint32_t id);
struct bfd_session *bfd_key_lookup(struct bfd_key key);

struct bfd_session *bfd_id_delete(uint32_t id);
struct bfd_session *bfd_key_delete(struct bfd_key key);

bool bfd_id_insert(struct bfd_session *bs);
bool bfd_key_insert(struct bfd_session *bs);

typedef void (*hash_iter_func)(struct hash_bucket *hb, void *arg);
void bfd_id_iterate(hash_iter_func hif, void *arg);
void bfd_key_iterate(hash_iter_func hif, void *arg);

unsigned long bfd_get_session_count(void);

/* Export callback functions for `event.c`. */
extern struct event_loop *master;

void bfd_recvtimer_cb(struct event *t);
void bfd_echo_recvtimer_cb(struct event *t);
void bfd_xmt_cb(struct event *t);
void bfd_echo_xmt_cb(struct event *t);

extern struct in6_addr zero_addr;

/**
 * Creates a new profile entry and insert into the global list.
 *
 * \param name the BFD profile name.
 *
 * \returns `NULL` if it already exists otherwise the new entry.
 */
struct bfd_profile *bfd_profile_new(const char *name);

/**
 * Search for configured BFD profiles (profile name is case insensitive).
 *
 * \param name the BFD profile name.
 *
 * \returns `NULL` if it doesn't exist otherwise the entry.
 */
struct bfd_profile *bfd_profile_lookup(const char *name);

/**
 * Removes profile from list and free memory.
 *
 * \param bp the BFD profile.
 */
void bfd_profile_free(struct bfd_profile *bp);

/**
 * Apply a profile configuration to an existing BFD session. The non default
 * values will not be overridden.
 *
 * NOTE: if the profile doesn't exist yet, then the profile will be applied
 * once it begins to exist.
 *
 * \param profile_name the BFD profile name.
 * \param bs the BFD session.
 */
void bfd_profile_apply(const char *profname, struct bfd_session *bs);

/**
 * Remove any applied profile from session and revert the session
 * configuration.
 *
 * \param bs the BFD session.
 */
void bfd_profile_remove(struct bfd_session *bs);

/**
 * Apply new profile values to sessions using it.
 *
 * \param[in] bp the BFD profile that got updated.
 */
void bfd_profile_update(struct bfd_profile *bp);

/*
 * bfdd_vty.c
 *
 * BFD daemon vty shell commands.
 */
void bfdd_vty_init(void);


/*
 * bfdd_cli.c
 *
 * BFD daemon CLI implementation.
 */
void bfdd_cli_init(void);


/*
 * ptm_adapter.c
 */
void bfdd_zclient_init(struct zebra_privs_t *bfdd_priv);
void bfdd_zclient_stop(void);
void bfdd_zclient_terminate(void);
void bfdd_zclient_unregister(vrf_id_t vrf_id);
void bfdd_zclient_register(vrf_id_t vrf_id);
void bfdd_sessions_enable_vrf(struct vrf *vrf);
void bfdd_sessions_disable_vrf(struct vrf *vrf);

int ptm_bfd_notify(struct bfd_session *bs, uint8_t notify_state);

/*
 * dplane.c
 */

/**
 * Initialize BFD data plane infrastructure for distributed BFD implementation.
 *
 * \param sa socket address.
 * \param salen socket address structure length.
 * \param client `true` means connecting socket, `false` listening socket.
 */
void bfd_dplane_init(const struct sockaddr *sa, socklen_t salen, bool client);

/**
 * Attempts to delegate the BFD session liveness detection to hardware.
 *
 * \param bs the BFD session data structure.
 *
 * \returns
 * `0` on success and BFD daemon should do nothing or `-1` on failure
 * and we should fallback to software implementation.
 */
int bfd_dplane_add_session(struct bfd_session *bs);

/**
 * Send new session settings to data plane.
 *
 * \param bs the BFD session to update.
 */
int bfd_dplane_update_session(const struct bfd_session *bs);

/**
 * Deletes session from data plane.
 *
 * \param bs the BFD session to delete.
 *
 * \returns `0` on success otherwise `-1`.
 */
int bfd_dplane_delete_session(struct bfd_session *bs);

/**
 * Asks the data plane for updated counters and update the session data
 * structure.
 *
 * \param bs the BFD session that needs updating.
 *
 * \returns `0` on success otherwise `-1` on failure.
 */
int bfd_dplane_update_session_counters(struct bfd_session *bs);

void bfd_dplane_show_counters(struct vty *vty);

#endif /* _BFD_H_ */
