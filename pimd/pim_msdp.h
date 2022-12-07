// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP MSDP for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */
#ifndef PIM_MSDP_H
#define PIM_MSDP_H

#include "lib/openbsd-queue.h"

enum pim_msdp_peer_state {
	PIM_MSDP_DISABLED,
	PIM_MSDP_INACTIVE,
	PIM_MSDP_LISTEN,
	PIM_MSDP_CONNECTING,
	PIM_MSDP_ESTABLISHED
};

/* SA and KA TLVs are processed; rest ignored */
enum pim_msdp_tlv {
	PIM_MSDP_V4_SOURCE_ACTIVE = 1,
	PIM_MSDP_V4_SOURCE_ACTIVE_REQUEST,
	PIM_MSDP_V4_SOURCE_ACTIVE_RESPONSE,
	PIM_MSDP_KEEPALIVE,
	PIM_MSDP_RESERVED,
	PIM_MSDP_TRACEROUTE_PROGRESS,
	PIM_MSDP_TRACEROUTE_REPLY,
};

/* MSDP error codes */
enum pim_msdp_err {
	PIM_MSDP_ERR_NONE = 0,
	PIM_MSDP_ERR_OOM = -1,
	PIM_MSDP_ERR_PEER_EXISTS = -2,
	PIM_MSDP_ERR_MAX_MESH_GROUPS = -3,
	PIM_MSDP_ERR_NO_PEER = -4,
	PIM_MSDP_ERR_MG_MBR_EXISTS = -5,
	PIM_MSDP_ERR_NO_MG = -6,
	PIM_MSDP_ERR_NO_MG_MBR = -7,
	PIM_MSDP_ERR_SIP_EQ_DIP = -8,
};

#define PIM_MSDP_STATE_STRLEN 16
#define PIM_MSDP_UPTIME_STRLEN 80
#define PIM_MSDP_TIMER_STRLEN 12
#define PIM_MSDP_TCP_PORT 639
#define PIM_MSDP_SOCKET_SNDBUF_SIZE 65536

enum pim_msdp_sa_flags {
	PIM_MSDP_SAF_NONE = 0,
	/* There are two cases where we can pickup an active source locally -
	 * 1. We are RP and got a source-register from the FHR
	 * 2. We are RP and FHR and learnt a new directly connected source on a
	 * DR interface */
	PIM_MSDP_SAF_LOCAL = (1 << 0),
	/* We got this in the MSDP SA TLV from a peer (and this passed peer-RPF
	 * checks) */
	PIM_MSDP_SAF_PEER = (1 << 1),
	PIM_MSDP_SAF_REF = (PIM_MSDP_SAF_LOCAL | PIM_MSDP_SAF_PEER),
	PIM_MSDP_SAF_STALE = (1 << 2), /* local entries can get kicked out on
					* misc pim events such as RP change */
	PIM_MSDP_SAF_UP_DEL_IN_PROG = (1 << 3)
};

struct pim_msdp_sa {
	struct pim_instance *pim;

	pim_sgaddr sg;
	char sg_str[PIM_SG_LEN];
	struct in_addr rp;   /* Last RP address associated with this SA */
	struct in_addr peer; /* last peer from who we heard this SA */
	enum pim_msdp_sa_flags flags;

/* rfc-3618 is missing default value for SA-hold-down-Period. pulled
 * this number from industry-standards */
#define PIM_MSDP_SA_HOLD_TIME ((3*60)+30)
	struct event *sa_state_timer; // 5.6
	int64_t uptime;

	struct pim_upstream *up;
};

enum pim_msdp_peer_flags {
	PIM_MSDP_PEERF_NONE = 0,
	PIM_MSDP_PEERF_LISTENER = (1 << 0),
#define PIM_MSDP_PEER_IS_LISTENER(mp) (mp->flags & PIM_MSDP_PEERF_LISTENER)
	PIM_MSDP_PEERF_SA_JUST_SENT = (1 << 1),
	/** Flag to signalize that peer belongs to a group. */
	PIM_MSDP_PEERF_IN_GROUP = (1 << 2),
};

enum msdp_auth_type {
	MSDP_AUTH_NONE = 0,
	MSDP_AUTH_MD5 = 1,
};

struct pim_msdp_peer {
	struct pim_instance *pim;

	/* configuration */
	struct in_addr local;
	struct in_addr peer;
	char *mesh_group_name;
	char key_str[INET_ADDRSTRLEN];

	/* Authentication data. */
	enum msdp_auth_type auth_type;
	char *auth_key;

	int auth_listen_sock;
	struct event *auth_listen_ev;

	/* state */
	enum pim_msdp_peer_state state;
	enum pim_msdp_peer_flags flags;

	/* TCP socket info */
	union sockunion su_local;
	union sockunion su_peer;
	int fd;

/* protocol timers */
#define PIM_MSDP_PEER_HOLD_TIME 75
	struct event *hold_timer; // 5.4
#define PIM_MSDP_PEER_KA_TIME 60
	struct event *ka_timer; // 5.5
#define PIM_MSDP_PEER_CONNECT_RETRY_TIME 30
	struct event *cr_timer; // 5.6

	/* packet thread and buffers */
	uint32_t packet_size;
	struct stream *ibuf;
	struct stream_fifo *obuf;
	struct event *t_read;
	struct event *t_write;

	/* stats */
	uint32_t conn_attempts;
	uint32_t est_flaps;
	uint32_t sa_cnt; /* number of SAs attributed to this peer */
#define PIM_MSDP_PEER_LAST_RESET_STR 20
	char last_reset[PIM_MSDP_PEER_LAST_RESET_STR];

	/* packet stats */
	uint32_t ka_tx_cnt;
	uint32_t sa_tx_cnt;
	uint32_t ka_rx_cnt;
	uint32_t sa_rx_cnt;
	uint32_t unk_rx_cnt;

	/* timestamps */
	int64_t uptime;

	/** SA input access list name. */
	char *acl_in;
	/** SA output access list name. */
	char *acl_out;
};

struct pim_msdp_mg_mbr {
	struct in_addr mbr_ip;
	struct pim_msdp_peer *mp;
};

/* PIM MSDP mesh-group */
struct pim_msdp_mg {
	char *mesh_group_name;
	struct in_addr src_ip;
	uint32_t mbr_cnt;
	struct list *mbr_list;

	/** Belongs to PIM instance list. */
	SLIST_ENTRY(pim_msdp_mg) mg_entry;
};

SLIST_HEAD(pim_mesh_group_list, pim_msdp_mg);

enum pim_msdp_flags {
	PIM_MSDPF_NONE = 0,
	PIM_MSDPF_ENABLE = (1 << 0),
	PIM_MSDPF_LISTENER = (1 << 1)
};

struct pim_msdp_listener {
	int fd;
	union sockunion su;
	struct event *thread;
};

struct pim_msdp {
	enum pim_msdp_flags flags;
	struct event_loop *master;
	struct pim_msdp_listener listener;
	uint32_t rejected_accepts;

	/* MSDP peer info */
	struct hash *peer_hash;
	struct list *peer_list;

/* MSDP active-source info */
#define PIM_MSDP_SA_ADVERTISMENT_TIME 60
	struct event *sa_adv_timer; // 5.6
	struct hash *sa_hash;
	struct list *sa_list;
	uint32_t local_cnt;

	/* keep a scratch pad for building SA TLVs */
	struct stream *work_obuf;

	struct in_addr originator_id;

	/** List of mesh groups. */
	struct pim_mesh_group_list mglist;

	/** MSDP global hold time period. */
	uint32_t hold_time;
	/** MSDP global keep alive period. */
	uint32_t keep_alive;
	/** MSDP global connection retry period. */
	uint32_t connection_retry;
};

#define PIM_MSDP_PEER_READ_ON(mp)                                              \
	event_add_read(mp->pim->msdp.master, pim_msdp_read, mp, mp->fd,        \
		       &mp->t_read)

#define PIM_MSDP_PEER_WRITE_ON(mp)                                             \
	event_add_write(mp->pim->msdp.master, pim_msdp_write, mp, mp->fd,      \
			&mp->t_write)

#define PIM_MSDP_PEER_READ_OFF(mp) event_cancel(&mp->t_read)
#define PIM_MSDP_PEER_WRITE_OFF(mp) event_cancel(&mp->t_write)

#if PIM_IPV != 6
// struct pim_msdp *msdp;
struct pim_instance;
void pim_msdp_init(struct pim_instance *pim, struct event_loop *master);
void pim_msdp_exit(struct pim_instance *pim);
char *pim_msdp_state_dump(enum pim_msdp_peer_state state, char *buf,
			  int buf_size);
struct pim_msdp_peer *pim_msdp_peer_find(struct pim_instance *pim,
					 struct in_addr peer_addr);
void pim_msdp_peer_established(struct pim_msdp_peer *mp);
void pim_msdp_peer_pkt_rxed(struct pim_msdp_peer *mp);
void pim_msdp_peer_stop_tcp_conn(struct pim_msdp_peer *mp, bool chg_state);
void pim_msdp_peer_reset_tcp_conn(struct pim_msdp_peer *mp, const char *rc_str);
void pim_msdp_write(struct event *thread);
int pim_msdp_config_write(struct pim_instance *pim, struct vty *vty);
bool pim_msdp_peer_config_write(struct vty *vty, struct pim_instance *pim);
void pim_msdp_peer_pkt_txed(struct pim_msdp_peer *mp);
void pim_msdp_sa_ref(struct pim_instance *pim, struct pim_msdp_peer *mp,
		     pim_sgaddr *sg, struct in_addr rp);
void pim_msdp_sa_local_update(struct pim_upstream *up);
void pim_msdp_sa_local_del(struct pim_instance *pim, pim_sgaddr *sg);
void pim_msdp_i_am_rp_changed(struct pim_instance *pim);
bool pim_msdp_peer_rpf_check(struct pim_msdp_peer *mp, struct in_addr rp);
void pim_msdp_up_join_state_changed(struct pim_instance *pim,
				    struct pim_upstream *xg_up);
void pim_msdp_up_del(struct pim_instance *pim, pim_sgaddr *sg);
enum pim_msdp_err pim_msdp_mg_del(struct pim_instance *pim,
				  const char *mesh_group_name);

/**
 * Allocates a new mesh group data structure under PIM instance.
 */
struct pim_msdp_mg *pim_msdp_mg_new(struct pim_instance *pim,
				    const char *mesh_group_name);
/**
 * Deallocates mesh group data structure under PIM instance.
 */
void pim_msdp_mg_free(struct pim_instance *pim, struct pim_msdp_mg **mgp);

/**
 * Change the source address of a mesh group peers. It will do the following:
 * - Close all peers TCP connections
 * - Recreate peers data structure
 * - Start TCP connections with new local address.
 */
void pim_msdp_mg_src_add(struct pim_instance *pim, struct pim_msdp_mg *mg,
			 struct in_addr *ai);

/**
 * Add new peer to mesh group and starts the connection if source address is
 * configured.
 */
struct pim_msdp_mg_mbr *pim_msdp_mg_mbr_add(struct pim_instance *pim,
					    struct pim_msdp_mg *mg,
					    struct in_addr *ia);

/**
 * Stops the connection and removes the peer data structures.
 */
void pim_msdp_mg_mbr_del(struct pim_msdp_mg *mg, struct pim_msdp_mg_mbr *mbr);

/**
 * Allocates MSDP peer data structure, adds peer to group name
 * `mesh_group_name` and starts state machine. If no group name is provided then
 * the peer will work standalone.
 *
 * \param pim PIM instance
 * \param peer_addr peer address
 * \param local_addr local listening address
 * \param mesh_group_name mesh group name (or `NULL` for peers without group).
 */
struct pim_msdp_peer *pim_msdp_peer_add(struct pim_instance *pim,
					const struct in_addr *peer_addr,
					const struct in_addr *local_addr,
					const char *mesh_group_name);

/**
 * Stops peer state machine and free memory.
 */
void pim_msdp_peer_del(struct pim_msdp_peer **mp);

/**
 * Changes peer source address.
 *
 * NOTE:
 * This will cause the connection to drop and start again.
 */
void pim_msdp_peer_change_source(struct pim_msdp_peer *mp,
				 const struct in_addr *addr);

/**
 * Restart peer's connection.
 *
 * This is used internally in MSDP and should be used by northbound
 * when wanting to immediately apply connections settings such as
 * authentication.
 */
void pim_msdp_peer_restart(struct pim_msdp_peer *mp);

#else /* PIM_IPV == 6 */
static inline void pim_msdp_init(struct pim_instance *pim,
				 struct event_loop *master)
{
}

static inline void pim_msdp_exit(struct pim_instance *pim)
{
}

static inline void pim_msdp_i_am_rp_changed(struct pim_instance *pim)
{
}

static inline void pim_msdp_up_join_state_changed(struct pim_instance *pim,
						  struct pim_upstream *xg_up)
{
}

static inline void pim_msdp_up_del(struct pim_instance *pim, pim_sgaddr *sg)
{
}

static inline void pim_msdp_sa_local_update(struct pim_upstream *up)
{
}

static inline void pim_msdp_sa_local_del(struct pim_instance *pim,
					 pim_sgaddr *sg)
{
}

static inline int pim_msdp_config_write(struct pim_instance *pim,
					struct vty *vty)
{
	return 0;
}

static inline bool pim_msdp_peer_config_write(struct vty *vty,
					      struct pim_instance *pim)
{
	return false;
}
#endif /* PIM_IPV == 6 */

#endif
