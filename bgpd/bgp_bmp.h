// SPDX-License-Identifier: GPL-2.0-or-later
/* BMP support.
 * Copyright (C) 2018 Yasuhiro Ohara
 * Copyright (C) 2019 David Lamparter for NetDEF, Inc.
 */

#ifndef _BGP_BMP_H_
#define _BGP_BMP_H_

#include "zebra.h"
#include "typesafe.h"
#include "pullwr.h"
#include "qobj.h"
#include "resolver.h"

#define BMP_VERSION_3	3

#define BMP_LENGTH_POS  1

/* BMP message types */
#define BMP_TYPE_ROUTE_MONITORING       0
#define BMP_TYPE_STATISTICS_REPORT      1
#define BMP_TYPE_PEER_DOWN_NOTIFICATION 2
#define BMP_TYPE_PEER_UP_NOTIFICATION   3
#define BMP_TYPE_INITIATION             4
#define BMP_TYPE_TERMINATION            5
#define BMP_TYPE_ROUTE_MIRRORING        6

#define BMP_READ_BUFSIZ	1024

/* bmp->state */
#define BMP_None        0
#define BMP_PeerUp      2
#define BMP_Run         3

/* This one is for BMP Route Monitoring messages, i.e. delivering updates
 * in somewhat processed (as opposed to fully raw, see mirroring below) form.
 * RFC explicitly says that we can skip old updates if we haven't sent them out
 * yet and another newer update for the same prefix arrives.
 *
 * So, at most one of these can exist for each (bgp, afi, safi, prefix, peerid)
 * tuple; if some prefix is "re-added" to the queue, the existing entry is
 * instead moved to the end of the queue.  This ensures that the queue size is
 * bounded by the BGP table size.
 *
 * bmp_qlist is the queue itself while bmp_qhash is used to efficiently check
 * whether a tuple is already on the list.  The queue is maintained per
 * bmp_target.
 *
 * refcount = number of "struct bmp *" whose queue position is before this
 * entry, i.e. number of BMP sessions where we still want to send this out.
 * Decremented on send so we know when we're done with an entry (i.e. this
 * always happens from the front of the queue.)
 */

PREDECL_DLIST(bmp_qlist);
PREDECL_HASH(bmp_qhash);

struct bmp_queue_entry {
	struct bmp_qlist_item bli;
	struct bmp_qhash_item bhi;

	struct prefix p;
	uint64_t peerid;
	afi_t afi;
	safi_t safi;

	size_t refcount;

	/* initialized only for L2VPN/EVPN (S)AFIs */
	struct prefix_rd rd;
};

/* This is for BMP Route Mirroring, which feeds fully raw BGP PDUs out to BMP
 * receivers.  So, this goes directly off packet RX/TX handling instead of
 * grabbing bits from tables.
 *
 * There is *one* queue for each "struct bgp *" where we throw everything on,
 * with a size limit.  Refcount works the same as for monitoring above.
 */

PREDECL_LIST(bmp_mirrorq);

struct bmp_mirrorq {
	struct bmp_mirrorq_item bmi;

	size_t refcount;
	uint64_t peerid;
	struct timeval tv;

	size_t len;
	uint8_t data[0];
};

enum {
	BMP_AFI_INACTIVE = 0,
	BMP_AFI_NEEDSYNC,
	BMP_AFI_SYNC,
	BMP_AFI_LIVE,
};

PREDECL_LIST(bmp_session);

struct bmp_active;
struct bmp_targets;

/* an established BMP session to a peer */
struct bmp {
	struct bmp_session_item bsi;
	struct bmp_targets *targets;
	struct bmp_active *active;

	int socket;
	char remote[SU_ADDRSTRLEN + 6];
	struct event *t_read;

	struct pullwr *pullwr;

	int state;

	/* queue positions must remain synced with refcounts in the items.
	 * Whenever appending a queue item, we need to know the correct number
	 * of "struct bmp *" that want it, and when moving these positions
	 * ahead we need to make sure that refcount is decremented.  Also, on
	 * disconnects we need to walk the queue and drop our reference.
	 */
	struct bmp_queue_entry *locrib_queuepos;
	struct bmp_queue_entry *queuepos;
	struct bmp_mirrorq *mirrorpos;
	bool mirror_lost;

	/* enum BMP_AFI_* */
	uint8_t afistate[AFI_MAX][SAFI_MAX];

	/* counters for the various BMP packet types */
	uint64_t cnt_update, cnt_mirror;
	/* number of times this peer wasn't fast enough in consuming the
	 * mirror queue
	 */
	uint64_t cnt_mirror_overruns;
	struct timeval t_up;

	/* synchronization / startup works by repeatedly finding the next
	 * table entry, the sync* fields note down what we sent last
	 */
	struct prefix syncpos;
	struct bgp_dest *syncrdpos;
	uint64_t syncpeerid;
	afi_t syncafi;
	safi_t syncsafi;
};

/* config & state for an active outbound connection.  When the connection
 * succeeds, "bmp" is set up.
 */

PREDECL_SORTLIST_UNIQ(bmp_actives);

#define BMP_DFLT_MINRETRY	30000
#define BMP_DFLT_MAXRETRY	720000

struct bmp_active {
	struct bmp_actives_item bai;
	struct bmp_targets *targets;
	struct bmp *bmp;

	char *hostname;
	int port;
	unsigned minretry, maxretry;
	char *ifsrc;
	union sockunion addrsrc;

	struct resolver_query resq;

	unsigned curretry;
	unsigned addrpos, addrtotal;
	union sockunion addrs[8];
	int socket;
	const char *last_err;
	struct event *t_timer, *t_read, *t_write;
};

/* config & state for passive / listening sockets */
PREDECL_SORTLIST_UNIQ(bmp_listeners);

struct bmp_listener {
	struct bmp_listeners_item bli;

	struct bmp_targets *targets;

	union sockunion addr;
	int port;

	struct event *t_accept;
	int sock;
};

/* bmp_targets - plural since it may contain multiple bmp_listener &
 * bmp_active items.  If they have the same config, BMP session should be
 * put in the same targets since that's a bit more effective.
 */
PREDECL_SORTLIST_UNIQ(bmp_targets);

struct bmp_targets {
	struct bmp_targets_item bti;

	struct bmp_bgp *bmpbgp;
	struct bgp *bgp;
	char *name;

	struct bmp_listeners_head listeners;

	char *acl_name;
	char *acl6_name;
#define BMP_STAT_DEFAULT_TIMER	60000
	int stat_msec;

	/* only supporting:
	 * - IPv4 / unicast & multicast & VPN
	 * - IPv6 / unicast & multicast & VPN
	 * - L2VPN / EVPN
	 */
#define BMP_MON_PREPOLICY	(1 << 0)
#define BMP_MON_POSTPOLICY	(1 << 1)
#define BMP_MON_LOC_RIB (1 << 2)

	uint8_t afimon[AFI_MAX][SAFI_MAX];
	bool mirror;

	struct bmp_actives_head actives;

	struct event *t_stats;
	struct bmp_session_head sessions;

	struct bmp_qhash_head updhash;
	struct bmp_qlist_head updlist;

	struct bmp_qhash_head locupdhash;
	struct bmp_qlist_head locupdlist;

	uint64_t cnt_accept, cnt_aclrefused;

	bool stats_send_experimental;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(bmp_targets);

/* per struct peer * data.  Lookup by peer->qobj_node.nid, created on demand,
 * deleted in peer_backward hook. */
PREDECL_HASH(bmp_peerh);

struct bmp_bgp_peer {
	struct bmp_peerh_item bpi;

	uint64_t peerid;
	/* struct peer *peer; */

	uint8_t *open_rx;
	size_t open_rx_len;

	uint8_t *open_tx;
	size_t open_tx_len;
};

/* per struct bgp * data */
PREDECL_HASH(bmp_bgph);

#define BMP_PEER_DOWN_NO_RELEVANT_EVENT_CODE 0x00

struct bmp_bgp {
	struct bmp_bgph_item bbi;

	struct bgp *bgp;
	struct bmp_targets_head targets;

	struct bmp_mirrorq_head mirrorq;
	size_t mirror_qsize, mirror_qsizemax;

	size_t mirror_qsizelimit;
};

enum {
	BMP_PEERDOWN_LOCAL_NOTIFY       = 1,
	BMP_PEERDOWN_LOCAL_FSM          = 2,
	BMP_PEERDOWN_REMOTE_NOTIFY      = 3,
	BMP_PEERDOWN_REMOTE_CLOSE       = 4,
	BMP_PEERDOWN_ENDMONITOR         = 5,
};

enum {
	BMP_STATS_PFX_REJECTED          = 0,
	BMP_STATS_PFX_DUP_ADV           = 1,
	BMP_STATS_PFX_DUP_WITHDRAW      = 2,
	BMP_STATS_UPD_LOOP_CLUSTER      = 3,
	BMP_STATS_UPD_LOOP_ASPATH       = 4,
	BMP_STATS_UPD_LOOP_ORIGINATOR   = 5,
	BMP_STATS_UPD_LOOP_CONFED       = 6,
	BMP_STATS_SIZE_ADJ_RIB_IN       = 7,
	BMP_STATS_SIZE_LOC_RIB          = 8,
	BMP_STATS_SIZE_ADJ_RIB_IN_SAFI  = 9,
	BMP_STATS_SIZE_LOC_RIB_IN_SAFI  = 10,
	BMP_STATS_UPD_7606_WITHDRAW     = 11,
	BMP_STATS_PFX_7606_WITHDRAW     = 12,
	BMP_STATS_UPD_DUP               = 13,
	BMP_STATS_FRR_NH_INVALID        = 65531,
};

DECLARE_MGROUP(BMP);

#endif /*_BGP_BMP_H_*/
