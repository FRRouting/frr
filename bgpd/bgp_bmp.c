// SPDX-License-Identifier: GPL-2.0-or-later
/* BMP support.
 * Copyright (C) 2018 Yasuhiro Ohara
 * Copyright (C) 2019 David Lamparter for NetDEF, Inc.
 */

#include <zebra.h>

#include "log.h"
#include "stream.h"
#include "sockunion.h"
#include "command.h"
#include "prefix.h"
#include "frrevent.h"
#include "linklist.h"
#include "queue.h"
#include "pullwr.h"
#include "memory.h"
#include "network.h"
#include "filter.h"
#include "lib_errors.h"
#include "stream.h"
#include "libfrr.h"
#include "lib/version.h"
#include "jhash.h"
#include "termtable.h"

#include "bgpd/bgp_table.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_bmp.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_trace.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_aspath.h"

static void bmp_close(struct bmp *bmp);
static struct bmp_bgp *bmp_bgp_find(struct bgp *bgp);
static void bmp_targets_put(struct bmp_targets *bt);
static struct bmp_bgp_peer *bmp_bgp_peer_find(uint64_t peerid);
static struct bmp_bgp_peer *bmp_bgp_peer_get(struct peer *peer);
static void bmp_active_disconnected(struct bmp_active *ba);
static void bmp_active_put(struct bmp_active *ba);

DEFINE_MGROUP(BMP, "BMP (BGP Monitoring Protocol)");

DEFINE_MTYPE_STATIC(BMP, BMP_CONN,	"BMP connection state");
DEFINE_MTYPE_STATIC(BMP, BMP_TARGETS,	"BMP targets");
DEFINE_MTYPE_STATIC(BMP, BMP_TARGETSNAME, "BMP targets name");
DEFINE_MTYPE_STATIC(BMP, BMP_LISTENER,	"BMP listener");
DEFINE_MTYPE_STATIC(BMP, BMP_ACTIVE,	"BMP active connection config");
DEFINE_MTYPE_STATIC(BMP, BMP_ACLNAME,	"BMP access-list name");
DEFINE_MTYPE_STATIC(BMP, BMP_QUEUE,	"BMP update queue item");
DEFINE_MTYPE_STATIC(BMP, BMP,		"BMP instance state");
DEFINE_MTYPE_STATIC(BMP, BMP_MIRRORQ,	"BMP route mirroring buffer");
DEFINE_MTYPE_STATIC(BMP, BMP_PEER,	"BMP per BGP peer data");
DEFINE_MTYPE_STATIC(BMP, BMP_OPEN,	"BMP stored BGP OPEN message");

DEFINE_QOBJ_TYPE(bmp_targets);

static int bmp_bgp_cmp(const struct bmp_bgp *a, const struct bmp_bgp *b)
{
	if (a->bgp < b->bgp)
		return -1;
	if (a->bgp > b->bgp)
		return 1;
	return 0;
}

static uint32_t bmp_bgp_hash(const struct bmp_bgp *e)
{
	return jhash(&e->bgp, sizeof(e->bgp), 0x55aa5a5a);
}

DECLARE_HASH(bmp_bgph, struct bmp_bgp, bbi, bmp_bgp_cmp, bmp_bgp_hash);

struct bmp_bgph_head bmp_bgph;

static int bmp_bgp_peer_cmp(const struct bmp_bgp_peer *a,
		const struct bmp_bgp_peer *b)
{
	if (a->peerid < b->peerid)
		return -1;
	if (a->peerid > b->peerid)
		return 1;
	return 0;
}

static uint32_t bmp_bgp_peer_hash(const struct bmp_bgp_peer *e)
{
	return e->peerid;
}

DECLARE_HASH(bmp_peerh, struct bmp_bgp_peer, bpi,
		bmp_bgp_peer_cmp, bmp_bgp_peer_hash);

struct bmp_peerh_head bmp_peerh;

DECLARE_LIST(bmp_mirrorq, struct bmp_mirrorq, bmi);

/* listener management */

static int bmp_listener_cmp(const struct bmp_listener *a,
		const struct bmp_listener *b)
{
	int c;

	c = sockunion_cmp(&a->addr, &b->addr);
	if (c)
		return c;
	if (a->port < b->port)
		return -1;
	if (a->port > b->port)
		return 1;
	return 0;
}

DECLARE_SORTLIST_UNIQ(bmp_listeners, struct bmp_listener, bli,
		      bmp_listener_cmp);

static void bmp_listener_put(struct bmp_listener *bl)
{
	bmp_listeners_del(&bl->targets->listeners, bl);
	XFREE(MTYPE_BMP_LISTENER, bl);
}

static int bmp_targets_cmp(const struct bmp_targets *a,
			   const struct bmp_targets *b)
{
	return strcmp(a->name, b->name);
}

DECLARE_SORTLIST_UNIQ(bmp_targets, struct bmp_targets, bti, bmp_targets_cmp);

DECLARE_LIST(bmp_session, struct bmp, bsi);

DECLARE_DLIST(bmp_qlist, struct bmp_queue_entry, bli);

static int bmp_qhash_cmp(const struct bmp_queue_entry *a,
		const struct bmp_queue_entry *b)
{
	int ret;
	if (a->afi == AFI_L2VPN && a->safi == SAFI_EVPN && b->afi == AFI_L2VPN
	    && b->safi == SAFI_EVPN) {
		ret = prefix_cmp(&a->rd, &b->rd);
		if (ret)
			return ret;
	} else if (a->afi == AFI_L2VPN && a->safi == SAFI_EVPN)
		return 1;
	else if (b->afi == AFI_L2VPN && b->safi == SAFI_EVPN)
		return -1;

	if (a->afi == b->afi && a->safi == SAFI_MPLS_VPN &&
	    b->safi == SAFI_MPLS_VPN) {
		ret = prefix_cmp(&a->rd, &b->rd);
		if (ret)
			return ret;
	} else if (a->safi == SAFI_MPLS_VPN)
		return 1;
	else if (b->safi == SAFI_MPLS_VPN)
		return -1;

	ret = prefix_cmp(&a->p, &b->p);
	if (ret)
		return ret;
	ret = memcmp(&a->peerid, &b->peerid,
			offsetof(struct bmp_queue_entry, refcount) -
			offsetof(struct bmp_queue_entry, peerid));
	return ret;
}

static uint32_t bmp_qhash_hkey(const struct bmp_queue_entry *e)
{
	uint32_t key;

	key = prefix_hash_key((void *)&e->p);
	key = jhash(&e->peerid,
		    offsetof(struct bmp_queue_entry, refcount)
			    - offsetof(struct bmp_queue_entry, peerid),
		    key);
	if ((e->afi == AFI_L2VPN && e->safi == SAFI_EVPN) ||
	    (e->safi == SAFI_MPLS_VPN))
		key = jhash(&e->rd,
			    offsetof(struct bmp_queue_entry, rd)
				    - offsetof(struct bmp_queue_entry, refcount)
				    + PSIZE(e->rd.prefixlen),
			    key);

	return key;
}

DECLARE_HASH(bmp_qhash, struct bmp_queue_entry, bhi,
		bmp_qhash_cmp, bmp_qhash_hkey);

static int bmp_active_cmp(const struct bmp_active *a,
		const struct bmp_active *b)
{
	int c;

	c = strcmp(a->hostname, b->hostname);
	if (c)
		return c;
	if (a->port < b->port)
		return -1;
	if (a->port > b->port)
		return 1;
	return 0;
}

DECLARE_SORTLIST_UNIQ(bmp_actives, struct bmp_active, bai, bmp_active_cmp);

static struct bmp *bmp_new(struct bmp_targets *bt, int bmp_sock)
{
	struct bmp *new = XCALLOC(MTYPE_BMP_CONN, sizeof(struct bmp));
	afi_t afi;
	safi_t safi;

	monotime(&new->t_up);
	new->targets = bt;
	new->socket = bmp_sock;
	new->syncafi = AFI_MAX;

	FOREACH_AFI_SAFI (afi, safi) {
		new->afistate[afi][safi] = bt->afimon[afi][safi]
			? BMP_AFI_NEEDSYNC : BMP_AFI_INACTIVE;
	}

	bmp_session_add_tail(&bt->sessions, new);
	return new;
}

static void bmp_free(struct bmp *bmp)
{
	bmp_session_del(&bmp->targets->sessions, bmp);
	XFREE(MTYPE_BMP_CONN, bmp);
}

#define BMP_PEER_TYPE_GLOBAL_INSTANCE 0
#define BMP_PEER_TYPE_RD_INSTANCE 1
#define BMP_PEER_TYPE_LOCAL_INSTANCE 2
#define BMP_PEER_TYPE_LOC_RIB_INSTANCE 3

/* determine the peer type for per-peer headers from a vrf_id
 * for non loc-rib peer type only
 */
static inline int bmp_get_peer_type_vrf(vrf_id_t vrf_id)
{
	switch (vrf_id) {
	case VRF_DEFAULT:
		return BMP_PEER_TYPE_GLOBAL_INSTANCE;
	case VRF_UNKNOWN:
		/* when the VRF is unknown consider it a local instance */
		return BMP_PEER_TYPE_LOCAL_INSTANCE;
	default:
		return BMP_PEER_TYPE_RD_INSTANCE;
	}
}

/* determine the peer type for per-peer headers from a struct peer
 * provide a bgp->peer_self for loc-rib
 */
static inline int bmp_get_peer_type(struct peer *peer)
{
	if (peer->bgp->peer_self == peer)
		return BMP_PEER_TYPE_LOC_RIB_INSTANCE;

	return bmp_get_peer_type_vrf(peer->bgp->vrf_id);
}

static inline int bmp_get_peer_distinguisher(struct bmp *bmp, afi_t afi,
					     uint8_t peer_type,
					     uint64_t *result_ref)
{

	/* remove this check when the other peer types get correct peer dist.
	 *(RFC7854) impl.
	 * for now, always return no error and 0 peer distinguisher as before
	 */
	if (peer_type != BMP_PEER_TYPE_LOC_RIB_INSTANCE)
		return (*result_ref = 0);

	/* sending vrf_id or rd could be turned into an option at some point */
	struct bgp *bgp = bmp->targets->bgp;

	/* vrf default => ok, distinguisher 0 */
	if (bgp->inst_type == VRF_DEFAULT)
		return (*result_ref = 0);

	/* use RD if set in VRF config for this AFI */
	struct prefix_rd *prd = &bgp->vpn_policy[afi].tovpn_rd;

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_RD_SET)) {
		memcpy(result_ref, prd->val, sizeof(prd->val));
		return 0;
	}

	/* VRF has no id => error => message should be skipped */
	if (bgp->vrf_id == VRF_UNKNOWN)
		return 1;

	/* use VRF id converted to ::vrf_id 64bits format */
	*result_ref = ((uint64_t)htonl(bgp->vrf_id)) << 32;
	return 0;
}

static void bmp_common_hdr(struct stream *s, uint8_t ver, uint8_t type)
{
	stream_putc(s, ver);
	stream_putl(s, 0); /* dummy message length. will be set later. */
	stream_putc(s, type);
}

static void bmp_per_peer_hdr(struct stream *s, struct bgp *bgp,
			     struct peer *peer, uint8_t flags,
			     uint8_t peer_type_flag,
			     uint64_t peer_distinguisher,
			     const struct timeval *tv)
{
#define BMP_PEER_FLAG_V (1 << 7)
#define BMP_PEER_FLAG_L (1 << 6)
#define BMP_PEER_FLAG_A (1 << 5)

	bool is_locrib = peer_type_flag == BMP_PEER_TYPE_LOC_RIB_INSTANCE;

	/* Peer Type */
	stream_putc(s, peer_type_flag);

	/* Peer Flags */
	if (!is_locrib && peer->connection->su.sa.sa_family == AF_INET6)
		SET_FLAG(flags, BMP_PEER_FLAG_V);
	else
		UNSET_FLAG(flags, BMP_PEER_FLAG_V);
	stream_putc(s, flags);

	/* Peer Distinguisher */
	stream_put(s, (uint8_t *)&peer_distinguisher, 8);

	/* Peer Address */
	/* Set to 0 if it's a LOC-RIB INSTANCE (RFC 9069) or if it's not an
	 * IPv4/6 address
	 */
	if (is_locrib || (peer->connection->su.sa.sa_family != AF_INET6 &&
			  peer->connection->su.sa.sa_family != AF_INET)) {
		stream_putl(s, 0);
		stream_putl(s, 0);
		stream_putl(s, 0);
		stream_putl(s, 0);
	} else if (peer->connection->su.sa.sa_family == AF_INET6)
		stream_put(s, &peer->connection->su.sin6.sin6_addr, IPV6_MAX_BYTELEN);
	else if (peer->connection->su.sa.sa_family == AF_INET) {
		stream_putl(s, 0);
		stream_putl(s, 0);
		stream_putl(s, 0);
		stream_put_in_addr(s, &peer->connection->su.sin.sin_addr);
	}

	/* Peer AS */
	/* set peer ASN but for LOC-RIB INSTANCE (RFC 9069) put the local bgp
	 * ASN
	 */
	as_t asn = !is_locrib ? peer->as : bgp->as;

	stream_putl(s, asn);

	/* Peer BGP ID */
	/* set router-id but for LOC-RIB INSTANCE (RFC 9069) put the instance
	 * router-id
	 */
	struct in_addr *bgp_id =
		!is_locrib ? &peer->remote_id : &bgp->router_id;

	stream_put_in_addr(s, bgp_id);

	/* Timestamp */
	if (tv) {
		stream_putl(s, tv->tv_sec);
		stream_putl(s, tv->tv_usec);
	} else {
		stream_putl(s, 0);
		stream_putl(s, 0);
	}
}

static void bmp_put_info_tlv(struct stream *s, uint16_t type,
		const char *string)
{
	int len = strlen (string);
	stream_putw(s, type);
	stream_putw(s, len);
	stream_put(s, string, len);
}

/* put the vrf table name of the bgp instance bmp is bound to in a tlv on the
 * stream
 */
static void bmp_put_vrftablename_info_tlv(struct stream *s, struct bgp *bgp)
{
	const char *vrftablename = "global";

#define BMP_INFO_TYPE_VRFTABLENAME 3

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		vrftablename = bgp->name;

	if (vrftablename != NULL)
		bmp_put_info_tlv(s, BMP_INFO_TYPE_VRFTABLENAME, vrftablename);
}

static int bmp_send_initiation(struct bmp *bmp)
{
	int len;
	struct stream *s = stream_new(BGP_MAX_PACKET_SIZE);

	bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_INITIATION);

#define BMP_INIT_INFO_TYPE_SYSDESCR 1
#define BMP_INIT_INFO_TYPE_SYSNAME  2
	bmp_put_info_tlv(s, BMP_INIT_INFO_TYPE_SYSDESCR,
			 FRR_FULL_NAME " " FRR_VER_SHORT);
	bmp_put_info_tlv(s, BMP_INIT_INFO_TYPE_SYSNAME, cmd_hostname_get());

	len = stream_get_endp(s);
	stream_putl_at(s, BMP_LENGTH_POS, len); /* message length is set. */

	pullwr_write_stream(bmp->pullwr, s);
	stream_free(s);
	return 0;
}

static void bmp_notify_put(struct stream *s, struct bgp_notify *nfy)
{
	size_t len_pos;
	uint8_t marker[16] = {
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
	};

	stream_put(s, marker, sizeof(marker));
	len_pos = stream_get_endp(s);
	stream_putw(s, 0);
	stream_putc(s, BGP_MSG_NOTIFY);
	stream_putc(s, nfy->code);
	stream_putc(s, nfy->subcode);
	stream_put(s, nfy->data, nfy->length);

	stream_putw_at(s, len_pos, stream_get_endp(s) - len_pos
			+ sizeof(marker));
}

/* send peer up/down for peer based on down boolean value
 * returns the message to send or NULL if the peer_distinguisher is not
 * available
 */
static struct stream *bmp_peerstate(struct peer *peer, bool down)
{
	struct stream *s;
	size_t len;
	struct timeval uptime, uptime_real;

	uptime.tv_sec = peer->uptime;
	uptime.tv_usec = 0;
	monotime_to_realtime(&uptime, &uptime_real);

	uint8_t peer_type = bmp_get_peer_type(peer);
	bool is_locrib = peer_type == BMP_PEER_TYPE_LOC_RIB_INSTANCE;

#define BGP_BMP_MAX_PACKET_SIZE	1024
#define BMP_PEERUP_INFO_TYPE_STRING 0
	s = stream_new(BGP_MAX_PACKET_SIZE);

	if ((peer_established(peer->connection) || is_locrib) && !down) {
		struct bmp_bgp_peer *bbpeer;

		bmp_common_hdr(s, BMP_VERSION_3,
				BMP_TYPE_PEER_UP_NOTIFICATION);
		bmp_per_peer_hdr(s, peer->bgp, peer, 0,
				 BMP_PEER_TYPE_GLOBAL_INSTANCE, 0,
				 &uptime_real);

		/* Local Address (16 bytes) */
		if (is_locrib)
			stream_put(s, 0, 16);
		else if (peer->su_local->sa.sa_family == AF_INET6)
			stream_put(s, &peer->su_local->sin6.sin6_addr, 16);
		else if (peer->su_local->sa.sa_family == AF_INET) {
			stream_putl(s, 0);
			stream_putl(s, 0);
			stream_putl(s, 0);
			stream_put_in_addr(s, &peer->su_local->sin.sin_addr);
		}

		/* Local Port, Remote Port */
		if (!peer->su_local || is_locrib)
			stream_putw(s, 0);
		else if (peer->su_local->sa.sa_family == AF_INET6)
			stream_putw(s, htons(peer->su_local->sin6.sin6_port));
		else if (peer->su_local->sa.sa_family == AF_INET)
			stream_putw(s, htons(peer->su_local->sin.sin_port));

		if (!peer->su_remote || is_locrib)
			stream_putw(s, 0);
		else if (peer->su_remote->sa.sa_family == AF_INET6)
			stream_putw(s, htons(peer->su_remote->sin6.sin6_port));
		else if (peer->su_remote->sa.sa_family == AF_INET)
			stream_putw(s, htons(peer->su_remote->sin.sin_port));

		/* TODO craft message with fields & capabilities for loc-rib */
		static const uint8_t dummy_open[] = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x13, 0x01,
		};

		bbpeer = bmp_bgp_peer_find(peer->qobj_node.nid);

		if (bbpeer && bbpeer->open_tx)
			stream_put(s, bbpeer->open_tx, bbpeer->open_tx_len);
		else {
			stream_put(s, dummy_open, sizeof(dummy_open));
			zlog_warn("bmp: missing TX OPEN message for peer %s",
				  peer->host);
		}
		if (bbpeer && bbpeer->open_rx)
			stream_put(s, bbpeer->open_rx, bbpeer->open_rx_len);
		else {
			stream_put(s, dummy_open, sizeof(dummy_open));
			zlog_warn("bmp: missing RX OPEN message for peer %s",
				  peer->host);
		}

		if (peer->desc)
			bmp_put_info_tlv(s, BMP_PEERUP_INFO_TYPE_STRING,
					 peer->desc);
	} else {
		uint8_t type;
		size_t type_pos;

		bmp_common_hdr(s, BMP_VERSION_3,
				BMP_TYPE_PEER_DOWN_NOTIFICATION);
		bmp_per_peer_hdr(s, peer->bgp, peer, 0,
				 BMP_PEER_TYPE_GLOBAL_INSTANCE, 0,
				 &uptime_real);

		type_pos = stream_get_endp(s);
		stream_putc(s, 0);	/* placeholder for down reason */

		if (is_locrib) {
			type = BMP_PEERDOWN_LOCAL_TLV;
		} else {
			switch (peer->last_reset) {
			case PEER_DOWN_NOTIFY_RECEIVED:
				type = BMP_PEERDOWN_REMOTE_NOTIFY;
				bmp_notify_put(s, &peer->notify);
				break;
			case PEER_DOWN_CLOSE_SESSION:
				type = BMP_PEERDOWN_REMOTE_CLOSE;
				break;
			case PEER_DOWN_WAITING_NHT:
				type = BMP_PEERDOWN_LOCAL_FSM;
				stream_putw(s, BGP_FSM_TcpConnectionFails);
				break;
			/*
			 * TODO: Map remaining PEER_DOWN_* reasons to RFC event
			 * codes.
			 * TODO: Implement BMP_PEERDOWN_LOCAL_NOTIFY.
			 *
			 * See RFC7854 ss. 4.9
			 */
			default:
				type = BMP_PEERDOWN_LOCAL_FSM;
				stream_putw(s, BMP_PEER_DOWN_NO_RELEVANT_EVENT_CODE);
				break;
			}
		}
		stream_putc_at(s, type_pos, type);
	}

	if (is_locrib)
		bmp_put_vrftablename_info_tlv(s, peer->bgp);

	len = stream_get_endp(s);
	stream_putl_at(s, BMP_LENGTH_POS, len); /* message length is set. */
	return s;
}


static int bmp_send_peerup(struct bmp *bmp)
{
	struct peer *peer;
	struct listnode *node;
	struct stream *s;

	/* Walk down all peers */
	for (ALL_LIST_ELEMENTS_RO(bmp->targets->bgp->peer, node, peer)) {
		s = bmp_peerstate(peer, false);
		pullwr_write_stream(bmp->pullwr, s);
		stream_free(s);
	}

	return 0;
}

static int bmp_send_peerup_vrf(struct bmp *bmp)
{
	struct bmp_bgp *bmpbgp = bmp->targets->bmpbgp;
	struct stream *s;

	/* send unconditionally because state may has been set before the
	 * session was up. and in this case the peer up has not been sent.
	 */
	bmp_bgp_update_vrf_status(bmpbgp, vrf_state_unknown);

	s = bmp_peerstate(bmpbgp->bgp->peer_self, bmpbgp->vrf_state == vrf_state_down);

	pullwr_write_stream(bmp->pullwr, s);
	stream_free(s);

	return 0;
}

/* send a stream to all bmp sessions configured in a bgp instance */
/* XXX: kludge - filling the pullwr's buffer */
static void bmp_send_all(struct bmp_bgp *bmpbgp, struct stream *s)
{
	struct bmp_targets *bt;
	struct bmp *bmp;

	frr_each(bmp_targets, &bmpbgp->targets, bt)
		frr_each(bmp_session, &bt->sessions, bmp)
			pullwr_write_stream(bmp->pullwr, s);
	stream_free(s);
}

static void bmp_send_all_safe(struct bmp_bgp *bmpbgp, struct stream *s)
{
	if (!bmpbgp) {
		stream_free(s);
		return;
	}

	bmp_send_all(bmpbgp, s);
}

/*
 * Route Mirroring
 */

#define BMP_MIRROR_TLV_TYPE_BGP_MESSAGE 0
#define BMP_MIRROR_TLV_TYPE_INFO        1

#define BMP_MIRROR_INFO_CODE_ERRORPDU   0
#define BMP_MIRROR_INFO_CODE_LOSTMSGS   1

static struct bmp_mirrorq *bmp_pull_mirror(struct bmp *bmp)
{
	struct bmp_mirrorq *bmq;

	bmq = bmp->mirrorpos;
	if (!bmq)
		return NULL;

	bmp->mirrorpos = bmp_mirrorq_next(&bmp->targets->bmpbgp->mirrorq, bmq);

	bmq->refcount--;
	if (!bmq->refcount) {
		bmp->targets->bmpbgp->mirror_qsize -= sizeof(*bmq) + bmq->len;
		bmp_mirrorq_del(&bmp->targets->bmpbgp->mirrorq, bmq);
	}
	return bmq;
}

static void bmp_mirror_cull(struct bmp_bgp *bmpbgp)
{
	while (bmpbgp->mirror_qsize > bmpbgp->mirror_qsizelimit) {
		struct bmp_mirrorq *bmq, *inner;
		struct bmp_targets *bt;
		struct bmp *bmp;

		bmq = bmp_mirrorq_first(&bmpbgp->mirrorq);

		frr_each(bmp_targets, &bmpbgp->targets, bt) {
			if (!bt->mirror)
				continue;
			frr_each(bmp_session, &bt->sessions, bmp) {
				if (bmp->mirrorpos != bmq)
					continue;

				while ((inner = bmp_pull_mirror(bmp))) {
					if (!inner->refcount)
						XFREE(MTYPE_BMP_MIRRORQ,
								inner);
				}

				zlog_warn("bmp[%s] lost mirror messages due to buffer size limit",
						bmp->remote);
				bmp->mirror_lost = true;
				pullwr_bump(bmp->pullwr);
			}
		}
	}
}

static int bmp_mirror_packet(struct peer *peer, uint8_t type, bgp_size_t size,
		struct stream *packet)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(peer->bgp);
	struct timeval tv;
	struct bmp_mirrorq *qitem;
	struct bmp_targets *bt;
	struct bmp *bmp;

	frrtrace(3, frr_bgp, bmp_mirror_packet, peer, type, packet);

	gettimeofday(&tv, NULL);

	if (type == BGP_MSG_OPEN) {
		struct bmp_bgp_peer *bbpeer = bmp_bgp_peer_get(peer);

		XFREE(MTYPE_BMP_OPEN, bbpeer->open_rx);

		bbpeer->open_rx_len = size;
		bbpeer->open_rx = XMALLOC(MTYPE_BMP_OPEN, size);
		memcpy(bbpeer->open_rx, packet->data, size);
	}

	if (!bmpbgp)
		return 0;

	qitem = XCALLOC(MTYPE_BMP_MIRRORQ, sizeof(*qitem) + size);
	qitem->peerid = peer->qobj_node.nid;
	qitem->tv = tv;
	qitem->len = size;
	memcpy(qitem->data, packet->data, size);

	frr_each(bmp_targets, &bmpbgp->targets, bt) {
		if (!bt->mirror)
			continue;
		frr_each(bmp_session, &bt->sessions, bmp) {
			qitem->refcount++;
			if (!bmp->mirrorpos)
				bmp->mirrorpos = qitem;
			pullwr_bump(bmp->pullwr);
		}
	}
	if (qitem->refcount == 0)
		XFREE(MTYPE_BMP_MIRRORQ, qitem);
	else {
		bmpbgp->mirror_qsize += sizeof(*qitem) + size;
		bmp_mirrorq_add_tail(&bmpbgp->mirrorq, qitem);

		bmp_mirror_cull(bmpbgp);

		bmpbgp->mirror_qsizemax = MAX(bmpbgp->mirror_qsizemax,
				bmpbgp->mirror_qsize);
	}
	return 0;
}

static void bmp_wrmirror_lost(struct bmp *bmp, struct pullwr *pullwr)
{
	struct stream *s;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	s = stream_new(BGP_MAX_PACKET_SIZE);

	bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_ROUTE_MIRRORING);
	bmp_per_peer_hdr(s, bmp->targets->bgp, bmp->targets->bgp->peer_self, 0,
			 BMP_PEER_TYPE_GLOBAL_INSTANCE, 0, &tv);

	stream_putw(s, BMP_MIRROR_TLV_TYPE_INFO);
	stream_putw(s, 2);
	stream_putw(s, BMP_MIRROR_INFO_CODE_LOSTMSGS);
	stream_putl_at(s, BMP_LENGTH_POS, stream_get_endp(s));

	bmp->cnt_mirror_overruns++;
	pullwr_write_stream(bmp->pullwr, s);
	stream_free(s);
}

static bool bmp_wrmirror(struct bmp *bmp, struct pullwr *pullwr)
{
	struct bmp_mirrorq *bmq;
	struct peer *peer;
	bool written = false;

	if (bmp->mirror_lost) {
		bmp_wrmirror_lost(bmp, pullwr);
		bmp->mirror_lost = false;
		return true;
	}

	bmq = bmp_pull_mirror(bmp);
	if (!bmq)
		return false;

	peer = QOBJ_GET_TYPESAFE(bmq->peerid, peer);
	if (!peer) {
		zlog_info("bmp: skipping mirror message for deleted peer");
		goto out;
	}

	struct stream *s;
	s = stream_new(BGP_MAX_PACKET_SIZE);

	bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_ROUTE_MIRRORING);
	bmp_per_peer_hdr(s, bmp->targets->bgp, peer, 0,
			 BMP_PEER_TYPE_GLOBAL_INSTANCE, 0, &bmq->tv);

	/* BMP Mirror TLV. */
	stream_putw(s, BMP_MIRROR_TLV_TYPE_BGP_MESSAGE);
	stream_putw(s, bmq->len);
	stream_putl_at(s, BMP_LENGTH_POS, stream_get_endp(s) + bmq->len);

	bmp->cnt_mirror++;
	pullwr_write_stream(bmp->pullwr, s);
	pullwr_write(bmp->pullwr, bmq->data, bmq->len);

	stream_free(s);
	written = true;

out:
	if (!bmq->refcount)
		XFREE(MTYPE_BMP_MIRRORQ, bmq);
	return written;
}

static int bmp_outgoing_packet(struct peer *peer, uint8_t type, bgp_size_t size,
		struct stream *packet)
{
	if (type == BGP_MSG_OPEN) {
		frrtrace(2, frr_bgp, bmp_update_saved_open, peer, packet);

		struct bmp_bgp_peer *bbpeer = bmp_bgp_peer_get(peer);

		XFREE(MTYPE_BMP_OPEN, bbpeer->open_tx);

		bbpeer->open_tx_len = size;
		bbpeer->open_tx = XMALLOC(MTYPE_BMP_OPEN, size);
		memcpy(bbpeer->open_tx, packet->data, size);
	}
	return 0;
}

static int bmp_peer_status_changed(struct peer *peer)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(peer->bgp);
	struct bmp_bgp_peer *bbpeer, *bbdopp;

	frrtrace(1, frr_bgp, bmp_peer_status_changed, peer);

	if (!bmpbgp)
		return 0;

	if (peer->connection->status == Deleted) {
		bbpeer = bmp_bgp_peer_find(peer->qobj_node.nid);
		if (bbpeer) {
			XFREE(MTYPE_BMP_OPEN, bbpeer->open_rx);
			XFREE(MTYPE_BMP_OPEN, bbpeer->open_tx);
			bmp_peerh_del(&bmp_peerh, bbpeer);
			XFREE(MTYPE_BMP_PEER, bbpeer);
		}
		return 0;
	}

	/* Check if this peer just went to Established */
	if ((peer->connection->ostatus != OpenConfirm) ||
	    !(peer_established(peer->connection)))
		return 0;

	if (peer->doppelganger &&
	    (peer->doppelganger->connection->status != Deleted)) {
		bbpeer = bmp_bgp_peer_get(peer);
		bbdopp = bmp_bgp_peer_find(peer->doppelganger->qobj_node.nid);
		if (bbdopp) {
			XFREE(MTYPE_BMP_OPEN, bbpeer->open_tx);
			XFREE(MTYPE_BMP_OPEN, bbpeer->open_rx);

			bbpeer->open_tx = bbdopp->open_tx;
			bbpeer->open_tx_len = bbdopp->open_tx_len;
			bbpeer->open_rx = bbdopp->open_rx;
			bbpeer->open_rx_len = bbdopp->open_rx_len;

			bmp_peerh_del(&bmp_peerh, bbdopp);
			XFREE(MTYPE_BMP_PEER, bbdopp);
		}
	}

	bmp_send_all_safe(bmpbgp, bmp_peerstate(peer, false));
	return 0;
}

static int bmp_peer_backward(struct peer *peer)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(peer->bgp);
	struct bmp_bgp_peer *bbpeer;

	frrtrace(1, frr_bgp, bmp_peer_backward_transition, peer);

	if (!bmpbgp)
		return 0;

	bbpeer = bmp_bgp_peer_find(peer->qobj_node.nid);
	if (bbpeer) {
		XFREE(MTYPE_BMP_OPEN, bbpeer->open_tx);
		bbpeer->open_tx_len = 0;
		XFREE(MTYPE_BMP_OPEN, bbpeer->open_rx);
		bbpeer->open_rx_len = 0;
	}

	bmp_send_all_safe(bmpbgp, bmp_peerstate(peer, true));
	return 0;
}

static void bmp_eor(struct bmp *bmp, afi_t afi, safi_t safi, uint8_t flags,
		    uint8_t peer_type_flag)
{
	struct peer *peer;
	struct listnode *node;
	struct stream *s, *s2;
	iana_afi_t pkt_afi = IANA_AFI_IPV4;
	iana_safi_t pkt_safi = IANA_SAFI_UNICAST;

	frrtrace(4, frr_bgp, bmp_eor, afi, safi, flags, peer_type_flag);

	s = stream_new(BGP_MAX_PACKET_SIZE);

	/* Make BGP update packet. */
	bgp_packet_set_marker(s, BGP_MSG_UPDATE);

	/* Unfeasible Routes Length */
	stream_putw(s, 0);

	if (afi == AFI_IP && safi == SAFI_UNICAST) {
		/* Total Path Attribute Length */
		stream_putw(s, 0);
	} else {
		/* Convert AFI, SAFI to values for packet. */
		bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

		/* Total Path Attribute Length */
		stream_putw(s, 6);
		stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
		stream_putc(s, BGP_ATTR_MP_UNREACH_NLRI);
		stream_putc(s, 3);
		stream_putw(s, pkt_afi);
		stream_putc(s, pkt_safi);
	}

	bgp_packet_set_size(s);

	for (ALL_LIST_ELEMENTS_RO(bmp->targets->bgp->peer, node, peer)) {
		if (!peer->afc_nego[afi][safi])
			continue;

		uint64_t peer_distinguisher = 0;
		/* skip this message if peer distinguisher is not available */
		if (bmp_get_peer_distinguisher(bmp, afi, peer_type_flag,
					       &peer_distinguisher)) {
			zlog_warn(
				"skipping bmp message for reason: can't get peer distinguisher");
			continue;
		}

		s2 = stream_new(BGP_MAX_PACKET_SIZE);

		bmp_common_hdr(s2, BMP_VERSION_3,
				BMP_TYPE_ROUTE_MONITORING);

		bmp_per_peer_hdr(s2, bmp->targets->bgp, peer, flags,
				 peer_type_flag, peer_distinguisher, NULL);

		stream_putl_at(s2, BMP_LENGTH_POS,
				stream_get_endp(s) + stream_get_endp(s2));

		bmp->cnt_update++;
		pullwr_write_stream(bmp->pullwr, s2);
		pullwr_write_stream(bmp->pullwr, s);
		stream_free(s2);
	}
	stream_free(s);
}

static struct stream *bmp_update(const struct prefix *p, struct prefix_rd *prd,
				 struct peer *peer, struct attr *attr,
				 afi_t afi, safi_t safi, mpls_label_t *label,
				 uint32_t num_labels)
{
	struct bpacket_attr_vec_arr vecarr;
	struct stream *s;
	size_t attrlen_pos = 0, mpattrlen_pos = 0;
	bgp_size_t total_attr_len = 0;

	bpacket_attr_vec_arr_reset(&vecarr);

	s = stream_new(BGP_MAX_PACKET_SIZE);
	bgp_packet_set_marker(s, BGP_MSG_UPDATE);

	/* 2: withdrawn routes length */
	stream_putw(s, 0);

	/* 3: total attributes length - attrlen_pos stores the position */
	attrlen_pos = stream_get_endp(s);
	stream_putw(s, 0);

	/* 5: Encode all the attributes, except MP_REACH_NLRI attr. */
	total_attr_len = bgp_packet_attribute(NULL, peer, s, attr, &vecarr, NULL, afi, safi, peer,
					      NULL, NULL, 0, 0, 0);

	/* space check? */

	/* peer_cap_enhe & add-path removed */
	if (afi == AFI_IP && safi == SAFI_UNICAST)
		stream_put_prefix(s, p);
	else {
		size_t p1 = stream_get_endp(s);

		/* MPLS removed for now */

		mpattrlen_pos = bgp_packet_mpattr_start(s, peer, afi, safi,
				&vecarr, attr);
		bgp_packet_mpattr_prefix(s, afi, safi, p, prd, label,
					 num_labels, 0, 0, attr);
		bgp_packet_mpattr_end(s, mpattrlen_pos);
		total_attr_len += stream_get_endp(s) - p1;
	}

	/* set the total attribute length correctly */
	stream_putw_at(s, attrlen_pos, total_attr_len);
	bgp_packet_set_size(s);
	return s;
}

static struct stream *bmp_withdraw(const struct prefix *p,
				   struct prefix_rd *prd, afi_t afi,
				   safi_t safi)
{
	struct stream *s;
	size_t attrlen_pos = 0, mp_start, mplen_pos;
	bgp_size_t total_attr_len = 0;
	bgp_size_t unfeasible_len;

	s = stream_new(BGP_MAX_PACKET_SIZE);

	bgp_packet_set_marker(s, BGP_MSG_UPDATE);
	stream_putw(s, 0);

	if (afi == AFI_IP && safi == SAFI_UNICAST) {
		stream_put_prefix(s, p);
		unfeasible_len = stream_get_endp(s) - BGP_HEADER_SIZE
				 - BGP_UNFEASIBLE_LEN;
		stream_putw_at(s, BGP_HEADER_SIZE, unfeasible_len);
		stream_putw(s, 0);
	} else {
		attrlen_pos = stream_get_endp(s);
		/* total attr length = 0 for now. reevaluate later */
		stream_putw(s, 0);
		mp_start = stream_get_endp(s);
		mplen_pos = bgp_packet_mpunreach_start(s, afi, safi);

		bgp_packet_mpunreach_prefix(s, p, afi, safi, prd, NULL, 0, 0, 0,
					    NULL);
		/* Set the mp_unreach attr's length */
		bgp_packet_mpunreach_end(s, mplen_pos);

		/* Set total path attribute length. */
		total_attr_len = stream_get_endp(s) - mp_start;
		stream_putw_at(s, attrlen_pos, total_attr_len);
	}

	bgp_packet_set_size(s);
	return s;
}

static void bmp_monitor(struct bmp *bmp, struct peer *peer, uint8_t flags,
			uint8_t peer_type_flag, const struct prefix *p,
			struct prefix_rd *prd, struct attr *attr, afi_t afi,
			safi_t safi, time_t uptime, mpls_label_t *label,
			uint32_t num_labels)
{
	struct stream *hdr, *msg;
	struct timeval tv = { .tv_sec = uptime, .tv_usec = 0 };
	struct timeval uptime_real;

	uint64_t peer_distinguisher = 0;
	/* skip this message if peer distinguisher is not available */
	if (bmp_get_peer_distinguisher(bmp, afi, peer_type_flag,
				       &peer_distinguisher)) {
		zlog_warn(
			"skipping bmp message for reason: can't get peer distinguisher");
		return;
	}

	monotime_to_realtime(&tv, &uptime_real);
	if (attr)
		msg = bmp_update(p, prd, peer, attr, afi, safi, label,
				 num_labels);
	else
		msg = bmp_withdraw(p, prd, afi, safi);

	hdr = stream_new(BGP_MAX_PACKET_SIZE);
	bmp_common_hdr(hdr, BMP_VERSION_3, BMP_TYPE_ROUTE_MONITORING);
	bmp_per_peer_hdr(hdr, bmp->targets->bgp, peer, flags, peer_type_flag,
			 peer_distinguisher,
			 uptime == (time_t)(-1L) ? NULL : &uptime_real);

	stream_putl_at(hdr, BMP_LENGTH_POS,
			stream_get_endp(hdr) + stream_get_endp(msg));

	bmp->cnt_update++;
	pullwr_write_stream(bmp->pullwr, hdr);
	pullwr_write_stream(bmp->pullwr, msg);
	stream_free(hdr);
	stream_free(msg);
}

static bool bmp_wrsync(struct bmp *bmp, struct pullwr *pullwr)
{
	uint8_t bpi_num_labels, adjin_num_labels;
	afi_t afi;
	safi_t safi;

	if (bmp->syncafi == AFI_MAX) {
		FOREACH_AFI_SAFI (afi, safi) {
			if (bmp->afistate[afi][safi] != BMP_AFI_NEEDSYNC)
				continue;

			bmp->afistate[afi][safi] = BMP_AFI_SYNC;

			bmp->syncafi = afi;
			bmp->syncsafi = safi;
			bmp->syncpeerid = 0;
			memset(&bmp->syncpos, 0, sizeof(bmp->syncpos));
			bmp->syncpos.family = afi2family(afi);
			bmp->syncrdpos = NULL;
			zlog_info("bmp[%s] %s %s sending table",
					bmp->remote,
					afi2str(bmp->syncafi),
					safi2str(bmp->syncsafi));
			/* break does not work here, 2 loops... */
			goto afibreak;
		}
		if (bmp->syncafi == AFI_MAX)
			return false;
	}

afibreak:
	afi = bmp->syncafi;
	safi = bmp->syncsafi;

	if (!bmp->targets->afimon[afi][safi]) {
		/* shouldn't happen */
		bmp->afistate[afi][safi] = BMP_AFI_INACTIVE;
		bmp->syncafi = AFI_MAX;
		bmp->syncsafi = SAFI_MAX;
		return true;
	}

	struct bgp_table *table = bmp->targets->bgp->rib[afi][safi];
	struct bgp_dest *bn = NULL;
	struct bgp_path_info *bpi = NULL, *bpiter;
	struct bgp_adj_in *adjin = NULL, *adjiter;

	if ((afi == AFI_L2VPN && safi == SAFI_EVPN) ||
	    (safi == SAFI_MPLS_VPN)) {
		/* initialize syncrdpos to the first
		 * mid-layer table entry
		 */
		if (!bmp->syncrdpos) {
			bmp->syncrdpos = bgp_table_top(table);
			if (!bmp->syncrdpos)
				goto eor;
		}

		/* look for a valid mid-layer table */
		do {
			table = bgp_dest_get_bgp_table_info(bmp->syncrdpos);
			if (table) {
				break;
			}
			bmp->syncrdpos = bgp_route_next(bmp->syncrdpos);
		} while (bmp->syncrdpos);

		/* mid-layer table completed */
		if (!bmp->syncrdpos)
			goto eor;
	}

	bn = bgp_node_lookup(table, &bmp->syncpos);
	do {
		if (!bn) {
			bn = bgp_table_get_next(table, &bmp->syncpos);
			if (!bn) {
				if ((afi == AFI_L2VPN && safi == SAFI_EVPN) ||
				    (safi == SAFI_MPLS_VPN)) {
					/* reset bottom-layer pointer */
					memset(&bmp->syncpos, 0,
					       sizeof(bmp->syncpos));
					bmp->syncpos.family = afi2family(afi);
					/* check whethere there is a valid
					 * next mid-layer table, otherwise
					 * declare table completed (eor)
					 */
					for (bmp->syncrdpos = bgp_route_next(
						     bmp->syncrdpos);
					     bmp->syncrdpos;
					     bmp->syncrdpos = bgp_route_next(
						     bmp->syncrdpos))
						if (bgp_dest_get_bgp_table_info(
							    bmp->syncrdpos))
							return true;
				}
			eor:
				zlog_info("bmp[%s] %s %s table completed (EoR)",
						bmp->remote, afi2str(afi),
						safi2str(safi));

				bmp_eor(bmp, afi, safi, BMP_PEER_FLAG_L,
					BMP_PEER_TYPE_GLOBAL_INSTANCE);
				bmp_eor(bmp, afi, safi, 0,
					BMP_PEER_TYPE_GLOBAL_INSTANCE);
				bmp_eor(bmp, afi, safi, 0,
					BMP_PEER_TYPE_LOC_RIB_INSTANCE);

				bmp->afistate[afi][safi] = BMP_AFI_LIVE;
				bmp->syncafi = AFI_MAX;
				bmp->syncsafi = SAFI_MAX;
				return true;
			}
			bmp->syncpeerid = 0;
			prefix_copy(&bmp->syncpos, bgp_dest_get_prefix(bn));
		}

		if (CHECK_FLAG(bmp->targets->afimon[afi][safi],
			       BMP_MON_POSTPOLICY) ||
		    CHECK_FLAG(bmp->targets->afimon[afi][safi],
			       BMP_MON_LOC_RIB)) {
			for (bpiter = bgp_dest_get_bgp_path_info(bn); bpiter;
			     bpiter = bpiter->next) {
				if (!CHECK_FLAG(bpiter->flags,
						BGP_PATH_VALID) &&
				    !CHECK_FLAG(bpiter->flags,
						BGP_PATH_SELECTED))
					continue;
				if (bpiter->peer->qobj_node.nid
				    <= bmp->syncpeerid)
					continue;
				if (bpi && bpiter->peer->qobj_node.nid
						> bpi->peer->qobj_node.nid)
					continue;
				bpi = bpiter;
			}
		}
		if (CHECK_FLAG(bmp->targets->afimon[afi][safi],
			       BMP_MON_PREPOLICY)) {
			for (adjiter = bn->adj_in; adjiter;
			     adjiter = adjiter->next) {
				if (adjiter->peer->qobj_node.nid
				    <= bmp->syncpeerid)
					continue;
				if (adjin && adjiter->peer->qobj_node.nid
						> adjin->peer->qobj_node.nid)
					continue;
				adjin = adjiter;
			}
		}
		if (bpi || adjin)
			break;

		bn = NULL;
	} while (1);

	if (adjin && bpi
	    && adjin->peer->qobj_node.nid < bpi->peer->qobj_node.nid) {
		bpi = NULL;
		bmp->syncpeerid = adjin->peer->qobj_node.nid;
	} else if (adjin && bpi
		   && adjin->peer->qobj_node.nid > bpi->peer->qobj_node.nid) {
		adjin = NULL;
		bmp->syncpeerid = bpi->peer->qobj_node.nid;
	} else if (bpi) {
		bmp->syncpeerid = bpi->peer->qobj_node.nid;
	} else if (adjin) {
		bmp->syncpeerid = adjin->peer->qobj_node.nid;
	}

	const struct prefix *bn_p = bgp_dest_get_prefix(bn);
	struct prefix_rd *prd = NULL;
	if (((afi == AFI_L2VPN) && (safi == SAFI_EVPN)) ||
	    (safi == SAFI_MPLS_VPN))
		prd = (struct prefix_rd *)bgp_dest_get_prefix(bmp->syncrdpos);

	bpi_num_labels = BGP_PATH_INFO_NUM_LABELS(bpi);

	if (bpi && CHECK_FLAG(bpi->flags, BGP_PATH_SELECTED) &&
	    CHECK_FLAG(bmp->targets->afimon[afi][safi], BMP_MON_LOC_RIB)) {
		bmp_monitor(bmp, bpi->peer, 0, BMP_PEER_TYPE_LOC_RIB_INSTANCE,
			    bn_p, prd, bpi->attr, afi, safi,
			    bpi && bpi->extra ? bpi->extra->bgp_rib_uptime
					      : (time_t)(-1L),
			    bpi_num_labels ? bpi->extra->labels->label : NULL,
			    bpi_num_labels);
	}

	if (bpi && CHECK_FLAG(bpi->flags, BGP_PATH_VALID) &&
	    CHECK_FLAG(bmp->targets->afimon[afi][safi], BMP_MON_POSTPOLICY))
		bmp_monitor(bmp, bpi->peer, BMP_PEER_FLAG_L,
			    BMP_PEER_TYPE_GLOBAL_INSTANCE, bn_p, prd, bpi->attr,
			    afi, safi, bpi->uptime,
			    bpi_num_labels ? bpi->extra->labels->label : NULL,
			    bpi_num_labels);

	if (adjin) {
		adjin_num_labels = adjin->labels ? adjin->labels->num_labels : 0;
		bmp_monitor(bmp, adjin->peer, 0, BMP_PEER_TYPE_GLOBAL_INSTANCE, bn_p, prd,
			    adjin->attr, afi, safi, adjin->uptime,
			    adjin_num_labels ? &adjin->labels->label[0] : NULL, adjin_num_labels);
	}

	if (bn)
		bgp_dest_unlock_node(bn);

	return true;
}

static struct bmp_queue_entry *
bmp_pull_from_queue(struct bmp_qlist_head *list, struct bmp_qhash_head *hash,
		    struct bmp_queue_entry **queuepos_ptr)
{
	struct bmp_queue_entry *bqe;

	bqe = *queuepos_ptr;
	if (!bqe)
		return NULL;

	*queuepos_ptr = bmp_qlist_next(list, bqe);

	bqe->refcount--;
	if (!bqe->refcount) {
		bmp_qhash_del(hash, bqe);
		bmp_qlist_del(list, bqe);
	}
	return bqe;
}

static inline struct bmp_queue_entry *bmp_pull(struct bmp *bmp)
{
	return bmp_pull_from_queue(&bmp->targets->updlist,
				   &bmp->targets->updhash, &bmp->queuepos);
}

static inline struct bmp_queue_entry *bmp_pull_locrib(struct bmp *bmp)
{
	return bmp_pull_from_queue(&bmp->targets->locupdlist,
				   &bmp->targets->locupdhash,
				   &bmp->locrib_queuepos);
}

/* TODO BMP_MON_LOCRIB find a way to merge properly this function with
 * bmp_wrqueue or abstract it if possible
 */
static bool bmp_wrqueue_locrib(struct bmp *bmp, struct pullwr *pullwr)
{

	struct bmp_queue_entry *bqe;
	struct peer *peer;
	struct bgp_dest *bn = NULL;
	bool written = false;
	uint8_t bpi_num_labels;

	bqe = bmp_pull_locrib(bmp);
	if (!bqe)
		return false;

	afi_t afi = bqe->afi;
	safi_t safi = bqe->safi;

	if (!CHECK_FLAG(bmp->targets->afimon[afi][safi], BMP_MON_LOC_RIB))
		goto out;

	switch (bmp->afistate[afi][safi]) {
	case BMP_AFI_INACTIVE:
	case BMP_AFI_NEEDSYNC:
		goto out;
	case BMP_AFI_SYNC:
		if (prefix_cmp(&bqe->p, &bmp->syncpos) <= 0)
			/* currently syncing but have already passed this
			 * prefix => send it.
			 */
			break;

		/* currently syncing & haven't reached this prefix yet
		 * => it'll be sent as part of the table sync, no need here
		 */
		goto out;
	case BMP_AFI_LIVE:
		break;
	}

	peer = QOBJ_GET_TYPESAFE(bqe->peerid, peer);
	if (!peer) {
		/* skipping queued item for deleted peer
		 */
		goto out;
	}
	if (peer != bmp->targets->bgp->peer_self && !peer_established(peer->connection)) {
		/* peer is neither self, nor established
		 */
		goto out;
	}

	bool is_vpn = (bqe->afi == AFI_L2VPN && bqe->safi == SAFI_EVPN) ||
		      (bqe->safi == SAFI_MPLS_VPN);

	struct prefix_rd *prd = is_vpn ? &bqe->rd : NULL;

	bn = bgp_safi_node_lookup(bmp->targets->bgp->rib[afi][safi], safi,
				  &bqe->p, prd);

	struct bgp_path_info *bpi;

	for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (!CHECK_FLAG(bpi->flags, BGP_PATH_SELECTED))
			continue;
		if (bpi->peer == peer)
			break;
	}

	bpi_num_labels = BGP_PATH_INFO_NUM_LABELS(bpi);

	bmp_monitor(bmp, peer, 0, BMP_PEER_TYPE_LOC_RIB_INSTANCE, &bqe->p, prd,
		    bpi ? bpi->attr : NULL, afi, safi,
		    bpi && bpi->extra ? bpi->extra->bgp_rib_uptime
				      : (time_t)(-1L),
		    bpi_num_labels ? bpi->extra->labels->label : NULL,
		    bpi_num_labels);
	written = true;

out:
	if (!bqe->refcount)
		XFREE(MTYPE_BMP_QUEUE, bqe);

	if (bn)
		bgp_dest_unlock_node(bn);

	return written;
}

static bool bmp_wrqueue(struct bmp *bmp, struct pullwr *pullwr)
{
	struct bmp_queue_entry *bqe;
	struct peer *peer;
	struct bgp_dest *bn = NULL;
	bool written = false;
	uint8_t bpi_num_labels, adjin_num_labels;

	bqe = bmp_pull(bmp);
	if (!bqe)
		return false;

	afi_t afi = bqe->afi;
	safi_t safi = bqe->safi;

	switch (bmp->afistate[afi][safi]) {
	case BMP_AFI_INACTIVE:
	case BMP_AFI_NEEDSYNC:
		goto out;
	case BMP_AFI_SYNC:
		if (prefix_cmp(&bqe->p, &bmp->syncpos) <= 0)
			/* currently syncing but have already passed this
			 * prefix => send it. */
			break;

		/* currently syncing & haven't reached this prefix yet
		 * => it'll be sent as part of the table sync, no need here */
		goto out;
	case BMP_AFI_LIVE:
		break;
	}

	peer = QOBJ_GET_TYPESAFE(bqe->peerid, peer);
	if (!peer) {
		zlog_info("bmp: skipping queued item for deleted peer");
		goto out;
	}
	if (!peer_established(peer->connection))
		goto out;

	bool is_vpn = (bqe->afi == AFI_L2VPN && bqe->safi == SAFI_EVPN) ||
		      (bqe->safi == SAFI_MPLS_VPN);

	struct prefix_rd *prd = is_vpn ? &bqe->rd : NULL;
	bn = bgp_safi_node_lookup(bmp->targets->bgp->rib[afi][safi], safi,
				  &bqe->p, prd);

	if (CHECK_FLAG(bmp->targets->afimon[afi][safi], BMP_MON_POSTPOLICY)) {
		struct bgp_path_info *bpi;

		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (!CHECK_FLAG(bpi->flags, BGP_PATH_VALID))
				continue;
			if (bpi->peer == peer)
				break;
		}

		bpi_num_labels = BGP_PATH_INFO_NUM_LABELS(bpi);

		bmp_monitor(bmp, peer, BMP_PEER_FLAG_L,
			    BMP_PEER_TYPE_GLOBAL_INSTANCE, &bqe->p, prd,
			    bpi ? bpi->attr : NULL, afi, safi,
			    bpi ? bpi->uptime : monotime(NULL),
			    bpi_num_labels ? bpi->extra->labels->label : NULL,
			    bpi_num_labels);
		written = true;
	}

	if (CHECK_FLAG(bmp->targets->afimon[afi][safi], BMP_MON_PREPOLICY)) {
		struct bgp_adj_in *adjin;

		for (adjin = bn ? bn->adj_in : NULL; adjin;
		     adjin = adjin->next) {
			if (adjin->peer == peer)
				break;
		}
		adjin_num_labels = adjin && adjin->labels ? adjin->labels->num_labels : 0;
		bmp_monitor(bmp, peer, 0, BMP_PEER_TYPE_GLOBAL_INSTANCE, &bqe->p, prd,
			    adjin ? adjin->attr : NULL, afi, safi,
			    adjin ? adjin->uptime : monotime(NULL),
			    adjin_num_labels ? &adjin->labels->label[0] : NULL, adjin_num_labels);
		written = true;
	}

out:
	if (!bqe->refcount)
		XFREE(MTYPE_BMP_QUEUE, bqe);

	if (bn)
		bgp_dest_unlock_node(bn);

	return written;
}

static void bmp_wrfill(struct bmp *bmp, struct pullwr *pullwr)
{
	switch(bmp->state) {
	case BMP_PeerUp:
		bmp_send_peerup_vrf(bmp);
		bmp_send_peerup(bmp);
		bmp->state = BMP_Run;
		break;

	case BMP_Run:
		if (bmp_wrmirror(bmp, pullwr))
			break;
		if (bmp_wrqueue(bmp, pullwr))
			break;
		if (bmp_wrqueue_locrib(bmp, pullwr))
			break;
		if (bmp_wrsync(bmp, pullwr))
			break;
		break;
	}
}

static void bmp_wrerr(struct bmp *bmp, struct pullwr *pullwr, bool eof)
{
	if (eof)
		zlog_info("bmp[%s] disconnected", bmp->remote);
	else
		flog_warn(EC_LIB_SYSTEM_CALL, "bmp[%s] connection error: %s",
				bmp->remote, strerror(errno));

	bmp_close(bmp);
	bmp_free(bmp);
}

static struct bmp_queue_entry *
bmp_process_one(struct bmp_targets *bt, struct bmp_qhash_head *updhash,
		struct bmp_qlist_head *updlist, struct bgp *bgp, afi_t afi,
		safi_t safi, struct bgp_dest *bn, struct peer *peer)
{
	struct bmp_queue_entry *bqe, bqeref;
	size_t refcount;

	refcount = bmp_session_count(&bt->sessions);
	if (refcount == 0)
		return NULL;

	memset(&bqeref, 0, sizeof(bqeref));
	prefix_copy(&bqeref.p, bgp_dest_get_prefix(bn));
	bqeref.peerid = peer->qobj_node.nid;
	bqeref.afi = afi;
	bqeref.safi = safi;

	if ((afi == AFI_L2VPN && safi == SAFI_EVPN && bn->pdest) ||
	    (safi == SAFI_MPLS_VPN))
		prefix_copy(&bqeref.rd,
			    (struct prefix_rd *)bgp_dest_get_prefix(bn->pdest));

	bqe = bmp_qhash_find(updhash, &bqeref);
	if (bqe) {
		if (bqe->refcount >= refcount)
			/* nothing to do here */
			return NULL;

		bmp_qlist_del(updlist, bqe);
	} else {
		bqe = XMALLOC(MTYPE_BMP_QUEUE, sizeof(*bqe));
		memcpy(bqe, &bqeref, sizeof(*bqe));

		bmp_qhash_add(updhash, bqe);
	}

	bqe->refcount = refcount;
	bmp_qlist_add_tail(updlist, bqe);

	return bqe;

	/* need to update correct queue pos for all sessions of the target after
	 * a call to this function
	 */
}

static int bmp_process(struct bgp *bgp, afi_t afi, safi_t safi,
		       struct bgp_dest *bn, struct peer *peer, bool withdraw)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(peer->bgp);
	struct bmp_targets *bt;
	struct bmp *bmp;

	if (frrtrace_enabled(frr_bgp, bmp_process)) {
		char pfxprint[PREFIX2STR_BUFFER];

		prefix2str(&bn->rn->p, pfxprint, sizeof(pfxprint));
		frrtrace(5, frr_bgp, bmp_process, peer, pfxprint, afi, safi,
			 withdraw);
	}

	if (!bmpbgp)
		return 0;

	frr_each(bmp_targets, &bmpbgp->targets, bt) {
		/* check if any monitoring is enabled (ignoring loc-rib since it
		 * uses another hook & queue
		 */
		if (!CHECK_FLAG(bt->afimon[afi][safi], ~BMP_MON_LOC_RIB))
			continue;

		struct bmp_queue_entry *last_item =
			bmp_process_one(bt, &bt->updhash, &bt->updlist, bgp,
					afi, safi, bn, peer);

		/* if bmp_process_one returns NULL
		 * we don't have anything to do next
		 */
		if (!last_item)
			continue;

		frr_each(bmp_session, &bt->sessions, bmp) {
			if (!bmp->queuepos)
				bmp->queuepos = last_item;

			pullwr_bump(bmp->pullwr);
		}
	}
	return 0;
}

static void bmp_stat_put_u32(struct stream *s, size_t *cnt, uint16_t type,
		uint32_t value)
{
	stream_putw(s, type);
	stream_putw(s, 4);
	stream_putl(s, value);
	(*cnt)++;
}

static void bmp_stat_put_u64(struct stream *s, size_t *cnt, uint16_t type,
			     uint64_t value)
{
	stream_putw(s, type);
	stream_putw(s, 8);
	stream_putq(s, value);
	(*cnt)++;
}

static void bmp_stats(struct event *thread)
{
	struct bmp_targets *bt = EVENT_ARG(thread);
	struct stream *s;
	struct peer *peer;
	struct listnode *node;
	struct timeval tv;

	if (bt->stat_msec)
		event_add_timer_msec(bm->master, bmp_stats, bt, bt->stat_msec,
				     &bt->t_stats);

	gettimeofday(&tv, NULL);

	/* Walk down all peers */
	for (ALL_LIST_ELEMENTS_RO(bt->bgp->peer, node, peer)) {
		size_t count = 0, count_pos, len;

		if (!peer_established(peer->connection))
			continue;

		s = stream_new(BGP_MAX_PACKET_SIZE);
		bmp_common_hdr(s, BMP_VERSION_3, BMP_TYPE_STATISTICS_REPORT);
		bmp_per_peer_hdr(s, bt->bgp, peer, 0,
				 BMP_PEER_TYPE_GLOBAL_INSTANCE, 0, &tv);

		count_pos = stream_get_endp(s);
		stream_putl(s, 0);

		bmp_stat_put_u32(s, &count, BMP_STATS_PFX_REJECTED,
				peer->stat_pfx_filter);
		bmp_stat_put_u32(s, &count, BMP_STATS_UPD_LOOP_ASPATH,
				peer->stat_pfx_aspath_loop);
		bmp_stat_put_u32(s, &count, BMP_STATS_UPD_LOOP_ORIGINATOR,
				peer->stat_pfx_originator_loop);
		bmp_stat_put_u32(s, &count, BMP_STATS_UPD_LOOP_CLUSTER,
				peer->stat_pfx_cluster_loop);
		bmp_stat_put_u32(s, &count, BMP_STATS_PFX_DUP_WITHDRAW,
				peer->stat_pfx_dup_withdraw);
		bmp_stat_put_u32(s, &count, BMP_STATS_UPD_7606_WITHDRAW,
				peer->stat_upd_7606);
		if (bt->stats_send_experimental)
			bmp_stat_put_u32(s, &count, BMP_STATS_FRR_NH_INVALID,
					 peer->stat_pfx_nh_invalid);
		bmp_stat_put_u64(s, &count, BMP_STATS_SIZE_ADJ_RIB_IN,
				 peer->stat_pfx_adj_rib_in);
		bmp_stat_put_u64(s, &count, BMP_STATS_SIZE_LOC_RIB,
				 peer->stat_pfx_loc_rib);

		stream_putl_at(s, count_pos, count);

		len = stream_get_endp(s);
		stream_putl_at(s, BMP_LENGTH_POS, len);

		bmp_send_all(bt->bmpbgp, s);
	}
}

/* read from the BMP socket to detect session termination */
static void bmp_read(struct event *t)
{
	struct bmp *bmp = EVENT_ARG(t);
	char buf[1024];
	ssize_t n;

	bmp->t_read = NULL;

	n = read(bmp->socket, buf, sizeof(buf));
	if (n >= 1) {
		zlog_info("bmp[%s]: unexpectedly received %zu bytes", bmp->remote, n);
	} else if (n == 0) {
		/* the TCP session was terminated by the far end */
		bmp_wrerr(bmp, NULL, true);
		return;
	} else if (!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
		/* the TCP session experienced a fatal error, likely a timeout */
		bmp_wrerr(bmp, NULL, false);
		return;
	}

	event_add_read(bm->master, bmp_read, bmp, bmp->socket, &bmp->t_read);
}

static struct bmp *bmp_open(struct bmp_targets *bt, int bmp_sock)
{
	union sockunion su, *sumem;
	struct prefix p;
	int on = 1;
	struct access_list *acl = NULL;
	enum filter_type ret;
	char buf[SU_ADDRSTRLEN];
	struct bmp *bmp;

	sumem = sockunion_getpeername(bmp_sock);
	if (!sumem) {
		close(bmp_sock);
		return NULL;
	}
	memcpy(&su, sumem, sizeof(su));
	sockunion_free(sumem);

	set_nonblocking(bmp_sock);
	set_cloexec(bmp_sock);

	if (!sockunion2hostprefix(&su, &p)) {
		close(bmp_sock);
		return NULL;
	}

	acl = NULL;
	switch (p.family) {
	case AF_INET:
		acl = access_list_lookup(AFI_IP, bt->acl_name);
		break;
	case AF_INET6:
		acl = access_list_lookup(AFI_IP6, bt->acl6_name);
		break;
	default:
		break;
	}

	ret = FILTER_PERMIT;
	if (acl) {
		ret = access_list_apply(acl, &p);
	}

	sockunion2str(&su, buf, SU_ADDRSTRLEN);
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), ":%u",
			su.sa.sa_family == AF_INET
				? ntohs(su.sin.sin_port)
				: ntohs(su.sin6.sin6_port));

	if (ret == FILTER_DENY) {
		bt->cnt_aclrefused++;
		zlog_info("bmp[%s] connection refused by access-list", buf);
		close(bmp_sock);
		return NULL;
	}
	bt->cnt_accept++;

	if (setsockopt(bmp_sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
		flog_err(EC_LIB_SOCKET, "bmp: %d can't setsockopt SO_KEEPALIVE: %s(%d)",
			 bmp_sock, safe_strerror(errno), errno);
	if (setsockopt(bmp_sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
		flog_err(EC_LIB_SOCKET, "bmp: %d can't setsockopt TCP_NODELAY: %s(%d)",
			 bmp_sock, safe_strerror(errno), errno);

	zlog_info("bmp[%s] connection established", buf);

	/* Allocate new BMP structure and set up default values. */
	bmp = bmp_new(bt, bmp_sock);
	strlcpy(bmp->remote, buf, sizeof(bmp->remote));

	bmp->state = BMP_PeerUp;
	bmp->pullwr = pullwr_new(bm->master, bmp_sock, bmp, bmp_wrfill,
			bmp_wrerr);
	event_add_read(bm->master, bmp_read, bmp, bmp_sock, &bmp->t_read);
	bmp_send_initiation(bmp);

	return bmp;
}

/* Accept BMP connection. */
static void bmp_accept(struct event *thread)
{
	union sockunion su;
	struct bmp_listener *bl = EVENT_ARG(thread);
	int bmp_sock;

	/* We continue hearing BMP socket. */
	event_add_read(bm->master, bmp_accept, bl, bl->sock, &bl->t_accept);

	memset(&su, 0, sizeof(union sockunion));

	/* We can handle IPv4 or IPv6 socket. */
	bmp_sock = sockunion_accept(bl->sock, &su);
	if (bmp_sock < 0) {
		zlog_info("bmp: accept_sock failed: %s", safe_strerror(errno));
		return;
	}
	bmp_open(bl->targets, bmp_sock);
}

static void bmp_close(struct bmp *bmp)
{
	struct bmp_queue_entry *bqe;
	struct bmp_mirrorq *bmq;

	EVENT_OFF(bmp->t_read);

	if (bmp->active)
		bmp_active_disconnected(bmp->active);

	while ((bmq = bmp_pull_mirror(bmp)))
		if (!bmq->refcount)
			XFREE(MTYPE_BMP_MIRRORQ, bmq);
	while ((bqe = bmp_pull(bmp)))
		if (!bqe->refcount)
			XFREE(MTYPE_BMP_QUEUE, bqe);
	while ((bqe = bmp_pull_locrib(bmp)))
		if (!bqe->refcount)
			XFREE(MTYPE_BMP_QUEUE, bqe);

	EVENT_OFF(bmp->t_read);
	pullwr_del(bmp->pullwr);
	close(bmp->socket);
}

static struct bmp_bgp *bmp_bgp_find(struct bgp *bgp)
{
	struct bmp_bgp dummy = { .bgp = bgp };
	return bmp_bgph_find(&bmp_bgph, &dummy);
}

static struct bmp_bgp *bmp_bgp_get(struct bgp *bgp)
{
	struct bmp_bgp *bmpbgp;

	bmpbgp = bmp_bgp_find(bgp);
	if (bmpbgp)
		return bmpbgp;

	bmpbgp = XCALLOC(MTYPE_BMP, sizeof(*bmpbgp));
	bmpbgp->bgp = bgp;
	bmpbgp->vrf_state = vrf_state_unknown;
	bmpbgp->mirror_qsizelimit = ~0UL;
	bmp_mirrorq_init(&bmpbgp->mirrorq);
	bmp_bgph_add(&bmp_bgph, bmpbgp);

	return bmpbgp;
}

static void bmp_bgp_put(struct bmp_bgp *bmpbgp)
{
	struct bmp_targets *bt;
	struct bmp_listener *bl;

	bmp_bgph_del(&bmp_bgph, bmpbgp);

	frr_each_safe (bmp_targets, &bmpbgp->targets, bt) {
		frr_each_safe (bmp_listeners, &bt->listeners, bl)
			bmp_listener_put(bl);

		bmp_targets_put(bt);
	}

	bmp_mirrorq_fini(&bmpbgp->mirrorq);
	XFREE(MTYPE_BMP, bmpbgp);
}

static int bmp_bgp_del(struct bgp *bgp)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(bgp);

	if (bmpbgp)
		bmp_bgp_put(bmpbgp);
	return 0;
}

static void bmp_bgp_peer_vrf(struct bmp_bgp_peer *bbpeer, struct bgp *bgp)
{
	struct peer *peer = bgp->peer_self;
	uint16_t send_holdtime;
	as_t local_as;

	if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER))
		send_holdtime = peer->holdtime;
	else
		send_holdtime = peer->bgp->default_holdtime;

	/* local-as Change */
	if (peer->change_local_as)
		local_as = peer->change_local_as;
	else
		local_as = peer->local_as;

	struct stream *s = bgp_open_make(peer, send_holdtime, local_as);
	size_t open_len = stream_get_endp(s);

	bbpeer->open_rx_len = open_len;
	bbpeer->open_rx = XMALLOC(MTYPE_BMP_OPEN, open_len);
	memcpy(bbpeer->open_rx, s->data, open_len);

	bbpeer->open_tx_len = open_len;
	bbpeer->open_tx = bbpeer->open_rx;

	stream_free(s);
}

/* update the vrf status of the bmpbgp struct for vrf peer up/down
 *
 * if force is unknown, use zebra vrf state
 *
 * returns true if state has changed
 */
bool bmp_bgp_update_vrf_status(struct bmp_bgp *bmpbgp, enum bmp_vrf_state force)
{
	enum bmp_vrf_state old_state;
	struct bmp_bgp_peer *bbpeer;
	struct peer *peer;
	struct vrf *vrf;
	struct bgp *bgp;
	bool changed;

	if (!bmpbgp || !bmpbgp->bgp)
		return false;

	bgp = bmpbgp->bgp;
	old_state = bmpbgp->vrf_state;

	vrf = bgp_vrf_lookup_by_instance_type(bgp);
	bmpbgp->vrf_state = force != vrf_state_unknown ? force
			    : vrf_is_enabled(vrf)      ? vrf_state_up
						       : vrf_state_down;

	changed = old_state != bmpbgp->vrf_state;
	if (changed) {
		peer = bmpbgp->bgp->peer_self;
		if (bmpbgp->vrf_state == vrf_state_up) {
			bbpeer = bmp_bgp_peer_get(peer);
			bmp_bgp_peer_vrf(bbpeer, bgp);
		} else {
			bbpeer = bmp_bgp_peer_find(peer->qobj_node.nid);
			if (bbpeer) {
				XFREE(MTYPE_BMP_OPEN, bbpeer->open_rx);
				bmp_peerh_del(&bmp_peerh, bbpeer);
				XFREE(MTYPE_BMP_PEER, bbpeer);
			}
		}
	}

	return changed;
}

static struct bmp_bgp_peer *bmp_bgp_peer_find(uint64_t peerid)
{
	struct bmp_bgp_peer dummy = { .peerid = peerid };
	return bmp_peerh_find(&bmp_peerh, &dummy);
}

static struct bmp_bgp_peer *bmp_bgp_peer_get(struct peer *peer)
{
	struct bmp_bgp_peer *bbpeer;

	bbpeer = bmp_bgp_peer_find(peer->qobj_node.nid);
	if (bbpeer)
		return bbpeer;

	bbpeer = XCALLOC(MTYPE_BMP_PEER, sizeof(*bbpeer));
	bbpeer->peerid = peer->qobj_node.nid;
	bmp_peerh_add(&bmp_peerh, bbpeer);

	return bbpeer;
}

static struct bmp_targets *bmp_targets_find1(struct bgp *bgp, const char *name)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(bgp);
	struct bmp_targets dummy;

	if (!bmpbgp)
		return NULL;
	dummy.name = (char *)name;
	return bmp_targets_find(&bmpbgp->targets, &dummy);
}

static struct bmp_targets *bmp_targets_get(struct bgp *bgp, const char *name)
{
	struct bmp_targets *bt;

	bt = bmp_targets_find1(bgp, name);
	if (bt)
		return bt;

	bt = XCALLOC(MTYPE_BMP_TARGETS, sizeof(*bt));
	bt->name = XSTRDUP(MTYPE_BMP_TARGETSNAME, name);
	bt->bgp = bgp;
	bt->bmpbgp = bmp_bgp_get(bgp);
	bt->stats_send_experimental = true;
	bmp_session_init(&bt->sessions);
	bmp_qhash_init(&bt->updhash);
	bmp_qlist_init(&bt->updlist);
	bmp_qhash_init(&bt->locupdhash);
	bmp_qlist_init(&bt->locupdlist);
	bmp_actives_init(&bt->actives);
	bmp_listeners_init(&bt->listeners);

	QOBJ_REG(bt, bmp_targets);
	bmp_targets_add(&bt->bmpbgp->targets, bt);
	return bt;
}

static void bmp_targets_put(struct bmp_targets *bt)
{
	struct bmp *bmp;
	struct bmp_active *ba;

	EVENT_OFF(bt->t_stats);

	frr_each_safe (bmp_actives, &bt->actives, ba)
		bmp_active_put(ba);

	frr_each_safe(bmp_session, &bt->sessions, bmp) {
		bmp_close(bmp);
		bmp_free(bmp);
	}

	bmp_targets_del(&bt->bmpbgp->targets, bt);
	QOBJ_UNREG(bt);

	bmp_listeners_fini(&bt->listeners);
	bmp_actives_fini(&bt->actives);
	bmp_qhash_fini(&bt->updhash);
	bmp_qlist_fini(&bt->updlist);
	bmp_qhash_fini(&bt->locupdhash);
	bmp_qlist_fini(&bt->locupdlist);

	XFREE(MTYPE_BMP_ACLNAME, bt->acl_name);
	XFREE(MTYPE_BMP_ACLNAME, bt->acl6_name);
	bmp_session_fini(&bt->sessions);

	XFREE(MTYPE_BMP_TARGETSNAME, bt->name);
	XFREE(MTYPE_BMP_TARGETS, bt);
}

static struct bmp_listener *bmp_listener_find(struct bmp_targets *bt,
					      const union sockunion *su,
					      int port)
{
	struct bmp_listener dummy;
	dummy.addr = *su;
	dummy.port = port;
	return bmp_listeners_find(&bt->listeners, &dummy);
}

static struct bmp_listener *bmp_listener_get(struct bmp_targets *bt,
					     const union sockunion *su,
					     int port)
{
	struct bmp_listener *bl = bmp_listener_find(bt, su, port);

	if (bl)
		return bl;

	bl = XCALLOC(MTYPE_BMP_LISTENER, sizeof(*bl));
	bl->targets = bt;
	bl->addr = *su;
	bl->port = port;
	bl->sock = -1;

	bmp_listeners_add(&bt->listeners, bl);
	return bl;
}

static void bmp_listener_start(struct bmp_listener *bl)
{
	int sock, ret;

	sock = socket(bl->addr.sa.sa_family, SOCK_STREAM, 0);
	if (sock < 0)
		return;

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);
	sockopt_v6only(bl->addr.sa.sa_family, sock);
	set_cloexec(sock);

	ret = sockunion_bind(sock, &bl->addr, bl->port, &bl->addr);
	if (ret < 0)
		goto out_sock;

	ret = listen(sock, 3);
	if (ret < 0)
		goto out_sock;

	bl->sock = sock;
	event_add_read(bm->master, bmp_accept, bl, sock, &bl->t_accept);
	return;
out_sock:
	close(sock);
}

static void bmp_listener_stop(struct bmp_listener *bl)
{
	EVENT_OFF(bl->t_accept);

	if (bl->sock != -1)
		close(bl->sock);
	bl->sock = -1;
}

static struct bmp_active *bmp_active_find(struct bmp_targets *bt,
					  const char *hostname, int port)
{
	struct bmp_active dummy;
	dummy.hostname = (char *)hostname;
	dummy.port = port;
	return bmp_actives_find(&bt->actives, &dummy);
}

static struct bmp_active *bmp_active_get(struct bmp_targets *bt,
					 const char *hostname, int port)
{
	struct bmp_active *ba;

	ba = bmp_active_find(bt, hostname, port);
	if (ba)
		return ba;

	ba = XCALLOC(MTYPE_BMP_ACTIVE, sizeof(*ba));
	ba->targets = bt;
	ba->hostname = XSTRDUP(MTYPE_TMP, hostname);
	ba->port = port;
	ba->minretry = BMP_DFLT_MINRETRY;
	ba->maxretry = BMP_DFLT_MAXRETRY;
	ba->socket = -1;

	bmp_actives_add(&bt->actives, ba);
	return ba;
}

static void bmp_active_put(struct bmp_active *ba)
{
	EVENT_OFF(ba->t_timer);
	EVENT_OFF(ba->t_read);
	EVENT_OFF(ba->t_write);

	bmp_actives_del(&ba->targets->actives, ba);

	if (ba->bmp) {
		ba->bmp->active = NULL;
		bmp_close(ba->bmp);
		bmp_free(ba->bmp);
	}
	if (ba->socket != -1)
		close(ba->socket);

	XFREE(MTYPE_TMP, ba->ifsrc);
	XFREE(MTYPE_TMP, ba->hostname);
	XFREE(MTYPE_BMP_ACTIVE, ba);
}

static void bmp_active_setup(struct bmp_active *ba);

static void bmp_active_connect(struct bmp_active *ba)
{
	enum connect_result res;
	struct interface *ifp;
	vrf_id_t vrf_id = VRF_DEFAULT;
	int res_bind;

	for (; ba->addrpos < ba->addrtotal; ba->addrpos++) {
		if (ba->ifsrc) {
			if (ba->targets && ba->targets->bgp)
				vrf_id = ba->targets->bgp->vrf_id;

			/* find interface and related */
			/* address with same family   */
			ifp = if_lookup_by_name(ba->ifsrc, vrf_id);
			if (!ifp) {
				zlog_warn("bmp[%s]: failed to find interface",
					  ba->ifsrc);
				continue;
			}

			if (bgp_update_address(ifp, &ba->addrs[ba->addrpos],
					       &ba->addrsrc)){
				zlog_warn("bmp[%s]: failed to find matching address",
					  ba->ifsrc);
				continue;
			}
			zlog_info("bmp[%s]: selected source address : %pSU",
				  ba->ifsrc, &ba->addrsrc);
		}

		ba->socket = sockunion_socket(&ba->addrs[ba->addrpos]);
		if (ba->socket < 0) {
			zlog_warn("bmp[%s]: failed to create socket",
				  ba->hostname);
			continue;
		}

		set_nonblocking(ba->socket);

		if (!sockunion_is_null(&ba->addrsrc)) {
			res_bind = sockunion_bind(ba->socket, &ba->addrsrc, 0,
						  &ba->addrsrc);
			if (res_bind < 0) {
				zlog_warn(
					"bmp[%s]: no bind currently to source address %pSU:%d",
					ba->hostname, &ba->addrsrc, ba->port);
				close(ba->socket);
				ba->socket = -1;
				sockunion_init(&ba->addrsrc);
				continue;
			}
		}


		res = sockunion_connect(ba->socket, &ba->addrs[ba->addrpos],
				      htons(ba->port), 0);
		switch (res) {
		case connect_error:
			zlog_warn("bmp[%s]: failed to connect to %pSU:%d",
				  ba->hostname, &ba->addrs[ba->addrpos],
				  ba->port);
			close(ba->socket);
			ba->socket = -1;
			sockunion_init(&ba->addrsrc);
			continue;
		case connect_success:
			zlog_info("bmp[%s]: connected to  %pSU:%d",
				  ba->hostname, &ba->addrs[ba->addrpos],
				  ba->port);
			break;
		case connect_in_progress:
			zlog_warn("bmp[%s]: connect in progress  %pSU:%d",
				  ba->hostname, &ba->addrs[ba->addrpos],
				  ba->port);
			bmp_active_setup(ba);
			return;
		}
	}

	/* exhausted all addresses */
	ba->curretry += ba->curretry / 2;
	bmp_active_setup(ba);
}

static void bmp_active_resolved(struct resolver_query *resq, const char *errstr,
				int numaddrs, union sockunion *addr)
{
	struct bmp_active *ba = container_of(resq, struct bmp_active, resq);
	unsigned i;

	if (numaddrs <= 0) {
		zlog_warn("bmp[%s]: hostname resolution failed: %s",
			  ba->hostname, errstr);
		ba->last_err = errstr;
		ba->curretry += ba->curretry / 2;
		ba->addrpos = 0;
		ba->addrtotal = 0;
		bmp_active_setup(ba);
		return;
	}

	if (numaddrs > (int)array_size(ba->addrs))
		numaddrs = array_size(ba->addrs);

	ba->addrpos = 0;
	ba->addrtotal = numaddrs;
	for (i = 0; i < ba->addrtotal; i++)
		memcpy(&ba->addrs[i], &addr[i], sizeof(ba->addrs[0]));

	bmp_active_connect(ba);
}

static void bmp_active_thread(struct event *t)
{
	struct bmp_active *ba = EVENT_ARG(t);
	socklen_t slen;
	int status, ret;
	vrf_id_t vrf_id;

	/* all 3 end up here, though only timer or read+write are active
	 * at a time */
	EVENT_OFF(ba->t_timer);
	EVENT_OFF(ba->t_read);
	EVENT_OFF(ba->t_write);

	ba->last_err = NULL;

	if (ba->socket == -1) {
		/* get vrf_id */
		if (!ba->targets || !ba->targets->bgp)
			vrf_id = VRF_DEFAULT;
		else
			vrf_id = ba->targets->bgp->vrf_id;
		resolver_resolve(&ba->resq, AF_UNSPEC, vrf_id, ba->hostname,
				 bmp_active_resolved);
		return;
	}

	slen = sizeof(status);
	ret = getsockopt(ba->socket, SOL_SOCKET, SO_ERROR, (void *)&status,
			 &slen);

	if (ret < 0 || status != 0) {
		ba->last_err = strerror(status);
		zlog_warn("bmp[%s]: failed to connect to %pSU:%d: %s",
			  ba->hostname, &ba->addrs[ba->addrpos], ba->port,
			  ba->last_err);
		goto out_next;
	}

	zlog_warn("bmp[%s]: outbound connection to %pSU:%d", ba->hostname,
		  &ba->addrs[ba->addrpos], ba->port);

	ba->bmp = bmp_open(ba->targets, ba->socket);
	if (!ba->bmp)
		goto out_next;

	ba->bmp->active = ba;
	ba->socket = -1;
	ba->curretry = ba->minretry;
	return;

out_next:
	close(ba->socket);
	ba->socket = -1;
	ba->addrpos++;
	bmp_active_connect(ba);
}

static void bmp_active_disconnected(struct bmp_active *ba)
{
	ba->bmp = NULL;
	bmp_active_setup(ba);
}

static void bmp_active_setup(struct bmp_active *ba)
{
	EVENT_OFF(ba->t_timer);
	EVENT_OFF(ba->t_read);
	EVENT_OFF(ba->t_write);

	if (ba->bmp)
		return;
	if (ba->resq.callback)
		return;

	if (ba->curretry > ba->maxretry)
		ba->curretry = ba->maxretry;

	if (ba->socket == -1)
		event_add_timer_msec(bm->master, bmp_active_thread, ba,
				     ba->curretry, &ba->t_timer);
	else {
		event_add_read(bm->master, bmp_active_thread, ba, ba->socket,
			       &ba->t_read);
		event_add_write(bm->master, bmp_active_thread, ba, ba->socket,
				&ba->t_write);
	}
}

static struct cmd_node bmp_node = {
	.name = "bmp",
	.node = BMP_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-bgp-bmp)# "
};

static void bmp_targets_autocomplete(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct bmp_targets *target;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		struct bmp_bgp *bmpbgp = bmp_bgp_find(bgp);

		if (!bmpbgp)
			continue;

		frr_each_safe (bmp_targets, &bmpbgp->targets, target)
			vector_set(comps,
				   XSTRDUP(MTYPE_COMPLETION, target->name));
	}
}

static const struct cmd_variable_handler bmp_targets_var_handlers[] = {
	{.tokenname = "BMPTARGETS", .completions = bmp_targets_autocomplete},
	{.completions = NULL}};

#define BMP_STR "BGP Monitoring Protocol\n"

#include "bgpd/bgp_bmp_clippy.c"

DEFPY_NOSH(bmp_targets_main,
      bmp_targets_cmd,
      "bmp targets BMPTARGETS",
      BMP_STR
      "Create BMP target group\n"
      "Name of the BMP target group\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bmp_targets *bt;

	bt = bmp_targets_get(bgp, bmptargets);

	VTY_PUSH_CONTEXT_SUB(BMP_NODE, bt);
	return CMD_SUCCESS;
}

DEFPY(no_bmp_targets_main,
      no_bmp_targets_cmd,
      "no bmp targets BMPTARGETS",
      NO_STR
      BMP_STR
      "Delete BMP target group\n"
      "Name of the BMP target group\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bmp_targets *bt;

	bt = bmp_targets_find1(bgp, bmptargets);
	if (!bt) {
		vty_out(vty, "%% BMP target group not found\n");
		return CMD_WARNING;
	}
	bmp_targets_put(bt);
	return CMD_SUCCESS;
}

DEFPY(bmp_listener_main,
      bmp_listener_cmd,
      "bmp listener <X:X::X:X|A.B.C.D> port (1-65535)",
      BMP_STR
      "Listen for inbound BMP connections\n"
      "IPv6 address to listen on\n"
      "IPv4 address to listen on\n"
      "TCP Port number\n"
      "TCP Port number\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);
	struct bmp_listener *bl;

	bl = bmp_listener_get(bt, listener, port);
	if (bl->sock == -1)
		bmp_listener_start(bl);

	return CMD_SUCCESS;
}

DEFPY(no_bmp_listener_main,
      no_bmp_listener_cmd,
      "no bmp listener <X:X::X:X|A.B.C.D> port (1-65535)",
      NO_STR
      BMP_STR
      "Create BMP listener\n"
      "IPv6 address to listen on\n"
      "IPv4 address to listen on\n"
      "TCP Port number\n"
      "TCP Port number\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);
	struct bmp_listener *bl;

	bl = bmp_listener_find(bt, listener, port);
	if (!bl) {
		vty_out(vty, "%% BMP listener not found\n");
		return CMD_WARNING;
	}
	bmp_listener_stop(bl);
	bmp_listener_put(bl);
	return CMD_SUCCESS;
}

DEFPY(bmp_connect,
      bmp_connect_cmd,
      "[no] bmp connect HOSTNAME port (1-65535) {min-retry (100-86400000)|max-retry (100-86400000)} [source-interface <WORD$srcif>]",
      NO_STR
      BMP_STR
      "Actively establish connection to monitoring station\n"
      "Monitoring station hostname or address\n"
      "TCP port\n"
      "TCP port\n"
      "Minimum connection retry interval\n"
      "Minimum connection retry interval (milliseconds)\n"
      "Maximum connection retry interval\n"
      "Maximum connection retry interval (milliseconds)\n"
      "Source interface to use\n"
      "Define an interface\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);
	struct bmp_active *ba;

	if (no) {
		ba = bmp_active_find(bt, hostname, port);
		if (!ba) {
			vty_out(vty, "%% No such active connection found\n");
			return CMD_WARNING;
		}
		/* connection deletion need same hostname port and interface */
		if (ba->ifsrc || srcif)
			if ((!ba->ifsrc) || (!srcif) ||
			    !strcmp(ba->ifsrc, srcif)) {
				vty_out(vty,
					"%% No such active connection found\n");
				return CMD_WARNING;
			}
		bmp_active_put(ba);
		return CMD_SUCCESS;
	}

	ba = bmp_active_get(bt, hostname, port);
	if (srcif)
		ba->ifsrc = XSTRDUP(MTYPE_TMP, srcif);
	if (min_retry_str)
		ba->minretry = min_retry;
	if (max_retry_str)
		ba->maxretry = max_retry;
	ba->curretry = ba->minretry;
	bmp_active_setup(ba);

	return CMD_SUCCESS;
}

DEFPY(bmp_acl,
      bmp_acl_cmd,
      "[no] <ip|ipv6>$af access-list ACCESSLIST_NAME$access_list",
      NO_STR
      IP_STR
      IPV6_STR
      "Access list to restrict BMP sessions\n"
      "Access list name\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);
	char **what;

	if (no)
		access_list = NULL;
	if (!strcmp(af, "ipv6"))
		what = &bt->acl6_name;
	else
		what = &bt->acl_name;

	XFREE(MTYPE_BMP_ACLNAME, *what);
	if (access_list)
		*what = XSTRDUP(MTYPE_BMP_ACLNAME, access_list);

	return CMD_SUCCESS;
}

DEFPY(bmp_stats_cfg,
      bmp_stats_cmd,
      "[no] bmp stats [interval (100-86400000)]",
      NO_STR
      BMP_STR
      "Send BMP statistics messages\n"
      "Specify BMP stats interval\n"
      "Interval (milliseconds) to send BMP Stats in\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);

	EVENT_OFF(bt->t_stats);
	if (no)
		bt->stat_msec = 0;
	else if (interval_str)
		bt->stat_msec = interval;
	else
		bt->stat_msec = BMP_STAT_DEFAULT_TIMER;

	if (bt->stat_msec)
		event_add_timer_msec(bm->master, bmp_stats, bt, bt->stat_msec,
				     &bt->t_stats);
	return CMD_SUCCESS;
}

DEFPY(bmp_stats_send_experimental,
      bmp_stats_send_experimental_cmd,
      "[no] bmp stats send-experimental",
      NO_STR
      BMP_STR
      "Send BMP statistics messages\n"
      "Send experimental BMP stats [65531-65534]\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);

	bt->stats_send_experimental = !no;

	return CMD_SUCCESS;
}

#define BMP_POLICY_IS_LOCRIB(str) ((str)[0] == 'l') /* __l__oc-rib */
#define BMP_POLICY_IS_PRE(str) ((str)[1] == 'r')    /* p__r__e-policy */

DEFPY(bmp_monitor_cfg, bmp_monitor_cmd,
      "[no] bmp monitor <ipv4|ipv6|l2vpn> <unicast|multicast|evpn|vpn> <pre-policy|post-policy|loc-rib>$policy",
      NO_STR BMP_STR
      "Send BMP route monitoring messages\n" BGP_AF_STR BGP_AF_STR BGP_AF_STR
	      BGP_AF_STR BGP_AF_STR BGP_AF_STR BGP_AF_STR
      "Send state before policy and filter processing\n"
      "Send state with policy and filters applied\n"
      "Send state after decision process is applied\n")
{
	int index = 0;
	uint8_t flag, prev;
	afi_t afi;
	safi_t safi;

	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);
	struct bmp *bmp;

	argv_find_and_parse_afi(argv, argc, &index, &afi);
	argv_find_and_parse_safi(argv, argc, &index, &safi);

	if (BMP_POLICY_IS_LOCRIB(policy))
		flag = BMP_MON_LOC_RIB;
	else if (BMP_POLICY_IS_PRE(policy))
		flag = BMP_MON_PREPOLICY;
	else
		flag = BMP_MON_POSTPOLICY;

	prev = bt->afimon[afi][safi];
	if (no)
		UNSET_FLAG(bt->afimon[afi][safi], flag);
	else
		SET_FLAG(bt->afimon[afi][safi], flag);

	if (prev == bt->afimon[afi][safi])
		return CMD_SUCCESS;

	frr_each (bmp_session, &bt->sessions, bmp) {
		if (bmp->syncafi == afi && bmp->syncsafi == safi) {
			bmp->syncafi = AFI_MAX;
			bmp->syncsafi = SAFI_MAX;
		}

		if (!bt->afimon[afi][safi]) {
			bmp->afistate[afi][safi] = BMP_AFI_INACTIVE;
			continue;
		}

		bmp->afistate[afi][safi] = BMP_AFI_NEEDSYNC;
	}

	return CMD_SUCCESS;
}

DEFPY(bmp_mirror_cfg,
      bmp_mirror_cmd,
      "[no] bmp mirror",
      NO_STR
      BMP_STR
      "Send BMP route mirroring messages\n")
{
	VTY_DECLVAR_CONTEXT_SUB(bmp_targets, bt);
	struct bmp *bmp;

	if (bt->mirror == !no)
		return CMD_SUCCESS;

	bt->mirror = !no;
	if (bt->mirror)
		return CMD_SUCCESS;

	frr_each (bmp_session, &bt->sessions, bmp) {
		struct bmp_mirrorq *bmq;

		while ((bmq = bmp_pull_mirror(bmp)))
			if (!bmq->refcount)
				XFREE(MTYPE_BMP_MIRRORQ, bmq);
	}
	return CMD_SUCCESS;
}

DEFPY(bmp_mirror_limit_cfg,
      bmp_mirror_limit_cmd,
      "bmp mirror buffer-limit (0-4294967294)",
      BMP_STR
      "Route Mirroring settings\n"
      "Configure maximum memory used for buffered mirroring messages\n"
      "Limit in bytes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bmp_bgp *bmpbgp;

	bmpbgp = bmp_bgp_get(bgp);
	bmpbgp->mirror_qsizelimit = buffer_limit;

	return CMD_SUCCESS;
}

DEFPY(no_bmp_mirror_limit_cfg,
      no_bmp_mirror_limit_cmd,
      "no bmp mirror buffer-limit [(0-4294967294)]",
      NO_STR
      BMP_STR
      "Route Mirroring settings\n"
      "Configure maximum memory used for buffered mirroring messages\n"
      "Limit in bytes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bmp_bgp *bmpbgp;

	bmpbgp = bmp_bgp_get(bgp);
	bmpbgp->mirror_qsizelimit = ~0UL;

	return CMD_SUCCESS;
}


DEFPY(show_bmp,
      show_bmp_cmd,
      "show bmp",
      SHOW_STR
      BMP_STR)
{
	struct bmp_bgp *bmpbgp;
	struct bmp_targets *bt;
	struct bmp_listener *bl;
	struct bmp_active *ba;
	struct bmp *bmp;
	struct ttable *tt;
	char uptime[BGP_UPTIME_LEN];
	char *out;

	frr_each(bmp_bgph, &bmp_bgph, bmpbgp) {
		vty_out(vty, "BMP state for BGP %s:\n\n",
				bmpbgp->bgp->name_pretty);
		vty_out(vty, "  Route Mirroring %9zu bytes (%zu messages) pending\n",
				bmpbgp->mirror_qsize,
				bmp_mirrorq_count(&bmpbgp->mirrorq));
		vty_out(vty, "                  %9zu bytes maximum buffer used\n",
				bmpbgp->mirror_qsizemax);
		if (bmpbgp->mirror_qsizelimit != ~0UL)
			vty_out(vty, "                  %9zu bytes buffer size limit\n",
					bmpbgp->mirror_qsizelimit);
		vty_out(vty, "\n");

		frr_each(bmp_targets, &bmpbgp->targets, bt) {
			vty_out(vty, "  Targets \"%s\":\n", bt->name);
			vty_out(vty, "    Route Mirroring %sabled\n",
				bt->mirror ? "en" : "dis");

			afi_t afi;
			safi_t safi;

			FOREACH_AFI_SAFI (afi, safi) {

				uint8_t afimon_flag = bt->afimon[afi][safi];

				if (!afimon_flag)
					continue;

				const char *pre_str =
					CHECK_FLAG(afimon_flag,
						   BMP_MON_PREPOLICY)
						? "pre-policy "
						: "";
				const char *post_str =
					CHECK_FLAG(afimon_flag,
						   BMP_MON_POSTPOLICY)
						? "post-policy "
						: "";
				const char *locrib_str =
					CHECK_FLAG(afimon_flag, BMP_MON_LOC_RIB)
						? "loc-rib"
						: "";

				vty_out(vty,
					"    Route Monitoring %s %s %s%s%s\n",
					afi2str(afi), safi2str(safi), pre_str,
					post_str, locrib_str);
			}

			vty_out(vty, "    Listeners:\n");
			frr_each (bmp_listeners, &bt->listeners, bl)
				vty_out(vty, "      %pSU:%d\n", &bl->addr,
					bl->port);

			vty_out(vty, "\n    Outbound connections:\n");
			tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
			ttable_add_row(tt, "remote|state||timer|local");
			ttable_rowseps(tt, 0, BOTTOM, true, '-');
			frr_each (bmp_actives, &bt->actives, ba) {
				const char *state_str = "?";

				if (ba->bmp) {
					peer_uptime(ba->bmp->t_up.tv_sec,
						    uptime, sizeof(uptime),
						    false, NULL);
					ttable_add_row(tt,
						       "%s:%d|Up|%s|%s|%pSU",
						       ba->hostname, ba->port,
						       ba->bmp->remote, uptime,
						       &ba->addrsrc);
					continue;
				}

				uptime[0] = '\0';

				if (ba->t_timer) {
					long trem = event_timer_remain_second(
						ba->t_timer);

					peer_uptime(monotime(NULL) - trem,
						    uptime, sizeof(uptime),
						    false, NULL);
					state_str = "RetryWait";
				} else if (ba->t_read) {
					state_str = "Connecting";
				} else if (ba->resq.callback) {
					state_str = "Resolving";
				}

				ttable_add_row(tt, "%s:%d|%s|%s|%s|%pSU",
					       ba->hostname, ba->port,
					       state_str,
					       ba->last_err ? ba->last_err : "",
					       uptime, &ba->addrsrc);
				continue;
			}
			out = ttable_dump(tt, "\n");
			vty_out(vty, "%s", out);
			XFREE(MTYPE_TMP_TTABLE, out);
			ttable_del(tt);

			vty_out(vty, "\n    %zu connected clients:\n",
					bmp_session_count(&bt->sessions));
			tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
			ttable_add_row(tt, "remote|uptime|MonSent|MirrSent|MirrLost|ByteSent|ByteQ|ByteQKernel");
			ttable_rowseps(tt, 0, BOTTOM, true, '-');

			frr_each (bmp_session, &bt->sessions, bmp) {
				uint64_t total;
				size_t q, kq;

				pullwr_stats(bmp->pullwr, &total, &q, &kq);

				peer_uptime(bmp->t_up.tv_sec, uptime,
					    sizeof(uptime), false, NULL);

				ttable_add_row(tt, "%s|%s|%Lu|%Lu|%Lu|%Lu|%zu|%zu",
					       bmp->remote, uptime,
					       bmp->cnt_update,
					       bmp->cnt_mirror,
					       bmp->cnt_mirror_overruns,
					       total, q, kq);
			}
			out = ttable_dump(tt, "\n");
			vty_out(vty, "%s", out);
			XFREE(MTYPE_TMP_TTABLE, out);
			ttable_del(tt);
			vty_out(vty, "\n");
		}
	}

	return CMD_SUCCESS;
}

static int bmp_config_write(struct bgp *bgp, struct vty *vty)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(bgp);
	struct bmp_targets *bt;
	struct bmp_listener *bl;
	struct bmp_active *ba;
	afi_t afi;
	safi_t safi;

	if (!bmpbgp)
		return 0;

	if (bmpbgp->mirror_qsizelimit != ~0UL)
		vty_out(vty, " !\n bmp mirror buffer-limit %zu\n",
			bmpbgp->mirror_qsizelimit);

	frr_each(bmp_targets, &bmpbgp->targets, bt) {
		vty_out(vty, " !\n bmp targets %s\n", bt->name);

		if (bt->acl6_name)
			vty_out(vty, "  ipv6 access-list %s\n", bt->acl6_name);
		if (bt->acl_name)
			vty_out(vty, "  ip access-list %s\n", bt->acl_name);

		if (!bt->stats_send_experimental)
			vty_out(vty, "  no bmp stats send-experimental\n");

		if (bt->stat_msec)
			vty_out(vty, "  bmp stats interval %d\n",
					bt->stat_msec);

		if (bt->mirror)
			vty_out(vty, "  bmp mirror\n");

		FOREACH_AFI_SAFI (afi, safi) {
			if (CHECK_FLAG(bt->afimon[afi][safi],
				       BMP_MON_PREPOLICY))
				vty_out(vty, "  bmp monitor %s %s pre-policy\n",
					afi2str_lower(afi), safi2str(safi));
			if (CHECK_FLAG(bt->afimon[afi][safi],
				       BMP_MON_POSTPOLICY))
				vty_out(vty,
					"  bmp monitor %s %s post-policy\n",
					afi2str_lower(afi), safi2str(safi));
			if (CHECK_FLAG(bt->afimon[afi][safi], BMP_MON_LOC_RIB))
				vty_out(vty, "  bmp monitor %s %s loc-rib\n",
					afi2str_lower(afi), safi2str(safi));
		}
		frr_each (bmp_listeners, &bt->listeners, bl)
			vty_out(vty, "   bmp listener %pSU port %d\n", &bl->addr, bl->port);

		frr_each (bmp_actives, &bt->actives, ba) {
			vty_out(vty, "  bmp connect %s port %u min-retry %u max-retry %u",
				ba->hostname, ba->port,
				ba->minretry, ba->maxretry);

			if (ba->ifsrc)
				vty_out(vty, " source-interface %s\n", ba->ifsrc);
			else
				vty_out(vty, "\n");
		}
		vty_out(vty, " exit\n");
	}

	return 0;
}

static int bgp_bmp_init(struct event_loop *tm)
{
	install_node(&bmp_node);
	install_default(BMP_NODE);

	cmd_variable_handler_register(bmp_targets_var_handlers);

	install_element(BGP_NODE, &bmp_targets_cmd);
	install_element(BGP_NODE, &no_bmp_targets_cmd);

	install_element(BMP_NODE, &bmp_listener_cmd);
	install_element(BMP_NODE, &no_bmp_listener_cmd);
	install_element(BMP_NODE, &bmp_connect_cmd);
	install_element(BMP_NODE, &bmp_acl_cmd);
	install_element(BMP_NODE, &bmp_stats_send_experimental_cmd);
	install_element(BMP_NODE, &bmp_stats_cmd);
	install_element(BMP_NODE, &bmp_monitor_cmd);
	install_element(BMP_NODE, &bmp_mirror_cmd);

	install_element(BGP_NODE, &bmp_mirror_limit_cmd);
	install_element(BGP_NODE, &no_bmp_mirror_limit_cmd);

	install_element(VIEW_NODE, &show_bmp_cmd);

	resolver_init(tm);
	return 0;
}

static int bmp_route_update(struct bgp *bgp, afi_t afi, safi_t safi,
			    struct bgp_dest *bn,
			    struct bgp_path_info *old_route,
			    struct bgp_path_info *new_route)
{
	bool is_locribmon_enabled = false;
	bool is_withdraw = old_route && !new_route;
	struct bgp_path_info *updated_route =
		is_withdraw ? old_route : new_route;


	/* this should never happen */
	if (!updated_route) {
		zlog_warn("%s: no updated route found!", __func__);
		return 0;
	}

	struct bmp_bgp *bmpbgp = bmp_bgp_get(bgp);
	struct peer *peer = updated_route->peer;
	struct bmp_targets *bt;
	struct bmp *bmp;

	frr_each (bmp_targets, &bmpbgp->targets, bt) {
		if (CHECK_FLAG(bt->afimon[afi][safi], BMP_MON_LOC_RIB)) {
			is_locribmon_enabled = true;
			break;
		}
	}

	if (!is_locribmon_enabled)
		return 0;

	/* route is not installed in locrib anymore and rib uptime was saved */
	if (old_route && old_route->extra)
		bgp_path_info_extra_get(old_route)->bgp_rib_uptime =
			(time_t)(-1L);

	/* route is installed in locrib from now on so
	 * save rib uptime in bgp_path_info_extra
	 */
	if (new_route)
		bgp_path_info_extra_get(new_route)->bgp_rib_uptime =
			monotime(NULL);

	frr_each (bmp_targets, &bmpbgp->targets, bt) {
		if (CHECK_FLAG(bt->afimon[afi][safi], BMP_MON_LOC_RIB)) {

			struct bmp_queue_entry *last_item = bmp_process_one(
				bt, &bt->locupdhash, &bt->locupdlist, bgp, afi,
				safi, bn, peer);

			/* if bmp_process_one returns NULL
			 * we don't have anything to do next
			 */
			if (!last_item)
				continue;

			frr_each (bmp_session, &bt->sessions, bmp) {
				if (!bmp->locrib_queuepos)
					bmp->locrib_queuepos = last_item;

				pullwr_bump(bmp->pullwr);
			};
		}
	};

	return 0;
}

static int bgp_bmp_early_fini(void)
{
	resolver_terminate();

	return 0;
}

/* called when a bgp instance goes up/down, implying that the underlying VRF
 * has been created or deleted in zebra
 */
static int bmp_vrf_state_changed(struct bgp *bgp)
{
	struct bmp_bgp *bmpbgp = bmp_bgp_find(bgp);

	if (!bmp_bgp_update_vrf_status(bmpbgp, vrf_state_unknown))
		return 1;

	bmp_send_all_safe(bmpbgp,
			  bmp_peerstate(bgp->peer_self, bmpbgp->vrf_state == vrf_state_down));

	return 0;
}

/* called when an interface goes up/down in a vrf, this may signal that the
 * VRF changed state and is how bgp_snmp detects vrf state changes
 */
static int bmp_vrf_itf_state_changed(struct bgp *bgp, struct interface *itf)
{
	struct bmp_bgp *bmpbgp;
	enum bmp_vrf_state new_state;

	/* if the update is not about the vrf device double-check
	 * the zebra status of the vrf
	 */
	if (!itf || !if_is_vrf(itf))
		return bmp_vrf_state_changed(bgp);

	bmpbgp = bmp_bgp_find(bgp);
	new_state = if_is_up(itf) ? vrf_state_up : vrf_state_down;
	if (bmp_bgp_update_vrf_status(bmpbgp, new_state))
		bmp_send_all(bmpbgp, bmp_peerstate(bgp->peer_self, new_state == vrf_state_down));

	return 0;
}

static int bgp_bmp_module_init(void)
{
	hook_register(bgp_packet_dump, bmp_mirror_packet);
	hook_register(bgp_packet_send, bmp_outgoing_packet);
	hook_register(peer_status_changed, bmp_peer_status_changed);
	hook_register(peer_backward_transition, bmp_peer_backward);
	hook_register(bgp_process, bmp_process);
	hook_register(bgp_inst_config_write, bmp_config_write);
	hook_register(bgp_inst_delete, bmp_bgp_del);
	hook_register(frr_late_init, bgp_bmp_init);
	hook_register(bgp_route_update, bmp_route_update);
	hook_register(frr_early_fini, bgp_bmp_early_fini);
	hook_register(bgp_instance_state, bmp_vrf_state_changed);
	hook_register(bgp_vrf_status_changed, bmp_vrf_itf_state_changed);
	return 0;
}

FRR_MODULE_SETUP(.name = "bgpd_bmp", .version = FRR_VERSION,
		 .description = "bgpd BMP module",
		 .init = bgp_bmp_module_init,
);
