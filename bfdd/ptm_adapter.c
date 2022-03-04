// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD PTM adapter code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 */

#include <zebra.h>

#include "lib/libfrr.h"
#include "lib/queue.h"
#include "lib/stream.h"
#include "lib/zclient.h"
#include "lib/printfrr.h"

#include "lib/bfd.h"

#include "bfd.h"

/*
 * Data structures
 */
struct ptm_client_notification {
	struct bfd_session *pcn_bs;
	struct ptm_client *pcn_pc;

	TAILQ_ENTRY(ptm_client_notification) pcn_entry;
};
TAILQ_HEAD(pcnqueue, ptm_client_notification);

struct ptm_client {
	uint32_t pc_pid;
	struct pcnqueue pc_pcnqueue;

	TAILQ_ENTRY(ptm_client) pc_entry;
};
TAILQ_HEAD(pcqueue, ptm_client);

static struct pcqueue pcqueue;
static struct zclient *zclient;


/*
 * Prototypes
 */
static int _ptm_msg_address(struct stream *msg, int family, const void *addr);

static void _ptm_msg_read_address(struct stream *msg, struct sockaddr_any *sa);
static int _ptm_msg_read(struct stream *msg, int command, vrf_id_t vrf_id,
			 struct bfd_peer_cfg *bpc, struct ptm_client **pc);

static struct ptm_client *pc_lookup(uint32_t pid);
static struct ptm_client *pc_new(uint32_t pid);
static void pc_free(struct ptm_client *pc);
static void pc_free_all(void);
static struct ptm_client_notification *pcn_new(struct ptm_client *pc,
					       struct bfd_session *bs);
static struct ptm_client_notification *pcn_lookup(struct ptm_client *pc,
						  struct bfd_session *bs);
static void pcn_free(struct ptm_client_notification *pcn);


static void bfdd_dest_register(struct stream *msg, vrf_id_t vrf_id);
static void bfdd_dest_deregister(struct stream *msg, vrf_id_t vrf_id);
static void bfdd_client_register(struct stream *msg);
static void bfdd_client_deregister(struct stream *msg);

/*
 * Functions
 */
PRINTFRR(2, 3)
static void debug_printbpc(const struct bfd_peer_cfg *bpc, const char *fmt, ...)
{
	char timers[3][128] = {};
	char minttl_str[32] = {};
	char addr[3][128] = {};
	char profile[128] = {};
	char cbit_str[32];
	char msgbuf[512];
	va_list vl;

	/* Avoid debug calculations if it's disabled. */
	if (bglobal.debug_zebra == false)
		return;

	snprintf(addr[0], sizeof(addr[0]), "peer:%s", satostr(&bpc->bpc_peer));
	if (bpc->bpc_local.sa_sin.sin_family)
		snprintf(addr[1], sizeof(addr[1]), " local:%s",
			 satostr(&bpc->bpc_local));

	if (bpc->bpc_has_localif)
		snprintf(addr[2], sizeof(addr[2]), " ifname:%s",
			 bpc->bpc_localif);

	if (bpc->bpc_has_vrfname)
		snprintf(addr[2], sizeof(addr[2]), " vrf:%s", bpc->bpc_vrfname);

	if (bpc->bpc_has_recvinterval)
		snprintfrr(timers[0], sizeof(timers[0]), " rx:%" PRIu64,
			   bpc->bpc_recvinterval);

	if (bpc->bpc_has_txinterval)
		snprintfrr(timers[1], sizeof(timers[1]), " tx:%" PRIu64,
			   bpc->bpc_recvinterval);

	if (bpc->bpc_has_detectmultiplier)
		snprintf(timers[2], sizeof(timers[2]), " detect-multiplier:%d",
			 bpc->bpc_detectmultiplier);

	snprintf(cbit_str, sizeof(cbit_str), " cbit:0x%02x", bpc->bpc_cbit);

	if (bpc->bpc_has_minimum_ttl)
		snprintf(minttl_str, sizeof(minttl_str), " minimum-ttl:%d",
			 bpc->bpc_minimum_ttl);

	if (bpc->bpc_has_profile)
		snprintf(profile, sizeof(profile), " profile:%s",
			 bpc->bpc_profile);

	va_start(vl, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, vl);
	va_end(vl);

	zlog_debug("%s [mhop:%s %s%s%s%s%s%s%s%s%s]", msgbuf,
		   bpc->bpc_mhop ? "yes" : "no", addr[0], addr[1], addr[2],
		   timers[0], timers[1], timers[2], cbit_str, minttl_str,
		   profile);
}

static void _ptm_bfd_session_del(struct bfd_session *bs, uint8_t diag)
{
	if (bglobal.debug_peer_event)
		zlog_debug("session-delete: %s", bs_to_string(bs));

	/* Change state and notify peer. */
	bs->ses_state = PTM_BFD_DOWN;
	bs->local_diag = diag;
	ptm_bfd_snd(bs, 0);

	/* Session reached refcount == 0, lets delete it. */
	if (bs->refcount == 0) {
		/*
		 * Sanity check: if there is a refcount bug, we can't delete
		 * the session a user configured manually. Lets leave a
		 * message here so we can catch the bug if it exists.
		 */
		if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG)) {
			zlog_err(
				"ptm-del-session: [%s] session refcount is zero but it was configured by CLI",
				bs_to_string(bs));
		} else {
			control_notify_config(BCM_NOTIFY_CONFIG_DELETE, bs);
			bfd_session_free(bs);
		}
	}
}

static int _ptm_msg_address(struct stream *msg, int family, const void *addr)
{
	stream_putc(msg, family);

	switch (family) {
	case AF_INET:
		stream_put(msg, addr, sizeof(struct in_addr));
		stream_putc(msg, 32);
		break;

	case AF_INET6:
		stream_put(msg, addr, sizeof(struct in6_addr));
		stream_putc(msg, 128);
		break;

	default:
		assert(0);
		break;
	}

	return 0;
}

int ptm_bfd_notify(struct bfd_session *bs, uint8_t notify_state)
{
	struct stream *msg;

	bs->stats.znotification++;

	/*
	 * Message format:
	 * - header: command, vrf
	 * - l: interface index
	 * - c: family
	 *   - AF_INET:
	 *     - 4 bytes: ipv4
	 *   - AF_INET6:
	 *     - 16 bytes: ipv6
	 *   - c: prefix length
	 * - l: bfd status
	 * - c: family
	 *   - AF_INET:
	 *     - 4 bytes: ipv4
	 *   - AF_INET6:
	 *     - 16 bytes: ipv6
	 *   - c: prefix length
	 * - c: cbit
	 *
	 * Commands: ZEBRA_BFD_DEST_REPLAY
	 *
	 * q(64), l(32), w(16), c(8)
	 */
	msg = zclient->obuf;
	stream_reset(msg);

	/* TODO: VRF handling */
	if (bs->vrf)
		zclient_create_header(msg, ZEBRA_BFD_DEST_REPLAY, bs->vrf->vrf_id);
	else
		zclient_create_header(msg, ZEBRA_BFD_DEST_REPLAY, VRF_DEFAULT);

	/* This header will be handled by `zebra_ptm.c`. */
	stream_putl(msg, ZEBRA_INTERFACE_BFD_DEST_UPDATE);

	/* NOTE: Interface is a shortcut to avoid comparing source address. */
	if (!CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH) && bs->ifp != NULL)
		stream_putl(msg, bs->ifp->ifindex);
	else
		stream_putl(msg, IFINDEX_INTERNAL);

	/* BFD destination prefix information. */
	_ptm_msg_address(msg, bs->key.family, &bs->key.peer);

	/* BFD status */
	switch (notify_state) {
	case PTM_BFD_UP:
		stream_putl(msg, BFD_STATUS_UP);
		break;

	case PTM_BFD_ADM_DOWN:
		stream_putl(msg, BFD_STATUS_ADMIN_DOWN);
		break;

	case PTM_BFD_DOWN:
	case PTM_BFD_INIT:
		stream_putl(msg, BFD_STATUS_DOWN);
		break;

	default:
		stream_putl(msg, BFD_STATUS_UNKNOWN);
		break;
	}

	/* BFD source prefix information. */
	_ptm_msg_address(msg, bs->key.family, &bs->key.local);

	stream_putc(msg, bs->remote_cbit);

	/* Write packet size. */
	stream_putw_at(msg, 0, stream_get_endp(msg));

	return zclient_send_message(zclient);
}

static void _ptm_msg_read_address(struct stream *msg, struct sockaddr_any *sa)
{
	uint16_t family;

	STREAM_GETW(msg, family);

	switch (family) {
	case AF_INET:
		sa->sa_sin.sin_family = family;
		STREAM_GET(&sa->sa_sin.sin_addr, msg,
			   sizeof(sa->sa_sin.sin_addr));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sa->sa_sin.sin_len = sizeof(sa->sa_sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return;

	case AF_INET6:
		sa->sa_sin6.sin6_family = family;
		STREAM_GET(&sa->sa_sin6.sin6_addr, msg,
			   sizeof(sa->sa_sin6.sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sa->sa_sin6.sin6_len = sizeof(sa->sa_sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return;

	default:
		zlog_warn("ptm-read-address: invalid family: %d", family);
		break;
	}

stream_failure:
	memset(sa, 0, sizeof(*sa));
}

static int _ptm_msg_read(struct stream *msg, int command, vrf_id_t vrf_id,
			 struct bfd_peer_cfg *bpc, struct ptm_client **pc)
{
	uint32_t pid;
	size_t ifnamelen;

	/*
	 * Register/Deregister/Update Message format:
	 *
	 * Old format (being used by PTM BFD).
	 * - header: Command, VRF
	 * - l: pid
	 * - w: family
	 *   - AF_INET:
	 *     - l: destination ipv4
	 *   - AF_INET6:
	 *     - 16 bytes: destination IPv6
	 * - command != ZEBRA_BFD_DEST_DEREGISTER
	 *   - l: min_rx
	 *   - l: min_tx
	 *   - c: detect multiplier
	 * - c: is_multihop?
	 *   - multihop:
	 *     - w: family
	 *       - AF_INET:
	 *         - l: source IPv4 address
	 *       - AF_INET6:
	 *         - 16 bytes: source IPv6 address
	 *     - c: ttl
	 *   - no multihop
	 *     - AF_INET6:
	 *       - w: family
	 *       - 16 bytes: source IPv6 address
	 *     - c: ifname length
	 *     - X bytes: interface name
	 *
	 * New format:
	 * - header: Command, VRF
	 * - l: pid
	 * - w: family
	 *   - AF_INET:
	 *     - l: destination IPv4 address
	 *   - AF_INET6:
	 *     - 16 bytes: destination IPv6 address
	 * - l: min_rx
	 * - l: min_tx
	 * - c: detect multiplier
	 * - c: is_multihop?
	 * - w: family
	 *   - AF_INET:
	 *     - l: source IPv4 address
	 *   - AF_INET6:
	 *     - 16 bytes: source IPv6 address
	 * - c: ttl
	 * - c: ifname length
	 * - X bytes: interface name
	 * - c: bfd_cbit
	 * - c: profile name length.
	 * - X bytes: profile name.
	 *
	 * q(64), l(32), w(16), c(8)
	 */

	/* Initialize parameters return values. */
	memset(bpc, 0, sizeof(*bpc));
	*pc = NULL;

	/* Find or allocate process context data. */
	STREAM_GETL(msg, pid);

	*pc = pc_new(pid);

	/* Register/update peer information. */
	_ptm_msg_read_address(msg, &bpc->bpc_peer);

	/* Determine IP type from peer destination. */
	bpc->bpc_ipv4 = (bpc->bpc_peer.sa_sin.sin_family == AF_INET);

	/* Get peer configuration. */
	STREAM_GETL(msg, bpc->bpc_recvinterval);
	bpc->bpc_has_recvinterval =
		(bpc->bpc_recvinterval != BPC_DEF_RECEIVEINTERVAL);

	STREAM_GETL(msg, bpc->bpc_txinterval);
	bpc->bpc_has_txinterval =
		(bpc->bpc_txinterval != BPC_DEF_TRANSMITINTERVAL);

	STREAM_GETC(msg, bpc->bpc_detectmultiplier);
	bpc->bpc_has_detectmultiplier =
		(bpc->bpc_detectmultiplier != BPC_DEF_DETECTMULTIPLIER);

	/* Read (single|multi)hop and its options. */
	STREAM_GETC(msg, bpc->bpc_mhop);

	/* Read multihop source address and TTL. */
	_ptm_msg_read_address(msg, &bpc->bpc_local);

	/* Read the minimum TTL (0 means unset or invalid). */
	STREAM_GETC(msg, bpc->bpc_minimum_ttl);
	if (bpc->bpc_minimum_ttl == 0) {
		bpc->bpc_minimum_ttl = BFD_DEF_MHOP_TTL;
		bpc->bpc_has_minimum_ttl = false;
	} else {
		bpc->bpc_minimum_ttl = (BFD_TTL_VAL + 1) - bpc->bpc_minimum_ttl;
		bpc->bpc_has_minimum_ttl = true;
	}

	/*
	 * Read interface name and make sure it fits our data
	 * structure, otherwise fail.
	 */
	STREAM_GETC(msg, ifnamelen);
	if (ifnamelen >= sizeof(bpc->bpc_localif)) {
		zlog_err("ptm-read: interface name is too big");
		return -1;
	}

	bpc->bpc_has_localif = ifnamelen > 0;
	if (bpc->bpc_has_localif) {
		STREAM_GET(bpc->bpc_localif, msg, ifnamelen);
		bpc->bpc_localif[ifnamelen] = 0;
	}

	if (vrf_id != VRF_DEFAULT) {
		struct vrf *vrf;

		vrf = vrf_lookup_by_id(vrf_id);
		if (vrf) {
			bpc->bpc_has_vrfname = true;
			strlcpy(bpc->bpc_vrfname, vrf->name, sizeof(bpc->bpc_vrfname));
		} else {
			zlog_err("ptm-read: vrf id %u could not be identified",
				 vrf_id);
			return -1;
		}
	} else {
		bpc->bpc_has_vrfname = true;
		strlcpy(bpc->bpc_vrfname, VRF_DEFAULT_NAME, sizeof(bpc->bpc_vrfname));
	}

	/* Read control plane independant configuration. */
	STREAM_GETC(msg, bpc->bpc_cbit);

	/* Handle profile names. */
	STREAM_GETC(msg, ifnamelen);
	bpc->bpc_has_profile = ifnamelen > 0;
	if (bpc->bpc_has_profile) {
		STREAM_GET(bpc->bpc_profile, msg, ifnamelen);
		bpc->bpc_profile[ifnamelen] = 0;
	}

	/* Sanity check: peer and local address must match IP types. */
	if (bpc->bpc_local.sa_sin.sin_family != AF_UNSPEC
	    && (bpc->bpc_local.sa_sin.sin_family
		!= bpc->bpc_peer.sa_sin.sin_family)) {
		zlog_warn("ptm-read: peer family doesn't match local type");
		return -1;
	}

	return 0;

stream_failure:
	return -1;
}

static void bfdd_dest_register(struct stream *msg, vrf_id_t vrf_id)
{
	struct ptm_client *pc;
	struct bfd_session *bs;
	struct bfd_peer_cfg bpc;

	/* Read the client context and peer data. */
	if (_ptm_msg_read(msg, ZEBRA_BFD_DEST_REGISTER, vrf_id, &bpc, &pc) == -1)
		return;

	debug_printbpc(&bpc, "ptm-add-dest: register peer");

	/* Find or start new BFD session. */
	bs = bs_peer_find(&bpc);
	if (bs == NULL) {
		bs = ptm_bfd_sess_new(&bpc);
		if (bs == NULL) {
			if (bglobal.debug_zebra)
				zlog_debug(
					"ptm-add-dest: failed to create BFD session");
			return;
		}
	} else {
		/*
		 * BFD session was already created, we are just updating the
		 * current peer.
		 *
		 * `ptm-bfd` (or `HAVE_BFDD == 0`) is the only implementation
		 * that allow users to set peer specific timers via protocol.
		 * BFD daemon (this code) on the other hand only supports
		 * changing peer configuration manually (through `peer` node)
		 * or via profiles.
		 */
		if (bpc.bpc_has_profile)
			bfd_profile_apply(bpc.bpc_profile, bs);
	}

	/* Create client peer notification register. */
	pcn_new(pc, bs);

	ptm_bfd_notify(bs, bs->ses_state);
}

static void bfdd_dest_deregister(struct stream *msg, vrf_id_t vrf_id)
{
	struct ptm_client *pc;
	struct ptm_client_notification *pcn;
	struct bfd_session *bs;
	struct bfd_peer_cfg bpc;

	/* Read the client context and peer data. */
	if (_ptm_msg_read(msg, ZEBRA_BFD_DEST_DEREGISTER, vrf_id, &bpc, &pc) == -1)
		return;

	debug_printbpc(&bpc, "ptm-del-dest: deregister peer");

	/* Find or start new BFD session. */
	bs = bs_peer_find(&bpc);
	if (bs == NULL) {
		if (bglobal.debug_zebra)
			zlog_debug("ptm-del-dest: failed to find BFD session");
		return;
	}

	/* Unregister client peer notification. */
	pcn = pcn_lookup(pc, bs);
	if (pcn != NULL) {
		pcn_free(pcn);
		return;
	}

	if (bglobal.debug_zebra)
		zlog_debug("ptm-del-dest: failed to find BFD session");

	/*
	 * XXX: We either got a double deregistration or the daemon who
	 * created this is no longer around. Lets try to delete it anyway
	 * and the worst case is the refcount will detain us.
	 */
	_ptm_bfd_session_del(bs, BD_NEIGHBOR_DOWN);
}

/*
 * header: command, VRF
 * l: pid
 */
static void bfdd_client_register(struct stream *msg)
{
	uint32_t pid;

	/* Find or allocate process context data. */
	STREAM_GETL(msg, pid);

	pc_new(pid);

	return;

stream_failure:
	zlog_err("ptm-add-client: failed to register client");
}

/*
 * header: command, VRF
 * l: pid
 */
static void bfdd_client_deregister(struct stream *msg)
{
	struct ptm_client *pc;
	uint32_t pid;

	/* Find or allocate process context data. */
	STREAM_GETL(msg, pid);

	pc = pc_lookup(pid);
	if (pc == NULL) {
		if (bglobal.debug_zebra)
			zlog_debug("ptm-del-client: failed to find client: %u",
				   pid);
		return;
	}

	if (bglobal.debug_zebra)
		zlog_debug("ptm-del-client: client pid %u", pid);

	pc_free(pc);

	return;

stream_failure:
	zlog_err("ptm-del-client: failed to deregister client");
}

static int bfdd_replay(ZAPI_CALLBACK_ARGS)
{
	struct stream *msg = zclient->ibuf;
	uint32_t rcmd;

	STREAM_GETL(msg, rcmd);

	switch (rcmd) {
	case ZEBRA_BFD_DEST_REGISTER:
	case ZEBRA_BFD_DEST_UPDATE:
		bfdd_dest_register(msg, vrf_id);
		break;
	case ZEBRA_BFD_DEST_DEREGISTER:
		bfdd_dest_deregister(msg, vrf_id);
		break;
	case ZEBRA_BFD_CLIENT_REGISTER:
		bfdd_client_register(msg);
		break;
	case ZEBRA_BFD_CLIENT_DEREGISTER:
		bfdd_client_deregister(msg);
		break;

	default:
		if (bglobal.debug_zebra)
			zlog_debug("ptm-replay: invalid message type %u", rcmd);
		return -1;
	}

	return 0;

stream_failure:
	zlog_err("ptm-replay: failed to find command");
	return -1;
}

static void bfdd_zebra_connected(struct zclient *zc)
{
	struct stream *msg = zc->obuf;

	/* Clean-up and free ptm clients data memory. */
	pc_free_all();

	/*
	 * The replay is an empty message just to trigger client daemons
	 * configuration replay.
	 */
	stream_reset(msg);
	zclient_create_header(msg, ZEBRA_BFD_DEST_REPLAY, VRF_DEFAULT);
	stream_putl(msg, ZEBRA_BFD_DEST_REPLAY);
	stream_putw_at(msg, 0, stream_get_endp(msg));

	/* Ask for interfaces information. */
	zclient_create_header(msg, ZEBRA_INTERFACE_ADD, VRF_DEFAULT);

	/* Send requests. */
	zclient_send_message(zclient);
}

static void bfdd_sessions_enable_interface(struct interface *ifp)
{
	struct bfd_session_observer *bso;
	struct bfd_session *bs;
	struct vrf *vrf;

	vrf = ifp->vrf;

	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		bs = bso->bso_bs;
		/* check vrf name */
		if (bs->key.vrfname[0] &&
		    strcmp(vrf->name, bs->key.vrfname))
			continue;

		/* If Interface matches vrfname, then bypass iface check */
		if (vrf_is_backend_netns() || strcmp(ifp->name, vrf->name)) {
			/* Interface name mismatch. */
			if (bs->key.ifname[0] &&
			    strcmp(ifp->name, bs->key.ifname))
				continue;
		}

		/* Skip enabled sessions. */
		if (bs->sock != -1)
			continue;

		/* Try to enable it. */
		bfd_session_enable(bs);
	}
}

static void bfdd_sessions_disable_interface(struct interface *ifp)
{
	struct bfd_session_observer *bso;
	struct bfd_session *bs;

	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		bs = bso->bso_bs;

		if (bs->ifp != ifp)
			continue;

		/* Skip disabled sessions. */
		if (bs->sock == -1) {
			bs->ifp = NULL;
			continue;
		}

		bfd_session_disable(bs);
		bs->ifp = NULL;
	}
}

void bfdd_sessions_enable_vrf(struct vrf *vrf)
{
	struct bfd_session_observer *bso;
	struct bfd_session *bs;

	/* it may affect configs without interfaces */
	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		bs = bso->bso_bs;
		if (bs->vrf)
			continue;
		if (bs->key.vrfname[0] &&
		    strcmp(vrf->name, bs->key.vrfname))
			continue;
		/* need to update the vrf information on
		 * bs so that callbacks are handled
		 */
		bs->vrf = vrf;
		/* Skip enabled sessions. */
		if (bs->sock != -1)
			continue;
		/* Try to enable it. */
		bfd_session_enable(bs);
	}
}

void bfdd_sessions_disable_vrf(struct vrf *vrf)
{
	struct bfd_session_observer *bso;
	struct bfd_session *bs;

	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		bs = bso->bso_bs;
		if (bs->key.vrfname[0] &&
		    strcmp(vrf->name, bs->key.vrfname))
			continue;
		/* Skip disabled sessions. */
		if (bs->sock == -1)
			continue;

		bfd_session_disable(bs);
		bs->vrf = NULL;
	}
}

static int bfd_ifp_destroy(struct interface *ifp)
{
	if (bglobal.debug_zebra)
		zlog_debug("zclient: delete interface %s (VRF %s(%u))",
			   ifp->name, ifp->vrf->name, ifp->vrf->vrf_id);

	bfdd_sessions_disable_interface(ifp);

	return 0;
}

static void bfdd_sessions_enable_address(struct connected *ifc)
{
	struct bfd_session_observer *bso;
	struct bfd_session *bs;
	struct prefix prefix;

	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		/* Skip enabled sessions. */
		bs = bso->bso_bs;
		if (bs->sock != -1)
			continue;

		/* Check address. */
		prefix = bso->bso_addr;
		prefix.prefixlen = ifc->address->prefixlen;
		if (prefix_cmp(&prefix, ifc->address))
			continue;

		/* Try to enable it. */
		bfd_session_enable(bs);
	}
}

static int bfdd_interface_address_update(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return 0;

	if (bglobal.debug_zebra)
		zlog_debug("zclient: %s local address %pFX (VRF %u)",
			   cmd == ZEBRA_INTERFACE_ADDRESS_ADD ? "add"
							      : "delete",
			   ifc->address, vrf_id);

	if (cmd == ZEBRA_INTERFACE_ADDRESS_ADD)
		bfdd_sessions_enable_address(ifc);
	else
		connected_free(&ifc);

	return 0;
}

static int bfd_ifp_create(struct interface *ifp)
{
	if (bglobal.debug_zebra)
		zlog_debug("zclient: add interface %s (VRF %s(%u))", ifp->name,
			   ifp->vrf->name, ifp->vrf->vrf_id);
	bfdd_sessions_enable_interface(ifp);

	return 0;
}

static zclient_handler *const bfd_handlers[] = {
	/*
	 * We'll receive all messages through replay, however it will
	 * contain a special field with the real command inside so we
	 * avoid having to create too many handlers.
	 */
	[ZEBRA_BFD_DEST_REPLAY] = bfdd_replay,

	/* Learn about new addresses being registered. */
	[ZEBRA_INTERFACE_ADDRESS_ADD] = bfdd_interface_address_update,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = bfdd_interface_address_update,
};

void bfdd_zclient_init(struct zebra_privs_t *bfdd_priv)
{
	if_zapi_callbacks(bfd_ifp_create, NULL, NULL, bfd_ifp_destroy);
	zclient = zclient_new(master, &zclient_options_default, bfd_handlers,
			      array_size(bfd_handlers));
	assert(zclient != NULL);
	zclient_init(zclient, ZEBRA_ROUTE_BFD, 0, bfdd_priv);

	/* Send replay request on zebra connect. */
	zclient->zebra_connected = bfdd_zebra_connected;
}

void bfdd_zclient_register(vrf_id_t vrf_id)
{
	if (!zclient || zclient->sock < 0)
		return;
	zclient_send_reg_requests(zclient, vrf_id);
}

void bfdd_zclient_unregister(vrf_id_t vrf_id)
{
	if (!zclient || zclient->sock < 0)
		return;
	zclient_send_dereg_requests(zclient, vrf_id);
}

void bfdd_zclient_stop(void)
{
	zclient_stop(zclient);

	/* Clean-up and free ptm clients data memory. */
	pc_free_all();
}


/*
 * Client handling.
 */
static struct ptm_client *pc_lookup(uint32_t pid)
{
	struct ptm_client *pc;

	TAILQ_FOREACH (pc, &pcqueue, pc_entry) {
		if (pc->pc_pid != pid)
			continue;

		break;
	}

	return pc;
}

static struct ptm_client *pc_new(uint32_t pid)
{
	struct ptm_client *pc;

	/* Look up first, if not found create the client. */
	pc = pc_lookup(pid);
	if (pc != NULL)
		return pc;

	/* Allocate the client data and save it. */
	pc = XCALLOC(MTYPE_BFDD_CONTROL, sizeof(*pc));

	pc->pc_pid = pid;
	TAILQ_INSERT_HEAD(&pcqueue, pc, pc_entry);
	return pc;
}

static void pc_free(struct ptm_client *pc)
{
	struct ptm_client_notification *pcn;

	TAILQ_REMOVE(&pcqueue, pc, pc_entry);

	while (!TAILQ_EMPTY(&pc->pc_pcnqueue)) {
		pcn = TAILQ_FIRST(&pc->pc_pcnqueue);
		pcn_free(pcn);
	}

	XFREE(MTYPE_BFDD_CONTROL, pc);
}

static void pc_free_all(void)
{
	struct ptm_client *pc;

	while (!TAILQ_EMPTY(&pcqueue)) {
		pc = TAILQ_FIRST(&pcqueue);
		pc_free(pc);
	}
}

static struct ptm_client_notification *pcn_new(struct ptm_client *pc,
					       struct bfd_session *bs)
{
	struct ptm_client_notification *pcn;

	/* Try to find an existing pcn fist. */
	pcn = pcn_lookup(pc, bs);
	if (pcn != NULL)
		return pcn;

	/* Save the client notification data. */
	pcn = XCALLOC(MTYPE_BFDD_NOTIFICATION, sizeof(*pcn));

	TAILQ_INSERT_HEAD(&pc->pc_pcnqueue, pcn, pcn_entry);
	pcn->pcn_pc = pc;
	pcn->pcn_bs = bs;
	bs->refcount++;

	return pcn;
}

static struct ptm_client_notification *pcn_lookup(struct ptm_client *pc,
						  struct bfd_session *bs)
{
	struct ptm_client_notification *pcn;

	TAILQ_FOREACH (pcn, &pc->pc_pcnqueue, pcn_entry) {
		if (pcn->pcn_bs != bs)
			continue;

		break;
	}

	return pcn;
}

static void pcn_free(struct ptm_client_notification *pcn)
{
	struct ptm_client *pc;
	struct bfd_session *bs;

	/* Handle session de-registration. */
	bs = pcn->pcn_bs;
	pcn->pcn_bs = NULL;
	bs->refcount--;

	/* Log modification to users. */
	if (bglobal.debug_zebra)
		zlog_debug("ptm-del-session: [%s] refcount=%" PRIu64,
			   bs_to_string(bs), bs->refcount);

	/* Set session down. */
	_ptm_bfd_session_del(bs, BD_NEIGHBOR_DOWN);

	/* Handle ptm_client deregistration. */
	pc = pcn->pcn_pc;
	pcn->pcn_pc = NULL;
	TAILQ_REMOVE(&pc->pc_pcnqueue, pcn, pcn_entry);

	XFREE(MTYPE_BFDD_NOTIFICATION, pcn);
}
