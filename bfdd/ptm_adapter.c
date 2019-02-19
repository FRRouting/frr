/*
 * BFD PTM adapter code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "lib/libfrr.h"
#include "lib/queue.h"
#include "lib/stream.h"
#include "lib/zclient.h"

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
static int _ptm_msg_address(struct stream *msg, struct sockaddr_any *sa);

static void _ptm_msg_read_address(struct stream *msg, struct sockaddr_any *sa);
static int _ptm_msg_read(struct stream *msg, int command,
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


static void bfdd_dest_register(struct stream *msg);
static void bfdd_dest_deregister(struct stream *msg);
static void bfdd_client_register(struct stream *msg);
static void bfdd_client_deregister(struct stream *msg);

/*
 * Functions
 */
#ifdef BFD_DEBUG
static void debug_printbpc(const char *func, unsigned int line,
			   struct bfd_peer_cfg *bpc);

static void debug_printbpc(const char *func, unsigned int line,
			   struct bfd_peer_cfg *bpc)
{
	char addr[3][128];
	char timers[3][128];

	addr[0][0] = addr[1][0] = addr[2][0] = timers[0][0] = timers[1][0] =
		timers[2][0] = 0;

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
		snprintf(timers[0], sizeof(timers[0]), " rx:%lu",
			 bpc->bpc_recvinterval);

	if (bpc->bpc_has_txinterval)
		snprintf(timers[1], sizeof(timers[1]), " tx:%lu",
			 bpc->bpc_recvinterval);

	if (bpc->bpc_has_detectmultiplier)
		snprintf(timers[2], sizeof(timers[2]), " detect-multiplier:%d",
			 bpc->bpc_detectmultiplier);

	log_debug("%s:%d: %s %s%s%s%s%s%s", func, line,
		  bpc->bpc_mhop ? "multi-hop" : "single-hop", addr[0], addr[1],
		  addr[2], timers[0], timers[1], timers[2]);
}

#define DEBUG_PRINTBPC(bpc) debug_printbpc(__FILE__, __LINE__, (bpc))
#else
#define DEBUG_PRINTBPC(bpc)
#endif /* BFD_DEBUG */

static int _ptm_msg_address(struct stream *msg, struct sockaddr_any *sa)
{
	switch (sa->sa_sin.sin_family) {
	case AF_INET:
		stream_putc(msg, sa->sa_sin.sin_family);
		stream_put_in_addr(msg, &sa->sa_sin.sin_addr);
		stream_putc(msg, 32);
		break;

	case AF_INET6:
		stream_putc(msg, sa->sa_sin6.sin6_family);
		stream_put(msg, &sa->sa_sin6.sin6_addr,
			   sizeof(sa->sa_sin6.sin6_addr));
		stream_putc(msg, 128);
		break;

	default:
		return -1;
	}

	return 0;
}

int ptm_bfd_notify(struct bfd_session *bs)
{
	struct stream *msg;
	struct sockaddr_any sac;

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
	 *
	 * Commands: ZEBRA_BFD_DEST_REPLAY
	 *
	 * q(64), l(32), w(16), c(8)
	 */
	msg = zclient->obuf;
	stream_reset(msg);

	/* TODO: VRF handling */
	zclient_create_header(msg, ZEBRA_BFD_DEST_REPLAY, VRF_DEFAULT);

	/* This header will be handled by `zebra_ptm.c`. */
	stream_putl(msg, ZEBRA_INTERFACE_BFD_DEST_UPDATE);

	/* NOTE: Interface is a shortcut to avoid comparing source address. */
	if (bs->ifp != NULL)
		stream_putl(msg, bs->ifp->ifindex);
	else
		stream_putl(msg, IFINDEX_INTERNAL);

	/* BFD destination prefix information. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
		_ptm_msg_address(msg, &bs->mhop.peer);
	else
		_ptm_msg_address(msg, &bs->shop.peer);

	/* BFD status */
	switch (bs->ses_state) {
	case PTM_BFD_UP:
		stream_putl(msg, BFD_STATUS_UP);
		break;

	case PTM_BFD_ADM_DOWN:
	case PTM_BFD_DOWN:
	case PTM_BFD_INIT:
		stream_putl(msg, BFD_STATUS_DOWN);
		break;

	default:
		stream_putl(msg, BFD_STATUS_UNKNOWN);
		break;
	}

	/* BFD source prefix information. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)) {
		_ptm_msg_address(msg, &bs->mhop.local);
	} else {
		if (bs->local_address.sa_sin.sin_family)
			_ptm_msg_address(msg, &bs->local_address);
		else if (bs->local_address.sa_sin.sin_family)
			_ptm_msg_address(msg, &bs->local_ip);
		else {
			sac = bs->shop.peer;
			switch (sac.sa_sin.sin_family) {
			case AF_INET:
				memset(&sac.sa_sin.sin_addr, 0,
				       sizeof(sac.sa_sin.sin_family));
				break;
			case AF_INET6:
				memset(&sac.sa_sin6.sin6_addr, 0,
				       sizeof(sac.sa_sin6.sin6_family));
				break;

			default:
				assert(false);
				break;
			}

			/* No local address found yet, so send zeroes. */
			_ptm_msg_address(msg, &sac);
		}
	}

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
		log_warning("ptm-read-address: invalid family: %d", family);
		break;
	}

stream_failure:
	memset(sa, 0, sizeof(*sa));
}

static int _ptm_msg_read(struct stream *msg, int command,
			 struct bfd_peer_cfg *bpc, struct ptm_client **pc)
{
	struct interface *ifp;
	uint32_t pid;
	uint8_t ttl __attribute__((unused));
	size_t ifnamelen;

	/*
	 * Register/Deregister/Update Message format:
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
	 *         - l: destination ipv4
	 *       - AF_INET6:
	 *         - 16 bytes: destination IPv6
	 *     - c: ttl
	 *   - no multihop
	 *     - AF_INET6:
	 *       - w: family
	 *       - 16 bytes: ipv6 address
	 *     - c: ifname length
	 *     - X bytes: interface name
	 *
	 * q(64), l(32), w(16), c(8)
	 */

	/* Initialize parameters return values. */
	memset(bpc, 0, sizeof(*bpc));
	*pc = NULL;

	/* Find or allocate process context data. */
	STREAM_GETL(msg, pid);

	*pc = pc_new(pid);
	if (*pc == NULL) {
		log_debug("ptm-read: failed to allocate memory");
		return -1;
	}

	/* Register/update peer information. */
	_ptm_msg_read_address(msg, &bpc->bpc_peer);

	/* Determine IP type from peer destination. */
	bpc->bpc_ipv4 = (bpc->bpc_peer.sa_sin.sin_family == AF_INET);

	/* Get peer configuration. */
	if (command != ZEBRA_BFD_DEST_DEREGISTER) {
		STREAM_GETL(msg, bpc->bpc_recvinterval);
		bpc->bpc_has_recvinterval =
			(bpc->bpc_recvinterval != BPC_DEF_RECEIVEINTERVAL);

		STREAM_GETL(msg, bpc->bpc_txinterval);
		bpc->bpc_has_txinterval =
			(bpc->bpc_txinterval != BPC_DEF_TRANSMITINTERVAL);

		STREAM_GETC(msg, bpc->bpc_detectmultiplier);
		bpc->bpc_has_detectmultiplier =
			(bpc->bpc_detectmultiplier != BPC_DEF_DETECTMULTIPLIER);
	}

	/* Read (single|multi)hop and its options. */
	STREAM_GETC(msg, bpc->bpc_mhop);
	if (bpc->bpc_mhop) {
		/* Read multihop source address and TTL. */
		_ptm_msg_read_address(msg, &bpc->bpc_local);
		STREAM_GETC(msg, ttl);
	} else {
		/* If target is IPv6, then we must obtain local address. */
		if (bpc->bpc_ipv4 == false)
			_ptm_msg_read_address(msg, &bpc->bpc_local);

		/*
		 * Read interface name and make sure it fits our data
		 * structure, otherwise fail.
		 */
		STREAM_GETC(msg, ifnamelen);
		if (ifnamelen >= sizeof(bpc->bpc_localif)) {
			log_error("ptm-read: interface name is too big");
			return -1;
		}

		bpc->bpc_has_localif = ifnamelen > 0;
		if (bpc->bpc_has_localif) {
			STREAM_GET(bpc->bpc_localif, msg, ifnamelen);
			bpc->bpc_localif[ifnamelen] = 0;

			/*
			 * IPv6 link-local addresses must use scope id,
			 * otherwise the session lookup will always fail
			 * and we'll have multiple sessions showing up.
			 *
			 * This problem only happens with single hop
			 * since it is not possible to have link-local
			 * address for multi hop sessions.
			 */
			if (bpc->bpc_ipv4 == false
			    && IN6_IS_ADDR_LINKLOCAL(
				       &bpc->bpc_peer.sa_sin6.sin6_addr)) {
				ifp = if_lookup_by_name_all_vrf(
					bpc->bpc_localif);
				if (ifp == NULL) {
					log_error(
						"ptm-read: interface %s doesn't exists",
						bpc->bpc_localif);
					return -1;
				}

				bpc->bpc_peer.sa_sin6.sin6_scope_id =
					ifp->ifindex;
			}
		}
	}

	/* Sanity check: peer and local address must match IP types. */
	if (bpc->bpc_local.sa_sin.sin_family != 0
	    && (bpc->bpc_local.sa_sin.sin_family
		!= bpc->bpc_peer.sa_sin.sin_family)) {
		log_warning("ptm-read: peer family doesn't match local type");
		return -1;
	}

	return 0;

stream_failure:
	return -1;
}

static void bfdd_dest_register(struct stream *msg)
{
	struct ptm_client *pc;
	struct ptm_client_notification *pcn;
	struct bfd_session *bs;
	struct bfd_peer_cfg bpc;

	/* Read the client context and peer data. */
	if (_ptm_msg_read(msg, ZEBRA_BFD_DEST_REGISTER, &bpc, &pc) == -1)
		return;

	DEBUG_PRINTBPC(&bpc);

	/* Find or start new BFD session. */
	bs = bs_peer_find(&bpc);
	if (bs == NULL) {
		bs = ptm_bfd_sess_new(&bpc);
		if (bs == NULL) {
			log_debug("ptm-add-dest: failed to create BFD session");
			return;
		}
	} else {
		/* Don't try to change echo/shutdown state. */
		bpc.bpc_echo = BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);
		bpc.bpc_shutdown =
			BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);
	}

	/* Create client peer notification register. */
	pcn = pcn_new(pc, bs);
	if (pcn == NULL) {
		log_error("ptm-add-dest: failed to registrate notifications");
		return;
	}

	ptm_bfd_notify(bs);
}

static void bfdd_dest_deregister(struct stream *msg)
{
	struct ptm_client *pc;
	struct ptm_client_notification *pcn;
	struct bfd_session *bs;
	struct bfd_peer_cfg bpc;

	/* Read the client context and peer data. */
	if (_ptm_msg_read(msg, ZEBRA_BFD_DEST_DEREGISTER, &bpc, &pc) == -1)
		return;

	DEBUG_PRINTBPC(&bpc);

	/* Find or start new BFD session. */
	bs = bs_peer_find(&bpc);
	if (bs == NULL) {
		log_debug("ptm-del-dest: failed to find BFD session");
		return;
	}

	/* Unregister client peer notification. */
	pcn = pcn_lookup(pc, bs);
	pcn_free(pcn);
}

/*
 * header: command, VRF
 * l: pid
 */
static void bfdd_client_register(struct stream *msg)
{
	struct ptm_client *pc;
	uint32_t pid;

	/* Find or allocate process context data. */
	STREAM_GETL(msg, pid);

	pc = pc_new(pid);
	if (pc == NULL) {
		log_error("ptm-add-client: failed to register client: %u", pid);
		return;
	}

	return;

stream_failure:
	log_error("ptm-add-client: failed to register client");
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
		log_debug("ptm-del-client: failed to find client: %u", pid);
		return;
	}

	pc_free(pc);

	return;

stream_failure:
	log_error("ptm-del-client: failed to deregister client");
}

static int bfdd_replay(int cmd, struct zclient *zc, uint16_t len, vrf_id_t vid)
{
	struct stream *msg = zc->ibuf;
	uint32_t rcmd;

	STREAM_GETL(msg, rcmd);

	switch (rcmd) {
	case ZEBRA_BFD_DEST_REGISTER:
	case ZEBRA_BFD_DEST_UPDATE:
		bfdd_dest_register(msg);
		break;
	case ZEBRA_BFD_DEST_DEREGISTER:
		bfdd_dest_deregister(msg);
		break;
	case ZEBRA_BFD_CLIENT_REGISTER:
		bfdd_client_register(msg);
		break;
	case ZEBRA_BFD_CLIENT_DEREGISTER:
		bfdd_client_deregister(msg);
		break;

	default:
		log_debug("ptm-replay: invalid message type %u", rcmd);
		return -1;
	}

	return 0;

stream_failure:
	log_error("ptm-replay: failed to find command");
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

	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		if (bso->bso_isinterface == false)
			continue;

		/* Interface name mismatch. */
		bs = bso->bso_bs;
		if (strcmp(ifp->name, bs->ifname))
			continue;
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
		if (bso->bso_isinterface == false)
			continue;

		/* Interface name mismatch. */
		bs = bso->bso_bs;
		if (strcmp(ifp->name, bs->ifname))
			continue;
		/* Skip disabled sessions. */
		if (bs->sock == -1)
			continue;

		/* Try to enable it. */
		bfd_session_disable(bs);

		TAILQ_INSERT_HEAD(&bglobal.bg_obslist, bso, bso_entry);
	}
}

static int bfdd_interface_update(int cmd, struct zclient *zc,
				 uint16_t len __attribute__((__unused__)),
				 vrf_id_t vrfid)
{
	struct interface *ifp;

	/*
	 * `zebra_interface_add_read` will handle the interface creation
	 * on `lib/if.c`. We'll use that data structure instead of
	 * rolling our own.
	 */
	if (cmd == ZEBRA_INTERFACE_ADD) {
		ifp = zebra_interface_add_read(zc->ibuf, vrfid);
		if (ifp == NULL)
			return 0;

		bfdd_sessions_enable_interface(ifp);
		return 0;
	}

	/* Update interface information. */
	ifp = zebra_interface_state_read(zc->ibuf, vrfid);
	if (ifp == NULL)
		return 0;

	bfdd_sessions_disable_interface(ifp);

	return 0;
}

static int bfdd_interface_vrf_update(int command __attribute__((__unused__)),
				     struct zclient *zclient,
				     zebra_size_t length
				     __attribute__((__unused__)),
				     vrf_id_t vrfid)
{
	struct interface *ifp;
	vrf_id_t nvrfid;

	ifp = zebra_interface_vrf_update_read(zclient->ibuf, vrfid, &nvrfid);
	if (ifp == NULL)
		return 0;

	if_update_to_new_vrf(ifp, nvrfid);

	return 0;
}

void bfdd_zclient_init(struct zebra_privs_t *bfdd_priv)
{
	zclient = zclient_new(master, &zclient_options_default);
	assert(zclient != NULL);
	zclient_init(zclient, ZEBRA_ROUTE_BFD, 0, bfdd_priv);

	/*
	 * We'll receive all messages through replay, however it will
	 * contain a special field with the real command inside so we
	 * avoid having to create too many handlers.
	 */
	zclient->bfd_dest_replay = bfdd_replay;

	/* Send replay request on zebra connect. */
	zclient->zebra_connected = bfdd_zebra_connected;

	/* Learn interfaces from zebra instead of the OS. */
	zclient->interface_add = bfdd_interface_update;
	zclient->interface_delete = bfdd_interface_update;

	/* Learn about interface VRF. */
	zclient->interface_vrf_update = bfdd_interface_vrf_update;
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
	if (pc == NULL)
		return NULL;

	pc->pc_pid = pid;
	TAILQ_INSERT_HEAD(&pcqueue, pc, pc_entry);
	return pc;
}

static void pc_free(struct ptm_client *pc)
{
	struct ptm_client_notification *pcn;

	if (pc == NULL)
		return;

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
	if (pcn == NULL)
		return NULL;

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

	if (pcn == NULL)
		return;

	/* Handle session de-registration. */
	bs = pcn->pcn_bs;
	pcn->pcn_bs = NULL;
	bs->refcount--;

	/* Handle ptm_client deregistration. */
	pc = pcn->pcn_pc;
	pcn->pcn_pc = NULL;
	TAILQ_REMOVE(&pc->pc_pcnqueue, pcn, pcn_entry);

	XFREE(MTYPE_BFDD_NOTIFICATION, pcn);
}
