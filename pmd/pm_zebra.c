/*
 * Zebra connect code for Path Monitoring Daemon
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "thread.h"
#include "command.h"
#include "log.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "jhash.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "pm_lib.h"

#include "pm.h"
#include "pm_echo.h"
#include "pm_memory.h"
#include "pm_zebra.h"

/* Zebra structure to hold current status. */
struct zclient *zclient;
static struct hash *pm_nht_hash;

int pm_nht_not_used;

/* For registering threads. */
extern struct thread_master *master;

DEFINE_MTYPE(PMD, PM_CONTROL, "PM Control contexts")
DEFINE_MTYPE(PMD, PM_NOTIFICATION, "PM Notification contexts")

struct pm_nht_data {
	struct prefix *nh;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint8_t nh_num;
};

struct pm_client_notification {
	struct pm_session *pcn_pm;
	struct pm_client *pcn_pc;

	TAILQ_ENTRY(pm_client_notification) pcn_entry;
};
TAILQ_HEAD(pcnqueue, pm_client_notification);

struct pm_client {
	uint32_t pc_pid;
	struct pcnqueue pc_pcnqueue;

	TAILQ_ENTRY(pm_client) pc_entry;
};
TAILQ_HEAD(pcqueue, pm_client);

static struct pcqueue pcqueue;

/* Peer status */
enum pm_peer_status {
	BPS_SHUTDOWN = 0, /* == PM_ADM_DOWN, "adm-down" */
	BPS_DOWN = 1,     /* == PM_DOWN, "down" */
	BPS_INIT = 2,     /* == PM_INIT, "init" */
	BPS_UP = 3,       /* == PM_UP, "up" */
};

struct pm_peer_cfg {
	bool bpc_ipv4;
	union sockunion bpc_peer;
	union sockunion bpc_local;

	bool bpc_has_localif;
	char bpc_localif[MAXNAMELEN + 1];

	bool bpc_has_vrfname;
	char bpc_vrfname[MAXNAMELEN + 1];

	bool bpc_has_interval;
	uint32_t bpc_interval;

	bool bpc_has_timeout;
	uint32_t bpc_timeout;

	bool bpc_has_packet_size;
	uint16_t bpc_packet_size;

	bool bpc_has_tos_val;
	uint8_t bpc_tos_val;

	bool bpc_shutdown;

	/* Status information */
	enum pm_peer_status bpc_bps;
	uint64_t bpc_lastevent;
};

static struct pm_client_notification *pcn_lookup(struct pm_client *pc,
						 struct pm_session *pm);

static void pc_free(struct pm_client *pc);

static int _pm_msg_address(struct stream *msg, union sockunion *peer);

#ifdef PM_DEBUG
static void debug_printbpc(const char *func, unsigned int line,
			   struct pm_peer_cfg *bpc);

static void debug_printbpc(const char *func, unsigned int line,
			   struct pm_peer_cfg *bpc)
{
	char addr[128];
	char vrf[128];
	char timers[2][128];
	char psize[20];
	char tos_val[20];
	char buf[SU_ADDRSTRLEN];

	addr[0] = vrf[0] = timers[0][0] = timers[1][0] = psize[0] = tos_val[0] = 0;

	snprintf(addr, sizeof(addr), "peer:%s",
		 inet_sutop(&bpc->bpc_peer, buf));

	if (bpc->bpc_has_vrfname)
		snprintf(vrf, sizeof(vrf), " vrf:%s", bpc->bpc_vrfname);

	if (bpc->bpc_has_interval)
		snprintf(timers[0], sizeof(timers[0]), " freq:%lu",
			 bpc->bpc_interval);

	if (bpc->bpc_has_timeout)
		snprintf(timers[1], sizeof(timers[1]), " timeout:%lu",
			 bpc->bpc_timeout);

	if (bpc->bpc_has_packet_size)
		snprintf(psize, sizeof(psize), " psize:%lu",
			 bpc->bpc_packet_size);

	if (bpc->bpc_has_tos_val)
		snprintf(tos_val, sizeof(tos_val), " tos-val:%d",
			 bpc->bpc_tos_val);

	zlog_debug("%s:%d: %s%s%s%s%s%s", func, line,
		   addr, vrf, timers[0], timers[1], psize, tos_val);
}

#define DEBUG_PRINTBPC(bpc) debug_printbpc(__FILE__, __LINE__, (bpc))
#else
#define DEBUG_PRINTBPC(bpc)
#endif /* PM_DEBUG */

static struct pm_client *pc_lookup(uint32_t pid)
{
	struct pm_client *pc;

	TAILQ_FOREACH (pc, &pcqueue, pc_entry) {
		if (pc->pc_pid != pid)
			continue;

		break;
	}

	return pc;
}

static struct pm_client *pc_new(uint32_t pid)
{
	struct pm_client *pc;

	/* Look up first, if not found create the client. */
	pc = pc_lookup(pid);
	if (pc != NULL)
		return pc;

	/* Allocate the client data and save it. */
	pc = XCALLOC(MTYPE_PM_CONTROL, sizeof(*pc));
	if (pc == NULL)
		return NULL;

	pc->pc_pid = pid;
	TAILQ_INSERT_HEAD(&pcqueue, pc, pc_entry);
	return pc;
}

static void pc_free_all(void)
{
	struct pm_client *pc;

	while (!TAILQ_EMPTY(&pcqueue)) {
		pc = TAILQ_FIRST(&pcqueue);
		pc_free(pc);
	}
}

static struct pm_client_notification *pcn_new(struct pm_client *pc,
					      struct pm_session *pm)
{
	struct pm_client_notification *pcn;

	/* Try to find an existing pcn fist. */
	pcn = pcn_lookup(pc, pm);
	if (pcn != NULL)
		return pcn;

	/* Save the client notification data. */
	pcn = XCALLOC(MTYPE_PM_NOTIFICATION, sizeof(*pcn));
	if (pcn == NULL)
		return NULL;

	TAILQ_INSERT_HEAD(&pc->pc_pcnqueue, pcn, pcn_entry);
	pcn->pcn_pc = pc;
	pcn->pcn_pm = pm;
	pm->refcount++;

	return pcn;
}

static struct pm_client_notification *pcn_lookup(struct pm_client *pc,
						 struct pm_session *pm)
{
	struct pm_client_notification *pcn;

	TAILQ_FOREACH (pcn, &pc->pc_pcnqueue, pcn_entry) {
		if (pcn->pcn_pm != pm)
			continue;

		break;
	}

	return pcn;
}

static void pcn_free(struct pm_client_notification *pcn)
{
	struct pm_client *pc;
	struct pm_session *pm;

	if (pcn == NULL)
		return;

	/* Handle session de-registration. */
	pm = pcn->pcn_pm;
	pcn->pcn_pm = NULL;
	pm->refcount--;

	/* Handle pm_client deregistration. */
	pc = pcn->pcn_pc;
	pcn->pcn_pc = NULL;
	TAILQ_REMOVE(&pc->pc_pcnqueue, pcn, pcn_entry);

	XFREE(MTYPE_PM_NOTIFICATION, pcn);
}

static void pc_free(struct pm_client *pc)
{
	struct pm_client_notification *pcn;

	if (pc == NULL)
		return;

	TAILQ_REMOVE(&pcqueue, pc, pc_entry);

	while (!TAILQ_EMPTY(&pc->pc_pcnqueue)) {
		pcn = TAILQ_FIRST(&pc->pc_pcnqueue);
		pcn_free(pcn);
	}

	XFREE(MTYPE_PM_CONTROL, pc);
}

static unsigned int pm_nht_hash_key(const void *data)
{
	const struct pm_nht_data *nhtd = data;
	unsigned int key = 0;

	key = prefix_hash_key(nhtd->nh);
	return jhash_1word(nhtd->nh_vrf_id, key);
}

static bool pm_nht_hash_cmp(const void *d1, const void *d2)
{
	const struct pm_nht_data *nhtd1 = d1;
	const struct pm_nht_data *nhtd2 = d2;

	if (nhtd1->nh_vrf_id != nhtd2->nh_vrf_id)
		return false;

	return prefix_same(nhtd1->nh, nhtd2->nh);
}

static void *pm_nht_hash_alloc(void *data)
{
	struct pm_nht_data *copy = data;
	struct pm_nht_data *new;

	new = XMALLOC(MTYPE_TMP, sizeof(*new));

	new->nh = prefix_new();
	prefix_copy(new->nh, copy->nh);
	new->refcount = 0;
	new->nh_num = 0;
	new->nh_vrf_id = copy->nh_vrf_id;

	return new;
}

static void pm_nht_hash_free(void *data)
{
	struct pm_nht_data *nhtd = data;

	prefix_free(&nhtd->nh);
	XFREE(MTYPE_TMP, nhtd);
}

static struct interface *zebra_interface_if_lookup(struct stream *s,
						   vrf_id_t vrf_id)
{
	char ifname_tmp[INTERFACE_NAMSIZ];

	/* Read interface name. */
	stream_get(ifname_tmp, s, INTERFACE_NAMSIZ);

	/* And look it up. */
	return if_lookup_by_name(ifname_tmp, vrf_id);
}

static int interface_address_add(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
	if (!ifc)
		return 0;
	pm_sessions_update();
	return 0;
}

static int interface_address_delete(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;

	c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static int pm_zebra_ifp_up(struct interface *ifp)
{
	return 0;
}

static int pm_zebra_ifp_down(struct interface *ifp)
{
	return 0;
}

static int _pm_msg_address(struct stream *msg, union sockunion *peer)
{
	stream_putw(msg, peer->sa.sa_family);

	switch (peer->sa.sa_family) {
	case 0:
		break;
	case AF_INET:
		stream_put(msg, &peer->sin.sin_addr, sizeof(struct in_addr));
		stream_putc(msg, 32);
		break;

	case AF_INET6:
		stream_put(msg, &peer->sin6.sin6_addr, sizeof(struct in6_addr));
		stream_putc(msg, 128);
		break;

	default:
		assert(0);
		break;
	}

	return 0;
}

static void _pm_msg_read_address(struct stream *msg, union sockunion *su)
{
	uint16_t family;

	STREAM_GETW(msg, family);

	switch (family) {
	case 0:
		/* no address. ignore */
		break;
	case AF_INET:
		su->sa.sa_family = family;
		STREAM_GET(&su->sin.sin_addr, msg,
			   sizeof(su->sin.sin_addr));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		su->sin.sin_len = sizeof(su->sin.sin_addr);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return;

	case AF_INET6:
		su->sa.sa_family = family;
		STREAM_GET(&su->sin6.sin6_addr, msg,
			   sizeof(su->sin6.sin6_addr));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		su->sin6.sin6_len = sizeof(su->sin6.sin6_addr);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return;

	default:
		zlog_warn("pm-read-address: invalid family: %d", family);
		break;
	}

stream_failure:
	memset(su, 0, sizeof(*su));
}

static int _pm_msg_read(struct stream *msg, int command, vrf_id_t vrf_id,
			struct pm_peer_cfg *bpc, struct pm_client **pc)
{
	uint32_t pid;
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
	 * - command != ZEBRA_PM_DEST_DEREGISTER
	 *   - l: interval
	 *   - l: timeout
	 *   - w: packet_size
	 *   - c: tos_val
	 * - w: is family ipv4 or ipv6 ?
	 *   - AF_INET:
	 *     - l: destination ipv4
	 *   - AF_INET6:
	 *     - 16 bytes: destination IPv6
	 * - c: ifname length > 0 ?
	 *   - X bytes: interface name
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
		zlog_debug("pm-read: failed to allocate memory");
		return -1;
	}

	/* Register/update peer information. */
	_pm_msg_read_address(msg, &bpc->bpc_peer);

	/* Determine IP type from peer destination. */
	bpc->bpc_ipv4 = (bpc->bpc_peer.sa.sa_family == AF_INET);

	/* Get peer configuration. */
	if (command != ZEBRA_PM_DEST_DEREGISTER) {
		STREAM_GETL(msg, bpc->bpc_interval);
		bpc->bpc_has_interval =
			(bpc->bpc_interval != PM_INTERVAL_DEFAULT);

		STREAM_GETL(msg, bpc->bpc_timeout);
		bpc->bpc_has_timeout =
			(bpc->bpc_timeout != PM_TIMEOUT_DEFAULT);

		STREAM_GETW(msg, bpc->bpc_packet_size);
		bpc->bpc_has_packet_size =
			(bpc->bpc_packet_size != PM_PACKET_SIZE_DEFAULT);

		STREAM_GETC(msg, bpc->bpc_tos_val);
		bpc->bpc_has_tos_val =
			(bpc->bpc_tos_val != PM_PACKET_TOS_DEFAULT);
	}

	_pm_msg_read_address(msg, &bpc->bpc_local);

	/*
	 * Read interface name and make sure it fits our data
	 * structure, otherwise fail.
	 */
	STREAM_GETC(msg, ifnamelen);
	if (ifnamelen >= sizeof(bpc->bpc_localif)) {
		zlog_err("pm-read: interface name is too big");
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
			strlcpy(bpc->bpc_vrfname, vrf->name,
				sizeof(bpc->bpc_vrfname));
		} else {
			zlog_err("pm-read: vrf id %u could not be identified",
				 vrf_id);
			return -1;
		}
	}
	return 0;

stream_failure:
	return -1;
}

static struct pm_session *pm_peer_auto(struct pm_peer_cfg *cfg,
					bool create)
{
	const char *vrfname, *ifname;
	char ebuf[128];
	const char *bpc_local;
	char addr_buf[INET6_ADDRSTRLEN];

	if (cfg->bpc_has_localif)
		ifname = cfg->bpc_localif;
	else
		ifname = NULL;

	if (cfg->bpc_local.sa.sa_family != AF_INET &&
	    cfg->bpc_local.sa.sa_family != AF_INET6)
		bpc_local = NULL;
	else
		bpc_local = sockunion2str(&cfg->bpc_local,
					  addr_buf, sizeof(addr_buf));
	if (cfg->bpc_has_vrfname)
		vrfname = cfg->bpc_vrfname;
	else
		vrfname = NULL;
	return pm_lookup_session(&cfg->bpc_peer, bpc_local, ifname,
				 vrfname, create,
				 ebuf, sizeof(ebuf));
}

static struct pm_session *pm_peer_sess_new(struct pm_peer_cfg *cfg)
{
	struct pm_session *pm = pm_peer_auto(cfg, true);
	char errormsg[128];

	if (!pm)
		return NULL;
	pm->timeout = cfg->bpc_timeout;
	pm->interval = cfg->bpc_interval;
	pm->packet_size = cfg->bpc_packet_size;
	pm->tos_val = cfg->bpc_tos_val;
	pm->retries_up = PM_PACKET_RETRIES_UP_DEFAULT;
	pm->retries_down = PM_PACKET_RETRIES_DOWN_DEFAULT;
	pm_initialise(pm, true, errormsg, sizeof(errormsg));
	return pm;
}

static struct pm_session *pm_peer_find(struct pm_peer_cfg *cfg)
{
	return pm_peer_auto(cfg, false);
}

static const char *pm_to_string(const struct pm_session *pm)
{
	static char buf[256];
	char addr_buf[INET6_ADDRSTRLEN];
	int pos;

	pos = snprintf(buf, sizeof(buf), " peer:%s",
		       sockunion2str(&pm->key.peer,
				     addr_buf, sizeof(addr_buf)));
	pos += snprintf(buf + pos, sizeof(buf) - pos, " local:%s",
			sockunion2str(&pm->key.local,
				      addr_buf, sizeof(addr_buf)));
	if (pm->key.vrfname[0])
		pos += snprintf(buf + pos, sizeof(buf) - pos, " vrf:%s",
				pm->key.vrfname);
	if (pm->key.ifname[0])
		pos += snprintf(buf + pos, sizeof(buf) - pos, " ifname:%s",
				pm->key.ifname);

	(void)pos;

	return buf;
}

static int pm_peer_del(struct pm_peer_cfg *cfg)
{
	struct pm_session *pm;
	char errormsg[128];

	pm = pm_peer_find(cfg);
	if (pm == NULL)
		return -1;

	/* This pointer is being referenced, don't let it be deleted. */
	if (pm->refcount > 0) {
		zlog_err("session-delete: refcount failure: %" PRIu64
			  " references",
			  pm->refcount);
		return -1;
	}
	zlog_info("session-delete: %s", pm_to_string(pm));

	QOBJ_UNREG(pm);
	pm_echo_stop(pm, errormsg, sizeof(errormsg), true);
	hash_release(pm_session_list, pm);
	XFREE(MTYPE_PM_SESSION, pm);

	return 0;
}

static void pmd_dest_register(struct stream *msg, vrf_id_t vrf_id)
{
	struct pm_client *pc;
	struct pm_client_notification *pcn;
	struct pm_session *pm;
	struct pm_peer_cfg bpc;

	/* Read the client context and peer data. */
	if (_pm_msg_read(msg, ZEBRA_PM_DEST_REGISTER, vrf_id, &bpc, &pc) == -1)
		return;

	DEBUG_PRINTBPC(&bpc);

	/* Find or start new PM session. */
	pm = pm_peer_find(&bpc);
	if (pm == NULL) {
		pm = pm_peer_sess_new(&bpc);
		if (pm == NULL) {
			zlog_debug("pm-add-dest: failed to create PM session");
			return;
		}
	}

	/* Create client peer notification register. */
	pcn = pcn_new(pc, pm);
	if (pcn == NULL) {
		zlog_err("pm-add-dest: failed to registrate notifications");
		return;
	}
	pm_zebra_notify(pm);

	pm_zebra_nht_register(pm, true, NULL);

}

static void pmd_dest_deregister(struct stream *msg, vrf_id_t vrf_id)
{
	struct pm_client *pc;
	struct pm_client_notification *pcn;
	struct pm_session *pm;
	struct pm_peer_cfg bpc;

	/* Read the client context and peer data. */
	if (_pm_msg_read(msg, ZEBRA_PM_DEST_DEREGISTER,
			 vrf_id, &bpc, &pc) == -1)
		return;

	DEBUG_PRINTBPC(&bpc);

	/* Find or start new PM session. */
	pm = pm_peer_find(&bpc);
	if (pm == NULL) {
		zlog_debug("pm-del-dest: failed to find PM session");
		return;
	}

	/* Unregister client peer notification. */
	pcn = pcn_lookup(pc, pm);
	pcn_free(pcn);
	if (pm->refcount ||
	    PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_CONFIG))
		return;
	pm_peer_del(&bpc);
}

/*
 * header: command, VRF
 * l: pid
 */
static void pmd_client_register(struct stream *msg)
{
	struct pm_client *pc;
	uint32_t pid;

	/* Find or allocate process context data. */
	STREAM_GETL(msg, pid);

	pc = pc_new(pid);
	if (pc == NULL) {
		zlog_err("pm-add-client: failed to register client: %u", pid);
		return;
	}

	return;

stream_failure:
	zlog_err("pm-add-client: failed to register client");
}

/*
 * header: command, VRF
 * l: pid
 */
static void pmd_client_deregister(struct stream *msg)
{
	struct pm_client *pc;
	uint32_t pid;

	/* Find or allocate process context data. */
	STREAM_GETL(msg, pid);

	pc = pc_lookup(pid);
	if (pc == NULL) {
		zlog_debug("pm-del-client: failed to find client: %u", pid);
		return;
	}

	pc_free(pc);

	return;

stream_failure:
	zlog_err("pm-del-client: failed to deregister client");
}

static int pmd_replay(int cmd, struct zclient *zc,
		      uint16_t len, vrf_id_t vrf_id)
{
	struct stream *msg = zc->ibuf;
	uint32_t rcmd;

	STREAM_GETL(msg, rcmd);

	switch (rcmd) {
	case ZEBRA_PM_DEST_REGISTER:
	case ZEBRA_PM_DEST_UPDATE:
		pmd_dest_register(msg, vrf_id);
		break;
	case ZEBRA_PM_DEST_DEREGISTER:
		pmd_dest_deregister(msg, vrf_id);
		break;
	case ZEBRA_PM_CLIENT_REGISTER:
		pmd_client_register(msg);
		break;
	case ZEBRA_PM_CLIENT_DEREGISTER:
		pmd_client_deregister(msg);
		break;

	default:
		zlog_debug("pm-replay: invalid message type %u", rcmd);
		return -1;
	}

	return 0;

stream_failure:
	zlog_err("pm-replay: failed to find command");
	return -1;
}

void pm_zclient_register(vrf_id_t vrf_id)
{
	if (!zclient || zclient->sock < 0)
		return;
	zclient_send_reg_requests(zclient, vrf_id);
}

void pm_zclient_unregister(vrf_id_t vrf_id)
{
	if (!zclient || zclient->sock < 0)
		return;
	zclient_send_dereg_requests(zclient, vrf_id);
}

static int pmd_interface_vrf_update(int command __attribute__((__unused__)),
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

static void zebra_connected(struct zclient *zclient)
{
	struct stream *msg = zclient->obuf;

	/* Clean-up and free pm clients data memory. */
	pc_free_all();

	/*
	 * The replay is an empty message just to trigger client daemons
	 * configuration replay.
	 */
	stream_reset(msg);
	zclient_create_header(msg, ZEBRA_PM_DEST_REPLAY, VRF_DEFAULT);
	stream_putl(msg, ZEBRA_PM_DEST_REPLAY);
	stream_putw_at(msg, 0, stream_get_endp(msg));

	/* for interfaces information. */
	zclient_create_header(msg, ZEBRA_INTERFACE_ADD, VRF_DEFAULT);

	/* Send requests. */
	zclient_send_message(zclient);

}

static int pm_nexthop_update(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct pm_nht_data *nhtd, lookup;
	struct zapi_route nhr;
	afi_t afi = AFI_IP;

	if (!zapi_nexthop_update_decode(zclient->ibuf, &nhr)) {
		zlog_warn("%s: Decode of update failed", __PRETTY_FUNCTION__);

		return 0;
	}

	if (nhr.prefix.family == AF_INET6)
		afi = AFI_IP6;

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = &nhr.prefix;
	lookup.nh_vrf_id = vrf_id;

	nhtd = hash_lookup(pm_nht_hash, &lookup);

	if (nhtd) {
		nhtd->nh_num = nhr.nexthop_num;

		pm_nht_update(&nhr.prefix, nhr.nexthop_num, afi,
			      nhtd->nh_vrf_id, NULL);
	} else
		zlog_err("No nhtd?");

	return 1;
}

extern struct zebra_privs_t pm_privs;

static int pm_zebra_ifp_create(struct interface *ifp)
{
	pm_sessions_change_interface(ifp, true);
	return 0;
}

static int pm_zebra_ifp_destroy(struct interface *ifp)
{
	pm_sessions_change_interface(ifp, false);
	return 0;
}

static void pm_zebra_fake_nht_register(struct pm_session *pm,
				       bool reg, struct vty *vty)
{
	char buf[SU_ADDRSTRLEN];

	zlog_info("PMD: session to %s, NHT ignored",
		  sockunion2str(&pm->key.peer, buf, sizeof(buf)));

	if (PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED) && reg)
		return;
	if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED) && !reg)
		return;
	if (reg)
		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED);
	else
		PM_UNSET_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED);

	if (reg) {
		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_NH_VALID);
		pm_try_run(vty, pm);
	}
}

void pm_zebra_nht_register(struct pm_session *pm, bool reg, struct vty *vty)
{
	struct pm_nht_data *nhtd, lookup;
	uint32_t cmd;
	struct prefix p;
	afi_t afi = AFI_IP;
	struct vrf *vrf;

	if (pm_nht_not_used) {
		pm_zebra_fake_nht_register(pm, reg, vty);
		return;
	}
	cmd = (reg) ?
		ZEBRA_NEXTHOP_REGISTER : ZEBRA_NEXTHOP_UNREGISTER;

	if (PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED) && reg)
		return;
	if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED) && !reg)
		return;

	memset(&p, 0, sizeof(p));
	if (sockunion_family(&pm->key.peer) == AF_INET) {
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = pm->key.peer.sin.sin_addr;
		afi = AFI_IP;
	} else if (sockunion_family(&pm->key.peer) == AF_INET6) {
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = pm->key.peer.sin6.sin6_addr;
		afi = AFI_IP6;
	}
	if (pm->key.vrfname[0])
		vrf = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf)
		return;

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = &p;
	lookup.nh_vrf_id = vrf->vrf_id;

	if (reg)
		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED);
	else
		PM_UNSET_FLAG(pm->flags, PM_SESS_FLAG_NH_REGISTERED);

	if (reg) {
		nhtd = hash_get(pm_nht_hash, &lookup,
				pm_nht_hash_alloc);
		nhtd->refcount++;

		if (nhtd->refcount > 1) {
			pm_nht_update(nhtd->nh, nhtd->nh_num,
				      afi, nhtd->nh_vrf_id, vty);
			return;
		}
	} else {
		nhtd = hash_lookup(pm_nht_hash, &lookup);
		if (!nhtd)
			return;

		nhtd->refcount--;
		if (nhtd->refcount >= 1)
			return;

		hash_release(pm_nht_hash, nhtd);
		pm_nht_hash_free(nhtd);
	}

	if (zclient_send_rnh(zclient, cmd, &p, false,
			     vrf->vrf_id) < 0)
		zlog_warn("%s: Failure to send nexthop to zebra",
			  __PRETTY_FUNCTION__);
}

void pm_zebra_nht(bool on)
{
	if (pm_nht_not_used && !on)
		return;
	if (!pm_nht_not_used && on)
		return;
	if (on) {
		pm_nht_not_used = 0;
		zclient->nexthop_update = pm_nexthop_update;
	} else {
		pm_nht_not_used = 1;
		zclient->nexthop_update = NULL;
	}
}

void pm_zebra_init(void)
{
	if_zapi_callbacks(pm_zebra_ifp_create, pm_zebra_ifp_up,
			  pm_zebra_ifp_down, pm_zebra_ifp_destroy);

	pm_nht_not_used = 0;
	zclient = zclient_new(master, &zclient_options_default);
	assert(zclient != NULL);
	zclient_init(zclient, ZEBRA_ROUTE_PM, 0, &pm_privs);

	zclient->zebra_connected = zebra_connected;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	if (pm_nht_not_used)
		zclient->nexthop_update = NULL;
	else
		zclient->nexthop_update = pm_nexthop_update;
	/* Learn about interface VRF. */
	zclient->interface_vrf_update = pmd_interface_vrf_update;

	zclient->pm_dest_replay = pmd_replay;

	pm_nht_hash = hash_create(pm_nht_hash_key,
				  pm_nht_hash_cmp,
				  "PM Nexthop Tracking hash");

}

int pm_zebra_notify(struct pm_session *pm)
{
	struct stream *msg;
	struct vrf *vrf = NULL;
	struct interface *ifp;
	vrf_id_t vrf_id = VRF_DEFAULT;
	ifindex_t idx = IFINDEX_INTERNAL;

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
	 * - l: pm status
	 * - c: family
	 *   - AF_INET:
	 *     - 4 bytes: ipv4
	 *   - AF_INET6:
	 *     - 16 bytes: ipv6
	 *   - c: prefix length
	 * - c: cbit
	 *
	 * Commands: ZEBRA_PM_DEST_REPLAY
	 *
	 * q(64), l(32), w(16), c(8)
	 */
	msg = zclient->obuf;
	stream_reset(msg);

	if (pm->key.vrfname[0]) {
		vrf = vrf_lookup_by_name(pm->key.vrfname);
		if (!vrf)
			return -1;
		vrf_id = vrf->vrf_id;
	}
	zclient_create_header(msg, ZEBRA_PM_DEST_REPLAY, vrf_id);

	/* This header will be handled by `zebra_pm.c`. */
	stream_putl(msg, ZEBRA_INTERFACE_PM_DEST_UPDATE);

	/* NOTE: Interface is a shortcut to avoid comparing source address. */
	if (pm->key.ifname[0]) {
		ifp = if_lookup_by_name(pm->key.ifname, vrf_id);
		if (ifp)
			idx = ifp->ifindex;
	}
	stream_putl(msg, idx);

	/* PM destination prefix information. */
	_pm_msg_address(msg, &pm->key.peer);

	/* PM status */
	switch (pm->ses_state) {
	case PM_UP:
		stream_putl(msg, PM_STATUS_UP);
		break;

	case PM_ADM_DOWN:
	case PM_DOWN:
	case PM_INIT:
		stream_putl(msg, PM_STATUS_DOWN);
		break;

	default:
		stream_putl(msg, PM_STATUS_UNKNOWN);
		break;
	}

	/* BFD source prefix information. */
	_pm_msg_address(msg, &pm->key.local);

	/* Write packet size. */
	stream_putw_at(msg, 0, stream_get_endp(msg));

	return zclient_send_message(zclient);
}
