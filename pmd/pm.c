/*
 * PMD - Path Monitoring Daemon
 * Copyright 2019 6WIND S.A.
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

#include <jhash.h>
#include <hash.h>
#include <memory.h>
#include <vrf.h>
#include <hook.h>
#include <if.h>
#include <prefix.h>
#include <prefix.h>
#include <log.h>

#include "pmd/pm.h"
#include "pmd/pm_echo.h"
#include "pmd/pm_memory.h"
#include "pmd/pm_zebra.h"
#include "pmd/pm_tracking.h"

/* definitions */

struct hash *pm_session_list;
struct hash *pm_id_list;

DEFINE_QOBJ_TYPE(pm_session);

DEFINE_MGROUP(PMD, "Path Monitoring Daemon");
DEFINE_MTYPE(PMD, PM_SESSION, "PM sessions");
DEFINE_MTYPE(PMD, PM_ECHO, "PM Echo contexts");
DEFINE_MTYPE(PMD, PM_PACKET, "PM Packets");
DEFINE_MTYPE(PMD, PM_RTT_STATS, "PM RTT stats");

DEFINE_HOOK(pm_tracking_new_session,
	    (struct pm_session *pm), (pm));
DEFINE_HOOK(pm_tracking_get_dest_address,
	    (struct pm_session *pm,
	     union sockunion *peer), (pm, peer));
DEFINE_HOOK(pm_tracking_get_gateway_address,
	    (struct pm_session *pm,
	     union sockunion *gw), (pm, gw));

static int pm_sessions_change_ifp_walkcb(struct hash_bucket *backet,
					 void *arg);

static void pm_session_peer_resolver_cb(struct resolver_query *q, const char *errstr,
					int n, union sockunion *addrs);

static unsigned int pm_id_list_hash_do(const void *p)
{
	const struct pm_echo *pme = p;

	return jhash_1word(pme->discriminator_id, 0);
}

static bool pm_id_list_hash_cmp(const void *n1, const void *n2)
{
	const struct pm_echo *pm1 = n1, *pm2 = n2;

	return pm1->discriminator_id == pm2->discriminator_id;
}

static unsigned int pm_session_hash_key(const void *arg)
{
	const struct pm_session *pm = arg;

	return jhash(&pm->key, sizeof(struct pm_session_key), 0);
}

static bool pm_session_hash_equal(const void *arg1, const void *arg2)
{
	const struct pm_session *a1 = arg1, *a2 = arg2;

	if (!strmatch(a1->key.peer, a2->key.peer))
		return false;
	if (memcmp(&a1->key.local, &a2->key.local,  sizeof(union sockunion)))
		return false;
	if (memcmp(&a1->key.ifname, &a2->key.ifname, MAXNAMELEN))
		return false;
	if (memcmp(&a1->key.vrfname, &a2->key.vrfname, MAXNAMELEN))
		return false;
	return true;
}

static void *pm_session_alloc_intern(void *arg)
{
	struct pm_session *new, *pms;

	pms = (struct pm_session *)arg;
	new = XCALLOC(MTYPE_PM_SESSION, sizeof(struct pm_session));
	memcpy(new, pms, sizeof(*pms));
	QOBJ_REG(new, pm_session);
	return new;
}

int pm_get_default_packet_size(struct pm_session *pm)
{
	if (sockunion_family(&pm->peer) == AF_INET)
		return PM_PACKET_SIZE_DEFAULT;
	return PM_PACKET_SIZE_DEFAULT_IPV6;
}

struct pm_search_ctx {
	struct pm_session *pm_to_search;
	struct pm_session *pm_found;
};

static int pm_lookup_unique_walker(struct hash_bucket *b, void *data)
{
	struct pm_search_ctx *psc = data;
	struct pm_session *pm = b->data;

	if (!strmatch(pm->key.peer, psc->pm_to_search->key.peer))
		return HASHWALK_CONTINUE;
	/* relax if session to search has no input local param
	 * and session configured has local param
	 */
	if (!sockunion_same(&pm->key.local, &psc->pm_to_search->key.local) &&
	    (sockunion_family(&psc->pm_to_search->key.local) == AF_INET ||
	     sockunion_family(&psc->pm_to_search->key.local) == AF_INET6))
		return HASHWALK_CONTINUE;
	if (memcmp(pm->key.ifname, psc->pm_to_search->key.ifname,
		   sizeof(pm->key.ifname)))
		return HASHWALK_CONTINUE;
	if (memcmp(pm->key.vrfname,
		   psc->pm_to_search->key.vrfname,
		   sizeof(pm->key.vrfname)))
		return HASHWALK_CONTINUE;
	psc->pm_found = pm;
	return HASHWALK_ABORT;
}

struct pm_session *pm_create_session(const char *peer,
				     const char *local,
				     const char *ifname,
				     const char *vrfname)
{
	struct pm_session pm, *pm_created;
	union sockunion lsa, *lsap;

	if (local) {
		str2sockunion(local, &lsa);
		lsap = &lsa;
	} else
		lsap = NULL;

	/* forge key */
	memset(&pm, 0, sizeof(struct pm_session));
	snprintf(pm.key.peer, sizeof(pm.key.peer), "%s", peer);
	str2sockunion(pm.key.peer, &pm.peer);
	if (lsap)
		memcpy(&pm.key.local, lsap, sizeof(union sockunion));
	if (ifname)
		memcpy(&pm.key.ifname, ifname, strlen(ifname));
	if (vrfname)
		memcpy(&pm.key.vrfname, vrfname, strlen(vrfname));

	/* create */
	pm_created = hash_get(pm_session_list,
			     &pm,
			     pm_session_alloc_intern);
	hook_call(pm_tracking_new_session, pm_created);
	return pm_created;
}

struct pm_session *pm_lookup_session(const char *peer,
				     const char *local,
				     const char *ifname,
				     const char *vrfname,
				     bool create,
				     char *ebuf, size_t ebuflen)
{
	union sockunion lsa, *lsap;
	struct pm_session pm;
	struct pm_session *pm_search;
	struct pm_search_ctx psc;

	if (local) {
		str2sockunion(local, &lsa);
		lsap = &lsa;
	} else
		lsap = NULL;

	if (strlen(peer) > HOSTNAME_LEN) {
		snprintf(ebuf, ebuflen, "invalid peer length");
		return NULL;
	}
	if (vrfname) {
		if (strlen(vrfname) > MAXNAMELEN) {
			snprintf(ebuf, ebuflen, "vrf name too long");
			return NULL;
		}
	}
	/* Handle interface specification configuration. */
	if (ifname) {
		if (strlen(ifname) > MAXNAMELEN) {
			snprintf(ebuf, ebuflen, "interface name too long");
			return NULL;
		}
	}
	/* forge key */
	memset(&pm, 0, sizeof(struct pm_session));
	snprintf(pm.key.peer, sizeof(pm.key.peer), "%s", peer);
	if (lsap)
		memcpy(&pm.key.local, lsap, sizeof(union sockunion));
	if (ifname)
		memcpy(&pm.key.ifname, ifname, strlen(ifname));
	if (vrfname)
		memcpy(&pm.key.vrfname, vrfname, strlen(vrfname));

	psc.pm_to_search = &pm;
	psc.pm_found = NULL;
	hash_walk(pm_session_list, pm_lookup_unique_walker, &psc);
	pm_search = psc.pm_found;
	if (!create || pm_search)
		return pm_search;

	/* create */
	return pm_create_session(peer, local, ifname, vrfname);
}

static bool pm_check_local_address_ifp(union sockunion *loc,
				       struct interface *ifp)
{
	struct connected *ifc;
	struct listnode *node;

	if (!ifp)
		return false;
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		if (!ifc->address)
			continue;
		if (sockunion_family(loc)
		    != ifc->address->family)
			continue;
		if (ifc->address->family == AF_INET &&
		    ifc->address->u.prefix4.s_addr !=
		    loc->sin.sin_addr.s_addr)
			continue;
		if (ifc->address->family == AF_INET6 &&
		    memcmp(&ifc->address->u.prefix6,
			   &loc->sin6.sin6_addr,
			   sizeof(struct in6_addr)))
			continue;
		return true;
	}
	return false;
}

static bool pm_check_local_address(union sockunion *loc, struct vrf *vrf)
{
	bool ret;
	struct interface *ifp;

	if (!vrf)
		return false;
	FOR_ALL_INTERFACES (vrf, ifp) {
		ret = pm_check_local_address_ifp(loc, ifp);
		if (ret)
			return true;
	}
	return false;
}
static int pm_session_peer_resolve(struct thread *t)
{
	struct pm_session *pm = THREAD_ARG(t);
	struct vrf *vrf;

	if (pm->key.vrfname[0])
		vrf = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf)
		return 0;
	resolver_resolve(&pm->dns_resolve, pm->afi_resolve, vrf->vrf_id,
			 pm->key.peer,
			 pm_session_peer_resolver_cb);
	return 0;
}

static void pm_session_peer_resolver_cb(struct resolver_query *q, const char *errstr,
					int n, union sockunion *addrs)
{
	struct pm_session *pm = container_of(q, struct pm_session, dns_resolve);
	char buf[SU_ADDRSTRLEN];
	int i;

	pm->t_resolve = NULL;
	if (n < 0) {
		if (pm->afi_resolve == AF_INET6 &&
		    sockunion_family(&pm->key.local) != AF_INET &&
		    sockunion_family(&pm->key.local) != AF_INET6) {
			zlog_warn("%% session to %s, IPv6 resolve failed (%s), trying with IPv4 in 5 sec",
				  pm->key.peer, errstr);
			pm->afi_resolve = AF_INET;
		}
		/* Failed, retry in a moment */
		thread_add_timer(master, pm_session_peer_resolve, pm, 5,
				 &pm->t_resolve);
		return;
	}
	thread_add_timer(master, pm_session_peer_resolve, pm, 2 * 60 * 60,
			 &pm->t_resolve);
	for (i = 0; i < n; i++) {
		/* no change */
		if (sockunion_same(&addrs[i], &pm->peer))
			break;
		/* update IP address */
		memcpy(&pm->peer, &addrs[i], sizeof(union sockunion));
		zlog_info("%% session to %s, resolution to %s ok, polling in 7200 sec",
			  pm->key.peer,
			  sockunion2str(&pm->peer, buf, sizeof(buf)));
		pm_zebra_nht_register(pm, true, NULL);
		pm_try_run(NULL, pm);
		break;
	}
}

void pm_initialise(struct pm_session *pm, bool validate_only,
		   char *ebuf, size_t ebuflen)
{
	struct vrf *vrf;
	struct interface *ifp = NULL;
	char buf[SU_ADDRSTRLEN];
	int ret;
	union sockunion peer;

	if (!validate_only) {
		/* initialise - config by default */
		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_CONFIG);
		/* initialise - shutdown by default */
		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN);
		pm_set_sess_state(pm, PM_ADM_DOWN);
		pm->timeout = PM_TIMEOUT_DEFAULT;
		pm->interval = PM_INTERVAL_DEFAULT;
		pm->packet_size = pm_get_default_packet_size(pm);
		pm->tos_val = PM_PACKET_TOS_DEFAULT;
		pm->retries_consecutive_up = PM_PACKET_RETRIES_CONSECUTIVE_UP_DEFAULT;
		pm->retries_consecutive_down = PM_PACKET_RETRIES_CONSECUTIVE_DOWN_DEFAULT;
		pm->retries_threshold = PM_PACKET_RETRIES_THRESHOLD_DEFAULT;
		pm->retries_total = PM_PACKET_RETRIES_TOTAL_DEFAULT;
		pm->retries_mode = PM_RETRIES_MODE_THRESHOLD;
		pm->ifindex_out = IFINDEX_INTERNAL;
	}

	/* check if consistent */
	if (pm->key.vrfname[0])
		vrf = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf) {
		snprintf(ebuf, ebuflen, "session to %s, vrf %s not available",
			 pm->key.peer, pm->key.vrfname);
		return;
	}

	ret = str2sockunion(pm->key.peer, &peer);
	/* it may be an hostname - try with ipv6 resolution */
	if (ret) {
		if (sockunion_family(&pm->peer) != AF_INET &&
		    sockunion_family(&pm->peer) != AF_INET6) {
			if (PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_RESOLUTION_ON)) {
				snprintf(ebuf, ebuflen,
					 "session to %s, resolution in progress",
					 pm->key.peer);
				return;
			}
			pm->afi_resolve = AF_INET6;
			if (sockunion_family(&pm->key.local) == AF_INET ||
			    sockunion_family(&pm->key.local) == AF_INET6)
				pm->afi_resolve = sockunion_family(&pm->key.local);
			snprintf(ebuf, ebuflen,
				 "session to %s, trying to resolve IP",
				 pm->key.peer);
			pm->flags |= PM_SESS_FLAG_RESOLUTION_ON;
			thread_add_timer(master, pm_session_peer_resolve, pm, 0,
					 &pm->t_resolve);
			return;
		}
	} else {
		memcpy(&pm->peer, &peer, sizeof(union sockunion));
		pm_zebra_nht_register(pm, true, NULL);
	}
	/* Validate address families. */
	if (sockunion_family(&pm->key.local) == AF_INET ||
	    sockunion_family(&pm->key.local) == AF_INET6) {
		if (sockunion_family(&pm->key.local) !=
		    sockunion_family(&pm->peer)) {
			snprintf(ebuf, ebuflen,
				 "local and peer address families not consistent");
			return;
		}
	}
	if (pm->key.ifname[0]) {
		ifp = if_lookup_by_name_vrf(pm->key.ifname, vrf);
		if (!ifp) {
			snprintf(ebuf, ebuflen,
				 "session to %s, interface %s not available",
				 pm->key.peer, pm->key.ifname);
			return;
		}
	}
	if (sockunion_family(&pm->key.local) == AF_INET ||
	    sockunion_family(&pm->key.local) == AF_INET6) {
		if (!pm_check_local_address(&pm->key.local, vrf)) {
			snprintf(ebuf, ebuflen,
				 "session to %s, local address not available",
				 pm->key.peer);
			return;
		}
	}
	if (pm->interval < pm->timeout) {
		snprintf(ebuf, ebuflen,
			 "session to %s, timeout %u greater than interval %u",
			 buf, pm->timeout, pm->interval);
		return;
	}
	pm->flags |= PM_SESS_FLAG_VALIDATE;

}

/* Lookup functions. */
static struct pm_echo *pm_id_list_lookup(uint32_t id)
{
	struct pm_echo pme;

	pme.discriminator_id = id;

	return hash_lookup(pm_id_list, &pme);
}

uint32_t pm_id_list_gen_id(void)
{
	uint32_t session_id;

	do {
		session_id = ((random() << 16) & 0xFFFF0000)
			     | (random() & 0x0000FFFF);
	} while (session_id == 0 || pm_id_list_lookup(session_id) != NULL);

	return session_id;
}

void pm_id_list_delete(struct pm_echo *pm)
{
	hash_release(pm_id_list, pm);
}

bool pm_id_list_insert(struct pm_echo *pm)
{
	return (hash_get(pm_id_list, pm, hash_alloc_intern) == pm);
}

static void pm_session_free_walker(struct hash_bucket *b, void *data)
{
	struct pm_session *pm = (struct pm_session *)b->data;
	char errormsg[128];

	QOBJ_UNREG(pm);
	pm_echo_stop(pm, errormsg, sizeof(errormsg), true);
	THREAD_OFF(pm->t_resolve);
	hash_release(pm_session_list, pm);
	XFREE(MTYPE_PM_SESSION, pm);
}

void pm_shutdown(void)
{
	hash_iterate(pm_session_list,
		     pm_session_free_walker, NULL);
}

void pm_init(void)
{
	pm_session_list  = hash_create_size(8, pm_session_hash_key,
					    pm_session_hash_equal,
					    "Session Hash");
	pm_id_list = hash_create_size(8, pm_id_list_hash_do,
				      pm_id_list_hash_cmp,
				      "PM unique identifier");
	pm_debug_echo = 0;
}

void pm_try_run(struct vty *vty, struct pm_session *pm)
{
	char errormsg[128];
	char buf[SU_ADDRSTRLEN];
	int ret;

	if (PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN))
		return;

	/* check config is consistent */
	pm_initialise(pm, true, errormsg, sizeof(errormsg));
	if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_VALIDATE)) {
		if (vty)
			vty_out(vty, "%% session could not be started: %s\n",
				errormsg);
		else
			zlog_err("%% session could not be started: %s",
				 errormsg);
		return;
	}

	if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_NH_VALID)) {
		if (vty)
			vty_out(vty, "%% session to %s (%s) could not be started:"
				" peer or gateway not resolved via nht\n",
				sockunion2str(&pm->peer,
					      buf, sizeof(buf)),
				pm->key.peer);
		else
			zlog_err("%% session to %s (%s) could not be started:"
				 " peer or gateway not resolved via nht",
				 sockunion2str(&pm->peer,
					       buf, sizeof(buf)),
				 pm->key.peer);
		return;
	}

	/* flush previous context if necessary */
	pm_echo_stop(pm, errormsg, sizeof(errormsg), false);
	/* rerun it */
	ret = pm_echo(pm, errormsg, sizeof(errormsg));
	if (ret) {
		if (vty)
			vty_out(vty, "%% session could not be run: %s\n",
				errormsg);
		else
			zlog_info("%% session could not be run: %s",
				 errormsg);
		return;
	}
	PM_SET_FLAG(pm->flags, PM_SESS_FLAG_RUN);
	if (vty)
		vty_out(vty, "%% session to %s(%s) runs now\n",
			sockunion2str(&pm->peer, buf, sizeof(buf)),
			pm->key.peer);
	else
		zlog_info("%% session to %s(%s) runs now",
			  sockunion2str(&pm->peer, buf, sizeof(buf)),
			  pm->key.peer);
}

struct pm_nht_ctx {
	vrf_id_t vrf_id;
	union sockunion peer;
	uint32_t nh_num;
	ifindex_t idx;
	struct vty *vty;
};

static int pm_nht_update_walkcb(struct hash_bucket *backet, void *arg)
{
	struct pm_nht_ctx *pnc = (struct pm_nht_ctx *)arg;
	struct pm_session *pm = (struct pm_session *)backet->data;
	struct vty *vty = pnc->vty;
	struct vrf *vrf;
	bool orig, new;
	bool reinstall = false;
	char buf[SU_ADDRSTRLEN];
	char errormsg[128];

	if (pm->key.vrfname[0])
		vrf = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf)
		return HASHWALK_CONTINUE;
	if (vrf->vrf_id != pnc->vrf_id)
		return HASHWALK_CONTINUE;
	if (!sockunion_same(&pm->peer, &pnc->peer) &&
	    !sockunion_same(&pm->nh, &pnc->peer))
		return HASHWALK_CONTINUE;
	orig = PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_NH_VALID);
	new = !!pnc->nh_num;
	if (orig != new)
		reinstall = true;
	if (reinstall) {
		if (!new) {
			zlog_info("PMD: session to %s,"
				  "NHT fails to reach address",
				  sockunion2str(&pm->peer,
						buf, sizeof(buf)));
			PM_UNSET_FLAG(pm->flags, PM_SESS_FLAG_NH_VALID);
			PM_UNSET_FLAG(pm->flags, PM_SESS_FLAG_RUN);
			pm_echo_trigger_down_event(pm);
			pm->ifindex_out = IFINDEX_INTERNAL;
			/* because nexthop failed, stop emitting */
			pm_echo_stop(pm, errormsg, sizeof(errormsg), false);
		} else {
			pm->ifindex_out = pnc->idx;
			zlog_info("PMD: session to %s, NHT OK",
				  sockunion2str(&pm->peer,
						buf, sizeof(buf)));
			PM_SET_FLAG(pm->flags, PM_SESS_FLAG_NH_VALID);
			pm_try_run(vty, pm);
		}
	}
	return HASHWALK_CONTINUE;
}

void pm_nht_update(struct prefix *p, uint32_t nh_num, afi_t afi,
		   vrf_id_t nh_vrf_id, struct vty *vty, ifindex_t idx)
{
	struct pm_nht_ctx pnc;

	memset(&pnc, 0, sizeof(struct pm_nht_ctx));
	pnc.vty = vty;
	pnc.peer.sa.sa_family = p->family;
	if (afi == AFI_IP)
		pnc.peer.sin.sin_addr = p->u.prefix4;
	else if (afi == AFI_IP6)
		memcpy(&pnc.peer.sin6.sin6_addr, &p->u.prefix6,
		       sizeof(struct in6_addr));
	pnc.vrf_id = nh_vrf_id;
	pnc.nh_num = nh_num;
	pnc.idx = idx;
	hash_walk(pm_session_list, pm_nht_update_walkcb, &pnc);
}

struct pm_session_vrf {
	struct vrf *vrf;
	bool enable;
};

struct pm_session_ifp {
	struct interface *ifp;
	bool enable;
};

static int pm_sessions_change_ifp_walkcb(struct hash_bucket *backet, void *arg)
{
	struct pm_session_ifp *psi = (struct pm_session_ifp *)arg;
	struct pm_session *pm = (struct pm_session *)backet->data;
	struct interface *ifp = psi->ifp;
	bool enable = psi->enable;
	struct interface *if_ctx;
	struct vrf *vrf, *vrf_ctx;
	char errormsg[128];

	vrf = vrf_lookup_by_id(ifp->vrf_id);
	if (!vrf)
		return HASHWALK_CONTINUE;

	if (pm->key.vrfname[0])
		vrf_ctx = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf_ctx = vrf_lookup_by_id(VRF_DEFAULT);
	if (vrf_ctx != vrf)
		return HASHWALK_CONTINUE;

	if (!pm->key.ifname[0])
		return HASHWALK_CONTINUE;
	if_ctx = if_lookup_by_name(pm->key.ifname, vrf->vrf_id);
	if (!if_ctx)
		return HASHWALK_CONTINUE;
	if (if_ctx != ifp)
		return HASHWALK_CONTINUE;
	if (!enable) {
		pm_echo_stop(pm, errormsg, sizeof(errormsg), true);
		pm_zebra_nht_register(pm, false, NULL);
	} else
		pm_zebra_nht_register(pm, true, NULL);

	return HASHWALK_CONTINUE;
}

static int pm_sessions_change_vrf_walkcb(struct hash_bucket *backet, void *arg)
{
	struct pm_session_vrf *psv = (struct pm_session_vrf *)arg;
	struct pm_session *pm = (struct pm_session *)backet->data;
	struct vrf *vrf = psv->vrf;
	bool enable = psv->enable;
	struct vrf *vrf_ctx;
	char errormsg[128];

	if (pm->key.vrfname[0])
		vrf_ctx = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf_ctx = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf)
		return HASHWALK_CONTINUE;
	if (vrf_ctx != vrf)
		return HASHWALK_CONTINUE;
	if (!enable) {
		pm_echo_stop(pm, errormsg, sizeof(errormsg), true);
		pm_zebra_nht_register(pm, false, NULL);
	} else
		pm_zebra_nht_register(pm, true, NULL);
	return HASHWALK_CONTINUE;
}

/* enable or disable vrf triggers pm_echo status */
static void pm_sessions_change_vrf(struct vrf *vrf, bool enable)
{
	struct pm_session_vrf psv;

	psv.vrf = vrf;
	psv.enable = enable;

	hash_walk(pm_session_list, pm_sessions_change_vrf_walkcb, &psv);
}

void pm_sessions_change_interface(struct interface *ifp, bool enable)
{
	struct pm_session_ifp psi;

	psi.ifp = ifp;
	psi.enable = enable;

	hash_walk(pm_session_list, pm_sessions_change_ifp_walkcb, &psi);
}

char *pm_get_probe_type(struct pm_session *pm, char *buf, size_t len)
{
	memset(buf, 0, len);

	switch (pm->type) {
	case PM_ICMP_ECHO:
		snprintf(buf, len, "icmp_echo");
		break;
	case PM_ICMP_TIMESTAMP:
		snprintf(buf, len, "icmp_timestamp");
		break;
	}
	return buf;
}

char *pm_get_state_str(struct pm_session *pm, char *buf, size_t len)
{
	memset(buf, 0, len);

	switch (pm->ses_state) {
	case PM_ADM_DOWN:
		snprintf(buf, len, "admin down");
		break;
	case PM_DOWN:
		snprintf(buf, len, "down");
		break;
	case PM_INIT:
		snprintf(buf, len, "init");
		break;
	case PM_UP:
		snprintf(buf, len, "up");
		break;
	default:
		break;
	}
	return buf;
}

static void pm_session_validate_walker(struct hash_bucket *b, void *data)
{
	struct pm_session *pm = (struct pm_session *)b->data;

	if (PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_VALIDATE))
		return;
	if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_RUN))
		pm_try_run(NULL, pm);
}

/* event from underlying system - new address or new vrf */
void pm_sessions_update(void)
{
	hash_iterate(pm_session_list,
		     pm_session_validate_walker, NULL);
}

void pm_get_peer(struct pm_session *pm, union sockunion *peer)
{
	int ret;

	if (!peer || !pm)
		return;
	memset(peer, 0, sizeof(union sockunion));
	ret = hook_call(pm_tracking_get_dest_address, pm, peer);
	if (!ret)
		memcpy(peer, &pm->peer, sizeof(union sockunion));
}

void pm_get_gw(struct pm_session *pm, union sockunion *gw)
{
	int ret;

	if (!gw || !pm)
		return;
	memset(gw, 0, sizeof(union sockunion));
	ret = hook_call(pm_tracking_get_gateway_address, pm, gw);
	if (!ret) {
		if (sockunion_family(&pm->nh) == AF_INET ||
		    sockunion_family(&pm->nh) == AF_INET6)
			memcpy(gw, &pm->nh, sizeof(union sockunion));
		else
			pm_get_peer(pm, gw);
	}
}

static int pm_vrf_new(struct vrf *vrf)
{
	zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);
	return 0;
}

static int pm_vrf_delete(struct vrf *vrf)
{
	zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);
	return 0;
}

static int pm_vrf_enable(struct vrf *vrf)
{
	zlog_debug("VRF enable add %s id %u", vrf->name, vrf->vrf_id);

	if (!strmatch(vrf->name, VRF_DEFAULT_NAME)) {
		pm_zclient_register(vrf->vrf_id);
		pm_sessions_change_vrf(vrf, true);
	}
	return 0;
}

static int pm_vrf_disable(struct vrf *vrf)
{
	if (!strmatch(vrf->name, VRF_DEFAULT_NAME)) {
		pm_sessions_change_vrf(vrf, false);
		pm_zclient_unregister(vrf->vrf_id);
	}

	zlog_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	return 0;
}

void pm_vrf_init(void)
{
	vrf_init(pm_vrf_new, pm_vrf_enable, pm_vrf_disable,
		 pm_vrf_delete, NULL);
	vrf_cmd_init(NULL, NULL);
}

void pm_vrf_terminate(void)
{
	vrf_terminate();
}

void pm_set_sess_state(struct pm_session *pm, uint8_t ses_state)
{
	if (pm->ses_state == ses_state)
		return;
	pm->ses_state = ses_state;
	monotime(&pm->last_time_change);

	pm_zebra_notify(pm);
}
