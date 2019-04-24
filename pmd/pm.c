/*
 * PMD - Path Monitoring Daemon
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

#include <jhash.h>
#include <hash.h>
#include <memory.h>
#include <vrf.h>
#include <if.h>
#include <prefix.h>
#include <prefix.h>

#include "pmd/pm.h"
#include "pmd/pm_echo.h"
#include "pmd/pm_memory.h"
/* definitions */

struct hash *pm_session_list;
struct hash *pm_id_list;

DEFINE_QOBJ_TYPE(pm_session);

DEFINE_MGROUP(PMD, "Path Monitoring Daemon")
DEFINE_MTYPE(PMD, PM_SESSION, "PM sessions")
DEFINE_MTYPE(PMD, PM_ECHO, "PM Echo contexts")
DEFINE_MTYPE(PMD, PM_PACKET, "PM Packets")

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

	if (memcmp(&a1->key.peer, &a2->key.peer, sizeof(union sockunion)))
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
	if (sockunion_family(&pm->key.peer) == AF_INET6)
		return PM_PACKET_SIZE_DEFAULT_IPV6;
	return PM_PACKET_SIZE_DEFAULT;
}

struct pm_session *pm_lookup_session(union sockunion *peer,
				     const char *local,
				     const char *ifname,
				     const char *vrfname,
				     bool create,
				     char *ebuf, size_t ebuflen)
{
	union sockunion lsa, *lsap;
	struct pm_session pm;
	struct pm_session *pm_search;

	if (local) {
		str2sockunion(local, &lsa);
		lsap = &lsa;
	} else
		lsap = NULL;

	/* Validate address families. */
	if (sockunion_family(peer) != AF_INET &&
	    sockunion_family(peer) != AF_INET6) {
		snprintf(ebuf, ebuflen, "invalid peer address family");
		return NULL;
	}
	if (lsap && sockunion_family(peer) !=
	    sockunion_family(lsap)) {
		snprintf(ebuf, ebuflen,
			 "local and peer address families not consistent");
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
	memcpy(&pm.key.peer, peer, sizeof(union sockunion));
	if (lsap)
		memcpy(&pm.key.local, lsap, sizeof(union sockunion));
	if (ifname)
		memcpy(&pm.key.ifname, ifname, strlen(ifname));
	if (vrfname)
		memcpy(&pm.key.vrfname, vrfname, strlen(vrfname));
	pm_search = hash_lookup(pm_session_list, &pm);
	if (pm_search || !create)
		return pm_search;
	/* create */
	pm_search = hash_get(pm_session_list,
			     &pm,
			     pm_session_alloc_intern);
	return pm_search;
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

void pm_initialise(struct pm_session *pm, bool validate_only,
		   char *ebuf, size_t ebuflen)
{
	struct vrf *vrf;
	struct interface *ifp = NULL;
	char buf[SU_ADDRSTRLEN];

	sockunion2str(&pm->key.peer, buf, sizeof(buf));
	if (!validate_only) {
		/* initialise - config by default */
		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_CONFIG);
		/* initialise - shutdown by default */
		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN);
		pm->timeout = PM_TIMEOUT_DEFAULT;
		pm->interval = PM_INTERVAL_DEFAULT;
		pm->packet_size = pm_get_default_packet_size(pm);
		pm->tos_val = PM_PACKET_TOS_DEFAULT;
	}

	/* check if consistent */
	if (pm->key.vrfname[0])
		vrf = vrf_lookup_by_name(pm->key.vrfname);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf) {
		snprintf(ebuf, ebuflen, "session to %s, vrf %s not available",
			 buf, pm->key.vrfname);
		return;
	}
	if (pm->key.ifname[0]) {
		ifp = if_lookup_by_name(pm->key.ifname, vrf->vrf_id);
		if (!ifp) {
			snprintf(ebuf, ebuflen,
				 "session to %s, interface %s not available",
				 buf, pm->key.ifname);
			return;
		}
	}
	if (sockunion_family(&pm->key.local) == AF_INET ||
	    sockunion_family(&pm->key.local) == AF_INET6) {
		if (!pm_check_local_address(&pm->key.local, vrf)) {
			snprintf(ebuf, ebuflen,
				 "session to %s, local address not available",
				 buf);
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
		vty_out(vty, "%% session could not be started: %s\n",
			errormsg);
		return;
	}
	/* flush previous context if necessary */
	pm_echo_stop(pm, errormsg, sizeof(errormsg), false);
	/* rerun it */
	ret = pm_echo(pm, errormsg, sizeof(errormsg));
	if (ret) {
		vty_out(vty, "%% session could not be run: %s\n",
			errormsg);
		return;
	}
	PM_SET_FLAG(pm->flags, PM_SESS_FLAG_RUN);
	vty_out(vty, "%% session to %s runs now\n",
		sockunion2str(&pm->key.peer, buf, sizeof(buf)));
}

struct pm_session_ifp {
	struct interface *ifp;
	bool enable;
};

static int pm_sessions_change_ifp_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct pm_session_ifp *psi = (struct pm_session_ifp *)arg;
	struct pm_session *pm = (struct pm_session *)bucket->data;
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
	if (!enable)
		pm_echo_stop(pm, errormsg, sizeof(errormsg), true);
	return HASHWALK_CONTINUE;
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
	if (!peer || !pm)
		return;
	memset(peer, 0, sizeof(union sockunion));
	memcpy(peer, &pm->key.peer, sizeof(union sockunion));
}

void pm_get_gw(struct pm_session *pm, union sockunion *gw)
{
	if (!gw || !pm)
		return;
	memset(gw, 0, sizeof(union sockunion));
	if (sockunion_family(&pm->nh) == AF_INET ||
	    sockunion_family(&pm->nh) == AF_INET6)
		memcpy(gw, &pm->nh, sizeof(union sockunion));
	else
		pm_get_peer(pm, gw);
}
