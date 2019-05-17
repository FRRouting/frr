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

#include "pm.h"
#include "pm_zebra.h"

/* Zebra structure to hold current status. */
struct zclient *zclient;
static struct hash *pm_nht_hash;

/* For registering threads. */
extern struct thread_master *master;

struct pm_nht_data {
	struct prefix *nh;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint8_t nh_num;
};

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
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
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

void pm_zebra_nht_register(struct pm_session *pm, bool reg, struct vty *vty)
{
	struct pm_nht_data *nhtd, lookup;
	uint32_t cmd;
	struct prefix p;
	afi_t afi = AFI_IP;
	struct vrf *vrf;

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

void pm_zebra_init(void)
{
	if_zapi_callbacks(pm_zebra_ifp_create, pm_zebra_ifp_up,
			  pm_zebra_ifp_down, pm_zebra_ifp_destroy);

	zclient = zclient_new(master, &zclient_options_default);
	assert(zclient != NULL);
	zclient_init(zclient, ZEBRA_ROUTE_PM, 0, &pm_privs);

	zclient->zebra_connected = zebra_connected;
	zclient->interface_address_add = interface_address_add;
	zclient->interface_address_delete = interface_address_delete;
	zclient->nexthop_update = pm_nexthop_update;

	/* Learn about interface VRF. */
	zclient->interface_vrf_update = pmd_interface_vrf_update;

	pm_nht_hash = hash_create(pm_nht_hash_key,
				  pm_nht_hash_cmp,
				  "PM Nexthop Tracking hash");

}
