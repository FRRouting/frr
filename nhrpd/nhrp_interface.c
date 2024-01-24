// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP interface
 * Copyright (c) 2014-2015 Timo Teräs
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <net/if_arp.h>
#include "zebra.h"
#include "linklist.h"
#include "memory.h"
#include "frrevent.h"

#include "nhrpd.h"
#include "os.h"
#include "hash.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_IF, "NHRP interface");
DEFINE_MTYPE_STATIC(NHRPD, NHRP_IF_GRE, "NHRP GRE interface");

struct hash *nhrp_gre_list;

static void nhrp_interface_update_cache_config(struct interface *ifp,
					       bool available,
					       uint8_t family);

static unsigned int nhrp_gre_info_key(const void *data)
{
	const struct nhrp_gre_info *r = data;

	return r->ifindex;
}

static bool nhrp_gre_info_cmp(const void *data, const void *key)
{
	const struct nhrp_gre_info *a = data, *b = key;

	if (a->ifindex == b->ifindex)
		return true;
	return false;
}

static void *nhrp_interface_gre_alloc(void *data)
{
	struct nhrp_gre_info *a;
	struct nhrp_gre_info *b = data;

	a = XMALLOC(MTYPE_NHRP_IF_GRE, sizeof(struct nhrp_gre_info));
	memcpy(a, b, sizeof(struct nhrp_gre_info));
	return a;
}

struct nhrp_gre_info *nhrp_gre_info_alloc(struct nhrp_gre_info *p)
{
	struct nhrp_gre_info *a;

	a = (struct nhrp_gre_info *)hash_get(nhrp_gre_list, p,
					     nhrp_interface_gre_alloc);
	return a;
}

static int nhrp_if_new_hook(struct interface *ifp)
{
	struct nhrp_interface *nifp;
	afi_t afi;

	nifp = XCALLOC(MTYPE_NHRP_IF, sizeof(struct nhrp_interface));

	ifp->info = nifp;
	nifp->ifp = ifp;

	notifier_init(&nifp->notifier_list);
	for (afi = 0; afi < AFI_MAX; afi++) {
		struct nhrp_afi_data *ad = &nifp->afi[afi];
		ad->holdtime = NHRPD_DEFAULT_HOLDTIME;
		nhrp_nhslist_init(&ad->nhslist_head);
		nhrp_mcastlist_init(&ad->mcastlist_head);
	}

	return 0;
}

static int nhrp_if_delete_hook(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;

	debugf(NHRP_DEBUG_IF, "Deleted interface (%s)", ifp->name);

	nhrp_cache_interface_del(ifp);
	nhrp_nhs_interface_del(ifp);
	nhrp_multicast_interface_del(ifp);
	nhrp_peer_interface_del(ifp);

	if (nifp->ipsec_profile)
		free(nifp->ipsec_profile);
	if (nifp->ipsec_fallback_profile)
		free(nifp->ipsec_fallback_profile);
	if (nifp->source)
		free(nifp->source);

	XFREE(MTYPE_NHRP_IF, ifp->info);
	return 0;
}

void nhrp_interface_init(void)
{
	hook_register_prio(if_add, 0, nhrp_if_new_hook);
	hook_register_prio(if_del, 0, nhrp_if_delete_hook);

	nhrp_gre_list = hash_create(nhrp_gre_info_key, nhrp_gre_info_cmp,
				    "NHRP GRE list Hash");
}

void nhrp_interface_update_mtu(struct interface *ifp, afi_t afi)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_afi_data *if_ad = &nifp->afi[afi];
	unsigned short new_mtu;

	if (if_ad->configured_mtu < 0)
		new_mtu = nifp->nbmaifp ? nifp->nbmaifp->mtu : 0;
	else
		new_mtu = if_ad->configured_mtu;
	if (new_mtu >= 1500)
		new_mtu = 0;

	if (new_mtu != if_ad->mtu) {
		debugf(NHRP_DEBUG_IF, "%s: MTU changed to %d", ifp->name,
		       new_mtu);
		if_ad->mtu = new_mtu;
		notifier_call(&nifp->notifier_list,
			      NOTIFY_INTERFACE_MTU_CHANGED);
	}
}

static void nhrp_interface_update_source(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;

	if (!nifp->source || !nifp->nbmaifp
	    || ((ifindex_t)nifp->link_idx == nifp->nbmaifp->ifindex
		&& (nifp->link_vrf_id == nifp->nbmaifp->vrf->vrf_id)))
		return;

	nifp->link_idx = nifp->nbmaifp->ifindex;
	nifp->link_vrf_id = nifp->nbmaifp->vrf->vrf_id;
	debugf(NHRP_DEBUG_IF, "%s: bound device index changed to %d, vr %u",
	       ifp->name, nifp->link_idx, nifp->link_vrf_id);
	nhrp_send_zebra_gre_source_set(ifp, nifp->link_idx, nifp->link_vrf_id);
}

static void nhrp_interface_interface_notifier(struct notifier_block *n,
					      unsigned long cmd)
{
	struct nhrp_interface *nifp =
		container_of(n, struct nhrp_interface, nbmanifp_notifier);
	struct interface *nbmaifp = nifp->nbmaifp;
	struct nhrp_interface *nbmanifp = nbmaifp->info;

	switch (cmd) {
	case NOTIFY_INTERFACE_CHANGED:
		nhrp_interface_update_nbma(nifp->ifp, NULL);
		break;
	case NOTIFY_INTERFACE_ADDRESS_CHANGED:
		nifp->nbma = nbmanifp->afi[AFI_IP].addr;
		nhrp_interface_update(nifp->ifp);
		notifier_call(&nifp->notifier_list,
			      NOTIFY_INTERFACE_NBMA_CHANGED);
		debugf(NHRP_DEBUG_IF, "%s: NBMA change: address %pSU",
		       nifp->ifp->name, &nifp->nbma);
		break;
	}
}

void nhrp_interface_update_nbma(struct interface *ifp,
				struct nhrp_gre_info *gre_info)
{
	struct nhrp_interface *nifp = ifp->info, *nbmanifp = NULL;
	struct interface *nbmaifp = NULL;
	union sockunion nbma;
	struct in_addr saddr = {0};

	sockunion_family(&nbma) = AF_UNSPEC;

	if (nifp->source)
		nbmaifp = if_lookup_by_name(nifp->source, nifp->link_vrf_id);

	if (ifp->ll_type != ZEBRA_LLT_IPGRE)
		debugf(NHRP_DEBUG_IF, "%s: Ignoring non GRE interface type %u",
		       __func__, ifp->ll_type);
	else {
		if (!gre_info) {
			nhrp_send_zebra_gre_request(ifp);
			return;
		}
		nifp->i_grekey = gre_info->ikey;
		nifp->o_grekey = gre_info->okey;
		nifp->link_idx = gre_info->ifindex_link;
		nifp->link_vrf_id = gre_info->vrfid_link;
		saddr.s_addr = gre_info->vtep_ip.s_addr;

		debugf(NHRP_DEBUG_IF, "%s: GRE: %x %x %x", ifp->name,
		       nifp->i_grekey, nifp->link_idx, saddr.s_addr);
		if (saddr.s_addr)
			sockunion_set(&nbma, AF_INET,
				      (uint8_t *)&saddr.s_addr,
				      sizeof(saddr.s_addr));
		else if (!nbmaifp && nifp->link_idx != IFINDEX_INTERNAL)
			nbmaifp =
				if_lookup_by_index(nifp->link_idx,
						   nifp->link_vrf_id);
	}

	if (nbmaifp)
		nbmanifp = nbmaifp->info;

	if (nbmaifp != nifp->nbmaifp) {
		if (nifp->nbmaifp) {
			struct nhrp_interface *prev_nifp = nifp->nbmaifp->info;

			notifier_del(&nifp->nbmanifp_notifier,
				     &prev_nifp->notifier_list);
		}
		nifp->nbmaifp = nbmaifp;
		if (nbmaifp) {
			notifier_add(&nifp->nbmanifp_notifier,
				     &nbmanifp->notifier_list,
				     nhrp_interface_interface_notifier);
			debugf(NHRP_DEBUG_IF, "%s: bound to %s", ifp->name,
			       nbmaifp->name);
		}
	}

	if (nbmaifp) {
		if (sockunion_family(&nbma) == AF_UNSPEC)
			nbma = nbmanifp->afi[AFI_IP].addr;
		nhrp_interface_update_mtu(ifp, AFI_IP);
		nhrp_interface_update_source(ifp);
	}

	if (!sockunion_same(&nbma, &nifp->nbma)) {
		nifp->nbma = nbma;
		nhrp_interface_update(nifp->ifp);
		debugf(NHRP_DEBUG_IF, "%s: NBMA address changed", ifp->name);
		notifier_call(&nifp->notifier_list,
			      NOTIFY_INTERFACE_NBMA_CHANGED);
	}

	nhrp_interface_update(ifp);
}

static void nhrp_interface_update_address(struct interface *ifp, afi_t afi,
					  int force)
{
	const int family = afi2family(afi);
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_afi_data *if_ad = &nifp->afi[afi];
	struct nhrp_cache *nc;
	struct connected *c, *best;
	union sockunion addr;
	char buf[PREFIX_STRLEN];

	/* Select new best match preferring primary address */
	best = NULL;
	frr_each (if_connected, ifp->connected, c) {
		if (PREFIX_FAMILY(c->address) != family)
			continue;
		if (best == NULL) {
			best = c;
			continue;
		}
		if ((best->flags & ZEBRA_IFA_SECONDARY)
		    && !(c->flags & ZEBRA_IFA_SECONDARY)) {
			best = c;
			continue;
		}
		if (!(best->flags & ZEBRA_IFA_SECONDARY)
		    && (c->flags & ZEBRA_IFA_SECONDARY))
			continue;
		if (best->address->prefixlen > c->address->prefixlen) {
			best = c;
			continue;
		}
		if (best->address->prefixlen < c->address->prefixlen)
			continue;
	}

	/* On NHRP interfaces a host prefix is required */
	if (best && if_ad->configured
	    && best->address->prefixlen != 8 * prefix_blen(best->address)) {
		zlog_notice("%s: %pFX is not a host prefix", ifp->name,
			    best->address);
		best = NULL;
	}

	/* Update address if it changed */
	if (best)
		prefix2sockunion(best->address, &addr);
	else
		memset(&addr, 0, sizeof(addr));

	if (!force && sockunion_same(&if_ad->addr, &addr))
		return;

	if (sockunion_family(&if_ad->addr) != AF_UNSPEC) {
		nc = nhrp_cache_get(ifp, &if_ad->addr, 0);
		if (nc)
			nhrp_cache_update_binding(nc, NHRP_CACHE_LOCAL, -1,
						  NULL, 0, NULL, NULL);
	}

	debugf(NHRP_DEBUG_KERNEL, "%s: IPv%d address changed to %s", ifp->name,
	       afi == AFI_IP ? 4 : 6,
	       best ? prefix2str(best->address, buf, sizeof(buf)) : "(none)");
	if_ad->addr = addr;

	if (if_ad->configured && sockunion_family(&if_ad->addr) != AF_UNSPEC) {
		nc = nhrp_cache_get(ifp, &addr, 1);
		if (nc)
			nhrp_cache_update_binding(nc, NHRP_CACHE_LOCAL, 0, NULL,
						  0, NULL, NULL);
	}

	notifier_call(&nifp->notifier_list, NOTIFY_INTERFACE_ADDRESS_CHANGED);
}

void nhrp_interface_update(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_afi_data *if_ad;
	afi_t afi;
	int enabled = 0;

	notifier_call(&nifp->notifier_list, NOTIFY_INTERFACE_CHANGED);

	for (afi = 0; afi < AFI_MAX; afi++) {
		if_ad = &nifp->afi[afi];

		if (sockunion_family(&nifp->nbma) == AF_UNSPEC
		    || ifp->ifindex == IFINDEX_INTERNAL || !if_is_up(ifp)
		    || !if_ad->network_id) {
			if (if_ad->configured) {
				if_ad->configured = 0;
				nhrp_interface_update_address(ifp, afi, 1);
			}
			continue;
		}

		if (!if_ad->configured) {
			os_configure_dmvpn(ifp->ifindex, ifp->name,
					   afi2family(afi));
			nhrp_interface_update_arp(ifp, true);
			nhrp_send_zebra_configure_arp(ifp, afi2family(afi));
			if_ad->configured = 1;
			nhrp_interface_update_address(ifp, afi, 1);
		}

		enabled = 1;
	}

	if (enabled != nifp->enabled) {
		nifp->enabled = enabled;
		notifier_call(&nifp->notifier_list,
			      enabled ? NOTIFY_INTERFACE_UP
				      : NOTIFY_INTERFACE_DOWN);
	}
}

int nhrp_ifp_create(struct interface *ifp)
{
	debugf(NHRP_DEBUG_IF, "if-add: %s, ifindex: %u, hw_type: %d %s",
	       ifp->name, ifp->ifindex, ifp->ll_type,
	       if_link_type_str(ifp->ll_type));

	nhrp_interface_update_nbma(ifp, NULL);

	return 0;
}

int nhrp_ifp_destroy(struct interface *ifp)
{
	debugf(NHRP_DEBUG_IF, "if-delete: %s", ifp->name);

	nhrp_interface_update_cache_config(ifp, false, AF_INET);
	nhrp_interface_update_cache_config(ifp, false, AF_INET6);
	nhrp_interface_update(ifp);

	return 0;
}

struct map_ctx {
	int family;
	bool enabled;
};

static void interface_config_update_nhrp_map(struct nhrp_cache_config *cc,
					     void *data)
{
	struct map_ctx *ctx = data;
	struct interface *ifp = cc->ifp;
	struct nhrp_cache *c;
	union sockunion nbma_addr;

	if (sockunion_family(&cc->remote_addr) != ctx->family)
		return;

	/* gre layer not ready */
	if (ifp->vrf->vrf_id == VRF_UNKNOWN)
		return;

	c = nhrp_cache_get(ifp, &cc->remote_addr, ctx->enabled ? 1 : 0);
	if (!c && !ctx->enabled)
		return;

	/* suppress */
	if (!ctx->enabled) {
		if (c && c->map) {
			nhrp_cache_update_binding(
				c, c->cur.type, -1,
				nhrp_peer_get(ifp, &nbma_addr), 0, NULL, NULL);
		}
		return;
	}

	/* Newly created */
	assert(c != NULL);

	c->map = 1;
	if (cc->type == NHRP_CACHE_LOCAL)
		nhrp_cache_update_binding(c, NHRP_CACHE_LOCAL, 0, NULL, 0,
					  NULL, NULL);
	else {
		nhrp_cache_update_binding(c, NHRP_CACHE_STATIC, 0,
					  nhrp_peer_get(ifp, &cc->nbma), 0,
					  NULL, NULL);
	}
}

static void nhrp_interface_update_cache_config(struct interface *ifp, bool available, uint8_t family)
{
	struct map_ctx mapctx;

	mapctx = (struct map_ctx){
		.family = family,
		.enabled = available
	};
	nhrp_cache_config_foreach(ifp, interface_config_update_nhrp_map,
				  &mapctx);

}

int nhrp_ifp_up(struct interface *ifp)
{
	debugf(NHRP_DEBUG_IF, "if-up: %s", ifp->name);
	nhrp_interface_update_nbma(ifp, NULL);

	return 0;
}

int nhrp_ifp_down(struct interface *ifp)
{
	debugf(NHRP_DEBUG_IF, "if-down: %s", ifp->name);
	nhrp_interface_update(ifp);

	return 0;
}

int nhrp_interface_address_add(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return 0;

	debugf(NHRP_DEBUG_IF, "if-addr-add: %s: %pFX", ifc->ifp->name,
	       ifc->address);

	nhrp_interface_update_address(
		ifc->ifp, family2afi(PREFIX_FAMILY(ifc->address)), 0);
	nhrp_interface_update_cache_config(ifc->ifp, true, PREFIX_FAMILY(ifc->address));
	return 0;
}

int nhrp_interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (ifc == NULL)
		return 0;

	debugf(NHRP_DEBUG_IF, "if-addr-del: %s: %pFX", ifc->ifp->name,
	       ifc->address);

	nhrp_interface_update_address(
		ifc->ifp, family2afi(PREFIX_FAMILY(ifc->address)), 0);
	connected_free(&ifc);

	return 0;
}

void nhrp_interface_notify_add(struct interface *ifp, struct notifier_block *n,
			       notifier_fn_t fn)
{
	struct nhrp_interface *nifp = ifp->info;

	notifier_add(n, &nifp->notifier_list, fn);
}

void nhrp_interface_notify_del(struct interface *ifp, struct notifier_block *n)
{
	struct nhrp_interface *nifp = ifp->info;

	notifier_del(n, &nifp->notifier_list);
}

void nhrp_interface_set_protection(struct interface *ifp, const char *profile,
				   const char *fallback_profile)
{
	struct nhrp_interface *nifp = ifp->info;

	if (nifp->ipsec_profile) {
		vici_terminate_vc_by_profile_name(nifp->ipsec_profile);
		nhrp_vc_reset();
		free(nifp->ipsec_profile);
	}
	nifp->ipsec_profile = profile ? strdup(profile) : NULL;

	if (nifp->ipsec_fallback_profile) {
		vici_terminate_vc_by_profile_name(nifp->ipsec_fallback_profile);
		nhrp_vc_reset();
		free(nifp->ipsec_fallback_profile);
	}
	nifp->ipsec_fallback_profile =
		fallback_profile ? strdup(fallback_profile) : NULL;

	notifier_call(&nifp->notifier_list, NOTIFY_INTERFACE_IPSEC_CHANGED);
}

void nhrp_interface_set_source(struct interface *ifp, const char *ifname)
{
	struct nhrp_interface *nifp = ifp->info;

	if (nifp->source)
		free(nifp->source);
	nifp->source = ifname ? strdup(ifname) : NULL;

	nhrp_interface_update_nbma(ifp, NULL);
}
