// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP peer functions
 * Copyright (c) 2014-2015 Timo Teräs
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/if_ether.h>

#include "zebra.h"
#include "memory.h"
#include "frrevent.h"
#include "hash.h"
#include "network.h"

#include "nhrpd.h"
#include "nhrp_protocol.h"
#include "os.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_PEER, "NHRP peer entry");

struct ipv6hdr {
	uint8_t priority_version;
	uint8_t flow_lbl[3];
	uint16_t payload_len;
	uint8_t nexthdr;
	uint8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

static void nhrp_packet_debug(struct zbuf *zb, const char *dir);

static void nhrp_peer_check_delete(struct nhrp_peer *p)
{
	struct nhrp_interface *nifp = p->ifp->info;

	if (p->ref || notifier_active(&p->notifier_list))
		return;

	debugf(NHRP_DEBUG_COMMON, "Deleting peer ref:%d remote:%pSU local:%pSU",
	       p->ref, &p->vc->remote.nbma, &p->vc->local.nbma);

	EVENT_OFF(p->t_fallback);
	EVENT_OFF(p->t_timer);
	if (nifp->peer_hash)
		hash_release(nifp->peer_hash, p);
	nhrp_interface_notify_del(p->ifp, &p->ifp_notifier);
	nhrp_vc_notify_del(p->vc, &p->vc_notifier);
	XFREE(MTYPE_NHRP_PEER, p);
}

static void nhrp_peer_notify_up(struct event *t)
{
	struct nhrp_peer *p = EVENT_ARG(t);
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;

	p->t_fallback = NULL;
	if (nifp->enabled && (!nifp->ipsec_profile || vc->ipsec)) {
		p->online = 1;
		nhrp_peer_ref(p);
		notifier_call(&p->notifier_list, NOTIFY_PEER_UP);
		nhrp_peer_unref(p);
	}
}

static void __nhrp_peer_check(struct nhrp_peer *p)
{
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;
	unsigned online;

	online = nifp->enabled && (!nifp->ipsec_profile || vc->ipsec);
	if (p->online != online) {
		EVENT_OFF(p->t_fallback);
		if (online && notifier_active(&p->notifier_list)) {
			/* If we requested the IPsec connection, delay
			 * the up notification a bit to allow things
			 * settle down. This allows IKE to install
			 * SPDs and SAs. */
			event_add_timer_msec(master, nhrp_peer_notify_up, p, 50,
					     &p->t_fallback);
		} else {
			nhrp_peer_ref(p);
			p->online = online;
			if (online) {
				notifier_call(&p->notifier_list,
					      NOTIFY_PEER_UP);
			} else {
				p->requested = p->fallback_requested = 0;
				notifier_call(&p->notifier_list,
					      NOTIFY_PEER_DOWN);
			}
			nhrp_peer_unref(p);
		}
	}
}

static void nhrp_peer_vc_notify(struct notifier_block *n, unsigned long cmd)
{
	struct nhrp_peer *p = container_of(n, struct nhrp_peer, vc_notifier);

	switch (cmd) {
	case NOTIFY_VC_IPSEC_CHANGED:
		__nhrp_peer_check(p);
		break;
	case NOTIFY_VC_IPSEC_UPDATE_NBMA:
		nhrp_peer_ref(p);
		notifier_call(&p->notifier_list, NOTIFY_PEER_NBMA_CHANGING);
		nhrp_peer_unref(p);
		break;
	}
}

static void nhrp_peer_ifp_notify(struct notifier_block *n, unsigned long cmd)
{
	struct nhrp_peer *p = container_of(n, struct nhrp_peer, ifp_notifier);
	struct nhrp_interface *nifp;
	struct nhrp_vc *vc;

	nhrp_peer_ref(p);
	switch (cmd) {
	case NOTIFY_INTERFACE_UP:
	case NOTIFY_INTERFACE_DOWN:
		__nhrp_peer_check(p);
		break;
	case NOTIFY_INTERFACE_NBMA_CHANGED:
		/* Source NBMA changed, rebind to new VC */
		nifp = p->ifp->info;
		vc = nhrp_vc_get(&nifp->nbma, &p->vc->remote.nbma, 1);
		if (vc && p->vc != vc) {
			nhrp_vc_notify_del(p->vc, &p->vc_notifier);
			p->vc = vc;
			nhrp_vc_notify_add(p->vc, &p->vc_notifier,
					   nhrp_peer_vc_notify);
			__nhrp_peer_check(p);
		}
		fallthrough; /* to post config update */
	case NOTIFY_INTERFACE_ADDRESS_CHANGED:
		notifier_call(&p->notifier_list, NOTIFY_PEER_IFCONFIG_CHANGED);
		break;
	case NOTIFY_INTERFACE_IPSEC_CHANGED:
		__nhrp_peer_check(p);
		notifier_call(&p->notifier_list, NOTIFY_PEER_IFCONFIG_CHANGED);
		break;
	case NOTIFY_INTERFACE_MTU_CHANGED:
		notifier_call(&p->notifier_list, NOTIFY_PEER_MTU_CHANGED);
		break;
	}
	nhrp_peer_unref(p);
}

static unsigned int nhrp_peer_key(const void *peer_data)
{
	const struct nhrp_peer *p = peer_data;
	return sockunion_hash(&p->vc->remote.nbma);
}

static bool nhrp_peer_cmp(const void *cache_data, const void *key_data)
{
	const struct nhrp_peer *a = cache_data;
	const struct nhrp_peer *b = key_data;

	return a->ifp == b->ifp && a->vc == b->vc;
}

static void *nhrp_peer_create(void *data)
{
	struct nhrp_peer *p, *key = data;

	p = XMALLOC(MTYPE_NHRP_PEER, sizeof(*p));

	*p = (struct nhrp_peer){
		.ref = 0,
		.ifp = key->ifp,
		.vc = key->vc,
		.notifier_list = NOTIFIER_LIST_INITIALIZER(&p->notifier_list),
	};
	nhrp_vc_notify_add(p->vc, &p->vc_notifier, nhrp_peer_vc_notify);
	nhrp_interface_notify_add(p->ifp, &p->ifp_notifier,
				  nhrp_peer_ifp_notify);

	return p;
}

static void do_peer_hash_free(void *hb_data)
{
	struct nhrp_peer *p = (struct nhrp_peer *)hb_data;

	nhrp_peer_check_delete(p);
}

void nhrp_peer_interface_del(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;

	debugf(NHRP_DEBUG_COMMON, "Cleaning up undeleted peer entries (%lu)",
	       nifp->peer_hash ? nifp->peer_hash->count : 0);

	hash_clean_and_free(&nifp->peer_hash, do_peer_hash_free);
}

struct nhrp_peer *nhrp_peer_get(struct interface *ifp,
				const union sockunion *remote_nbma)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_peer key, *p;
	struct nhrp_vc *vc;

	if (!nifp->peer_hash) {
		nifp->peer_hash = hash_create(nhrp_peer_key, nhrp_peer_cmp,
					      "NHRP Peer Hash");
		if (!nifp->peer_hash)
			return NULL;
	}

	vc = nhrp_vc_get(&nifp->nbma, remote_nbma, 1);
	if (!vc)
		return NULL;

	key.ifp = ifp;
	key.vc = vc;

	p = hash_get(nifp->peer_hash, &key, nhrp_peer_create);
	nhrp_peer_ref(p);
	if (p->ref == 1)
		__nhrp_peer_check(p);

	return p;
}

struct nhrp_peer *nhrp_peer_ref(struct nhrp_peer *p)
{
	if (p)
		p->ref++;
	return p;
}

void nhrp_peer_unref(struct nhrp_peer *p)
{
	if (p) {
		p->ref--;
		nhrp_peer_check_delete(p);
	}
}

static void nhrp_peer_request_timeout(struct event *t)
{
	struct nhrp_peer *p = EVENT_ARG(t);
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;


	if (p->online)
		return;

	if (nifp->ipsec_fallback_profile && !p->prio
	    && !p->fallback_requested) {
		p->fallback_requested = 1;
		vici_request_vc(nifp->ipsec_fallback_profile, &vc->local.nbma,
				&vc->remote.nbma, p->prio);
		event_add_timer(master, nhrp_peer_request_timeout, p, 30,
				&p->t_fallback);
	} else {
		p->requested = p->fallback_requested = 0;
	}
}

static void nhrp_peer_defer_vici_request(struct event *t)
{
	struct nhrp_peer *p = EVENT_ARG(t);
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;

	EVENT_OFF(p->t_timer);

	if (p->online) {
		debugf(NHRP_DEBUG_COMMON,
		       "IPsec connection to %pSU already established",
		       &vc->remote.nbma);
	} else {
		vici_request_vc(nifp->ipsec_profile, &vc->local.nbma,
				&vc->remote.nbma, p->prio);
		event_add_timer(master, nhrp_peer_request_timeout, p,
				(nifp->ipsec_fallback_profile && !p->prio) ? 15
									   : 30,
				&p->t_fallback);
	}
}

int nhrp_peer_check(struct nhrp_peer *p, int establish)
{
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;

	if (p->online)
		return 1;
	if (!establish)
		return 0;
	if (p->requested)
		return 0;
	if (!nifp->ipsec_profile)
		return 0;
	if (sockunion_family(&vc->local.nbma) == AF_UNSPEC)
		return 0;
	if (vc->ipsec)
		return 1;

	p->prio = establish > 1;
	p->requested = 1;

	/* All NHRP registration requests are prioritized */
	if (p->prio) {
		vici_request_vc(nifp->ipsec_profile, &vc->local.nbma,
				&vc->remote.nbma, p->prio);
		event_add_timer(master, nhrp_peer_request_timeout, p,
				(nifp->ipsec_fallback_profile && !p->prio) ? 15
									   : 30,
				&p->t_fallback);
	} else {
		/* Maximum timeout is 1 second */
		int r_time_ms = frr_weak_random() % 1000;

		debugf(NHRP_DEBUG_COMMON,
		       "Initiating IPsec connection request to %pSU after %d ms:",
		       &vc->remote.nbma, r_time_ms);
		event_add_timer_msec(master, nhrp_peer_defer_vici_request, p,
				     r_time_ms, &p->t_timer);
	}

	return 0;
}

void nhrp_peer_notify_add(struct nhrp_peer *p, struct notifier_block *n,
			  notifier_fn_t fn)
{
	notifier_add(n, &p->notifier_list, fn);
}

void nhrp_peer_notify_del(struct nhrp_peer *p, struct notifier_block *n)
{
	notifier_del(n, &p->notifier_list);
	nhrp_peer_check_delete(p);
}

void nhrp_peer_send(struct nhrp_peer *p, struct zbuf *zb)
{
	nhrp_packet_debug(zb, "Send");

	if (!p->online)
		return;

	debugf(NHRP_DEBUG_KERNEL, "PACKET: Send %pSU -> %pSU",
	       &p->vc->local.nbma, &p->vc->remote.nbma);

	os_sendmsg(zb->head, zbuf_used(zb), p->ifp->ifindex,
		   sockunion_get_addr(&p->vc->remote.nbma),
		   sockunion_get_addrlen(&p->vc->remote.nbma), ETH_P_NHRP);
	zbuf_reset(zb);
}

static void nhrp_process_nat_extension(struct nhrp_packet_parser *pp,
				       union sockunion *proto,
				       union sockunion *cie_nbma)
{
	union sockunion cie_proto;
	struct zbuf payload;
	struct nhrp_extension_header *ext;
	struct zbuf *extensions;

	if (!cie_nbma)
		return;

	sockunion_family(cie_nbma) = AF_UNSPEC;

	if (!proto || sockunion_family(proto) == AF_UNSPEC)
		return;

	/* Handle extensions */
	extensions = zbuf_alloc(zbuf_used(&pp->extensions));
	if (extensions) {
		zbuf_copy_peek(extensions, &pp->extensions,
				 zbuf_used(&pp->extensions));
		while ((ext = nhrp_ext_pull(extensions, &payload)) != NULL) {
			switch (htons(ext->type)
				& ~NHRP_EXTENSION_FLAG_COMPULSORY) {
			case NHRP_EXTENSION_NAT_ADDRESS:
				/* Process the NBMA and proto address in NAT
				 * extension and update the cache without which
				 * the neighbor table in the kernel contains the
				 * source NBMA address which is not reachable
				 * since it is behind a NAT device
				 */
				debugf(NHRP_DEBUG_COMMON,
				       "shortcut res_resp: Processing NAT Extension for %pSU",
				       proto);
				while (nhrp_cie_pull(&payload, pp->hdr,
						     cie_nbma, &cie_proto)) {
					if (sockunion_family(&cie_proto)
					    == AF_UNSPEC)
						continue;

					if (!sockunion_cmp(proto, &cie_proto)) {
						debugf(NHRP_DEBUG_COMMON,
						       "cie_nbma for proto %pSU is %pSU",
						       proto, cie_nbma);
						break;
					}
				}
			}
		}
		zbuf_free(extensions);
	}
}

static void nhrp_handle_resolution_req(struct nhrp_packet_parser *pp)
{
	struct interface *ifp = pp->ifp;
	struct zbuf *zb, payload;
	struct nhrp_packet_header *hdr;
	struct nhrp_cie_header *cie;
	struct nhrp_extension_header *ext;
	struct nhrp_cache *c;
	union sockunion cie_nbma, cie_nbma_nat, cie_proto, *proto_addr,
		*nbma_addr, *claimed_nbma_addr;
	int holdtime, prefix_len, hostprefix_len;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_peer *peer;
	size_t paylen;

	if (!(pp->if_ad->flags & NHRP_IFF_SHORTCUT)) {
		debugf(NHRP_DEBUG_COMMON, "Shortcuts disabled");
		/* FIXME: Send error indication? */
		return;
	}

	if (pp->if_ad->network_id && pp->route_type == NHRP_ROUTE_OFF_NBMA
	    && pp->route_prefix.prefixlen < 8) {
		debugf(NHRP_DEBUG_COMMON,
		       "Shortcut to more generic than /8 dropped");
		return;
	}

	debugf(NHRP_DEBUG_COMMON, "Parsing and replying to Resolution Req");

	if (nhrp_route_address(ifp, &pp->src_proto, NULL, &peer)
	    != NHRP_ROUTE_NBMA_NEXTHOP)
		return;

	/* Copy payload CIE */
	hostprefix_len = 8 * sockunion_get_addrlen(&pp->if_ad->addr);
	paylen = zbuf_used(&pp->payload);
	debugf(NHRP_DEBUG_COMMON, "shortcut res_rep: paylen %zu", paylen);

	while ((cie = nhrp_cie_pull(&pp->payload, pp->hdr, &cie_nbma,
				    &cie_proto))
	       != NULL) {
		prefix_len = cie->prefix_length;
		debugf(NHRP_DEBUG_COMMON,
		       "shortcut res_rep: parsing CIE with prefixlen=%u",
		       prefix_len);
		if (prefix_len == 0 || prefix_len >= hostprefix_len)
			prefix_len = hostprefix_len;

		if (prefix_len != hostprefix_len
		    && !(pp->hdr->flags
			 & htons(NHRP_FLAG_REGISTRATION_UNIQUE))) {
			cie->code = NHRP_CODE_BINDING_NON_UNIQUE;
			continue;
		}

		/* We currently support only unique prefix registrations */
		if (prefix_len != hostprefix_len) {
			cie->code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
			continue;
		}

		proto_addr = (sockunion_family(&cie_proto) == AF_UNSPEC)
				     ? &pp->src_proto
				     : &cie_proto;

		/* Check for this proto_addr in NHRP_NAT_EXTENSION */
		nhrp_process_nat_extension(pp, proto_addr, &cie_nbma_nat);

		if (sockunion_family(&cie_nbma_nat) == AF_UNSPEC) {
			/* It may be possible that this resolution reply is
			 * coming directly from NATTED Spoke and there is not
			 * NAT Extension present
			 */
			debugf(NHRP_DEBUG_COMMON,
			       "shortcut res_rep: No NAT Extension for %pSU",
			       proto_addr);

			if (!sockunion_same(&pp->src_nbma,
					    &pp->peer->vc->remote.nbma)
			    && !nhrp_nhs_match_ip(&pp->peer->vc->remote.nbma,
						  nifp)) {
				cie_nbma_nat = pp->peer->vc->remote.nbma;
				debugf(NHRP_DEBUG_COMMON,
				       "shortcut res_rep: NAT detected using %pSU as cie_nbma",
				       &cie_nbma_nat);
			}
		}

		if (sockunion_family(&cie_nbma_nat) != AF_UNSPEC)
			nbma_addr = &cie_nbma_nat;
		else if (sockunion_family(&cie_nbma) != AF_UNSPEC)
			nbma_addr = &cie_nbma;
		else
			nbma_addr = &pp->src_nbma;

		if (sockunion_family(&cie_nbma) != AF_UNSPEC)
			claimed_nbma_addr = &cie_nbma;
		else
			claimed_nbma_addr = &pp->src_nbma;

		holdtime = htons(cie->holding_time);
		debugf(NHRP_DEBUG_COMMON,
		       "shortcut res_rep: holdtime is %u (if 0, using %u)",
		       holdtime, pp->if_ad->holdtime);
		if (!holdtime)
			holdtime = pp->if_ad->holdtime;

		c = nhrp_cache_get(ifp, proto_addr, 1);
		if (!c) {
			debugf(NHRP_DEBUG_COMMON,
			       "shortcut res_rep: no cache found");
			cie->code = NHRP_CODE_INSUFFICIENT_RESOURCES;
			continue;
		}

		debugf(NHRP_DEBUG_COMMON,
		       "shortcut res_rep: updating binding for nmba addr %pSU",
		       nbma_addr);
		if (!nhrp_cache_update_binding(
			    c, NHRP_CACHE_DYNAMIC, holdtime,
			    nhrp_peer_get(pp->ifp, nbma_addr), htons(cie->mtu),
			    nbma_addr, claimed_nbma_addr)) {
			cie->code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
			continue;
		}

		cie->code = NHRP_CODE_SUCCESS;
	}

	/* Create reply */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_RESOLUTION_REPLY, &pp->src_nbma,
			       &pp->src_proto, &pp->dst_proto);

	/* Copied information from request */
	hdr->flags = pp->hdr->flags
		     & htons(NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER
			     | NHRP_FLAG_RESOLUTION_SOURCE_STABLE);
	hdr->flags |= htons(NHRP_FLAG_RESOLUTION_DESTINATION_STABLE
			    | NHRP_FLAG_RESOLUTION_AUTHORATIVE);
	hdr->u.request_id = pp->hdr->u.request_id;

	/* CIE payload for the reply packet */
	cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, &nifp->nbma,
			    &pp->if_ad->addr);
	cie->holding_time = htons(pp->if_ad->holdtime);
	cie->mtu = htons(pp->if_ad->mtu);
	if (pp->if_ad->network_id && pp->route_type == NHRP_ROUTE_OFF_NBMA)
		cie->prefix_length = pp->route_prefix.prefixlen;
	else
		cie->prefix_length =
			8 * sockunion_get_addrlen(&pp->if_ad->addr);

	/* Handle extensions */
	while ((ext = nhrp_ext_pull(&pp->extensions, &payload)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_NAT_ADDRESS:
			ext = nhrp_ext_push(zb, hdr,
					    NHRP_EXTENSION_NAT_ADDRESS);
			if (!ext)
				goto err;
			if (sockunion_family(&nifp->nat_nbma) != AF_UNSPEC) {
				cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS,
						    &nifp->nat_nbma,
						    &pp->if_ad->addr);
				if (!cie)
					goto err;
				cie->prefix_length =
					8 * sockunion_get_addrlen(
							&pp->if_ad->addr);

				cie->mtu = htons(pp->if_ad->mtu);
				nhrp_ext_complete(zb, ext);
			}
			break;
		case NHRP_EXTENSION_AUTHENTICATION:
			/* Extensions can be copied from original packet except
			 * authentication extension which must be regenerated
			 * hop by hop.
			 */
			break;
		default:
			if (nhrp_ext_reply(zb, hdr, ifp, ext, &payload) < 0)
				goto err;
			break;
		}
	}
	nhrp_packet_complete(zb, hdr, ifp);
	nhrp_peer_send(peer, zb);
err:
	nhrp_peer_unref(peer);
	zbuf_free(zb);
}

static void nhrp_handle_registration_request(struct nhrp_packet_parser *p)
{
	struct interface *ifp = p->ifp;
	struct zbuf *zb, payload;
	struct nhrp_packet_header *hdr;
	struct nhrp_cie_header *cie;
	struct nhrp_extension_header *ext;
	struct nhrp_cache *c;
	union sockunion cie_nbma, cie_proto, *proto_addr, *nbma_addr,
		*nbma_natoa;
	int holdtime, prefix_len, hostprefix_len, natted = 0;
	size_t paylen;
	void *pay;

	debugf(NHRP_DEBUG_COMMON, "Parsing and replying to Registration Req");
	hostprefix_len = 8 * sockunion_get_addrlen(&p->if_ad->addr);

	if (!sockunion_same(&p->src_nbma, &p->peer->vc->remote.nbma))
		natted = 1;

	/* Create reply */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_REGISTRATION_REPLY, &p->src_nbma,
			       &p->src_proto, &p->if_ad->addr);

	/* Copied information from request */
	hdr->flags = p->hdr->flags & htons(NHRP_FLAG_REGISTRATION_UNIQUE
					   | NHRP_FLAG_REGISTRATION_NAT);
	hdr->u.request_id = p->hdr->u.request_id;

	/* Copy payload CIEs */
	paylen = zbuf_used(&p->payload);
	pay = zbuf_pushn(zb, paylen);
	if (!pay)
		goto err;
	memcpy(pay, zbuf_pulln(&p->payload, paylen), paylen);
	zbuf_init(&payload, pay, paylen, paylen);

	while ((cie = nhrp_cie_pull(&payload, hdr, &cie_nbma, &cie_proto))
	       != NULL) {
		prefix_len = cie->prefix_length;
		if (prefix_len == 0 || prefix_len >= hostprefix_len)
			prefix_len = hostprefix_len;

		if (prefix_len != hostprefix_len
		    && !(p->hdr->flags
			 & htons(NHRP_FLAG_REGISTRATION_UNIQUE))) {
			cie->code = NHRP_CODE_BINDING_NON_UNIQUE;
			continue;
		}

		/* We currently support only unique prefix registrations */
		if (prefix_len != hostprefix_len) {
			cie->code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
			continue;
		}

		proto_addr = (sockunion_family(&cie_proto) == AF_UNSPEC)
				     ? &p->src_proto
				     : &cie_proto;
		nbma_addr = (sockunion_family(&cie_nbma) == AF_UNSPEC)
				    ? &p->src_nbma
				    : &cie_nbma;
		nbma_natoa = NULL;
		if (natted) {
			nbma_natoa =
				(sockunion_family(&p->peer->vc->remote.nbma)
				 == AF_UNSPEC)
					? nbma_addr
					: &p->peer->vc->remote.nbma;
		}

		holdtime = htons(cie->holding_time);
		if (!holdtime)
			holdtime = p->if_ad->holdtime;

		c = nhrp_cache_get(ifp, proto_addr, 1);
		if (!c) {
			cie->code = NHRP_CODE_INSUFFICIENT_RESOURCES;
			continue;
		}

		if (!nhrp_cache_update_binding(c, NHRP_CACHE_DYNAMIC, holdtime,
					       nhrp_peer_ref(p->peer),
					       htons(cie->mtu), nbma_natoa,
					       nbma_addr)) {
			cie->code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
			continue;
		}

		cie->code = NHRP_CODE_SUCCESS;
	}

	/* Handle extensions */
	while ((ext = nhrp_ext_pull(&p->extensions, &payload)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_NAT_ADDRESS:
			ext = nhrp_ext_push(zb, hdr,
					    NHRP_EXTENSION_NAT_ADDRESS);
			if (!ext)
				goto err;
			zbuf_copy(zb, &payload, zbuf_used(&payload));
			if (natted) {
				cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS,
						    &p->peer->vc->remote.nbma,
						    &p->src_proto);
				cie->prefix_length =
					8 * sockunion_get_addrlen(
						    &p->if_ad->addr);
				cie->mtu = htons(p->if_ad->mtu);
			}
			nhrp_ext_complete(zb, ext);
			break;
		default:
			if (nhrp_ext_reply(zb, hdr, ifp, ext, &payload) < 0)
				goto err;
			break;
		}
	}

	/* auth ext was validated and copied from the request */
	nhrp_packet_complete_auth(zb, hdr, ifp, false);
	nhrp_peer_send(p->peer, zb);
err:
	zbuf_free(zb);
}

static int parse_ether_packet(struct zbuf *zb, uint16_t protocol_type,
			      union sockunion *src, union sockunion *dst)
{
	switch (protocol_type) {
	case ETH_P_IP: {
		struct iphdr *iph = zbuf_pull(zb, struct iphdr);
		if (iph) {
			if (src)
				sockunion_set(src, AF_INET,
					      (uint8_t *)&iph->saddr,
					      sizeof(iph->saddr));
			if (dst)
				sockunion_set(dst, AF_INET,
					      (uint8_t *)&iph->daddr,
					      sizeof(iph->daddr));
		}
	} break;
	case ETH_P_IPV6: {
		struct ipv6hdr *iph = zbuf_pull(zb, struct ipv6hdr);
		if (iph) {
			if (src)
				sockunion_set(src, AF_INET6,
					      (uint8_t *)&iph->saddr,
					      sizeof(iph->saddr));
			if (dst)
				sockunion_set(dst, AF_INET6,
					      (uint8_t *)&iph->daddr,
					      sizeof(iph->daddr));
		}
	} break;
	default:
		return 0;
	}
	return 1;
}

void nhrp_peer_send_indication(struct interface *ifp, uint16_t protocol_type,
			       struct zbuf *pkt)
{
	union sockunion dst;
	struct zbuf *zb, payload;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_afi_data *if_ad;
	struct nhrp_packet_header *hdr;
	struct nhrp_peer *p;

	if (!nifp->enabled)
		return;

	payload = *pkt;
	if (!parse_ether_packet(&payload, protocol_type, &dst, NULL))
		return;

	if (nhrp_route_address(ifp, &dst, NULL, &p) != NHRP_ROUTE_NBMA_NEXTHOP)
		return;

	if_ad = &nifp->afi[family2afi(sockunion_family(&dst))];
	if (!(if_ad->flags & NHRP_IFF_REDIRECT)) {
		debugf(NHRP_DEBUG_COMMON,
		       "Send Traffic Indication to %pSU about packet to %pSU ignored",
		       &p->vc->remote.nbma, &dst);
		return;
	}

	debugf(NHRP_DEBUG_COMMON,
	       "Send Traffic Indication to %pSU (online=%d) about packet to %pSU",
	       &p->vc->remote.nbma, p->online, &dst);

	/* Create reply */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_TRAFFIC_INDICATION, &nifp->nbma,
			       &if_ad->addr, &dst);
	hdr->hop_count = 1;

	/* Payload is the packet causing indication */
	zbuf_copy(zb, pkt, zbuf_used(pkt));
	nhrp_packet_complete(zb, hdr, ifp);
	nhrp_peer_send(p, zb);
	nhrp_peer_unref(p);
	zbuf_free(zb);
}

static void nhrp_handle_error_ind(struct nhrp_packet_parser *pp)
{
	struct zbuf origmsg = pp->payload;
	struct nhrp_packet_header *hdr;
	struct nhrp_reqid *reqid;
	union sockunion src_nbma, src_proto, dst_proto;

	hdr = nhrp_packet_pull(&origmsg, &src_nbma, &src_proto, &dst_proto);
	if (!hdr)
		return;

	debugf(NHRP_DEBUG_COMMON,
	       "Error Indication from %pSU about packet to %pSU ignored",
	       &pp->src_proto, &dst_proto);

	reqid = nhrp_reqid_lookup(&nhrp_packet_reqid, htonl(hdr->u.request_id));
	if (reqid)
		reqid->cb(reqid, pp);
}

static void nhrp_handle_traffic_ind(struct nhrp_packet_parser *p)
{
	union sockunion dst;

	if (!parse_ether_packet(&p->payload, htons(p->hdr->protocol_type), NULL,
				&dst))
		return;

	debugf(NHRP_DEBUG_COMMON,
	       "Traffic Indication from %pSU about packet to %pSU: %s",
	       &p->src_proto, &dst,
	       (p->if_ad->flags & NHRP_IFF_SHORTCUT) ? "trying shortcut"
						     : "ignored");

	if (p->if_ad->flags & NHRP_IFF_SHORTCUT)
		nhrp_shortcut_initiate(&dst);
}

enum packet_type_t {
	PACKET_UNKNOWN = 0,
	PACKET_REQUEST,
	PACKET_REPLY,
	PACKET_INDICATION,
};

static struct {
	enum packet_type_t type;
	const char *name;
	void (*handler)(struct nhrp_packet_parser *);
} packet_types[] = {[0] =
			    {
				    .type = PACKET_UNKNOWN,
				    .name = "UNKNOWN",
			    },
		    [NHRP_PACKET_RESOLUTION_REQUEST] =
			    {
				    .type = PACKET_REQUEST,
				    .name = "Resolution-Request",
				    .handler = nhrp_handle_resolution_req,
			    },
		    [NHRP_PACKET_RESOLUTION_REPLY] =
			    {
				    .type = PACKET_REPLY,
				    .name = "Resolution-Reply",
			    },
		    [NHRP_PACKET_REGISTRATION_REQUEST] =
			    {
				    .type = PACKET_REQUEST,
				    .name = "Registration-Request",
				    .handler = nhrp_handle_registration_request,
			    },
		    [NHRP_PACKET_REGISTRATION_REPLY] =
			    {
				    .type = PACKET_REPLY,
				    .name = "Registration-Reply",
			    },
		    [NHRP_PACKET_PURGE_REQUEST] =
			    {
				    .type = PACKET_REQUEST,
				    .name = "Purge-Request",
			    },
		    [NHRP_PACKET_PURGE_REPLY] =
			    {
				    .type = PACKET_REPLY,
				    .name = "Purge-Reply",
			    },
		    [NHRP_PACKET_ERROR_INDICATION] =
			    {
				    .type = PACKET_INDICATION,
				    .name = "Error-Indication",
				    .handler = nhrp_handle_error_ind,
			    },
		    [NHRP_PACKET_TRAFFIC_INDICATION] = {
			    .type = PACKET_INDICATION,
			    .name = "Traffic-Indication",
			    .handler = nhrp_handle_traffic_ind,
		    }};

static void nhrp_peer_forward(struct nhrp_peer *p,
			      struct nhrp_packet_parser *pp)
{
	struct zbuf *zb, *zb_copy, extpl;
	struct nhrp_packet_header *hdr;
	struct nhrp_extension_header *ext, *dst;
	struct nhrp_cie_header *cie;
	struct nhrp_interface *nifp = pp->ifp->info;
	struct nhrp_afi_data *if_ad = pp->if_ad;
	union sockunion cie_nbma, cie_protocol, cie_protocol_mandatory, *proto;
	uint16_t type, len;
	struct nhrp_cache *c;

	if (pp->hdr->hop_count == 0)
		return;

	/* Create forward packet - copy header */
	zb = zbuf_alloc(1500);
	zb_copy = zbuf_alloc(1500);

	hdr = nhrp_packet_push(zb, pp->hdr->type, &pp->src_nbma, &pp->src_proto,
			       &pp->dst_proto);
	hdr->flags = pp->hdr->flags;
	hdr->hop_count = pp->hdr->hop_count - 1;
	hdr->u.request_id = pp->hdr->u.request_id;

	/* Copy payload */
	zbuf_copy_peek(zb_copy, &pp->payload, zbuf_used(&pp->payload));
	zbuf_copy(zb, &pp->payload, zbuf_used(&pp->payload));

	/* Get CIE Extension from Mandatory part */
	sockunion_family(&cie_protocol_mandatory) = AF_UNSPEC;
	nhrp_cie_pull(zb_copy, pp->hdr, &cie_nbma, &cie_protocol_mandatory);

	/* Copy extensions */
	while ((ext = nhrp_ext_pull(&pp->extensions, &extpl)) != NULL) {
		type = htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY;
		len = htons(ext->length);

		if (type == NHRP_EXTENSION_END)
			break;

		dst = NULL;
		if (type != NHRP_EXTENSION_AUTHENTICATION) {
			dst = nhrp_ext_push(zb, hdr, htons(ext->type));
			if (!dst)
				goto err;
		}

		switch (type) {
		case NHRP_EXTENSION_FORWARD_TRANSIT_NHS:
		case NHRP_EXTENSION_REVERSE_TRANSIT_NHS:
			zbuf_put(zb, extpl.head, len);
			if ((type == NHRP_EXTENSION_REVERSE_TRANSIT_NHS)
			    == (packet_types[hdr->type].type == PACKET_REPLY)) {
				/* Check NHS list for forwarding loop */
				while (nhrp_cie_pull(&extpl, pp->hdr,
						     &cie_nbma,
						     &cie_protocol) != NULL) {
					if (sockunion_same(&p->vc->remote.nbma,
							   &cie_nbma))
						goto err;
				}
				/* Append our selves to the list */
				cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS,
						    &nifp->nbma, &if_ad->addr);
				if (!cie)
					goto err;
				cie->mtu = htons(if_ad->mtu);
				cie->holding_time = htons(if_ad->holdtime);
			}
			break;
		case NHRP_EXTENSION_NAT_ADDRESS:
			c = NULL;
			proto = NULL;

			/* If NAT extension is empty then attempt to populate
			 * it with cached NBMA information
			 */
			if (len == 0) {
				if (packet_types[hdr->type].type
				    == PACKET_REQUEST) {
					debugf(NHRP_DEBUG_COMMON,
					       "Processing NHRP_EXTENSION_NAT_ADDRESS while forwarding the request packet");
					proto = &pp->src_proto;
				} else if (packet_types[hdr->type].type
					   == PACKET_REPLY) {
					debugf(NHRP_DEBUG_COMMON,
					       "Processing NHRP_EXTENSION_NAT_ADDRESS while forwarding the reply packet");
					/* For reply packet use protocol
					 * specified in CIE of mandatory part
					 * for cache lookup
					 */
					if (sockunion_family(
						    &cie_protocol_mandatory)
					    != AF_UNSPEC)
						proto = &cie_protocol_mandatory;
				}
			}

			if (proto) {
				debugf(NHRP_DEBUG_COMMON, "Proto is %pSU",
				       proto);
				c = nhrp_cache_get(nifp->ifp, proto, 0);
			}

			if (c) {
				debugf(NHRP_DEBUG_COMMON,
				       "c->cur.remote_nbma_natoa is %pSU",
				       &c->cur.remote_nbma_natoa);
				if (sockunion_family(&c->cur.remote_nbma_natoa)
				    != AF_UNSPEC) {
					cie = nhrp_cie_push(
						zb,
						NHRP_CODE_SUCCESS,
						&c->cur.remote_nbma_natoa,
						proto);
					if (!cie)
						goto err;
				}
			} else {
				if (proto)
					debugf(NHRP_DEBUG_COMMON,
					       "No cache entry for proto %pSU",
					       proto);
				/* Copy existing NAT extension to new packet if
				 * either it was already not-empty, or we do not
				 * have valid cache information
				 */
				zbuf_put(zb, extpl.head, len);
			}
			break;
		case NHRP_EXTENSION_AUTHENTICATION:
			/* Extensions can be copied from original packet except
			 * authentication extension which must be regenerated
			 * hop by hop.
			 */
			break;
		default:
			if (htons(ext->type) & NHRP_EXTENSION_FLAG_COMPULSORY)
				/* FIXME: RFC says to just copy, but not
				 * append our selves to the transit NHS list
				 */
				goto err;
			fallthrough;
		case NHRP_EXTENSION_RESPONDER_ADDRESS:
			/* Supported compulsory extensions, and any
			 * non-compulsory that is not explicitly handled,
			 * should be just copied.
			 */
			zbuf_copy(zb, &extpl, len);
			break;
		}
		if (dst)
			nhrp_ext_complete(zb, dst);
	}

	nhrp_packet_complete_auth(zb, hdr, pp->ifp, true);
	nhrp_peer_send(p, zb);
	zbuf_free(zb);
	zbuf_free(zb_copy);
	return;
err:
	nhrp_packet_debug(pp->pkt, "FWD-FAIL");
	zbuf_free(zb);
	zbuf_free(zb_copy);
}

static void nhrp_packet_debug(struct zbuf *zb, const char *dir)
{
	union sockunion src_nbma, src_proto, dst_proto;
	struct nhrp_packet_header *hdr;
	struct zbuf zhdr;
	int reply;

	if (likely(!(debug_flags & NHRP_DEBUG_COMMON)))
		return;

	zbuf_init(&zhdr, zb->buf, zb->tail - zb->buf, zb->tail - zb->buf);
	hdr = nhrp_packet_pull(&zhdr, &src_nbma, &src_proto, &dst_proto);

	reply = packet_types[hdr->type].type == PACKET_REPLY;
	debugf(NHRP_DEBUG_COMMON, "%s %s(%d) %pSU -> %pSU", dir,
	       (packet_types[hdr->type].name ? : "Unknown"),
	       hdr->type, reply ? &dst_proto : &src_proto,
	       reply ? &src_proto : &dst_proto);
}

static int proto2afi(uint16_t proto)
{
	switch (proto) {
	case ETH_P_IP:
		return AFI_IP;
	case ETH_P_IPV6:
		return AFI_IP6;
	}
	return AF_UNSPEC;
}

static int nhrp_packet_send_error(struct nhrp_packet_parser *pp,
				  uint16_t indication_code, uint16_t offset)
{
	union sockunion src_proto, dst_proto;
	struct nhrp_packet_header *hdr;
	struct zbuf *zb;

	src_proto = pp->src_proto;
	dst_proto = pp->dst_proto;
	if (packet_types[pp->hdr->type].type != PACKET_REPLY) {
		src_proto = pp->dst_proto;
		dst_proto = pp->src_proto;
	}
	/* Create reply */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_ERROR_INDICATION, &pp->src_nbma,
			       &src_proto, &dst_proto);

	hdr->u.error.code = htons(indication_code);
	hdr->u.error.offset = htons(offset);
	hdr->flags = pp->hdr->flags;
	hdr->hop_count = 0; /* XXX: cisco returns 255 */

	/* Payload is the packet causing error */
	/* Don`t add extension according to RFC */
	zbuf_put(zb, pp->hdr, sizeof(*pp->hdr));
	zbuf_put(zb, sockunion_get_addr(&pp->src_nbma),
		 hdr->src_nbma_address_len);
	zbuf_put(zb, sockunion_get_addr(&pp->src_proto),
		 hdr->src_protocol_address_len);
	zbuf_put(zb, sockunion_get_addr(&pp->dst_proto),
		 hdr->dst_protocol_address_len);
	nhrp_packet_complete_auth(zb, hdr, pp->ifp, false);

	nhrp_peer_send(pp->peer, zb);
	zbuf_free(zb);
	return 0;
}

static bool nhrp_connection_authorized(struct nhrp_packet_parser *pp)
{
	struct nhrp_cisco_authentication_extension *auth_ext;
	struct nhrp_interface *nifp = pp->ifp->info;
	struct zbuf *auth = nifp->auth_token;
	struct nhrp_extension_header *ext;
	struct zbuf *extensions, pl;
	int cmp = 1;
	int pl_pass_length, auth_pass_length;
	size_t auth_size, pl_size;

	extensions = zbuf_alloc(zbuf_used(&pp->extensions));
	zbuf_copy_peek(extensions, &pp->extensions, zbuf_used(&pp->extensions));
	while ((ext = nhrp_ext_pull(extensions, &pl)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_AUTHENTICATION:
			/* Size of authentication extensions
			 * (varies based on password length)
			 */
			auth_size = zbuf_size(auth);
			pl_size = zbuf_size(&pl);
			auth_ext = (struct nhrp_cisco_authentication_extension *)
					   auth->buf;

			if (auth_size == pl_size)
				cmp = memcmp(auth_ext, pl.buf, auth_size);
			else
				cmp = 1;

			if (unlikely(debug_flags & NHRP_DEBUG_COMMON)) {
				/* 4 bytes in nhrp_cisco_authentication_extension are allocated
				 * toward the authentication type. The remaining bytes are used for the
				 * password - so the password length is just the length of the extension - 4
				 */
				auth_pass_length = (auth_size - 4);
				pl_pass_length = (pl_size - 4);
				/* Because characters are to be printed in HEX, (2* the max pass length) + 1
				 * is needed for the string representation
				 */
				char auth_pass[(2 * NHRP_CISCO_PASS_LEN) + 1] = { 0 },
					       pl_pass[(2 * NHRP_CISCO_PASS_LEN) + 1] = { 0 };
				/* Converting bytes in buffer to HEX and saving output as a string -
				 * Passphrase is converted to HEX in order to avoid printing
				 * non ACII-compliant characters
				 */
				for (int i = 0; i < (auth_pass_length); i++)
					snprintf(auth_pass + (i * 2), 3, "%02X",
						 auth_ext->secret[i]);
				for (int i = 0; i < (pl_pass_length); i++)
					snprintf(pl_pass + (i * 2), 3, "%02X",
						 ((struct nhrp_cisco_authentication_extension *)pl.buf)
							 ->secret[i]);

				debugf(NHRP_DEBUG_COMMON,
				       "Processing Authentication Extension for (%s:%s|%d)",
				       auth_pass, pl_pass, cmp);
			}
			break;
		default:
			/* Ignoring all received extensions except Authentication*/
			break;
		}
	}
	zbuf_free(extensions);
	return cmp == 0;
}

void nhrp_peer_recv(struct nhrp_peer *p, struct zbuf *zb)
{
	struct nhrp_packet_header *hdr;
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_packet_parser pp;
	struct nhrp_peer *peer = NULL;
	struct nhrp_reqid *reqid;
	const char *info = NULL;
	union sockunion *target_addr;
	unsigned paylen, extoff, extlen, realsize;
	afi_t nbma_afi, proto_afi;

	debugf(NHRP_DEBUG_KERNEL, "PACKET: Recv %pSU -> %pSU", &vc->remote.nbma,
	       &vc->local.nbma);

	if (!p->online) {
		info = "peer not online";
		goto drop;
	}

	if (nhrp_packet_calculate_checksum(zb->head, zbuf_used(zb)) != 0) {
		info = "bad checksum";
		goto drop;
	}

	realsize = zbuf_used(zb);
	hdr = nhrp_packet_pull(zb, &pp.src_nbma, &pp.src_proto, &pp.dst_proto);
	if (!hdr) {
		info = "corrupt header";
		goto drop;
	}

	pp.ifp = ifp;
	pp.pkt = zb;
	pp.hdr = hdr;
	pp.peer = p;

	nbma_afi = htons(hdr->afnum);
	proto_afi = proto2afi(htons(hdr->protocol_type));
	if (hdr->type > NHRP_PACKET_MAX || hdr->version != NHRP_VERSION_RFC2332
	    || nbma_afi >= AFI_MAX || proto_afi == AF_UNSPEC
	    || packet_types[hdr->type].type == PACKET_UNKNOWN
	    || htons(hdr->packet_size) > realsize) {
		zlog_info(
			"From %pSU: error: packet type %d, version %d, AFI %d, proto %x, size %d (real size %d)",
			&vc->remote.nbma, (int)hdr->type, (int)hdr->version,
			(int)nbma_afi, (int)htons(hdr->protocol_type),
			(int)htons(hdr->packet_size), (int)realsize);
		goto drop;
	}
	pp.if_ad = &((struct nhrp_interface *)ifp->info)->afi[proto_afi];

	extoff = htons(hdr->extension_offset);
	if (extoff) {
		assert(zb->head > zb->buf);
		uint32_t header_offset = zb->head - zb->buf;
		if (extoff >= realsize) {
			info = "extoff larger than packet";
			goto drop;
		}
		if (extoff < header_offset) {
			info = "extoff smaller than header offset";
			goto drop;
		}
		paylen = extoff - header_offset;
	} else {
		paylen = zbuf_used(zb);
	}
	zbuf_init(&pp.payload, zbuf_pulln(zb, paylen), paylen, paylen);
	extlen = zbuf_used(zb);
	zbuf_init(&pp.extensions, zbuf_pulln(zb, extlen), extlen, extlen);

	if (!nifp->afi[proto_afi].network_id) {
		info = "nhrp not enabled";
		goto drop;
	}

	/* RFC2332 5.3.4 - Authentication is always done pairwise on an NHRP
	 * hop-by-hop basis; i.e. regenerated at each hop. */
	nhrp_packet_debug(zb, "Recv");
	if (nifp->auth_token &&
	    (hdr->type != NHRP_PACKET_ERROR_INDICATION ||
	     hdr->u.error.code != NHRP_ERROR_AUTHENTICATION_FAILURE)) {
		if (!nhrp_connection_authorized(&pp)) {
			nhrp_packet_send_error(&pp,
					       NHRP_ERROR_AUTHENTICATION_FAILURE,
					       0);
			info = "authentication failure";
			goto drop;
		}
	}

	/* Figure out if this is local */
	target_addr = (packet_types[hdr->type].type == PACKET_REPLY)
			      ? &pp.src_proto
			      : &pp.dst_proto;

	if (sockunion_same(&pp.src_proto, &pp.dst_proto))
		pp.route_type = NHRP_ROUTE_LOCAL;
	else
		pp.route_type = nhrp_route_address(pp.ifp, target_addr,
						   &pp.route_prefix, &peer);

	switch (pp.route_type) {
	case NHRP_ROUTE_LOCAL:
		nhrp_packet_debug(zb, "!LOCAL");
		if (packet_types[hdr->type].type == PACKET_REPLY) {
			reqid = nhrp_reqid_lookup(&nhrp_packet_reqid,
						  htonl(hdr->u.request_id));
			if (reqid) {
				reqid->cb(reqid, &pp);
				break;
			} else {
				nhrp_packet_debug(zb, "!UNKNOWN-REQID");
				/* FIXME: send error-indication */
			}
		}
		fallthrough; /* FIXME: double check, is this correct? */
	case NHRP_ROUTE_OFF_NBMA:
		if (packet_types[hdr->type].handler) {
			packet_types[hdr->type].handler(&pp);
			break;
		}
		break;
	case NHRP_ROUTE_NBMA_NEXTHOP:
		nhrp_peer_forward(peer, &pp);
		break;
	case NHRP_ROUTE_BLACKHOLE:
		break;
	}

drop:
	if (info) {
		zlog_info("From %pSU: error: %s", &vc->remote.nbma, info);
	}
	if (peer)
		nhrp_peer_unref(peer);
	zbuf_free(zb);
}
