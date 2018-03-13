/* NHRP peer functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <netinet/if_ether.h>

#include "zebra.h"
#include "memory.h"
#include "thread.h"
#include "hash.h"

#include "nhrpd.h"
#include "nhrp_protocol.h"
#include "os.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_PEER, "NHRP peer entry")

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

	THREAD_OFF(p->t_fallback);
	hash_release(nifp->peer_hash, p);
	nhrp_interface_notify_del(p->ifp, &p->ifp_notifier);
	nhrp_vc_notify_del(p->vc, &p->vc_notifier);
	XFREE(MTYPE_NHRP_PEER, p);
}

static int nhrp_peer_notify_up(struct thread *t)
{
	struct nhrp_peer *p = THREAD_ARG(t);
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

	return 0;
}

static void __nhrp_peer_check(struct nhrp_peer *p)
{
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;
	unsigned online;

	online = nifp->enabled && (!nifp->ipsec_profile || vc->ipsec);
	if (p->online != online) {
		THREAD_OFF(p->t_fallback);
		if (online && notifier_active(&p->notifier_list)) {
			/* If we requested the IPsec connection, delay
			 * the up notification a bit to allow things
			 * settle down. This allows IKE to install
			 * SPDs and SAs. */
			thread_add_timer_msec(master, nhrp_peer_notify_up, p,
					      50, &p->t_fallback);
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
		/* fallthru */ /* to post config update */
	case NOTIFY_INTERFACE_ADDRESS_CHANGED:
		notifier_call(&p->notifier_list, NOTIFY_PEER_IFCONFIG_CHANGED);
		break;
	case NOTIFY_INTERFACE_MTU_CHANGED:
		notifier_call(&p->notifier_list, NOTIFY_PEER_MTU_CHANGED);
		break;
	}
	nhrp_peer_unref(p);
}

static unsigned int nhrp_peer_key(void *peer_data)
{
	struct nhrp_peer *p = peer_data;
	return sockunion_hash(&p->vc->remote.nbma);
}

static int nhrp_peer_cmp(const void *cache_data, const void *key_data)
{
	const struct nhrp_peer *a = cache_data;
	const struct nhrp_peer *b = key_data;
	return a->ifp == b->ifp && a->vc == b->vc;
}

static void *nhrp_peer_create(void *data)
{
	struct nhrp_peer *p, *key = data;

	p = XMALLOC(MTYPE_NHRP_PEER, sizeof(*p));
	if (p) {
		*p = (struct nhrp_peer){
			.ref = 0,
			.ifp = key->ifp,
			.vc = key->vc,
			.notifier_list =
				NOTIFIER_LIST_INITIALIZER(&p->notifier_list),
		};
		nhrp_vc_notify_add(p->vc, &p->vc_notifier, nhrp_peer_vc_notify);
		nhrp_interface_notify_add(p->ifp, &p->ifp_notifier,
					  nhrp_peer_ifp_notify);
	}
	return p;
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

static int nhrp_peer_request_timeout(struct thread *t)
{
	struct nhrp_peer *p = THREAD_ARG(t);
	struct nhrp_vc *vc = p->vc;
	struct interface *ifp = p->ifp;
	struct nhrp_interface *nifp = ifp->info;

	p->t_fallback = NULL;

	if (p->online)
		return 0;

	if (nifp->ipsec_fallback_profile && !p->prio
	    && !p->fallback_requested) {
		p->fallback_requested = 1;
		vici_request_vc(nifp->ipsec_fallback_profile, &vc->local.nbma,
				&vc->remote.nbma, p->prio);
		thread_add_timer(master, nhrp_peer_request_timeout, p, 30,
				 &p->t_fallback);
	} else {
		p->requested = p->fallback_requested = 0;
	}

	return 0;
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

	p->prio = establish > 1;
	p->requested = 1;
	vici_request_vc(nifp->ipsec_profile, &vc->local.nbma, &vc->remote.nbma,
			p->prio);
	thread_add_timer(master, nhrp_peer_request_timeout, p,
			 (nifp->ipsec_fallback_profile && !p->prio) ? 15 : 30,
			 &p->t_fallback);

	return 0;
}

void nhrp_peer_notify_add(struct nhrp_peer *p, struct notifier_block *n,
			  notifier_fn_t fn)
{
	notifier_add(n, &p->notifier_list, fn);
}

void nhrp_peer_notify_del(struct nhrp_peer *p, struct notifier_block *n)
{
	notifier_del(n);
	nhrp_peer_check_delete(p);
}

void nhrp_peer_send(struct nhrp_peer *p, struct zbuf *zb)
{
	char buf[2][256];

	nhrp_packet_debug(zb, "Send");

	if (!p->online)
		return;

	debugf(NHRP_DEBUG_KERNEL, "PACKET: Send %s -> %s",
	       sockunion2str(&p->vc->local.nbma, buf[0], sizeof buf[0]),
	       sockunion2str(&p->vc->remote.nbma, buf[1], sizeof buf[1]));

	os_sendmsg(zb->head, zbuf_used(zb), p->ifp->ifindex,
		   sockunion_get_addr(&p->vc->remote.nbma),
		   sockunion_get_addrlen(&p->vc->remote.nbma));
	zbuf_reset(zb);
}

static void nhrp_handle_resolution_req(struct nhrp_packet_parser *p)
{
	struct zbuf *zb, payload;
	struct nhrp_packet_header *hdr;
	struct nhrp_cie_header *cie;
	struct nhrp_extension_header *ext;
	struct nhrp_interface *nifp;
	struct nhrp_peer *peer;

	if (!(p->if_ad->flags & NHRP_IFF_SHORTCUT)) {
		debugf(NHRP_DEBUG_COMMON, "Shortcuts disabled");
		/* FIXME: Send error indication? */
		return;
	}

	if (p->if_ad->network_id && p->route_type == NHRP_ROUTE_OFF_NBMA
	    && p->route_prefix.prefixlen < 8) {
		debugf(NHRP_DEBUG_COMMON,
		       "Shortcut to more generic than /8 dropped");
		return;
	}

	debugf(NHRP_DEBUG_COMMON, "Parsing and replying to Resolution Req");

	if (nhrp_route_address(p->ifp, &p->src_proto, NULL, &peer)
	    != NHRP_ROUTE_NBMA_NEXTHOP)
		return;

#if 0
	/* FIXME: Update requestors binding if CIE specifies holding time */
	nhrp_cache_update_binding(
			NHRP_CACHE_CACHED, &p->src_proto,
			nhrp_peer_get(p->ifp, &p->src_nbma),
			htons(cie->holding_time));
#endif

	nifp = peer->ifp->info;

	/* Create reply */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_RESOLUTION_REPLY, &p->src_nbma,
			       &p->src_proto, &p->dst_proto);

	/* Copied information from request */
	hdr->flags =
		p->hdr->flags & htons(NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER
				      | NHRP_FLAG_RESOLUTION_SOURCE_STABLE);
	hdr->flags |= htons(NHRP_FLAG_RESOLUTION_DESTINATION_STABLE
			    | NHRP_FLAG_RESOLUTION_AUTHORATIVE);
	hdr->u.request_id = p->hdr->u.request_id;

	/* CIE payload */
	cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, &nifp->nbma,
			    &p->if_ad->addr);
	cie->holding_time = htons(p->if_ad->holdtime);
	cie->mtu = htons(p->if_ad->mtu);
	if (p->if_ad->network_id && p->route_type == NHRP_ROUTE_OFF_NBMA)
		cie->prefix_length = p->route_prefix.prefixlen;
	else
		cie->prefix_length = 8 * sockunion_get_addrlen(&p->if_ad->addr);

	/* Handle extensions */
	while ((ext = nhrp_ext_pull(&p->extensions, &payload)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_NAT_ADDRESS:
			if (sockunion_family(&nifp->nat_nbma) == AF_UNSPEC)
				break;
			ext = nhrp_ext_push(zb, hdr,
					    NHRP_EXTENSION_NAT_ADDRESS);
			if (!ext)
				goto err;
			cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS,
					    &nifp->nat_nbma, &p->if_ad->addr);
			if (!cie)
				goto err;
			nhrp_ext_complete(zb, ext);
			break;
		default:
			if (nhrp_ext_reply(zb, hdr, p->ifp, ext, &payload) < 0)
				goto err;
			break;
		}
	}

	nhrp_packet_complete(zb, hdr);
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
			nbma_natoa = nbma_addr;
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
					       htons(cie->mtu), nbma_natoa)) {
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
				nhrp_cie_push(zb, NHRP_CODE_SUCCESS,
					      &p->peer->vc->remote.nbma,
					      &p->src_proto);
			}
			nhrp_ext_complete(zb, ext);
			break;
		default:
			if (nhrp_ext_reply(zb, hdr, ifp, ext, &payload) < 0)
				goto err;
			break;
		}
	}

	nhrp_packet_complete(zb, hdr);
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
	char buf[2][SU_ADDRSTRLEN];

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
		       "Send Traffic Indication to %s about packet to %s ignored",
		       sockunion2str(&p->vc->remote.nbma, buf[0],
				     sizeof buf[0]),
		       sockunion2str(&dst, buf[1], sizeof buf[1]));
		return;
	}

	debugf(NHRP_DEBUG_COMMON,
	       "Send Traffic Indication to %s (online=%d) about packet to %s",
	       sockunion2str(&p->vc->remote.nbma, buf[0], sizeof buf[0]),
	       p->online, sockunion2str(&dst, buf[1], sizeof buf[1]));

	/* Create reply */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_TRAFFIC_INDICATION, &nifp->nbma,
			       &if_ad->addr, &dst);
	hdr->hop_count = 0;

	/* Payload is the packet causing indication */
	zbuf_copy(zb, pkt, zbuf_used(pkt));
	nhrp_packet_complete(zb, hdr);
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
	char buf[2][SU_ADDRSTRLEN];

	hdr = nhrp_packet_pull(&origmsg, &src_nbma, &src_proto, &dst_proto);
	if (!hdr)
		return;

	debugf(NHRP_DEBUG_COMMON,
	       "Error Indication from %s about packet to %s ignored",
	       sockunion2str(&pp->src_proto, buf[0], sizeof buf[0]),
	       sockunion2str(&dst_proto, buf[1], sizeof buf[1]));

	reqid = nhrp_reqid_lookup(&nhrp_packet_reqid, htonl(hdr->u.request_id));
	if (reqid)
		reqid->cb(reqid, pp);
}

static void nhrp_handle_traffic_ind(struct nhrp_packet_parser *p)
{
	union sockunion dst;
	char buf[2][SU_ADDRSTRLEN];

	if (!parse_ether_packet(&p->payload, htons(p->hdr->protocol_type), NULL,
				&dst))
		return;

	debugf(NHRP_DEBUG_COMMON,
	       "Traffic Indication from %s about packet to %s: %s",
	       sockunion2str(&p->src_proto, buf[0], sizeof buf[0]),
	       sockunion2str(&dst, buf[1], sizeof buf[1]),
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
	struct zbuf *zb, extpl;
	struct nhrp_packet_header *hdr;
	struct nhrp_extension_header *ext, *dst;
	struct nhrp_cie_header *cie;
	struct nhrp_interface *nifp = pp->ifp->info;
	struct nhrp_afi_data *if_ad = pp->if_ad;
	union sockunion cie_nbma, cie_protocol;
	uint16_t type, len;

	if (pp->hdr->hop_count == 0)
		return;

	/* Create forward packet - copy header */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(zb, pp->hdr->type, &pp->src_nbma, &pp->src_proto,
			       &pp->dst_proto);
	hdr->flags = pp->hdr->flags;
	hdr->hop_count = pp->hdr->hop_count - 1;
	hdr->u.request_id = pp->hdr->u.request_id;

	/* Copy payload */
	zbuf_copy(zb, &pp->payload, zbuf_used(&pp->payload));

	/* Copy extensions */
	while ((ext = nhrp_ext_pull(&pp->extensions, &extpl)) != NULL) {
		type = htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY;
		len = htons(ext->length);

		if (type == NHRP_EXTENSION_END)
			break;

		dst = nhrp_ext_push(zb, hdr, htons(ext->type));
		if (!dst)
			goto err;

		switch (type) {
		case NHRP_EXTENSION_FORWARD_TRANSIT_NHS:
		case NHRP_EXTENSION_REVERSE_TRANSIT_NHS:
			zbuf_put(zb, extpl.head, len);
			if ((type == NHRP_EXTENSION_REVERSE_TRANSIT_NHS)
			    == (packet_types[hdr->type].type == PACKET_REPLY)) {
				/* Check NHS list for forwarding loop */
				while ((cie = nhrp_cie_pull(&extpl, pp->hdr,
							    &cie_nbma,
							    &cie_protocol))
				       != NULL) {
					if (sockunion_same(&p->vc->remote.nbma,
							   &cie_nbma))
						goto err;
				}
				/* Append our selves to the list */
				cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS,
						    &nifp->nbma, &if_ad->addr);
				if (!cie)
					goto err;
				cie->holding_time = htons(if_ad->holdtime);
			}
			break;
		default:
			if (htons(ext->type) & NHRP_EXTENSION_FLAG_COMPULSORY)
				/* FIXME: RFC says to just copy, but not
				 * append our selves to the transit NHS list */
				goto err;
		/* fallthru */
		case NHRP_EXTENSION_RESPONDER_ADDRESS:
			/* Supported compulsory extensions, and any
			 * non-compulsory that is not explicitly handled,
			 * should be just copied. */
			zbuf_copy(zb, &extpl, len);
			break;
		}
		nhrp_ext_complete(zb, dst);
	}

	nhrp_packet_complete(zb, hdr);
	nhrp_peer_send(p, zb);
	zbuf_free(zb);
	return;
err:
	nhrp_packet_debug(pp->pkt, "FWD-FAIL");
	zbuf_free(zb);
}

static void nhrp_packet_debug(struct zbuf *zb, const char *dir)
{
	char buf[2][SU_ADDRSTRLEN];
	union sockunion src_nbma, src_proto, dst_proto;
	struct nhrp_packet_header *hdr;
	struct zbuf zhdr;
	int reply;

	if (likely(!(debug_flags & NHRP_DEBUG_COMMON)))
		return;

	zbuf_init(&zhdr, zb->buf, zb->tail - zb->buf, zb->tail - zb->buf);
	hdr = nhrp_packet_pull(&zhdr, &src_nbma, &src_proto, &dst_proto);

	sockunion2str(&src_proto, buf[0], sizeof buf[0]);
	sockunion2str(&dst_proto, buf[1], sizeof buf[1]);

	reply = packet_types[hdr->type].type == PACKET_REPLY;
	debugf(NHRP_DEBUG_COMMON, "%s %s(%d) %s -> %s", dir,
	       packet_types[hdr->type].name ?: "Unknown", hdr->type,
	       reply ? buf[1] : buf[0], reply ? buf[0] : buf[1]);
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

struct nhrp_route_info {
	int local;
	struct interface *ifp;
	struct nhrp_vc *vc;
};

void nhrp_peer_recv(struct nhrp_peer *p, struct zbuf *zb)
{
	char buf[2][SU_ADDRSTRLEN];
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

	debugf(NHRP_DEBUG_KERNEL, "PACKET: Recv %s -> %s",
	       sockunion2str(&vc->remote.nbma, buf[0], sizeof buf[0]),
	       sockunion2str(&vc->local.nbma, buf[1], sizeof buf[1]));

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
			"From %s: error: packet type %d, version %d, AFI %d, proto %x, size %d (real size %d)",
			sockunion2str(&vc->remote.nbma, buf[0], sizeof buf[0]),
			(int)hdr->type, (int)hdr->version, (int)nbma_afi,
			(int)htons(hdr->protocol_type),
			(int)htons(hdr->packet_size), (int)realsize);
		goto drop;
	}
	pp.if_ad = &((struct nhrp_interface *)ifp->info)->afi[proto_afi];

	extoff = htons(hdr->extension_offset);
	if (extoff) {
		if (extoff >= realsize) {
			info = "extoff larger than packet";
			goto drop;
		}
		paylen = extoff - (zb->head - zb->buf);
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

	nhrp_packet_debug(zb, "Recv");

	/* FIXME: Check authentication here. This extension needs to be
	 * pre-handled. */

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
		/* fallthru */ /* FIXME: double check, is this correct? */
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
		zlog_info(
			"From %s: error: %s",
			sockunion2str(&vc->remote.nbma, buf[0], sizeof buf[0]),
			info);
	}
	if (peer)
		nhrp_peer_unref(peer);
	zbuf_free(zb);
}
