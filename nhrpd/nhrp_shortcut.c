/* NHRP shortcut related functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "nhrpd.h"
#include "table.h"
#include "memory.h"
#include "thread.h"
#include "log.h"
#include "nhrp_protocol.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_SHORTCUT, "NHRP shortcut")

static struct route_table *shortcut_rib[AFI_MAX];

static int nhrp_shortcut_do_purge(struct thread *t);
static void nhrp_shortcut_delete(struct nhrp_shortcut *s);
static void nhrp_shortcut_send_resolution_req(struct nhrp_shortcut *s);

static void nhrp_shortcut_check_use(struct nhrp_shortcut *s)
{
	char buf[PREFIX_STRLEN];

	if (s->expiring && s->cache && s->cache->used) {
		debugf(NHRP_DEBUG_ROUTE, "Shortcut %s used and expiring",
		       prefix2str(s->p, buf, sizeof buf));
		nhrp_shortcut_send_resolution_req(s);
	}
}

static int nhrp_shortcut_do_expire(struct thread *t)
{
	struct nhrp_shortcut *s = THREAD_ARG(t);

	s->t_timer = NULL;
	thread_add_timer(master, nhrp_shortcut_do_purge, s, s->holding_time / 3,
			 &s->t_timer);
	s->expiring = 1;
	nhrp_shortcut_check_use(s);

	return 0;
}

static void nhrp_shortcut_cache_notify(struct notifier_block *n,
				       unsigned long cmd)
{
	struct nhrp_shortcut *s =
		container_of(n, struct nhrp_shortcut, cache_notifier);

	switch (cmd) {
	case NOTIFY_CACHE_UP:
		if (!s->route_installed) {
			nhrp_route_announce(1, s->type, s->p, NULL,
					    &s->cache->remote_addr, 0);
			s->route_installed = 1;
		}
		break;
	case NOTIFY_CACHE_USED:
		nhrp_shortcut_check_use(s);
		break;
	case NOTIFY_CACHE_DOWN:
	case NOTIFY_CACHE_DELETE:
		if (s->route_installed) {
			nhrp_route_announce(0, NHRP_CACHE_INVALID, s->p, NULL,
					    NULL, 0);
			s->route_installed = 0;
		}
		if (cmd == NOTIFY_CACHE_DELETE)
			nhrp_shortcut_delete(s);
		break;
	}
}

static void nhrp_shortcut_update_binding(struct nhrp_shortcut *s,
					 enum nhrp_cache_type type,
					 struct nhrp_cache *c, int holding_time)
{
	s->type = type;
	if (c != s->cache) {
		if (s->cache) {
			nhrp_cache_notify_del(s->cache, &s->cache_notifier);
			s->cache = NULL;
		}
		s->cache = c;
		if (s->cache) {
			nhrp_cache_notify_add(s->cache, &s->cache_notifier,
					      nhrp_shortcut_cache_notify);
			if (s->cache->route_installed) {
				/* Force renewal of Zebra announce on prefix
				 * change */
				s->route_installed = 0;
				nhrp_shortcut_cache_notify(&s->cache_notifier,
							   NOTIFY_CACHE_UP);
			}
		}
		if (!s->cache || !s->cache->route_installed)
			nhrp_shortcut_cache_notify(&s->cache_notifier,
						   NOTIFY_CACHE_DOWN);
	}
	if (s->type == NHRP_CACHE_NEGATIVE && !s->route_installed) {
		nhrp_route_announce(1, s->type, s->p, NULL, NULL, 0);
		s->route_installed = 1;
	} else if (s->type == NHRP_CACHE_INVALID && s->route_installed) {
		nhrp_route_announce(0, NHRP_CACHE_INVALID, s->p, NULL, NULL, 0);
		s->route_installed = 0;
	}

	THREAD_OFF(s->t_timer);
	if (holding_time) {
		s->expiring = 0;
		s->holding_time = holding_time;
		thread_add_timer(master, nhrp_shortcut_do_expire, s,
				 2 * holding_time / 3, &s->t_timer);
	}
}

static void nhrp_shortcut_delete(struct nhrp_shortcut *s)
{
	struct route_node *rn;
	afi_t afi = family2afi(PREFIX_FAMILY(s->p));
	char buf[PREFIX_STRLEN];

	THREAD_OFF(s->t_timer);
	nhrp_reqid_free(&nhrp_packet_reqid, &s->reqid);

	debugf(NHRP_DEBUG_ROUTE, "Shortcut %s purged",
	       prefix2str(s->p, buf, sizeof buf));

	nhrp_shortcut_update_binding(s, NHRP_CACHE_INVALID, NULL, 0);

	/* Delete node */
	rn = route_node_lookup(shortcut_rib[afi], s->p);
	if (rn) {
		XFREE(MTYPE_NHRP_SHORTCUT, rn->info);
		rn->info = NULL;
		route_unlock_node(rn);
		route_unlock_node(rn);
	}
}

static int nhrp_shortcut_do_purge(struct thread *t)
{
	struct nhrp_shortcut *s = THREAD_ARG(t);
	s->t_timer = NULL;
	nhrp_shortcut_delete(s);
	return 0;
}

static struct nhrp_shortcut *nhrp_shortcut_get(struct prefix *p)
{
	struct nhrp_shortcut *s;
	struct route_node *rn;
	char buf[PREFIX_STRLEN];
	afi_t afi = family2afi(PREFIX_FAMILY(p));

	if (!shortcut_rib[afi])
		return 0;

	rn = route_node_get(shortcut_rib[afi], p);
	if (!rn->info) {
		s = rn->info = XCALLOC(MTYPE_NHRP_SHORTCUT,
				       sizeof(struct nhrp_shortcut));
		s->type = NHRP_CACHE_INVALID;
		s->p = &rn->p;

		debugf(NHRP_DEBUG_ROUTE, "Shortcut %s created",
		       prefix2str(s->p, buf, sizeof buf));
	} else {
		s = rn->info;
		route_unlock_node(rn);
	}
	return s;
}

static void nhrp_shortcut_recv_resolution_rep(struct nhrp_reqid *reqid,
					      void *arg)
{
	struct nhrp_packet_parser *pp = arg;
	struct nhrp_shortcut *s =
		container_of(reqid, struct nhrp_shortcut, reqid);
	struct nhrp_shortcut *ps;
	struct nhrp_extension_header *ext;
	struct nhrp_cie_header *cie;
	struct nhrp_cache *c = NULL;
	union sockunion *proto, cie_proto, *nbma, *nbma_natoa, cie_nbma,
		nat_nbma;
	struct prefix prefix, route_prefix;
	struct zbuf extpl;
	char bufp[PREFIX_STRLEN], buf[3][SU_ADDRSTRLEN];
	int holding_time = pp->if_ad->holdtime;

	nhrp_reqid_free(&nhrp_packet_reqid, &s->reqid);
	THREAD_OFF(s->t_timer);
	thread_add_timer(master, nhrp_shortcut_do_purge, s, 1, &s->t_timer);

	if (pp->hdr->type != NHRP_PACKET_RESOLUTION_REPLY) {
		if (pp->hdr->type == NHRP_PACKET_ERROR_INDICATION
		    && pp->hdr->u.error.code
			       == NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE) {
			debugf(NHRP_DEBUG_COMMON,
			       "Shortcut: Resolution: Protocol address unreachable");
			nhrp_shortcut_update_binding(s, NHRP_CACHE_NEGATIVE,
						     NULL, holding_time);
		} else {
			debugf(NHRP_DEBUG_COMMON,
			       "Shortcut: Resolution failed");
		}
		return;
	}

	/* Parse extensions */
	memset(&nat_nbma, 0, sizeof nat_nbma);
	while ((ext = nhrp_ext_pull(&pp->extensions, &extpl)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_NAT_ADDRESS:
			nhrp_cie_pull(&extpl, pp->hdr, &nat_nbma, &cie_proto);
			break;
		}
	}

	/* Minor sanity check */
	prefix2sockunion(s->p, &cie_proto);
	if (!sockunion_same(&cie_proto, &pp->dst_proto)) {
		debugf(NHRP_DEBUG_COMMON,
		       "Shortcut: Warning dst_proto altered from %s to %s",
		       sockunion2str(&cie_proto, buf[0], sizeof buf[0]),
		       sockunion2str(&pp->dst_proto, buf[1], sizeof buf[1]));
	}

	/* One or more CIEs should be given as reply, we support only one */
	cie = nhrp_cie_pull(&pp->payload, pp->hdr, &cie_nbma, &cie_proto);
	if (!cie || cie->code != NHRP_CODE_SUCCESS) {
		debugf(NHRP_DEBUG_COMMON, "Shortcut: CIE code %d",
		       cie ? cie->code : -1);
		return;
	}

	proto = sockunion_family(&cie_proto) != AF_UNSPEC ? &cie_proto
							  : &pp->dst_proto;
	if (cie->holding_time)
		holding_time = htons(cie->holding_time);

	prefix = *s->p;
	prefix.prefixlen = cie->prefix_length;

	/* Sanity check prefix length */
	if (prefix.prefixlen >= 8 * prefix_blen(&prefix)
	    || prefix.prefixlen == 0) {
		prefix.prefixlen = 8 * prefix_blen(&prefix);
	} else if (nhrp_route_address(NULL, &pp->dst_proto, &route_prefix, NULL)
		   == NHRP_ROUTE_NBMA_NEXTHOP) {
		if (prefix.prefixlen < route_prefix.prefixlen)
			prefix.prefixlen = route_prefix.prefixlen;
	}

	debugf(NHRP_DEBUG_COMMON,
	       "Shortcut: %s is at proto %s cie-nbma %s nat-nbma %s cie-holdtime %d",
	       prefix2str(&prefix, bufp, sizeof bufp),
	       sockunion2str(proto, buf[0], sizeof buf[0]),
	       sockunion2str(&cie_nbma, buf[1], sizeof buf[1]),
	       sockunion2str(&nat_nbma, buf[2], sizeof buf[2]),
	       htons(cie->holding_time));

	/* Update cache entry for the protocol to nbma binding */
	if (sockunion_family(&nat_nbma) != AF_UNSPEC) {
		nbma = &nat_nbma;
		nbma_natoa = &cie_nbma;
	} else {
		nbma = &cie_nbma;
		nbma_natoa = NULL;
	}
	if (sockunion_family(nbma)) {
		c = nhrp_cache_get(pp->ifp, proto, 1);
		if (c) {
			nhrp_cache_update_binding(c, NHRP_CACHE_CACHED,
						  holding_time,
						  nhrp_peer_get(pp->ifp, nbma),
						  htons(cie->mtu), nbma_natoa);
		}
	}

	/* Update shortcut entry for subnet to protocol gw binding */
	if (c && !sockunion_same(proto, &pp->dst_proto)) {
		ps = nhrp_shortcut_get(&prefix);
		if (ps) {
			ps->addr = s->addr;
			nhrp_shortcut_update_binding(ps, NHRP_CACHE_CACHED, c,
						     holding_time);
		}
	}

	debugf(NHRP_DEBUG_COMMON, "Shortcut: Resolution reply handled");
}

static void nhrp_shortcut_send_resolution_req(struct nhrp_shortcut *s)
{
	struct zbuf *zb;
	struct nhrp_packet_header *hdr;
	struct interface *ifp;
	struct nhrp_interface *nifp;
	struct nhrp_peer *peer;

	if (nhrp_route_address(NULL, &s->addr, NULL, &peer)
	    != NHRP_ROUTE_NBMA_NEXTHOP)
		return;

	if (s->type == NHRP_CACHE_INVALID || s->type == NHRP_CACHE_NEGATIVE)
		s->type = NHRP_CACHE_INCOMPLETE;

	ifp = peer->ifp;
	nifp = ifp->info;

	/* Create request */
	zb = zbuf_alloc(1500);
	hdr = nhrp_packet_push(
		zb, NHRP_PACKET_RESOLUTION_REQUEST, &nifp->nbma,
		&nifp->afi[family2afi(sockunion_family(&s->addr))].addr,
		&s->addr);
	hdr->u.request_id =
		htonl(nhrp_reqid_alloc(&nhrp_packet_reqid, &s->reqid,
				       nhrp_shortcut_recv_resolution_rep));
	hdr->flags = htons(NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER
			   | NHRP_FLAG_RESOLUTION_AUTHORATIVE
			   | NHRP_FLAG_RESOLUTION_SOURCE_STABLE);

	/* RFC2332 - One or zero CIEs, if CIE is present contains:
	 *  - Prefix length: widest acceptable prefix we accept (if U set, 0xff)
	 *  - MTU: MTU of the source station
	 *  - Holding Time: Max time to cache the source information
	 * */
	/* FIXME: Send holding time, and MTU */

	nhrp_ext_request(zb, hdr, ifp);

	/* Cisco NAT detection extension */
	hdr->flags |= htons(NHRP_FLAG_RESOLUTION_NAT);
	nhrp_ext_push(zb, hdr, NHRP_EXTENSION_NAT_ADDRESS);

	nhrp_packet_complete(zb, hdr);

	nhrp_peer_send(peer, zb);
	nhrp_peer_unref(peer);
	zbuf_free(zb);
}

void nhrp_shortcut_initiate(union sockunion *addr)
{
	struct prefix p;
	struct nhrp_shortcut *s;

	sockunion2hostprefix(addr, &p);
	s = nhrp_shortcut_get(&p);
	if (s && s->type != NHRP_CACHE_INCOMPLETE) {
		s->addr = *addr;
		THREAD_OFF(s->t_timer);
		thread_add_timer(master, nhrp_shortcut_do_purge, s, 30,
				 &s->t_timer);
		nhrp_shortcut_send_resolution_req(s);
	}
}

void nhrp_shortcut_init(void)
{
	shortcut_rib[AFI_IP] = route_table_init();
	shortcut_rib[AFI_IP6] = route_table_init();
}

void nhrp_shortcut_terminate(void)
{
	route_table_finish(shortcut_rib[AFI_IP]);
	route_table_finish(shortcut_rib[AFI_IP6]);
}

void nhrp_shortcut_foreach(afi_t afi,
			   void (*cb)(struct nhrp_shortcut *, void *),
			   void *ctx)
{
	struct route_table *rt = shortcut_rib[afi];
	struct route_node *rn;
	route_table_iter_t iter;

	if (!rt)
		return;

	route_table_iter_init(&iter, rt);
	while ((rn = route_table_iter_next(&iter)) != NULL) {
		if (rn->info)
			cb(rn->info, ctx);
	}
	route_table_iter_cleanup(&iter);
}

struct purge_ctx {
	const struct prefix *p;
	int deleted;
};

void nhrp_shortcut_purge(struct nhrp_shortcut *s, int force)
{
	THREAD_OFF(s->t_timer);
	nhrp_reqid_free(&nhrp_packet_reqid, &s->reqid);

	if (force) {
		/* Immediate purge on route with draw or pending shortcut */
		thread_add_timer_msec(master, nhrp_shortcut_do_purge, s, 5,
				      &s->t_timer);
	} else {
		/* Soft expire - force immediate renewal, but purge
		 * in few seconds to make sure stale route is not
		 * used too long. In practice most purges are caused
		 * by hub bgp change, but target usually stays same.
		 * This allows to keep nhrp route up, and to not
		 * cause temporary rerouting via hubs causing latency
		 * jitter. */
		thread_add_timer_msec(master, nhrp_shortcut_do_purge, s, 3000,
				      &s->t_timer);
		s->expiring = 1;
		nhrp_shortcut_check_use(s);
	}
}

static void nhrp_shortcut_purge_prefix(struct nhrp_shortcut *s, void *ctx)
{
	struct purge_ctx *pctx = ctx;

	if (prefix_match(pctx->p, s->p))
		nhrp_shortcut_purge(s, pctx->deleted || !s->cache);
}

void nhrp_shortcut_prefix_change(const struct prefix *p, int deleted)
{
	struct purge_ctx pctx = {
		.p = p, .deleted = deleted,
	};
	nhrp_shortcut_foreach(family2afi(PREFIX_FAMILY(p)),
			      nhrp_shortcut_purge_prefix, &pctx);
}
