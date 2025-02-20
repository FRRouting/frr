// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP shortcut related functions
 * Copyright (c) 2014-2015 Timo Teräs
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "nhrpd.h"
#include "table.h"
#include "memory.h"
#include "frrevent.h"
#include "log.h"
#include "nhrp_protocol.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_SHORTCUT, "NHRP shortcut");

static struct route_table *shortcut_rib[AFI_MAX];

static void nhrp_shortcut_do_purge(struct event *t);
static void nhrp_shortcut_delete(struct nhrp_shortcut *s,
				 void *arg __attribute__((__unused__)));
static void nhrp_shortcut_send_resolution_req(struct nhrp_shortcut *s,
					      bool retry);
static void nhrp_shortcut_retry_resolution_req(struct event *t);

static void nhrp_shortcut_check_use(struct nhrp_shortcut *s)
{
	if (s->expiring && s->cache && s->cache->used) {
		debugf(NHRP_DEBUG_ROUTE, "Shortcut %pFX used and expiring",
		       s->p);
		nhrp_shortcut_send_resolution_req(s, false);
	}
}

static void nhrp_shortcut_do_expire(struct event *t)
{
	struct nhrp_shortcut *s = EVENT_ARG(t);

	event_add_timer(master, nhrp_shortcut_do_purge, s, s->holding_time / 3,
			&s->t_shortcut_purge);
	s->expiring = 1;
	nhrp_shortcut_check_use(s);
}

static void nhrp_shortcut_cache_notify(struct notifier_block *n,
				       unsigned long cmd)
{
	struct nhrp_shortcut *s =
		container_of(n, struct nhrp_shortcut, cache_notifier);
	struct nhrp_cache *c = s->cache;

	switch (cmd) {
	case NOTIFY_CACHE_UP:
		if (!s->route_installed) {
			debugf(NHRP_DEBUG_ROUTE,
			       "Shortcut: route install %pFX nh %pSU dev %s",
			       s->p, &c->remote_addr,
			       c && c->ifp ? c->ifp->name : "<unk>");

			nhrp_route_announce(1, s->type, s->p, c ? c->ifp : NULL,
					    c ? &c->remote_addr : NULL, 0);
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
			nhrp_shortcut_delete(s, NULL);
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
				debugf(NHRP_DEBUG_ROUTE,
				       "Shortcut: forcing renewal of zebra announce on prefix change peer %pSU ht %u cur nbma %pSU dev %s",
				       &s->cache->remote_addr, holding_time,
				       &s->cache->cur.remote_nbma_natoa,
				       s->cache->ifp->name);
				nhrp_shortcut_cache_notify(&s->cache_notifier,
							   NOTIFY_CACHE_UP);
			}
		}
		if (!s->cache || !s->cache->route_installed) {
			debugf(NHRP_DEBUG_ROUTE,
			       "Shortcut: notify cache down because cache?%s or ri?%s",
			       s->cache ? "yes" : "no",
			       s->cache ? (s->cache->route_installed ? "yes"
								     : "no")
					: "n/a");
			nhrp_shortcut_cache_notify(&s->cache_notifier,
						   NOTIFY_CACHE_DOWN);
		}
	}
	if (s->type == NHRP_CACHE_NEGATIVE && !s->route_installed) {
		nhrp_route_announce(1, s->type, s->p, NULL, NULL, 0);
		s->route_installed = 1;
	} else if (s->type == NHRP_CACHE_INVALID && s->route_installed) {
		nhrp_route_announce(0, NHRP_CACHE_INVALID, s->p, NULL, NULL, 0);
		s->route_installed = 0;
	}

	EVENT_OFF(s->t_shortcut_purge);
	if (holding_time) {
		s->expiring = 0;
		s->holding_time = holding_time;
		event_add_timer(master, nhrp_shortcut_do_expire, s,
				2 * holding_time / 3, &s->t_shortcut_purge);
	}
}

static void nhrp_shortcut_delete(struct nhrp_shortcut *s,
				 void *arg __attribute__((__unused__)))
{
	struct route_node *rn;
	afi_t afi = family2afi(PREFIX_FAMILY(s->p));

	EVENT_OFF(s->t_shortcut_purge);
	EVENT_OFF(s->t_retry_resolution);
	nhrp_reqid_free(&nhrp_packet_reqid, &s->reqid);

	debugf(NHRP_DEBUG_ROUTE, "Shortcut %pFX purged", s->p);

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

static void nhrp_shortcut_do_purge(struct event *t)
{
	struct nhrp_shortcut *s = EVENT_ARG(t);
	s->t_shortcut_purge = NULL;
	EVENT_OFF(s->t_retry_resolution);
	nhrp_shortcut_delete(s, NULL);
}

static struct nhrp_shortcut *nhrp_shortcut_get(struct prefix *p)
{
	struct nhrp_shortcut *s;
	struct route_node *rn;
	afi_t afi = family2afi(PREFIX_FAMILY(p));

	if (!shortcut_rib[afi])
		return 0;

	rn = route_node_get(shortcut_rib[afi], p);
	if (!rn->info) {
		s = rn->info = XCALLOC(MTYPE_NHRP_SHORTCUT,
				       sizeof(struct nhrp_shortcut));
		s->type = NHRP_CACHE_INVALID;
		s->p = &rn->p;

		debugf(NHRP_DEBUG_ROUTE, "Shortcut %pFX created", s->p);
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
	struct interface *ifp = pp->ifp;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_shortcut *s =
		container_of(reqid, struct nhrp_shortcut, reqid);
	struct nhrp_shortcut *ps;
	struct nhrp_extension_header *ext;
	struct nhrp_cie_header *cie;
	struct nhrp_cache *c = NULL;
	struct nhrp_cache *c_dst = NULL;
	union sockunion *proto, cie_proto, *nbma, cie_nbma, nat_nbma;
	struct prefix prefix, route_prefix;
	struct zbuf extpl;
	int holding_time = pp->if_ad->holdtime;

	nhrp_reqid_free(&nhrp_packet_reqid, &s->reqid);
	EVENT_OFF(s->t_shortcut_purge);
	EVENT_OFF(s->t_retry_resolution);
	event_add_timer(master, nhrp_shortcut_do_purge, s, 1,
			&s->t_shortcut_purge);

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

	/* Minor sanity check */
	prefix2sockunion(s->p, &cie_proto);
	if (!sockunion_same(&cie_proto, &pp->dst_proto)) {
		debugf(NHRP_DEBUG_COMMON,
		       "Shortcut: Warning dst_proto altered from %pSU to %pSU",
		       &cie_proto, &pp->dst_proto);
		;
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

	/* Parse extensions */
	memset(&nat_nbma, 0, sizeof(nat_nbma));
	while ((ext = nhrp_ext_pull(&pp->extensions, &extpl)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_NAT_ADDRESS: {
			struct nhrp_cie_header *cie_nat;

			do {
				union sockunion cie_nat_proto, cie_nat_nbma;

				sockunion_family(&cie_nat_proto) = AF_UNSPEC;
				sockunion_family(&cie_nat_nbma) = AF_UNSPEC;
				cie_nat = nhrp_cie_pull(&extpl, pp->hdr,
							&cie_nat_nbma,
							&cie_nat_proto);
				/* We are interested only in peer CIE */
				if (cie_nat
				    && sockunion_same(&cie_nat_proto, proto)) {
					nat_nbma = cie_nat_nbma;
				}
			} while (cie_nat);
		} break;
		default:
			break;
		}
	}

	/* Update cache entry for the protocol to nbma binding */
	if (sockunion_family(&nat_nbma) != AF_UNSPEC) {
		debugf(NHRP_DEBUG_COMMON,
		       "Shortcut: NAT detected (NAT extension) proto %pSU NBMA %pSU claimed-NBMA %pSU",
		       proto, &nat_nbma, &cie_nbma);
		nbma = &nat_nbma;
	}
	/* For NHRP resolution reply the cie_nbma in mandatory part is the
	 * address of the actual address of the sender
	 */
	else if (!sockunion_same(&cie_nbma, &pp->peer->vc->remote.nbma)
		 && !nhrp_nhs_match_ip(&pp->peer->vc->remote.nbma, nifp)) {
		debugf(NHRP_DEBUG_COMMON,
		       "Shortcut: NAT detected (no NAT Extension) proto %pSU NBMA %pSU claimed-NBMA %pSU",
		       proto, &pp->peer->vc->remote.nbma, &cie_nbma);
		nbma = &pp->peer->vc->remote.nbma;
		nat_nbma = *nbma;
	} else {
		nbma = &cie_nbma;
	}

	debugf(NHRP_DEBUG_COMMON,
	       "Shortcut: %pFX is at proto %pSU dst_proto %pSU NBMA %pSU cie-holdtime %d",
	       &prefix, proto, &pp->dst_proto, nbma,
	       htons(cie->holding_time));

	if (sockunion_family(nbma)) {
		c = nhrp_cache_get(pp->ifp, proto, 1);
		if (c) {
			debugf(NHRP_DEBUG_COMMON,
			       "Shortcut: cache found, update binding");
			nhrp_cache_update_binding(c, NHRP_CACHE_DYNAMIC,
						  holding_time,
						  nhrp_peer_get(pp->ifp, nbma),
						  htons(cie->mtu),
						  nbma,
						  &cie_nbma);
		} else {
			debugf(NHRP_DEBUG_COMMON,
			       "Shortcut: no cache for proto %pSU", proto);
		}

		/* Update cache binding for dst_proto as well */
		if (sockunion_cmp(proto, &pp->dst_proto)) {
			c_dst = nhrp_cache_get(pp->ifp, &pp->dst_proto, 1);
			if (c_dst) {
				debugf(NHRP_DEBUG_COMMON,
				       "Shortcut: cache found, update binding");
				nhrp_cache_update_binding(c_dst,
						  NHRP_CACHE_DYNAMIC,
						  holding_time,
						  nhrp_peer_get(pp->ifp, nbma),
						  htons(cie->mtu),
						  nbma,
						  &cie_nbma);
			} else {
				debugf(NHRP_DEBUG_COMMON,
				       "Shortcut: no cache for proto %pSU",
				       &pp->dst_proto);
			}
		}
	}

	/* Update shortcut entry for subnet to protocol gw binding */
	if (c) {
		ps = nhrp_shortcut_get(&prefix);
		if (ps) {
			ps->addr = s->addr;
			debugf(NHRP_DEBUG_COMMON,
			       "Shortcut: calling update_binding");
			nhrp_shortcut_update_binding(ps, NHRP_CACHE_DYNAMIC, c,
						     holding_time);
		} else {
			debugf(NHRP_DEBUG_COMMON,
			       "Shortcut: proto diff but no ps");
		}
	} else {
		debugf(NHRP_DEBUG_COMMON,
		       "NO Shortcut because c NULL?%s or same proto?%s",
		       c ? "no" : "yes",
		       proto && pp && sockunion_same(proto, &pp->dst_proto)
			       ? "yes"
			       : "no");
	}

	debugf(NHRP_DEBUG_COMMON, "Shortcut: Resolution reply handled");
}

static void nhrp_shortcut_send_resolution_req(struct nhrp_shortcut *s,
					      bool retry)
{
	struct zbuf *zb;
	struct nhrp_packet_header *hdr;
	struct interface *ifp;
	struct nhrp_interface *nifp;
	struct nhrp_afi_data *if_ad;
	struct nhrp_peer *peer;
	struct nhrp_cie_header *cie;
	struct nhrp_extension_header *ext;

	if (nhrp_route_address(NULL, &s->addr, NULL, &peer)
	    != NHRP_ROUTE_NBMA_NEXTHOP)
		return;

	/*Retry interval for NHRP resolution request
	 * will start at 1 second and will be doubled every time
	 * another resolution request is sent, until it is
	 * eventually upper-bounded by the purge time of
	 * the shortcut.
	 */
	if (!retry)
		s->retry_interval = 1;
	event_add_timer(master, nhrp_shortcut_retry_resolution_req, s,
			s->retry_interval, &s->t_retry_resolution);
	if (s->retry_interval != (NHRPD_DEFAULT_PURGE_TIME / 4))
		s->retry_interval = ((s->retry_interval * 2) <
				     (NHRPD_DEFAULT_PURGE_TIME / 4))
					    ? (s->retry_interval * 2)
					    : (NHRPD_DEFAULT_PURGE_TIME / 4);

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

	/* RFC2332 - The value is taken from a 32 bit counter that is incremented
	 * each time a new "request" is transmitted.  The same value MUST
	 * be used when resending a "request", i.e., when a "reply" has not been
	 * received for a "request" and a retry is sent after an
	 * appropriate interval
	 */
	if (!retry)
		hdr->u.request_id = htonl(
			nhrp_reqid_alloc(&nhrp_packet_reqid, &s->reqid,
					 nhrp_shortcut_recv_resolution_rep));
	else
		/* Just pull request_id from existing incomplete
		 * shortcut in the case of a retry
		 */
		hdr->u.request_id = htonl(s->reqid.request_id);

	hdr->flags = htons(NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER
			   | NHRP_FLAG_RESOLUTION_AUTHORATIVE
			   | NHRP_FLAG_RESOLUTION_SOURCE_STABLE);

	/* RFC2332 - One or zero CIEs, if CIE is present contains:
	 *  - Prefix length: widest acceptable prefix we accept (if U set, 0xff)
	 *  - MTU: MTU of the source station
	 *  - Holding Time: Max time to cache the source information
	 */
	/* FIXME: push CIE for each local protocol address */
	cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, NULL, NULL);
	if_ad = &nifp->afi[family2afi(sockunion_family(&s->addr))];
	cie->prefix_length = (if_ad->flags & NHRP_IFF_REG_NO_UNIQUE)
				? 8 * sockunion_get_addrlen(&s->addr)
				: 0xff;
	cie->holding_time = htons(if_ad->holdtime);
	cie->mtu = htons(if_ad->mtu);
	debugf(NHRP_DEBUG_COMMON,
	       "Shortcut res_req: set cie ht to %u and mtu to %u. shortcut ht is %u",
	       ntohs(cie->holding_time), ntohs(cie->mtu), s->holding_time);

	nhrp_ext_request(zb, hdr);

	/* Cisco NAT detection extension */
	hdr->flags |= htons(NHRP_FLAG_RESOLUTION_NAT);
	ext = nhrp_ext_push(zb, hdr, NHRP_EXTENSION_NAT_ADDRESS);
	if (sockunion_family(&nifp->nat_nbma) != AF_UNSPEC) {
		cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, &nifp->nat_nbma,
				    &if_ad->addr);
		cie->prefix_length = 8 * sockunion_get_addrlen(&if_ad->addr);
		cie->mtu = htons(if_ad->mtu);
		nhrp_ext_complete(zb, ext);
	}

	nhrp_packet_complete(zb, hdr, ifp);

	nhrp_peer_send(peer, zb);
	nhrp_peer_unref(peer);
	zbuf_free(zb);
}

void nhrp_shortcut_initiate(union sockunion *addr)
{
	struct prefix p;
	struct nhrp_shortcut *s;

	if (!sockunion2hostprefix(addr, &p))
		return;

	s = nhrp_shortcut_get(&p);
	if (s && s->type != NHRP_CACHE_INCOMPLETE) {
		s->addr = *addr;
		EVENT_OFF(s->t_shortcut_purge);
		EVENT_OFF(s->t_retry_resolution);

		event_add_timer(master, nhrp_shortcut_do_purge, s,
				NHRPD_DEFAULT_PURGE_TIME, &s->t_shortcut_purge);
		nhrp_shortcut_send_resolution_req(s, false);
	}
}

static void nhrp_shortcut_retry_resolution_req(struct event *t)
{
	struct nhrp_shortcut *s = EVENT_ARG(t);

	EVENT_OFF(s->t_retry_resolution);
	debugf(NHRP_DEBUG_COMMON, "Shortcut: Retrying Resolution Request");
	nhrp_shortcut_send_resolution_req(s, true);
}


void nhrp_shortcut_init(void)
{
	shortcut_rib[AFI_IP] = route_table_init();
	shortcut_rib[AFI_IP6] = route_table_init();
}

void nhrp_shortcut_terminate(void)
{
	nhrp_shortcut_foreach(AFI_IP, nhrp_shortcut_delete, NULL);
	nhrp_shortcut_foreach(AFI_IP6, nhrp_shortcut_delete, NULL);
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
	EVENT_OFF(s->t_shortcut_purge);
	EVENT_OFF(s->t_retry_resolution);
	nhrp_reqid_free(&nhrp_packet_reqid, &s->reqid);

	if (force) {
		/* Immediate purge on route with draw or pending shortcut */
		event_add_timer_msec(master, nhrp_shortcut_do_purge, s, 5,
				     &s->t_shortcut_purge);
	} else {
		/* Soft expire - force immediate renewal, but purge
		 * in few seconds to make sure stale route is not
		 * used too long. In practice most purges are caused
		 * by hub bgp change, but target usually stays same.
		 * This allows to keep nhrp route up, and to not
		 * cause temporary rerouting via hubs causing latency
		 * jitter. */
		event_add_timer_msec(master, nhrp_shortcut_do_purge, s,
				     NHRPD_PURGE_EXPIRE, &s->t_shortcut_purge);
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
