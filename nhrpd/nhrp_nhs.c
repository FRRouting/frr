// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP NHC nexthop server functions (registration)
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zebra.h"
#include "zbuf.h"
#include "memory.h"
#include "frrevent.h"
#include "nhrpd.h"
#include "nhrp_protocol.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_NHS, "NHRP next hop server");
DEFINE_MTYPE_STATIC(NHRPD, NHRP_REGISTRATION, "NHRP registration entries");

static void nhrp_nhs_resolve(struct event *t);
static void nhrp_reg_send_req(struct event *t);

static void nhrp_reg_reply(struct nhrp_reqid *reqid, void *arg)
{
	struct nhrp_packet_parser *p = arg;
	struct nhrp_registration *r =
		container_of(reqid, struct nhrp_registration, reqid);
	struct nhrp_nhs *nhs = r->nhs;
	struct interface *ifp = nhs->ifp;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_extension_header *ext;
	struct nhrp_cie_header *cie;
	struct nhrp_cache *c;
	struct zbuf extpl;
	union sockunion cie_nbma, cie_nbma_nhs, cie_proto, cie_proto_nhs,
		*proto;
	int ok = 0, holdtime;
	unsigned short mtu = 0;

	nhrp_reqid_free(&nhrp_packet_reqid, &r->reqid);

	if (p->hdr->type != NHRP_PACKET_REGISTRATION_REPLY) {
		debugf(NHRP_DEBUG_COMMON, "NHS: Registration failed");
		return;
	}

	debugf(NHRP_DEBUG_COMMON, "NHS: Reg.reply received");

	ok = 1;
	while ((cie = nhrp_cie_pull(&p->payload, p->hdr, &cie_nbma, &cie_proto))
	       != NULL) {
		proto = sockunion_family(&cie_proto) != AF_UNSPEC
				? &cie_proto
				: &p->src_proto;
		debugf(NHRP_DEBUG_COMMON, "NHS: CIE registration: %pSU: %d",
		       proto, cie->code);
		if (!((cie->code == NHRP_CODE_SUCCESS)
		      || (cie->code == NHRP_CODE_ADMINISTRATIVELY_PROHIBITED
			  && nhs->hub)))
			ok = 0;
		mtu = ntohs(cie->mtu);
		debugf(NHRP_DEBUG_COMMON, "NHS: CIE MTU: %d", mtu);
	}

	if (!ok)
		return;

	/* Parse extensions */
	sockunion_family(&nifp->nat_nbma) = AF_UNSPEC;
	sockunion_family(&cie_nbma_nhs) = AF_UNSPEC;
	while ((ext = nhrp_ext_pull(&p->extensions, &extpl)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_NAT_ADDRESS:
			/* NHS adds second CIE if NAT is detected */
			if (nhrp_cie_pull(&extpl, p->hdr, &cie_nbma, &cie_proto)
			    && nhrp_cie_pull(&extpl, p->hdr, &cie_nbma,
					     &cie_proto)) {
				nifp->nat_nbma = cie_nbma;
				debugf(NHRP_DEBUG_IF,
				       "%s: NAT detected, real NBMA address: %pSU",
				       ifp->name, &nifp->nbma);
			}
			break;
		case NHRP_EXTENSION_RESPONDER_ADDRESS:
			/* NHS adds its own record as responder address */
			nhrp_cie_pull(&extpl, p->hdr, &cie_nbma_nhs,
				      &cie_proto_nhs);
			break;
		}
	}

	/* Success - schedule next registration, and route NHS */
	r->timeout = 2;
	holdtime = nifp->afi[nhs->afi].holdtime;
	EVENT_OFF(r->t_register);

	/* RFC 2332 5.2.3 - Registration is recommend to be renewed
	 * every one third of holdtime */
	event_add_timer(master, nhrp_reg_send_req, r, holdtime / 3,
			&r->t_register);

	r->proto_addr = p->dst_proto;
	c = nhrp_cache_get(ifp, &p->dst_proto, 1);
	if (c)
		nhrp_cache_update_binding(c, NHRP_CACHE_NHS, holdtime,
					  nhrp_peer_ref(r->peer), mtu, NULL,
					  &cie_nbma_nhs);
}

static void nhrp_reg_timeout(struct event *t)
{
	struct nhrp_registration *r = EVENT_ARG(t);
	struct nhrp_cache *c;


	if (r->timeout >= 16 && sockunion_family(&r->proto_addr) != AF_UNSPEC) {
		nhrp_reqid_free(&nhrp_packet_reqid, &r->reqid);
		c = nhrp_cache_get(r->nhs->ifp, &r->proto_addr, 0);
		if (c)
			nhrp_cache_update_binding(c, NHRP_CACHE_NHS, -1, NULL,
						  0, NULL, NULL);
		sockunion_family(&r->proto_addr) = AF_UNSPEC;
	}

	r->timeout <<= 1;
	if (r->timeout > 64) {
		/* If registration fails repeatedly, this may be because the
		 * IPSec connection is not working. Close the connection so it
		 * can be re-established correctly
		 */
		if (r->peer && r->peer->vc && r->peer->vc->ike_uniqueid) {
			debugf(NHRP_DEBUG_COMMON,
			       "Terminating IPSec Connection for %d",
			       r->peer->vc->ike_uniqueid);
			vici_terminate_vc_by_ike_id(r->peer->vc->ike_uniqueid);
			r->peer->vc->ike_uniqueid = 0;
		}
		r->timeout = 2;
	}
	event_add_timer_msec(master, nhrp_reg_send_req, r, 10, &r->t_register);
}

static void nhrp_reg_peer_notify(struct notifier_block *n, unsigned long cmd)
{
	struct nhrp_registration *r =
		container_of(n, struct nhrp_registration, peer_notifier);

	switch (cmd) {
	case NOTIFY_PEER_UP:
	case NOTIFY_PEER_DOWN:
	case NOTIFY_PEER_IFCONFIG_CHANGED:
	case NOTIFY_PEER_MTU_CHANGED:
		debugf(NHRP_DEBUG_COMMON, "NHS: Flush timer for %pSU",
		       &r->peer->vc->remote.nbma);
		EVENT_OFF(r->t_register);
		event_add_timer_msec(master, nhrp_reg_send_req, r, 10,
				     &r->t_register);
		break;
	}
}

static void nhrp_reg_send_req(struct event *t)
{
	struct nhrp_registration *r = EVENT_ARG(t);
	struct nhrp_nhs *nhs = r->nhs;
	struct interface *ifp = nhs->ifp;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_afi_data *if_ad = &nifp->afi[nhs->afi];
	union sockunion *dst_proto, nhs_proto;
	struct zbuf *zb;
	struct nhrp_packet_header *hdr;
	struct nhrp_extension_header *ext;
	struct nhrp_cie_header *cie;

	if (!nhrp_peer_check(r->peer, 2)) {
		int renewtime = if_ad->holdtime / 4;
		/* RFC 2332 5.2.0.1 says "a retry is sent after an appropriate
		 * interval." Using holdtime/4, to be shorter than
		 * recommended renew time (holdtime/3), see RFC2332 Sec 5.2.3
		 */
		debugf(NHRP_DEBUG_COMMON,
		       "NHS: Waiting link for %pSU, retrying in %d seconds",
		       &r->peer->vc->remote.nbma, renewtime);
		event_add_timer(master, nhrp_reg_send_req, r, renewtime,
				&r->t_register);
		return;
	}

	event_add_timer(master, nhrp_reg_timeout, r, r->timeout,
			&r->t_register);

	/* RFC2332 5.2.3 NHC uses it's own address as dst if NHS is unknown */
	dst_proto = &nhs->proto_addr;
	if (sockunion_family(dst_proto) == AF_UNSPEC)
		dst_proto = &if_ad->addr;

	debugf(NHRP_DEBUG_COMMON, "NHS: Register %pSU -> %pSU (timeout %d)",
	       &if_ad->addr, dst_proto, r->timeout);

	/* No protocol address configured for tunnel interface */
	if (sockunion_family(&if_ad->addr) == AF_UNSPEC)
		return;

	zb = zbuf_alloc(1400);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_REGISTRATION_REQUEST,
			       &nifp->nbma, &if_ad->addr, dst_proto);
	hdr->hop_count = 1;
	if (!(if_ad->flags & NHRP_IFF_REG_NO_UNIQUE))
		hdr->flags |= htons(NHRP_FLAG_REGISTRATION_UNIQUE);

	hdr->u.request_id = htonl(nhrp_reqid_alloc(&nhrp_packet_reqid,
						   &r->reqid, nhrp_reg_reply));

	/* FIXME: push CIE for each local protocol address */
	cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, NULL, NULL);
	/* RFC2332 5.2.1 if unique is set then prefix length must be 0xff */
	cie->prefix_length = (if_ad->flags & NHRP_IFF_REG_NO_UNIQUE)
				     ? 8 * sockunion_get_addrlen(dst_proto)
				     : 0xff;
	cie->holding_time = htons(if_ad->holdtime);
	cie->mtu = htons(if_ad->mtu);

	nhrp_ext_request(zb, hdr);

	/* Cisco NAT detection extension */
	if (sockunion_family(&r->proto_addr) != AF_UNSPEC) {
		nhs_proto = r->proto_addr;
	} else if (sockunion_family(&nhs->proto_addr) != AF_UNSPEC) {
		nhs_proto = nhs->proto_addr;
	} else {
		/* cisco magic: If NHS is not known then use all 0s as
		 * client protocol address in NAT Extension header
		 */
		memset(&nhs_proto, 0, sizeof(nhs_proto));
		sockunion_family(&nhs_proto) = afi2family(nhs->afi);
	}

	hdr->flags |= htons(NHRP_FLAG_REGISTRATION_NAT);
	ext = nhrp_ext_push(zb, hdr, NHRP_EXTENSION_NAT_ADDRESS);
	/* push NHS details */
	cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, &r->peer->vc->remote.nbma,
			    &nhs_proto);
	cie->prefix_length = 8 * sockunion_get_addrlen(&if_ad->addr);
	cie->mtu = htons(if_ad->mtu);
	nhrp_ext_complete(zb, ext);

	nhrp_packet_complete(zb, hdr, ifp);
	nhrp_peer_send(r->peer, zb);
	zbuf_free(zb);
}

static void nhrp_reg_delete(struct nhrp_registration *r)
{
	nhrp_peer_notify_del(r->peer, &r->peer_notifier);
	nhrp_peer_unref(r->peer);
	nhrp_reglist_del(&r->nhs->reglist_head, r);
	EVENT_OFF(r->t_register);
	XFREE(MTYPE_NHRP_REGISTRATION, r);
}

static struct nhrp_registration *
nhrp_reg_by_nbma(struct nhrp_nhs *nhs, const union sockunion *nbma_addr)
{
	struct nhrp_registration *r;

	frr_each (nhrp_reglist, &nhs->reglist_head, r)
		if (sockunion_same(&r->peer->vc->remote.nbma, nbma_addr))
			return r;
	return NULL;
}

static void nhrp_nhs_resolve_cb(struct resolver_query *q, const char *errstr,
				int n, union sockunion *addrs)
{
	struct nhrp_nhs *nhs = container_of(q, struct nhrp_nhs, dns_resolve);
	struct nhrp_interface *nifp = nhs->ifp->info;
	struct nhrp_registration *reg;
	int i;

	if (n < 0) {
		/* Failed, retry in a moment */
		event_add_timer(master, nhrp_nhs_resolve, nhs, 5,
				&nhs->t_resolve);
		return;
	}

	event_add_timer(master, nhrp_nhs_resolve, nhs, 2 * 60 * 60,
			&nhs->t_resolve);

	frr_each (nhrp_reglist, &nhs->reglist_head, reg)
		reg->mark = 1;

	nhs->hub = 0;
	for (i = 0; i < n; i++) {
		if (sockunion_same(&addrs[i], &nifp->nbma)) {
			nhs->hub = 1;
			continue;
		}

		reg = nhrp_reg_by_nbma(nhs, &addrs[i]);
		if (reg) {
			reg->mark = 0;
			continue;
		}

		reg = XCALLOC(MTYPE_NHRP_REGISTRATION, sizeof(*reg));
		reg->peer = nhrp_peer_get(nhs->ifp, &addrs[i]);
		reg->nhs = nhs;
		reg->timeout = 1;
		nhrp_reglist_add_tail(&nhs->reglist_head, reg);
		nhrp_peer_notify_add(reg->peer, &reg->peer_notifier,
				     nhrp_reg_peer_notify);
		event_add_timer_msec(master, nhrp_reg_send_req, reg, 50,
				     &reg->t_register);
	}

	frr_each_safe (nhrp_reglist, &nhs->reglist_head, reg)
		if (reg->mark)
			nhrp_reg_delete(reg);
}

static void nhrp_nhs_resolve(struct event *t)
{
	struct nhrp_nhs *nhs = EVENT_ARG(t);

	resolver_resolve(&nhs->dns_resolve, AF_INET, VRF_DEFAULT,
			 nhs->nbma_fqdn, nhrp_nhs_resolve_cb);
}

int nhrp_nhs_add(struct interface *ifp, afi_t afi, union sockunion *proto_addr,
		 const char *nbma_fqdn)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_nhs *nhs;

	if (sockunion_family(proto_addr) != AF_UNSPEC
	    && sockunion_family(proto_addr) != afi2family(afi))
		return NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH;

	frr_each (nhrp_nhslist, &nifp->afi[afi].nhslist_head, nhs) {
		if (sockunion_family(&nhs->proto_addr) != AF_UNSPEC
		    && sockunion_family(proto_addr) != AF_UNSPEC
		    && sockunion_same(&nhs->proto_addr, proto_addr))
			return NHRP_ERR_ENTRY_EXISTS;

		if (strcmp(nhs->nbma_fqdn, nbma_fqdn) == 0)
			return NHRP_ERR_ENTRY_EXISTS;
	}

	nhs = XMALLOC(MTYPE_NHRP_NHS, sizeof(struct nhrp_nhs));

	*nhs = (struct nhrp_nhs){
		.afi = afi,
		.ifp = ifp,
		.proto_addr = *proto_addr,
		.nbma_fqdn = strdup(nbma_fqdn),
		.reglist_head = INIT_DLIST(nhs->reglist_head),
	};
	nhrp_nhslist_add_tail(&nifp->afi[afi].nhslist_head, nhs);
	event_add_timer_msec(master, nhrp_nhs_resolve, nhs, 1000,
			     &nhs->t_resolve);

	return NHRP_OK;
}

int nhrp_nhs_del(struct interface *ifp, afi_t afi, union sockunion *proto_addr,
		 const char *nbma_fqdn)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_nhs *nhs;
	int ret = NHRP_ERR_ENTRY_NOT_FOUND;

	if (sockunion_family(proto_addr) != AF_UNSPEC
	    && sockunion_family(proto_addr) != afi2family(afi))
		return NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH;

	frr_each_safe (nhrp_nhslist, &nifp->afi[afi].nhslist_head, nhs) {
		if (!sockunion_same(&nhs->proto_addr, proto_addr))
			continue;
		if (strcmp(nhs->nbma_fqdn, nbma_fqdn) != 0)
			continue;

		nhrp_nhs_free(nifp, afi, nhs);
		ret = NHRP_OK;
	}

	return ret;
}

int nhrp_nhs_free(struct nhrp_interface *nifp, afi_t afi, struct nhrp_nhs *nhs)
{
	struct nhrp_registration *r;

	frr_each_safe (nhrp_reglist, &nhs->reglist_head, r)
		nhrp_reg_delete(r);
	EVENT_OFF(nhs->t_resolve);
	nhrp_nhslist_del(&nifp->afi[afi].nhslist_head, nhs);
	free((void *)nhs->nbma_fqdn);
	XFREE(MTYPE_NHRP_NHS, nhs);
	return 0;
}

void nhrp_nhs_interface_del(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_nhs *nhs;
	afi_t afi;

	for (afi = 0; afi < AFI_MAX; afi++) {
		debugf(NHRP_DEBUG_COMMON, "Cleaning up nhs entries (%zu)",
		       nhrp_nhslist_count(&nifp->afi[afi].nhslist_head));

		frr_each_safe (nhrp_nhslist, &nifp->afi[afi].nhslist_head, nhs)
			nhrp_nhs_free(nifp, afi, nhs);
	}
}

void nhrp_nhs_terminate(void)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct nhrp_interface *nifp;
	struct nhrp_nhs *nhs;
	afi_t afi;

	FOR_ALL_INTERFACES (vrf, ifp) {
		nifp = ifp->info;
		for (afi = 0; afi < AFI_MAX; afi++) {
			frr_each_safe (nhrp_nhslist,
				       &nifp->afi[afi].nhslist_head, nhs)
				nhrp_nhs_free(nifp, afi, nhs);
		}
		nhrp_peer_interface_del(ifp);
	}
}

void nhrp_nhs_foreach(struct interface *ifp, afi_t afi,
		      void (*cb)(struct nhrp_nhs *, struct nhrp_registration *,
				 void *),
		      void *ctx)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_nhs *nhs;
	struct nhrp_registration *reg;

	frr_each (nhrp_nhslist, &nifp->afi[afi].nhslist_head, nhs) {
		if (nhrp_reglist_count(&nhs->reglist_head)) {
			frr_each (nhrp_reglist, &nhs->reglist_head, reg)
				cb(nhs, reg, ctx);
		} else
			cb(nhs, 0, ctx);
	}
}

int nhrp_nhs_match_ip(union sockunion *in_ip, struct nhrp_interface *nifp)
{
	int i;
	struct nhrp_nhs *nhs;
	struct nhrp_registration *reg;

	for (i = 0; i < AFI_MAX; i++) {
		frr_each (nhrp_nhslist, &nifp->afi[i].nhslist_head, nhs) {
			if (!nhrp_reglist_count(&nhs->reglist_head))
				continue;

			frr_each (nhrp_reglist, &nhs->reglist_head, reg) {
				if (!sockunion_cmp(in_ip,
						   &reg->peer->vc->remote.nbma))
					return 1;
			}
		}
	}
	return 0;
}
