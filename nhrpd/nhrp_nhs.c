/* NHRP NHC nexthop server functions (registration)
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "zebra.h"
#include "zbuf.h"
#include "memory.h"
#include "thread.h"
#include "nhrpd.h"
#include "nhrp_protocol.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_NHS, "NHRP next hop server")
DEFINE_MTYPE_STATIC(NHRPD, NHRP_REGISTRATION, "NHRP registration entries")

static int nhrp_nhs_resolve(struct thread *t);
static int nhrp_reg_send_req(struct thread *t);

static void nhrp_reg_reply(struct nhrp_reqid *reqid, void *arg)
{
	struct nhrp_packet_parser *p = arg;
	struct nhrp_registration *r = container_of(reqid, struct nhrp_registration, reqid);
	struct nhrp_nhs *nhs = r->nhs;
	struct interface *ifp = nhs->ifp;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_extension_header *ext;
	struct nhrp_cie_header *cie;
	struct nhrp_cache *c;
	struct zbuf extpl;
	union sockunion cie_nbma, cie_proto, *proto;
	char buf[64];
	int ok = 0, holdtime;

	nhrp_reqid_free(&nhrp_packet_reqid, &r->reqid);

	if (p->hdr->type != NHRP_PACKET_REGISTRATION_REPLY) {
		debugf(NHRP_DEBUG_COMMON, "NHS: Registration failed");
		return;
	}

	debugf(NHRP_DEBUG_COMMON, "NHS: Reg.reply received");

	ok = 1;
	while ((cie = nhrp_cie_pull(&p->payload, p->hdr, &cie_nbma, &cie_proto)) != NULL) {
		proto = sockunion_family(&cie_proto) != AF_UNSPEC ? &cie_proto : &p->src_proto;
		debugf(NHRP_DEBUG_COMMON, "NHS: CIE registration: %s: %d",
			sockunion2str(proto, buf, sizeof(buf)),
			cie->code);
		if (!((cie->code == NHRP_CODE_SUCCESS) ||
                      (cie->code == NHRP_CODE_ADMINISTRATIVELY_PROHIBITED && nhs->hub)))
			ok = 0;
	}

	if (!ok)
		return;

	/* Parse extensions */
	sockunion_family(&nifp->nat_nbma) = AF_UNSPEC;
	while ((ext = nhrp_ext_pull(&p->extensions, &extpl)) != NULL) {
		switch (htons(ext->type) & ~NHRP_EXTENSION_FLAG_COMPULSORY) {
		case NHRP_EXTENSION_NAT_ADDRESS:
			/* NHS adds second CIE if NAT is detected */
			if (nhrp_cie_pull(&extpl, p->hdr, &cie_nbma, &cie_proto) &&
			    nhrp_cie_pull(&extpl, p->hdr, &cie_nbma, &cie_proto)) {
				nifp->nat_nbma = cie_nbma;
				debugf(NHRP_DEBUG_IF, "%s: NAT detected, real NBMA address: %s",
					ifp->name, sockunion2str(&nifp->nbma, buf, sizeof(buf)));
			}
			break;
		}
	}

	/* Success - schedule next registration, and route NHS */
	r->timeout = 2;
	holdtime = nifp->afi[nhs->afi].holdtime;
	THREAD_OFF(r->t_register);

	/* RFC 2332 5.2.3 - Registration is recommend to be renewed
	 * every one third of holdtime */
	thread_add_timer(master, nhrp_reg_send_req, r, holdtime / 3,
			 &r->t_register);

	r->proto_addr = p->dst_proto;
	c = nhrp_cache_get(ifp, &p->dst_proto, 1);
	if (c) nhrp_cache_update_binding(c, NHRP_CACHE_NHS, holdtime, nhrp_peer_ref(r->peer), 0, NULL);
}

static int nhrp_reg_timeout(struct thread *t)
{
	struct nhrp_registration *r = THREAD_ARG(t);
	struct nhrp_cache *c;

	r->t_register = NULL;

	if (r->timeout >= 16 && sockunion_family(&r->proto_addr) != AF_UNSPEC) {
		nhrp_reqid_free(&nhrp_packet_reqid, &r->reqid);
		c = nhrp_cache_get(r->nhs->ifp, &r->proto_addr, 0);
		if (c) nhrp_cache_update_binding(c, NHRP_CACHE_NHS, -1, NULL, 0, NULL);
		sockunion_family(&r->proto_addr) = AF_UNSPEC;
	}

	r->timeout <<= 1;
	if (r->timeout > 64) r->timeout = 2;
	thread_add_timer_msec(master, nhrp_reg_send_req, r, 10,
			      &r->t_register);

	return 0;
}

static void nhrp_reg_peer_notify(struct notifier_block *n, unsigned long cmd)
{
	struct nhrp_registration *r = container_of(n, struct nhrp_registration, peer_notifier);
	char buf[SU_ADDRSTRLEN];

	switch (cmd) {
	case NOTIFY_PEER_UP:
	case NOTIFY_PEER_DOWN:
	case NOTIFY_PEER_IFCONFIG_CHANGED:
	case NOTIFY_PEER_MTU_CHANGED:
		debugf(NHRP_DEBUG_COMMON, "NHS: Flush timer for %s",
			sockunion2str(&r->peer->vc->remote.nbma, buf, sizeof buf));
		THREAD_TIMER_OFF(r->t_register);
		thread_add_timer_msec(master, nhrp_reg_send_req, r, 10,
				      &r->t_register);
		break;
	}
}

static int nhrp_reg_send_req(struct thread *t)
{
	struct nhrp_registration *r = THREAD_ARG(t);
	struct nhrp_nhs *nhs = r->nhs;
	char buf1[SU_ADDRSTRLEN], buf2[SU_ADDRSTRLEN];
	struct interface *ifp = nhs->ifp;
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_afi_data *if_ad = &nifp->afi[nhs->afi];
	union sockunion *dst_proto;
	struct zbuf *zb;
	struct nhrp_packet_header *hdr;
	struct nhrp_extension_header *ext;
	struct nhrp_cie_header *cie;

	r->t_register = NULL;
	if (!nhrp_peer_check(r->peer, 2)) {
		debugf(NHRP_DEBUG_COMMON, "NHS: Waiting link for %s",
			sockunion2str(&r->peer->vc->remote.nbma, buf1, sizeof buf1));
		thread_add_timer(master, nhrp_reg_send_req, r, 120,
				 &r->t_register);
		return 0;
	}

	thread_add_timer(master, nhrp_reg_timeout, r, r->timeout,
			 &r->t_register);

	/* RFC2332 5.2.3 NHC uses it's own address as dst if NHS is unknown */
	dst_proto = &nhs->proto_addr;
	if (sockunion_family(dst_proto) == AF_UNSPEC)
		dst_proto = &if_ad->addr;

	sockunion2str(&if_ad->addr, buf1, sizeof(buf1));
	sockunion2str(dst_proto, buf2, sizeof(buf2));
	debugf(NHRP_DEBUG_COMMON, "NHS: Register %s -> %s (timeout %d)", buf1, buf2, r->timeout);

	/* No protocol address configured for tunnel interface */
	if (sockunion_family(&if_ad->addr) == AF_UNSPEC)
		return 0;

	zb = zbuf_alloc(1400);
	hdr = nhrp_packet_push(zb, NHRP_PACKET_REGISTRATION_REQUEST, &nifp->nbma, &if_ad->addr, dst_proto);
	hdr->hop_count = 1;
	if (!(if_ad->flags & NHRP_IFF_REG_NO_UNIQUE))
		hdr->flags |= htons(NHRP_FLAG_REGISTRATION_UNIQUE);

	hdr->u.request_id = htonl(nhrp_reqid_alloc(&nhrp_packet_reqid, &r->reqid, nhrp_reg_reply));

	/* FIXME: push CIE for each local protocol address */
	cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, NULL, NULL);
	cie->prefix_length = 0xff;
	cie->holding_time = htons(if_ad->holdtime);
	cie->mtu = htons(if_ad->mtu);

	nhrp_ext_request(zb, hdr, ifp);

	/* Cisco NAT detection extension */
	hdr->flags |= htons(NHRP_FLAG_REGISTRATION_NAT);
	ext = nhrp_ext_push(zb, hdr, NHRP_EXTENSION_NAT_ADDRESS);
	cie = nhrp_cie_push(zb, NHRP_CODE_SUCCESS, &nifp->nbma, &if_ad->addr);
	cie->prefix_length = 8 * sockunion_get_addrlen(&if_ad->addr);
	nhrp_ext_complete(zb, ext);

	nhrp_packet_complete(zb, hdr);
	nhrp_peer_send(r->peer, zb);
	zbuf_free(zb);

	return 0;
}

static void nhrp_reg_delete(struct nhrp_registration *r)
{
	nhrp_peer_notify_del(r->peer, &r->peer_notifier);
	nhrp_peer_unref(r->peer);
	list_del(&r->reglist_entry);
	THREAD_OFF(r->t_register);
	XFREE(MTYPE_NHRP_REGISTRATION, r);
}

static struct nhrp_registration *nhrp_reg_by_nbma(struct nhrp_nhs *nhs, const union sockunion *nbma_addr)
{
	struct nhrp_registration *r;

	list_for_each_entry(r, &nhs->reglist_head, reglist_entry)
		if (sockunion_same(&r->peer->vc->remote.nbma, nbma_addr))
			return r;
	return NULL;
}

static void nhrp_nhs_resolve_cb(struct resolver_query *q, int n, union sockunion *addrs)
{
	struct nhrp_nhs *nhs = container_of(q, struct nhrp_nhs, dns_resolve);
	struct nhrp_interface *nifp = nhs->ifp->info;
	struct nhrp_registration *reg, *regn;
	int i;

	nhs->t_resolve = NULL;
	if (n < 0) {
		/* Failed, retry in a moment */
		thread_add_timer(master, nhrp_nhs_resolve, nhs, 5,
				 &nhs->t_resolve);
		return;
	}

	thread_add_timer(master, nhrp_nhs_resolve, nhs, 2 * 60 * 60,
			 &nhs->t_resolve);

	list_for_each_entry(reg, &nhs->reglist_head, reglist_entry)
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
		list_init(&reg->reglist_entry);
		list_add_tail(&reg->reglist_entry, &nhs->reglist_head);
		nhrp_peer_notify_add(reg->peer, &reg->peer_notifier, nhrp_reg_peer_notify);
		thread_add_timer_msec(master, nhrp_reg_send_req, reg, 50,
				      &reg->t_register);
	}

	list_for_each_entry_safe(reg, regn, &nhs->reglist_head, reglist_entry) {
		if (reg->mark)
			nhrp_reg_delete(reg);
	}
}

static int nhrp_nhs_resolve(struct thread *t)
{
	struct nhrp_nhs *nhs = THREAD_ARG(t);

	resolver_resolve(&nhs->dns_resolve, AF_INET, nhs->nbma_fqdn, nhrp_nhs_resolve_cb);

	return 0;
}

int nhrp_nhs_add(struct interface *ifp, afi_t afi, union sockunion *proto_addr, const char *nbma_fqdn)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_nhs *nhs;

	if (sockunion_family(proto_addr) != AF_UNSPEC &&
	    sockunion_family(proto_addr) != afi2family(afi))
		return NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH;

	list_for_each_entry(nhs, &nifp->afi[afi].nhslist_head, nhslist_entry) {
		if (sockunion_family(&nhs->proto_addr) != AF_UNSPEC &&
		    sockunion_family(proto_addr) != AF_UNSPEC &&
		    sockunion_same(&nhs->proto_addr, proto_addr))
			return NHRP_ERR_ENTRY_EXISTS;

		if (strcmp(nhs->nbma_fqdn, nbma_fqdn) == 0)
			return NHRP_ERR_ENTRY_EXISTS;
	}

	nhs = XMALLOC(MTYPE_NHRP_NHS, sizeof(struct nhrp_nhs));
	if (!nhs) return NHRP_ERR_NO_MEMORY;

	*nhs = (struct nhrp_nhs) {
		.afi = afi,
		.ifp = ifp,
		.proto_addr = *proto_addr,
		.nbma_fqdn = strdup(nbma_fqdn),
		.reglist_head = LIST_INITIALIZER(nhs->reglist_head),
	};
	list_add_tail(&nhs->nhslist_entry, &nifp->afi[afi].nhslist_head);
	thread_add_timer_msec(master, nhrp_nhs_resolve, nhs, 1000,
			      &nhs->t_resolve);

	return NHRP_OK;
}

int nhrp_nhs_del(struct interface *ifp, afi_t afi, union sockunion *proto_addr, const char *nbma_fqdn)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_nhs *nhs, *nnhs;
	int ret = NHRP_ERR_ENTRY_NOT_FOUND;

	if (sockunion_family(proto_addr) != AF_UNSPEC &&
	    sockunion_family(proto_addr) != afi2family(afi))
		return NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH;

	list_for_each_entry_safe(nhs, nnhs, &nifp->afi[afi].nhslist_head, nhslist_entry) {
		if (!sockunion_same(&nhs->proto_addr, proto_addr))
			continue;
		if (strcmp(nhs->nbma_fqdn, nbma_fqdn) != 0)
			continue;

		nhrp_nhs_free(nhs);
		ret = NHRP_OK;
	}

	return ret;
}

int nhrp_nhs_free(struct nhrp_nhs *nhs)
{
	struct nhrp_registration *r, *rn;

	list_for_each_entry_safe(r, rn, &nhs->reglist_head, reglist_entry)
		nhrp_reg_delete(r);
	THREAD_OFF(nhs->t_resolve);
	list_del(&nhs->nhslist_entry);
	free((void*) nhs->nbma_fqdn);
	XFREE(MTYPE_NHRP_NHS, nhs);
	return 0;
}

void nhrp_nhs_terminate(void)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct nhrp_interface *nifp;
	struct nhrp_nhs *nhs, *tmp;
	afi_t afi;

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		nifp = ifp->info;
		for (afi = 0; afi < AFI_MAX; afi++) {
			list_for_each_entry_safe(nhs, tmp, &nifp->afi[afi].nhslist_head, nhslist_entry)
				nhrp_nhs_free(nhs);
		}
	}
}

void nhrp_nhs_foreach(struct interface *ifp, afi_t afi, void (*cb)(struct nhrp_nhs *, struct nhrp_registration *, void *), void *ctx)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_nhs *nhs;
	struct nhrp_registration *reg;

	list_for_each_entry(nhs, &nifp->afi[afi].nhslist_head, nhslist_entry) {
		if (!list_empty(&nhs->reglist_head)) {
			list_for_each_entry(reg, &nhs->reglist_head, reglist_entry)
				cb(nhs, reg, ctx);
		} else
			cb(nhs, 0, ctx);
	}
}
