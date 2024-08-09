// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra SR-TE code
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>

#include "lib/zclient.h"
#include "lib/lib_errors.h"
#include "frrdistance.h"

#include "zebra/zebra_srte.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zapi_msg.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_SR_POLICY, "SR Policy");

static void zebra_sr_policy_deactivate(struct zebra_sr_policy *policy);

/* Generate rb-tree of SR Policy instances. */
static inline int
zebra_sr_policy_instance_compare(const struct zebra_sr_policy *a,
				 const struct zebra_sr_policy *b)
{
	return sr_policy_compare(&a->endpoint, &b->endpoint, a->color,
				 b->color);
}
RB_GENERATE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	    zebra_sr_policy_instance_compare)

struct zebra_sr_policy_instance_head zebra_sr_policy_instances =
	RB_INITIALIZER(&zebra_sr_policy_instances);

struct zebra_sr_policy *zebra_sr_policy_add(uint32_t color,
					    struct ipaddr *endpoint, char *name)
{
	struct zebra_sr_policy *policy;

	policy = XCALLOC(MTYPE_ZEBRA_SR_POLICY, sizeof(*policy));
	policy->color = color;
	policy->endpoint = *endpoint;
	strlcpy(policy->name, name, sizeof(policy->name));
	policy->status = ZEBRA_SR_POLICY_DOWN;
	RB_INSERT(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);

	return policy;
}

void zebra_sr_policy_del(struct zebra_sr_policy *policy)
{
	if (policy->status == ZEBRA_SR_POLICY_UP)
		zebra_sr_policy_deactivate(policy);
	RB_REMOVE(zebra_sr_policy_instance_head, &zebra_sr_policy_instances,
		  policy);
	XFREE(MTYPE_ZEBRA_SR_POLICY, policy);
}

struct zebra_sr_policy *zebra_sr_policy_find(uint32_t color,
					     struct ipaddr *endpoint)
{
	struct zebra_sr_policy policy = {};

	policy.color = color;
	policy.endpoint = *endpoint;
	return RB_FIND(zebra_sr_policy_instance_head,
		       &zebra_sr_policy_instances, &policy);
}

struct zebra_sr_policy *zebra_sr_policy_find_by_name(char *name)
{
	struct zebra_sr_policy *policy;

	// TODO: create index for policy names
	RB_FOREACH (policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		if (strcmp(policy->name, name) == 0)
			return policy;
	}

	return NULL;
}

static int process_routes_for_policy(struct zebra_sr_policy *policy,
				     struct zserv *client, uint32_t message,
				     struct stream *s, struct zapi_nexthop *znh,
				     unsigned long *nump)
{
	int num = 0;
	int ret, i;
	struct prefix p = {};

	assert(policy->status == ZEBRA_SR_POLICY_UP);
	p.family = AF_INET6;
	p.prefixlen = IPV6_MAX_BITLEN;
	memcpy(&p.u.prefix6, &policy->endpoint.ipaddr_v6, sizeof(p.u.prefix6));

	stream_putc(s, ZEBRA_ROUTE_SRTE);
	stream_putw(s, 0); /* instance - not available */
	stream_putc(s, policy->segment_list.distance);
	stream_putl(s, policy->segment_list.metric);
	*nump = stream_get_endp(s);
	stream_putc(s, 0);

	for (i = 0; i < policy->segment_list.nexthop_resolved_num; i++) {
		znh = &policy->segment_list.nexthop_resolved[i];
		/* add SRTE in znh */
		if (CHECK_FLAG(message, ZAPI_MESSAGE_SRTE))
			znh->srte_color = policy->color;
		ret = zapi_nexthop_encode(s, znh, 0, message);
		if (ret < 0)
			goto failure;
		num++;
	}
	stream_putc_at(s, *nump, num);
	stream_putw_at(s, 0, stream_get_endp(s));

	client->nh_last_upd_time = monotime(NULL);
	return zserv_send_message(client, s);

failure:
	stream_free(s);
	/* Handle failure as needed */
	return ret;
}

static int zebra_sr_policy_notify_update_client(struct zebra_sr_policy *policy,
						struct zserv *client)
{
	const struct zebra_nhlfe *nhlfe;
	struct stream *s;
	uint32_t message = 0;
	unsigned long nump = 0;
	uint8_t num;
	struct zapi_nexthop znh;
	int ret;

	/* Get output stream. */
	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_NEXTHOP_UPDATE, zvrf_id(policy->zvrf));

	/* Message flags. */
	SET_FLAG(message, ZAPI_MESSAGE_SRTE);
	stream_putl(s, message);

	stream_putw(s, SAFI_UNICAST);
	/*
	 * The prefix is copied twice because the ZEBRA_NEXTHOP_UPDATE
	 * code was modified to send back both the matched against
	 * as well as the actual matched.  There does not appear to
	 * be an equivalent here so just send the same thing twice.
	 */
	switch (policy->endpoint.ipa_type) {
	case IPADDR_V4:
		stream_putw(s, AF_INET);
		stream_putc(s, IPV4_MAX_BITLEN);
		stream_put_in_addr(s, &policy->endpoint.ipaddr_v4);
		stream_putw(s, AF_INET);
		stream_putc(s, IPV4_MAX_BITLEN);
		stream_put_in_addr(s, &policy->endpoint.ipaddr_v4);
		break;
	case IPADDR_V6:
		stream_putw(s, AF_INET6);
		stream_putc(s, IPV6_MAX_BITLEN);
		stream_put(s, &policy->endpoint.ipaddr_v6, IPV6_MAX_BYTELEN);
		stream_putw(s, AF_INET6);
		stream_putc(s, IPV6_MAX_BITLEN);
		stream_put(s, &policy->endpoint.ipaddr_v6, IPV6_MAX_BYTELEN);
		break;
	case IPADDR_NONE:
		flog_warn(EC_LIB_DEVELOPMENT,
			  "%s: unknown policy endpoint address family: %u",
			  __func__, policy->endpoint.ipa_type);
		exit(1);
	}
	stream_putl(s, policy->color);

	if (policy->segment_list.srv6_segs.num_segs > SRV6_MAX_SIDS)
		policy->segment_list.srv6_segs.num_segs = SRV6_MAX_SIDS;

	if (policy->segment_list.srv6_segs.num_segs > 0)
		return process_routes_for_policy(policy, client, message, s,
						 &znh, &nump);

	num = 0;
	frr_each (nhlfe_list_const, &policy->lsp->nhlfe_list, nhlfe) {
		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
		    || CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			continue;

		if (num == 0) {
			stream_putc(s, re_type_from_lsp_type(nhlfe->type));
			stream_putw(s, 0); /* instance - not available */
			stream_putc(s, nhlfe->distance);
			stream_putl(s, 0); /* metric - not available */
			nump = stream_get_endp(s);
			stream_putc(s, 0);
		}

		zapi_nexthop_from_nexthop(&znh, nhlfe->nexthop);
		ret = zapi_nexthop_encode(s, &znh, 0, message);
		if (ret < 0)
			goto failure;

		num++;
	}
	stream_putc_at(s, nump, num);
	stream_putw_at(s, 0, stream_get_endp(s));

	client->nh_last_upd_time = monotime(NULL);
	return zserv_send_message(client, s);

failure:

	stream_free(s);
	return -1;
}

static void zebra_sr_policy_notify_update(struct zebra_sr_policy *policy)
{
	struct rnh *rnh;
	struct prefix p = {};
	struct zebra_vrf *zvrf;
	struct listnode *node;
	struct zserv *client;

	zvrf = policy->zvrf;
	switch (policy->endpoint.ipa_type) {
	case IPADDR_V4:
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;
		p.u.prefix4 = policy->endpoint.ipaddr_v4;
		break;
	case IPADDR_V6:
		p.family = AF_INET6;
		p.prefixlen = IPV6_MAX_BITLEN;
		p.u.prefix6 = policy->endpoint.ipaddr_v6;
		break;
	case IPADDR_NONE:
		flog_warn(EC_LIB_DEVELOPMENT,
			  "%s: unknown policy endpoint address family: %u",
			  __func__, policy->endpoint.ipa_type);
		exit(1);
	}

	rnh = zebra_lookup_rnh(&p, zvrf_id(zvrf), SAFI_UNICAST);
	if (!rnh)
		return;

	for (ALL_LIST_ELEMENTS_RO(rnh->client_list, node, client)) {
		if (policy->status == ZEBRA_SR_POLICY_UP)
			zebra_sr_policy_notify_update_client(policy, client);
		else
			/* Fallback to the IGP shortest path. */
			zebra_send_rnh_update(rnh, client, zvrf_id(zvrf),
					      policy->color);
	}
}

static void zebra_sr_policy_srv6_activate(struct zebra_sr_policy *policy)
{
	policy->status = ZEBRA_SR_POLICY_UP;
	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_UP);
	zebra_sr_policy_notify_update(policy);
}

static void zebra_sr_policy_activate(struct zebra_sr_policy *policy,
				     struct zebra_lsp *lsp)
{
	policy->status = ZEBRA_SR_POLICY_UP;
	policy->lsp = lsp;
	(void)zebra_sr_policy_bsid_install(policy);
	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_UP);
	zebra_sr_policy_notify_update(policy);
}

static void zebra_sr_policy_update(struct zebra_sr_policy *policy,
				   struct zebra_lsp *lsp,
				   struct zapi_srte_tunnel *old_tunnel)
{
	bool bsid_mpls_changed;
	bool segment_list_mpls_changed, segment_list_srv6_changed;

	policy->lsp = lsp;

	bsid_mpls_changed = policy->segment_list.local_label !=
			    old_tunnel->local_label;

	segment_list_mpls_changed =
		policy->segment_list.label_num != old_tunnel->label_num ||
		memcmp(policy->segment_list.labels, old_tunnel->labels,
		       sizeof(mpls_label_t) * policy->segment_list.label_num);

	segment_list_srv6_changed =
		policy->segment_list.srv6_segs.num_segs !=
			old_tunnel->srv6_segs.num_segs ||
		memcmp(policy->segment_list.srv6_segs.segs,
		       old_tunnel->srv6_segs.segs,
		       sizeof(struct in6_addr) *
			       policy->segment_list.srv6_segs.num_segs);

	/* Re-install label stack if necessary. */
	if (bsid_mpls_changed || segment_list_mpls_changed) {
		zebra_sr_policy_bsid_uninstall(policy, old_tunnel->local_label);
		(void)zebra_sr_policy_bsid_install(policy);
	}

	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_UP);

	/* Handle segment-list update. */
	if (segment_list_mpls_changed || segment_list_srv6_changed)
		zebra_sr_policy_notify_update(policy);
}

static void zebra_sr_policy_deactivate(struct zebra_sr_policy *policy)
{
	policy->status = ZEBRA_SR_POLICY_DOWN;
	policy->lsp = NULL;

	if (policy->segment_list.local_label)
		zebra_sr_policy_bsid_uninstall(policy,
					       policy->segment_list.local_label);

	zsend_sr_policy_notify_status(policy->color, &policy->endpoint,
				      policy->name, ZEBRA_SR_POLICY_DOWN);
	zebra_sr_policy_notify_update(policy);
}

int zebra_sr_policy_validate(struct zebra_sr_policy *policy,
			     struct zapi_srte_tunnel *new_tunnel)
{
	struct zapi_srte_tunnel old_tunnel = policy->segment_list;
	struct zebra_lsp *lsp = NULL;
	bool srv6_sid_resolved = false;

	if (new_tunnel)
		policy->segment_list = *new_tunnel;

	/* Try to resolve the Binding-SID nexthops. */
	if (policy->segment_list.type == ZEBRA_SR_LSP_SRTE)
		lsp = mpls_lsp_find(policy->zvrf,
				    policy->segment_list.labels[0]);

	/* Check if there are resolved nexthops in the segment list. */
	srv6_sid_resolved = policy->segment_list.nexthop_resolved_num ? true
								      : false;

	if ((!lsp || !lsp->best_nhlfe ||
	     lsp->addr_family != ipaddr_family(&policy->endpoint)) &&
	    !srv6_sid_resolved) {
		if (policy->status == ZEBRA_SR_POLICY_UP)
			zebra_sr_policy_deactivate(policy);
		return -1;
	}

	/* First label was resolved successfully. */
	if (policy->status == ZEBRA_SR_POLICY_DOWN) {
		zebra_sr_policy_activate(policy, lsp);
		zebra_sr_policy_srv6_activate(policy);
	} else
		zebra_sr_policy_update(policy, lsp, &old_tunnel);

	return 0;
}

int zebra_sr_policy_bsid_install(struct zebra_sr_policy *policy)
{
	struct zapi_srte_tunnel *zt = &policy->segment_list;
	struct zebra_nhlfe *nhlfe;

	if (zt->local_label == MPLS_LABEL_NONE)
		return 0;

	frr_each_safe (nhlfe_list, &policy->lsp->nhlfe_list, nhlfe) {
		uint8_t num_out_labels;
		mpls_label_t *out_labels;
		mpls_label_t null_label = MPLS_LABEL_IMPLICIT_NULL;

		if (!CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
		    || CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_DELETED))
			continue;

		/*
		 * Don't push the first SID if the corresponding action in the
		 * LFIB is POP.
		 */
		if (!nhlfe->nexthop->nh_label
		    || !nhlfe->nexthop->nh_label->num_labels
		    || nhlfe->nexthop->nh_label->label[0]
			       == MPLS_LABEL_IMPLICIT_NULL) {
			if (zt->label_num > 1) {
				num_out_labels = zt->label_num - 1;
				out_labels = &zt->labels[1];
			} else {
				num_out_labels = 1;
				out_labels = &null_label;
			}
		} else {
			num_out_labels = zt->label_num;
			out_labels = zt->labels;
		}

		if (mpls_lsp_install(policy->zvrf,
				     lsp_type_from_sr_type(zt->type),
				     zt->local_label, num_out_labels, out_labels,
				     nhlfe->nexthop->type, &nhlfe->nexthop->gate,
				     nhlfe->nexthop->ifindex) < 0)
			return -1;
	}

	return 0;
}

void zebra_sr_policy_bsid_uninstall(struct zebra_sr_policy *policy,
				    mpls_label_t old_bsid)
{
	struct zapi_srte_tunnel *zt = &policy->segment_list;

	mpls_lsp_uninstall_all_vrf(policy->zvrf,
				   lsp_type_from_sr_type(zt->type), old_bsid);
}

int zebra_sr_policy_label_update(mpls_label_t label,
				 enum zebra_sr_policy_update_label_mode mode)
{
	struct zebra_sr_policy *policy;

	RB_FOREACH (policy, zebra_sr_policy_instance_head,
		    &zebra_sr_policy_instances) {
		mpls_label_t next_hop_label;

		next_hop_label = policy->segment_list.labels[0];
		if (next_hop_label != label)
			continue;

		switch (mode) {
		case ZEBRA_SR_POLICY_LABEL_CREATED:
		case ZEBRA_SR_POLICY_LABEL_UPDATED:
		case ZEBRA_SR_POLICY_LABEL_REMOVED:
			zebra_sr_policy_validate(policy, NULL);
			break;
		}
	}

	return 0;
}

static int zebra_srte_client_close_cleanup(struct zserv *client)
{
	int sock = client->sock;
	struct zebra_sr_policy *policy, *policy_temp;

	if (!sock)
		return 0;

	RB_FOREACH_SAFE (policy, zebra_sr_policy_instance_head,
			 &zebra_sr_policy_instances, policy_temp) {
		if (policy->sock == sock)
			zebra_sr_policy_del(policy);
	}
	return 1;
}

void zebra_srte_init(void)
{
	hook_register(zserv_client_close, zebra_srte_client_close_cleanup);
}
