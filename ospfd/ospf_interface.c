// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF Interface functions.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "log.h"
#include "network.h"
#include "zclient.h"
#include "bfd.h"
#include "ldp_sync.h"
#include "plist.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_ldp_sync.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_te.h"

DEFINE_QOBJ_TYPE(ospf_interface);
DEFINE_HOOK(ospf_vl_add, (struct ospf_vl_data * vd), (vd));
DEFINE_HOOK(ospf_vl_delete, (struct ospf_vl_data * vd), (vd));
DEFINE_HOOK(ospf_if_update, (struct interface * ifp), (ifp));
DEFINE_HOOK(ospf_if_delete, (struct interface * ifp), (ifp));

int ospf_interface_neighbor_count(struct ospf_interface *oi)
{
	int count = 0;
	struct route_node *rn;
	struct ospf_neighbor *nbr = NULL;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;
		if (!nbr)
			continue;

		/* Do not show myself. */
		if (nbr == oi->nbr_self)
			continue;
		/* Down state is not shown. */
		if (nbr->state == NSM_Down)
			continue;
		count++;
	}

	return count;
}


void ospf_intf_neighbor_filter_apply(struct ospf_interface *oi)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr = NULL;
	struct prefix nbr_src_prefix = { AF_INET, IPV4_MAX_BITLEN, { 0 } };

	if (!oi->nbr_filter)
		return;

	/*
	 * Kill neighbors that don't match the neighbor filter prefix-list
	 * excluding the neighbor for the router itself and any neighbors
	 * that are already down.
	 */
	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;
		if (nbr && nbr != oi->nbr_self && nbr->state != NSM_Down) {
			nbr_src_prefix.u.prefix4 = nbr->src;
			if (prefix_list_apply(oi->nbr_filter,
					      (struct prefix *)&(
						      nbr_src_prefix)) !=
			    PREFIX_PERMIT)
				OSPF_NSM_EVENT_EXECUTE(nbr, NSM_KillNbr);
		}
	}
}

int ospf_if_get_output_cost(struct ospf_interface *oi)
{
	/* If all else fails, use default OSPF cost */
	uint32_t cost;
	uint32_t bw, refbw;

	/* if LDP-IGP Sync is running on interface set cost so interface
	 * is used only as last resort
	 */
	if (ldp_sync_if_is_enabled(IF_DEF_PARAMS(oi->ifp)->ldp_sync_info))
		return (LDP_OSPF_LSINFINITY);

	/* ifp speed and bw can be 0 in some platforms, use ospf default bw
	   if bw is configured under interface it would be used.
	 */
	if (!oi->ifp->bandwidth && oi->ifp->speed)
		bw = oi->ifp->speed;
	else
		bw = oi->ifp->bandwidth ? oi->ifp->bandwidth
					: OSPF_DEFAULT_BANDWIDTH;
	refbw = oi->ospf->ref_bandwidth;

	/* A specified ip ospf cost overrides a calculated one. */
	if (OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(oi->ifp), output_cost_cmd)
	    || OSPF_IF_PARAM_CONFIGURED(oi->params, output_cost_cmd))
		cost = OSPF_IF_PARAM(oi, output_cost_cmd);
	/* See if a cost can be calculated from the zebra processes
	   interface bandwidth field. */
	else {
		cost = (uint32_t)((double)refbw / (double)bw + (double)0.5);
		if (cost < 1)
			cost = 1;
		else if (cost > 65535)
			cost = 65535;

		if (if_is_loopback(oi->ifp))
			cost = 0;
	}

	return cost;
}

void ospf_if_recalculate_output_cost(struct interface *ifp)
{
	uint32_t newcost;
	struct route_node *rn;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi;

		if ((oi = rn->info) == NULL)
			continue;

		newcost = ospf_if_get_output_cost(oi);

		/* Is actual output cost changed? */
		if (oi->output_cost != newcost) {
			oi->output_cost = newcost;
			ospf_router_lsa_update_area(oi->area);
		}
	}
}

/* Simulate down/up on the interface.  This is needed, for example, when
   the MTU changes. */
void ospf_if_reset(struct interface *ifp)
{
	struct route_node *rn;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi;

		if ((oi = rn->info) == NULL)
			continue;

		ospf_if_down(oi);
		ospf_if_up(oi);
	}
}

static void ospf_if_default_variables(struct ospf_interface *oi)
{
	/* Set default values. */

	oi->type = OSPF_IFTYPE_BROADCAST;

	oi->state = ISM_Down;

	oi->crypt_seqnum = 0;

	/* This must be short, (less than RxmtInterval)
	   - RFC 2328 Section 13.5 para 3.  Set to 1 second to avoid Acks being
	     held back for too long - MAG */
	oi->v_ls_ack = 1;
}

/* lookup oi for specified prefix/ifp */
struct ospf_interface *ospf_if_table_lookup(struct interface *ifp,
					    struct prefix *prefix)
{
	struct prefix p;
	struct route_node *rn;
	struct ospf_interface *rninfo = NULL;

	p = *prefix;
	p.prefixlen = IPV4_MAX_BITLEN;

	/* route_node_get implicitely locks */
	if ((rn = route_node_lookup(IF_OIFS(ifp), &p))) {
		rninfo = (struct ospf_interface *)rn->info;
		route_unlock_node(rn);
	}

	return rninfo;
}

static void ospf_add_to_if(struct interface *ifp, struct ospf_interface *oi)
{
	struct route_node *rn;
	struct prefix p;

	p = *oi->address;
	p.prefixlen = IPV4_MAX_BITLEN;
	apply_mask(&p);

	rn = route_node_get(IF_OIFS(ifp), &p);
	/* rn->info should either be NULL or equal to this oi
	 * as route_node_get may return an existing node
	 */
	assert(!rn->info || rn->info == oi);
	rn->info = oi;
}

static void ospf_delete_from_if(struct interface *ifp,
				struct ospf_interface *oi)
{
	struct route_node *rn;
	struct prefix p;

	p = *oi->address;
	p.prefixlen = IPV4_MAX_BITLEN;

	rn = route_node_lookup(IF_OIFS(oi->ifp), &p);
	assert(rn);
	assert(rn->info);
	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);
}

struct ospf_interface *ospf_if_new(struct ospf *ospf, struct interface *ifp,
				   struct prefix *p)
{
	struct ospf_interface *oi;

	oi = ospf_if_table_lookup(ifp, p);
	if (oi)
		return oi;

	oi = XCALLOC(MTYPE_OSPF_IF, sizeof(struct ospf_interface));

	oi->obuf = ospf_fifo_new();

	/* Set zebra interface pointer. */
	oi->ifp = ifp;
	oi->address = p;

	ospf_add_to_if(ifp, oi);
	listnode_add(ospf->oiflist, oi);

	/* Initialize neighbor list. */
	oi->nbrs = route_table_init();

	/* Initialize static neighbor list. */
	oi->nbr_nbma = list_new();

	/* Initialize Link State Acknowledgment list. */
	oi->ls_ack = list_new();
	oi->ls_ack_direct.ls_ack = list_new();

	/* Set default values. */
	ospf_if_default_variables(oi);

	/* Set pseudo neighbor to Null */
	oi->nbr_self = NULL;

	oi->ls_upd_queue = route_table_init();
	oi->t_ls_upd_event = NULL;
	oi->t_ls_ack_direct = NULL;

	oi->crypt_seqnum = frr_sequence32_next();

	ospf_opaque_type9_lsa_init(oi);

	oi->ospf = ospf;

	QOBJ_REG(oi, ospf_interface);

	/* If first oi, check per-intf write socket */
	if (ospf->oi_running && ospf->intf_socket_enabled)
		ospf_ifp_sock_init(ifp);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: ospf interface %s vrf %s id %u created",
			   __func__, ifp->name, ospf_get_name(ospf),
			   ospf->vrf_id);

	return oi;
}

/* Restore an interface to its pre UP state
   Used from ism_interface_down only */
void ospf_if_cleanup(struct ospf_interface *oi)
{
	struct route_node *rn;
	struct listnode *node, *nnode;
	struct ospf_neighbor *nbr;
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf_lsa *lsa;

	/* oi->nbrs and oi->nbr_nbma should be deleted on InterfaceDown event */
	/* delete all static neighbors attached to this interface */
	for (ALL_LIST_ELEMENTS(oi->nbr_nbma, node, nnode, nbr_nbma)) {
		EVENT_OFF(nbr_nbma->t_poll);

		if (nbr_nbma->nbr) {
			nbr_nbma->nbr->nbr_nbma = NULL;
			nbr_nbma->nbr = NULL;
		}

		nbr_nbma->oi = NULL;

		listnode_delete(oi->nbr_nbma, nbr_nbma);
	}

	/* send Neighbor event KillNbr to all associated neighbors. */
	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		if ((nbr = rn->info) != NULL)
			if (nbr != oi->nbr_self)
				OSPF_NSM_EVENT_EXECUTE(nbr, NSM_KillNbr);
	}

	/* Cleanup Link State Acknowlegdment list. */
	for (ALL_LIST_ELEMENTS(oi->ls_ack, node, nnode, lsa))
		ospf_lsa_unlock(&lsa); /* oi->ls_ack */
	list_delete_all_node(oi->ls_ack);

	oi->crypt_seqnum = 0;

	/* Empty link state update queue */
	ospf_ls_upd_queue_empty(oi);

	/* Reset pseudo neighbor. */
	ospf_nbr_self_reset(oi, oi->ospf->router_id);
}

void ospf_if_free(struct ospf_interface *oi)
{
	struct interface *ifp = oi->ifp;

	ospf_if_down(oi);

	ospf_fifo_free(oi->obuf);

	assert(oi->state == ISM_Down);

	ospf_opaque_type9_lsa_if_cleanup(oi);

	ospf_opaque_type9_lsa_term(oi);

	QOBJ_UNREG(oi);

	/* Free Pseudo Neighbour */
	ospf_nbr_delete(oi->nbr_self);

	route_table_finish(oi->nbrs);
	route_table_finish(oi->ls_upd_queue);

	/* Free any lists that should be freed */
	list_delete(&oi->nbr_nbma);

	list_delete(&oi->ls_ack);
	list_delete(&oi->ls_ack_direct.ls_ack);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: ospf interface %s vrf %s id %u deleted",
			   __func__, oi->ifp->name, oi->ifp->vrf->name,
			   oi->ifp->vrf->vrf_id);

	ospf_delete_from_if(oi->ifp, oi);

	listnode_delete(oi->ospf->oiflist, oi);
	listnode_delete(oi->area->oiflist, oi);

	event_cancel_event(master, oi);

	/* If last oi, close per-interface socket */
	if (ospf_oi_count(ifp) == 0)
		ospf_ifp_sock_close(ifp);

	memset(oi, 0, sizeof(*oi));
	XFREE(MTYPE_OSPF_IF, oi);
}

int ospf_if_is_up(struct ospf_interface *oi)
{
	return if_is_up(oi->ifp);
}

/* Lookup OSPF interface by router LSA posistion */
struct ospf_interface *ospf_if_lookup_by_lsa_pos(struct ospf_area *area,
						 int lsa_pos)
{
	struct listnode *node;
	struct ospf_interface *oi;

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi)) {
		if (lsa_pos >= oi->lsa_pos_beg && lsa_pos < oi->lsa_pos_end)
			return oi;
	}
	return NULL;
}

struct ospf_interface *ospf_if_lookup_by_local_addr(struct ospf *ospf,
						    struct interface *ifp,
						    struct in_addr address)
{
	struct listnode *node;
	struct ospf_interface *oi;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
		if (oi->type != OSPF_IFTYPE_VIRTUALLINK) {
			if (ifp && oi->ifp != ifp)
				continue;

			if (IPV4_ADDR_SAME(&address, &oi->address->u.prefix4))
				return oi;
		}

	return NULL;
}

struct ospf_interface *ospf_if_lookup_by_prefix(struct ospf *ospf,
						struct prefix_ipv4 *p)
{
	struct listnode *node;
	struct ospf_interface *oi;

	/* Check each Interface. */
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		if (oi->type != OSPF_IFTYPE_VIRTUALLINK) {
			struct prefix ptmp;

			prefix_copy(&ptmp, CONNECTED_PREFIX(oi->connected));
			apply_mask(&ptmp);
			if (prefix_same(&ptmp, (struct prefix *)p))
				return oi;
		}
	}
	return NULL;
}

/* determine receiving interface by ifp and source address */
struct ospf_interface *ospf_if_lookup_recv_if(struct ospf *ospf,
					      struct in_addr src,
					      struct interface *ifp)
{
	struct route_node *rn;
	struct prefix_ipv4 addr;
	struct ospf_interface *oi, *match, *unnumbered_match;

	addr.family = AF_INET;
	addr.prefix = src;
	addr.prefixlen = IPV4_MAX_BITLEN;

	match = unnumbered_match = NULL;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		oi = rn->info;

		if (!oi) /* oi can be NULL for PtP aliases */
			continue;

		if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
			continue;

		if (if_is_loopback(oi->ifp))
			continue;

		if (CHECK_FLAG(oi->connected->flags, ZEBRA_IFA_UNNUMBERED))
			unnumbered_match = oi;
		else if (prefix_match(CONNECTED_PREFIX(oi->connected),
				      (struct prefix *)&addr)) {
			if ((match == NULL) || (match->address->prefixlen
						< oi->address->prefixlen))
				match = oi;
		}
	}

	if (match)
		return match;

	return unnumbered_match;
}

void ospf_interface_fifo_flush(struct ospf_interface *oi)
{
	struct ospf *ospf = oi->ospf;

	ospf_fifo_flush(oi->obuf);

	if (oi->on_write_q) {
		listnode_delete(ospf->oi_write_q, oi);
		if (list_isempty(ospf->oi_write_q))
			EVENT_OFF(ospf->t_write);
		oi->on_write_q = 0;
	}
}

static void ospf_if_reset_stats(struct ospf_interface *oi)
{
	oi->hello_in = oi->hello_out = 0;
	oi->db_desc_in = oi->db_desc_out = 0;
	oi->ls_req_in = oi->ls_req_out = 0;
	oi->ls_upd_in = oi->ls_upd_out = 0;
	oi->ls_ack_in = oi->ls_ack_out = 0;
}

void ospf_if_stream_unset(struct ospf_interface *oi)
{
	/* flush the interface packet queue */
	ospf_interface_fifo_flush(oi);
	/*reset protocol stats */
	ospf_if_reset_stats(oi);
}


static struct ospf_if_params *ospf_new_if_params(void)
{
	struct ospf_if_params *oip;

	oip = XCALLOC(MTYPE_OSPF_IF_PARAMS, sizeof(struct ospf_if_params));

	UNSET_IF_PARAM(oip, output_cost_cmd);
	UNSET_IF_PARAM(oip, transmit_delay);
	UNSET_IF_PARAM(oip, retransmit_interval);
	UNSET_IF_PARAM(oip, passive_interface);
	UNSET_IF_PARAM(oip, v_hello);
	UNSET_IF_PARAM(oip, fast_hello);
	UNSET_IF_PARAM(oip, v_gr_hello_delay);
	UNSET_IF_PARAM(oip, v_wait);
	UNSET_IF_PARAM(oip, priority);
	UNSET_IF_PARAM(oip, type);
	UNSET_IF_PARAM(oip, auth_simple);
	UNSET_IF_PARAM(oip, auth_crypt);
	UNSET_IF_PARAM(oip, auth_type);
	UNSET_IF_PARAM(oip, if_area);
	UNSET_IF_PARAM(oip, opaque_capable);
	UNSET_IF_PARAM(oip, keychain_name);
	UNSET_IF_PARAM(oip, nbr_filter_name);

	oip->auth_crypt = list_new();

	oip->network_lsa_seqnum = htonl(OSPF_INITIAL_SEQUENCE_NUMBER);
	oip->is_v_wait_set = false;

	oip->ptp_dmvpn = 0;
	oip->p2mp_delay_reflood = OSPF_P2MP_DELAY_REFLOOD_DEFAULT;
	oip->opaque_capable = OSPF_OPAQUE_CAPABLE_DEFAULT;

	return oip;
}

static void ospf_del_if_params(struct interface *ifp,
			       struct ospf_if_params *oip)
{
	list_delete(&oip->auth_crypt);
	XFREE(MTYPE_OSPF_IF_PARAMS, oip->keychain_name);
	XFREE(MTYPE_OSPF_IF_PARAMS, oip->nbr_filter_name);
	ospf_interface_disable_bfd(ifp, oip);
	ldp_sync_info_free(&(oip->ldp_sync_info));
	XFREE(MTYPE_OSPF_IF_PARAMS, oip);
}

void ospf_free_if_params(struct interface *ifp, struct in_addr addr)
{
	struct ospf_if_params *oip;
	struct prefix_ipv4 p;
	struct route_node *rn;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = addr;
	rn = route_node_lookup(IF_OIFS_PARAMS(ifp), (struct prefix *)&p);
	if (!rn || !rn->info)
		return;

	oip = rn->info;
	route_unlock_node(rn);

	if (!OSPF_IF_PARAM_CONFIGURED(oip, output_cost_cmd) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, transmit_delay) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, retransmit_interval) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, passive_interface) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, v_hello) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, fast_hello) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, v_wait) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, priority) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, type) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, auth_simple) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, auth_type) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, if_area) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, opaque_capable) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, prefix_suppression) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, keychain_name) &&
	    !OSPF_IF_PARAM_CONFIGURED(oip, nbr_filter_name) &&
	    listcount(oip->auth_crypt) == 0) {
		ospf_del_if_params(ifp, oip);
		rn->info = NULL;
		route_unlock_node(rn);
	}
}

struct ospf_if_params *ospf_lookup_if_params(struct interface *ifp,
					     struct in_addr addr)
{
	struct prefix_ipv4 p;
	struct route_node *rn;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = addr;

	rn = route_node_lookup(IF_OIFS_PARAMS(ifp), (struct prefix *)&p);

	if (rn) {
		route_unlock_node(rn);
		return rn->info;
	}

	return NULL;
}

struct ospf_if_params *ospf_get_if_params(struct interface *ifp,
					  struct in_addr addr)
{
	struct prefix_ipv4 p;
	struct route_node *rn;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = addr;
	apply_mask_ipv4(&p);

	rn = route_node_get(IF_OIFS_PARAMS(ifp), (struct prefix *)&p);

	if (rn->info == NULL)
		rn->info = ospf_new_if_params();
	else
		route_unlock_node(rn);

	return rn->info;
}

void ospf_if_update_params(struct interface *ifp, struct in_addr addr)
{
	struct route_node *rn;
	struct ospf_interface *oi;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		if ((oi = rn->info) == NULL)
			continue;

		if (IPV4_ADDR_SAME(&oi->address->u.prefix4, &addr))
			oi->params = ospf_lookup_if_params(
				ifp, oi->address->u.prefix4);
	}
}

int ospf_if_new_hook(struct interface *ifp)
{
	int rc = 0;

	ifp->info = XCALLOC(MTYPE_OSPF_IF_INFO, sizeof(struct ospf_if_info));

	IF_OSPF_IF_INFO(ifp)->oii_fd = -1;

	IF_OIFS(ifp) = route_table_init();
	IF_OIFS_PARAMS(ifp) = route_table_init();

	IF_DEF_PARAMS(ifp) = ospf_new_if_params();

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), transmit_delay);
	IF_DEF_PARAMS(ifp)->transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), retransmit_interval);
	IF_DEF_PARAMS(ifp)->retransmit_interval =
		OSPF_RETRANSMIT_INTERVAL_DEFAULT;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), priority);
	IF_DEF_PARAMS(ifp)->priority = OSPF_ROUTER_PRIORITY_DEFAULT;

	IF_DEF_PARAMS(ifp)->mtu_ignore = OSPF_MTU_IGNORE_DEFAULT;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), v_hello);
	IF_DEF_PARAMS(ifp)->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), fast_hello);
	IF_DEF_PARAMS(ifp)->fast_hello = OSPF_FAST_HELLO_DEFAULT;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), v_gr_hello_delay);
	IF_DEF_PARAMS(ifp)->v_gr_hello_delay = OSPF_HELLO_DELAY_DEFAULT;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), v_wait);
	IF_DEF_PARAMS(ifp)->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), auth_simple);
	memset(IF_DEF_PARAMS(ifp)->auth_simple, 0, OSPF_AUTH_SIMPLE_SIZE);

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), auth_type);
	IF_DEF_PARAMS(ifp)->auth_type = OSPF_AUTH_NOTSET;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), opaque_capable);
	IF_DEF_PARAMS(ifp)->opaque_capable = OSPF_OPAQUE_CAPABLE_DEFAULT;

	IF_DEF_PARAMS(ifp)->prefix_suppression = OSPF_PREFIX_SUPPRESSION_DEFAULT;

	rc = ospf_opaque_new_if(ifp);
	return rc;
}

static int ospf_if_delete_hook(struct interface *ifp)
{
	int rc = 0;
	struct route_node *rn;
	struct ospf_if_info *oii;

	rc = ospf_opaque_del_if(ifp);

	/*
	 * This function must be called before `route_table_finish` due to
	 * BFD integration need to iterate over the interface neighbors to
	 * remove all registrations.
	 */
	ospf_del_if_params(ifp, IF_DEF_PARAMS(ifp));

	for (rn = route_top(IF_OIFS_PARAMS(ifp)); rn; rn = route_next(rn))
		if (rn->info)
			ospf_del_if_params(ifp, rn->info);

	route_table_finish(IF_OIFS(ifp));
	route_table_finish(IF_OIFS_PARAMS(ifp));

	/* Close per-interface socket */
	oii = ifp->info;
	if (oii && oii->oii_fd > 0) {
		close(oii->oii_fd);
		oii->oii_fd = -1;
	}

	XFREE(MTYPE_OSPF_IF_INFO, ifp->info);

	return rc;
}

int ospf_if_is_enable(struct ospf_interface *oi)
{
	if (!(if_is_loopback(oi->ifp)))
		if (if_is_up(oi->ifp))
			return 1;

	return 0;
}

void ospf_if_set_multicast(struct ospf_interface *oi)
{
	if ((oi->state > ISM_Loopback) && (oi->type != OSPF_IFTYPE_LOOPBACK)
	    && (oi->type != OSPF_IFTYPE_VIRTUALLINK)
	    && (OSPF_IF_PASSIVE_STATUS(oi) == OSPF_IF_ACTIVE)) {
		/* The interface should belong to the OSPF-all-routers group. */
		if (!OI_MEMBER_CHECK(oi, MEMBER_ALLROUTERS)
		    && (ospf_if_add_allspfrouters(oi->ospf, oi->address,
						  oi->ifp->ifindex)
			>= 0))
			/* Set the flag only if the system call to join
			 * succeeded. */
			OI_MEMBER_JOINED(oi, MEMBER_ALLROUTERS);
	} else {
		/* The interface should NOT belong to the OSPF-all-routers
		 * group. */
		if (OI_MEMBER_CHECK(oi, MEMBER_ALLROUTERS)) {
			/* Only actually drop if this is the last reference */
			if (OI_MEMBER_COUNT(oi, MEMBER_ALLROUTERS) == 1)
				ospf_if_drop_allspfrouters(oi->ospf,
							   oi->address,
							   oi->ifp->ifindex);
			/* Unset the flag regardless of whether the system call
			   to leave
			   the group succeeded, since it's much safer to assume
			   that
			   we are not a member. */
			OI_MEMBER_LEFT(oi, MEMBER_ALLROUTERS);
		}
	}

	if (((oi->type == OSPF_IFTYPE_BROADCAST)
	     || (oi->type == OSPF_IFTYPE_POINTOPOINT))
	    && ((oi->state == ISM_DR) || (oi->state == ISM_Backup))
	    && (OSPF_IF_PASSIVE_STATUS(oi) == OSPF_IF_ACTIVE)) {
		/* The interface should belong to the OSPF-designated-routers
		 * group. */
		if (!OI_MEMBER_CHECK(oi, MEMBER_DROUTERS)
		    && (ospf_if_add_alldrouters(oi->ospf, oi->address,
						oi->ifp->ifindex)
			>= 0))
			/* Set the flag only if the system call to join
			 * succeeded. */
			OI_MEMBER_JOINED(oi, MEMBER_DROUTERS);
	} else {
		/* The interface should NOT belong to the
		 * OSPF-designated-routers group */
		if (OI_MEMBER_CHECK(oi, MEMBER_DROUTERS)) {
			/* drop only if last reference */
			if (OI_MEMBER_COUNT(oi, MEMBER_DROUTERS) == 1)
				ospf_if_drop_alldrouters(oi->ospf, oi->address,
							 oi->ifp->ifindex);

			/* Unset the flag regardless of whether the system call
			   to leave
			   the group succeeded, since it's much safer to assume
			   that
			   we are not a member. */
			OI_MEMBER_LEFT(oi, MEMBER_DROUTERS);
		}
	}
}

int ospf_if_up(struct ospf_interface *oi)
{
	if (oi == NULL)
		return 0;

	if (oi->type == OSPF_IFTYPE_LOOPBACK)
		OSPF_ISM_EVENT_SCHEDULE(oi, ISM_LoopInd);
	else {
		OSPF_ISM_EVENT_SCHEDULE(oi, ISM_InterfaceUp);
	}

	return 1;
}

/* This function will mark routes with next-hops matching the down
 * OSPF interface as changed. It is used to assure routes that get
 * removed from the zebra RIB when an interface goes down are
 * reinstalled if the interface comes back up prior to an intervening
 * SPF calculation.
 */
static void ospf_if_down_mark_routes_changed(struct route_table *table,
					     struct ospf_interface *oi)
{
	struct route_node *rn;
	struct ospf_route *or;
	struct listnode *nh;
	struct ospf_path *op;

	for (rn = route_top(table); rn; rn = route_next(rn)) {
		or = rn->info;

		if (or == NULL)
			continue;

		for (nh = listhead(or->paths); nh;
		     nh = listnextnode_unchecked(nh)) {
			op = listgetdata(nh);
			if (op->ifindex == oi->ifp->ifindex) {
				or->changed = true;
				break;
			}
		}
	}
}

int ospf_if_down(struct ospf_interface *oi)
{
	struct ospf *ospf;

	if (oi == NULL)
		return 0;

	ospf = oi->ospf;

	/* Cease the HELPER role for all the neighbours
	 * of this interface.
	 */
	if (ospf->is_helper_supported) {
		struct route_node *rn = NULL;

		if (ospf_interface_neighbor_count(oi)) {
			for (rn = route_top(oi->nbrs); rn;
			     rn = route_next(rn)) {
				struct ospf_neighbor *nbr = NULL;

				if (!rn->info)
					continue;

				nbr = rn->info;

				if (OSPF_GR_IS_ACTIVE_HELPER(nbr))
					ospf_gr_helper_exit(
						nbr, OSPF_GR_HELPER_TOPO_CHG);
			}
		}
	}

	OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
	/* delete position in router LSA */
	oi->lsa_pos_beg = 0;
	oi->lsa_pos_end = 0;
	/* Shutdown packet reception and sending */
	ospf_if_stream_unset(oi);

	if (ospf->new_table)
		ospf_if_down_mark_routes_changed(ospf->new_table, oi);

	if (ospf->new_external_route)
		ospf_if_down_mark_routes_changed(ospf->new_external_route, oi);

	return 1;
}


/* Virtual Link related functions. */

struct ospf_vl_data *ospf_vl_data_new(struct ospf_area *area,
				      struct in_addr vl_peer)
{
	struct ospf_vl_data *vl_data;

	vl_data = XCALLOC(MTYPE_OSPF_VL_DATA, sizeof(struct ospf_vl_data));

	vl_data->vl_peer.s_addr = vl_peer.s_addr;
	vl_data->vl_area_id = area->area_id;
	vl_data->vl_area_id_fmt = area->area_id_fmt;

	return vl_data;
}

void ospf_vl_data_free(struct ospf_vl_data *vl_data)
{
	XFREE(MTYPE_OSPF_VL_DATA, vl_data);
}

unsigned int vlink_count = 0;

struct ospf_interface *ospf_vl_new(struct ospf *ospf,
				   struct ospf_vl_data *vl_data)
{
	struct ospf_interface *voi;
	struct interface *vi;
	char ifname[IFNAMSIZ];
	struct ospf_area *area;
	struct in_addr area_id;
	struct connected *co;
	struct prefix_ipv4 *p;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: (%s): Start", __func__, ospf_get_name(ospf));
	if (vlink_count == OSPF_VL_MAX_COUNT) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: Alarm: cannot create more than OSPF_MAX_VL_COUNT virtual links",
				__func__);

		return NULL;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: creating pseudo zebra interface vrf id %u",
			   __func__, ospf->vrf_id);

	snprintf(ifname, sizeof(ifname), "VLINK%u", vlink_count);
	vi = if_get_by_name(ifname, ospf->vrf_id, ospf->name);
	/*
	 * if_get_by_name sets ZEBRA_INTERFACE_LINKDETECTION
	 * virtual links don't need this.
	 */
	UNSET_FLAG(vi->status, ZEBRA_INTERFACE_LINKDETECTION);
	co = connected_new();
	co->ifp = vi;
	if_connected_add_tail(vi->connected, co);

	p = prefix_ipv4_new();
	p->family = AF_INET;
	p->prefix.s_addr = INADDR_ANY;
	p->prefixlen = 0;

	co->address = (struct prefix *)p;

	voi = ospf_if_new(ospf, vi, co->address);
	if (voi == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: Alarm: OSPF int structure is not created",
				__func__);

		return NULL;
	}
	voi->connected = co;
	voi->vl_data = vl_data;
	voi->ifp->mtu = OSPF_VL_MTU;
	voi->type = OSPF_IFTYPE_VIRTUALLINK;

	vlink_count++;
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Created name: %s set if->name to %s", __func__,
			   ifname, vi->name);

	area_id.s_addr = INADDR_ANY;
	area = ospf_area_get(ospf, area_id);
	voi->area = area;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: set associated area to the backbone", __func__);

	/* Add pseudo neighbor. */
	ospf_nbr_self_reset(voi, voi->ospf->router_id);

	ospf_area_add_if(voi->area, voi);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Stop", __func__);
	return voi;
}

static void ospf_vl_if_delete(struct ospf_vl_data *vl_data)
{
	struct interface *ifp = vl_data->vl_oi->ifp;
	struct vrf *vrf = ifp->vrf;

	vl_data->vl_oi->address->u.prefix4.s_addr = INADDR_ANY;
	vl_data->vl_oi->address->prefixlen = 0;
	ospf_if_free(vl_data->vl_oi);
	if_delete(&ifp);
	if (!vrf_is_enabled(vrf))
		vrf_delete(vrf);
}

/* for a defined area, count the number of configured vl
 */
int ospf_vl_count(struct ospf *ospf, struct ospf_area *area)
{
	int count = 0;
	struct ospf_vl_data *vl_data;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->vlinks, node, vl_data)) {
		if (area
		    && !IPV4_ADDR_SAME(&vl_data->vl_area_id, &area->area_id))
			continue;
		count++;
	}
	return count;
}

/* Look up vl_data for given peer, optionally qualified to be in the
 * specified area. NULL area returns first found..
 */
struct ospf_vl_data *ospf_vl_lookup(struct ospf *ospf, struct ospf_area *area,
				    struct in_addr vl_peer)
{
	struct ospf_vl_data *vl_data;
	struct listnode *node;

	if (IS_DEBUG_OSPF_EVENT) {
		zlog_debug("%s: Looking for %pI4", __func__, &vl_peer);
		if (area)
			zlog_debug("%s: in area %pI4", __func__,
				   &area->area_id);
	}

	for (ALL_LIST_ELEMENTS_RO(ospf->vlinks, node, vl_data)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: VL %s, peer %pI4", __func__,
				   vl_data->vl_oi->ifp->name,
				   &vl_data->vl_peer);

		if (area
		    && !IPV4_ADDR_SAME(&vl_data->vl_area_id, &area->area_id))
			continue;

		if (IPV4_ADDR_SAME(&vl_data->vl_peer, &vl_peer))
			return vl_data;
	}

	return NULL;
}

static void ospf_vl_shutdown(struct ospf_vl_data *vl_data)
{
	struct ospf_interface *oi;

	if ((oi = vl_data->vl_oi) == NULL)
		return;

	oi->address->u.prefix4.s_addr = INADDR_ANY;
	oi->address->prefixlen = 0;

	UNSET_FLAG(oi->ifp->flags, IFF_UP);
	/* OSPF_ISM_EVENT_SCHEDULE (oi, ISM_InterfaceDown); */
	OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
}

void ospf_vl_add(struct ospf *ospf, struct ospf_vl_data *vl_data)
{
	listnode_add(ospf->vlinks, vl_data);
	hook_call(ospf_vl_add, vl_data);
}

void ospf_vl_delete(struct ospf *ospf, struct ospf_vl_data *vl_data)
{
	ospf_vl_shutdown(vl_data);
	ospf_vl_if_delete(vl_data);

	hook_call(ospf_vl_delete, vl_data);
	listnode_delete(ospf->vlinks, vl_data);

	ospf_vl_data_free(vl_data);
}

static int ospf_vl_set_params(struct ospf_area *area,
			      struct ospf_vl_data *vl_data, struct vertex *v)
{
	int changed = 0;
	struct ospf_interface *voi;
	struct listnode *node;
	struct vertex_parent *vp = NULL;
	unsigned int i;
	struct router_lsa *rl;
	struct ospf_interface *oi;

	voi = vl_data->vl_oi;

	if (voi->output_cost != v->distance) {

		voi->output_cost = v->distance;
		changed = 1;
	}

	for (ALL_LIST_ELEMENTS_RO(v->parents, node, vp)) {
		vl_data->nexthop.lsa_pos = vp->nexthop->lsa_pos;
		vl_data->nexthop.router = vp->nexthop->router;

		/*
		 * Only deal with interface data when the local
		 * (calculating) node is the SPF root node
		 */
		if (!area->spf_dry_run) {
			oi = ospf_if_lookup_by_lsa_pos(
				area, vl_data->nexthop.lsa_pos);

			if (!IPV4_ADDR_SAME(&voi->address->u.prefix4,
					    &oi->address->u.prefix4))
				changed = 1;

			voi->address->u.prefix4 = oi->address->u.prefix4;
			voi->address->prefixlen = oi->address->prefixlen;
		}

		break; /* We take the first interface. */
	}

	rl = (struct router_lsa *)v->lsa;

	/* use SPF determined backlink index in struct vertex
	 * for virtual link destination address
	 */
	if (vp && vp->backlink >= 0) {
		if (!IPV4_ADDR_SAME(&vl_data->peer_addr,
				    &rl->link[vp->backlink].link_data))
			changed = 1;
		vl_data->peer_addr = rl->link[vp->backlink].link_data;
	} else {
		/* This is highly odd, there is no backlink index
		 * there should be due to the ospf_spf_has_link() check
		 * in SPF. Lets warn and try pick a link anyway.
		 */
		zlog_info("ospf_vl_set_params: No backlink for %s!",
			  vl_data->vl_oi->ifp->name);
		for (i = 0; i < ntohs(rl->links); i++) {
			switch (rl->link[i].type) {
			case LSA_LINK_TYPE_VIRTUALLINK:
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"found back link through VL");
				fallthrough;
			case LSA_LINK_TYPE_TRANSIT:
			case LSA_LINK_TYPE_POINTOPOINT:
				if (!IPV4_ADDR_SAME(&vl_data->peer_addr,
						    &rl->link[i].link_data))
					changed = 1;
				vl_data->peer_addr = rl->link[i].link_data;
			}
		}
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: %s peer address: %pI4, cost: %d,%schanged",
			   __func__, vl_data->vl_oi->ifp->name,
			   &vl_data->peer_addr, voi->output_cost,
			   (changed ? " " : " un"));

	return changed;
}


void ospf_vl_up_check(struct ospf_area *area, struct in_addr rid,
		      struct vertex *v)
{
	struct ospf *ospf = area->ospf;
	struct listnode *node;
	struct ospf_vl_data *vl_data;
	struct ospf_interface *oi;

	if (IS_DEBUG_OSPF_EVENT) {
		zlog_debug("%s: Start", __func__);
		zlog_debug("%s: Router ID is %pI4 Area is %pI4", __func__, &rid,
			   &area->area_id);
	}

	for (ALL_LIST_ELEMENTS_RO(ospf->vlinks, node, vl_data)) {
		if (IS_DEBUG_OSPF_EVENT) {
			zlog_debug("%s: considering VL, %s in area %pI4",
				   __func__, vl_data->vl_oi->ifp->name,
				   &vl_data->vl_area_id);
			zlog_debug("%s: peer ID: %pI4", __func__,
				   &vl_data->vl_peer);
		}

		if (IPV4_ADDR_SAME(&vl_data->vl_peer, &rid)
		    && IPV4_ADDR_SAME(&vl_data->vl_area_id, &area->area_id)) {
			oi = vl_data->vl_oi;
			SET_FLAG(vl_data->flags, OSPF_VL_FLAG_APPROVED);

			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: this VL matched", __func__);

			if (oi->state == ISM_Down) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"%s: VL is down, waking it up",
						__func__);
				SET_FLAG(oi->ifp->flags, IFF_UP);
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
			}

			if (ospf_vl_set_params(area, vl_data, v)) {
				if (IS_DEBUG_OSPF(ism, ISM_EVENTS))
					zlog_debug(
						"%s: VL cost change, scheduling router lsa refresh",
						__func__);
				if (ospf->backbone)
					ospf_router_lsa_update_area(
						ospf->backbone);
				else if (IS_DEBUG_OSPF(ism, ISM_EVENTS))
					zlog_debug(
						"%s: VL cost change, no backbone!",
						__func__);
			}
		}
	}
}

void ospf_vl_unapprove(struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_vl_data *vl_data;

	for (ALL_LIST_ELEMENTS_RO(ospf->vlinks, node, vl_data))
		UNSET_FLAG(vl_data->flags, OSPF_VL_FLAG_APPROVED);
}

void ospf_vl_shut_unapproved(struct ospf *ospf)
{
	struct listnode *node, *nnode;
	struct ospf_vl_data *vl_data;

	for (ALL_LIST_ELEMENTS(ospf->vlinks, node, nnode, vl_data))
		if (!CHECK_FLAG(vl_data->flags, OSPF_VL_FLAG_APPROVED))
			ospf_vl_shutdown(vl_data);
}

int ospf_full_virtual_nbrs(struct ospf_area *area)
{
	if (IS_DEBUG_OSPF_EVENT) {
		zlog_debug(
			"counting fully adjacent virtual neighbors in area %pI4",
			&area->area_id);
		zlog_debug("there are %d of them", area->full_vls);
	}

	return area->full_vls;
}

int ospf_vls_in_area(struct ospf_area *area)
{
	struct listnode *node;
	struct ospf_vl_data *vl_data;
	int c = 0;

	for (ALL_LIST_ELEMENTS_RO(area->ospf->vlinks, node, vl_data))
		if (IPV4_ADDR_SAME(&vl_data->vl_area_id, &area->area_id))
			c++;

	return c;
}


struct crypt_key *ospf_crypt_key_new(void)
{
	return XCALLOC(MTYPE_OSPF_CRYPT_KEY, sizeof(struct crypt_key));
}

void ospf_crypt_key_add(struct list *crypt, struct crypt_key *ck)
{
	listnode_add(crypt, ck);
}

struct crypt_key *ospf_crypt_key_lookup(struct list *auth_crypt, uint8_t key_id)
{
	struct listnode *node;
	struct crypt_key *ck;

	for (ALL_LIST_ELEMENTS_RO(auth_crypt, node, ck))
		if (ck->key_id == key_id)
			return ck;

	return NULL;
}

int ospf_crypt_key_delete(struct list *auth_crypt, uint8_t key_id)
{
	struct listnode *node, *nnode;
	struct crypt_key *ck;

	for (ALL_LIST_ELEMENTS(auth_crypt, node, nnode, ck)) {
		if (ck->key_id == key_id) {
			listnode_delete(auth_crypt, ck);
			XFREE(MTYPE_OSPF_CRYPT_KEY, ck);
			return 1;
		}
	}

	return 0;
}

uint8_t ospf_default_iftype(struct interface *ifp)
{
	if (if_is_pointopoint(ifp))
		return OSPF_IFTYPE_POINTOPOINT;
	else if (if_is_loopback(ifp))
		return OSPF_IFTYPE_LOOPBACK;
	else
		return OSPF_IFTYPE_BROADCAST;
}

void ospf_if_interface(struct interface *ifp)
{
	hook_call(ospf_if_update, ifp);
}

uint32_t ospf_if_count_area_params(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct route_node *rn;
	uint32_t count = 0;

	params = IF_DEF_PARAMS(ifp);
	if (OSPF_IF_PARAM_CONFIGURED(params, if_area))
		count++;

	for (rn = route_top(IF_OIFS_PARAMS(ifp)); rn; rn = route_next(rn))
		if ((params = rn->info)
		    && OSPF_IF_PARAM_CONFIGURED(params, if_area))
			count++;

	return count;
}

static int ospf_ifp_create(struct interface *ifp)
{
	struct ospf *ospf = NULL;
	struct ospf_if_info *oii;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug(
			"Zebra: interface add %s vrf %s[%u] index %d flags %llx metric %d mtu %d speed %u status 0x%x",
			ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
			ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu, ifp->speed, ifp->status);

	assert(ifp->info);

	oii = ifp->info;
	oii->curr_mtu = ifp->mtu;

	/* Change ospf type param based on following
	 * condition:
	 * ospf type params is not set (first creation),
	 * OR ospf param type is changed based on
	 * link event, currently only handle for
	 * loopback interface type, for other ospf interface,
	 * type can be set from user config which needs to be
	 * preserved.
	 */
	if (IF_DEF_PARAMS(ifp) &&
	    (!OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(ifp), type) ||
	     if_is_loopback(ifp))) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), type);
		if (!IF_DEF_PARAMS(ifp)->type_cfg)
			IF_DEF_PARAMS(ifp)->type = ospf_default_iftype(ifp);
	}

	ospf = ifp->vrf->info;
	if (!ospf)
		return 0;

	if (ospf_if_count_area_params(ifp) > 0)
		ospf_interface_area_set(ospf, ifp);

	ospf_if_recalculate_output_cost(ifp);

	ospf_if_update(ospf, ifp);

	if (HAS_LINK_PARAMS(ifp))
		ospf_mpls_te_update_if(ifp);

	hook_call(ospf_if_update, ifp);

	return 0;
}

static int ospf_ifp_up(struct interface *ifp)
{
	struct ospf_interface *oi;
	struct route_node *rn;
	struct ospf_if_info *oii = ifp->info;
	struct ospf *ospf;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to up.",
			   ifp->name);

	/* Open per-intf write socket if configured */
	ospf = ifp->vrf->info;

	if (ospf && ospf->oi_running && ospf->intf_socket_enabled)
		ospf_ifp_sock_init(ifp);

	ospf_if_recalculate_output_cost(ifp);

	if (oii && oii->curr_mtu != ifp->mtu) {
		if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
			zlog_debug(
				"Zebra: Interface[%s] MTU change %u -> %u.",
				ifp->name, oii->curr_mtu, ifp->mtu);

		oii->curr_mtu = ifp->mtu;
		/* Must reset the interface (simulate down/up) when MTU
		 * changes. */
		ospf_if_reset(ifp);

		return 0;
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		if ((oi = rn->info) == NULL)
			continue;

		ospf_if_up(oi);
	}

	if (HAS_LINK_PARAMS(ifp))
		ospf_mpls_te_update_if(ifp);

	return 0;
}

static int ospf_ifp_down(struct interface *ifp)
{
	struct ospf_interface *oi;
	struct route_node *node;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("Zebra: Interface[%s] state change to down.",
			   ifp->name);

	for (node = route_top(IF_OIFS(ifp)); node; node = route_next(node)) {
		if ((oi = node->info) == NULL)
			continue;
		ospf_if_down(oi);
	}

	/* Close per-interface write socket if configured */
	ospf_ifp_sock_close(ifp);

	return 0;
}

static int ospf_ifp_destroy(struct interface *ifp)
{
	struct ospf *ospf;
	struct route_node *rn;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug(
			"Zebra: interface delete %s vrf %s[%u] index %d flags %llx metric %d mtu %d",
			ifp->name, ifp->vrf->name, ifp->vrf->vrf_id,
			ifp->ifindex, (unsigned long long)ifp->flags,
			ifp->metric, ifp->mtu);

	hook_call(ospf_if_delete, ifp);

	ospf = ifp->vrf->info;
	if (ospf) {
		if (ospf_if_count_area_params(ifp) > 0)
			ospf_interface_area_unset(ospf, ifp);
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn))
		if (rn->info)
			ospf_if_free((struct ospf_interface *)rn->info);

	return 0;
}

/* Resetting ospf hello timer */
void ospf_reset_hello_timer(struct interface *ifp, struct in_addr addr,
			    bool is_addr)
{
	struct route_node *rn;

	if (is_addr) {
		struct prefix p;
		struct ospf_interface *oi = NULL;

		p.u.prefix4 = addr;
		p.family = AF_INET;
		p.prefixlen = IPV4_MAX_BITLEN;

		oi = ospf_if_table_lookup(ifp, &p);

		if (oi) {
			/* Send hello before restart the hello timer
			 * to avoid session flaps in case of bigger
			 * hello interval configurations.
			 */
			ospf_hello_send(oi);

			/* Restart hello timer for this interface */
			EVENT_OFF(oi->t_hello);
			OSPF_HELLO_TIMER_ON(oi);
		}

		return;
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		/* If hello interval configured on this oi, don't restart. */
		if (OSPF_IF_PARAM_CONFIGURED(oi->params, v_hello))
			continue;

		/* Send hello before restart the hello timer
		 * to avoid session flaps in case of bigger
		 * hello interval configurations.
		 */
		ospf_hello_send(oi);

		/* Restart the hello timer. */
		EVENT_OFF(oi->t_hello);
		OSPF_HELLO_TIMER_ON(oi);
	}
}

void ospf_if_init(void)
{
	hook_register_prio(if_real, 0, ospf_ifp_create);
	hook_register_prio(if_up, 0, ospf_ifp_up);
	hook_register_prio(if_down, 0, ospf_ifp_down);
	hook_register_prio(if_unreal, 0, ospf_ifp_destroy);

	/* Initialize Zebra interface data structure. */
	hook_register_prio(if_add, 0, ospf_if_new_hook);
	hook_register_prio(if_del, 0, ospf_if_delete_hook);
}
