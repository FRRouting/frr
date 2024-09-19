// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of Segment Routing
 * as per RFC 8665 - OSPF Extensions for Segment Routing
 * and RFC 8476 - Signaling Maximum SID Depth (MSD) Using OSPF
 *
 * Module name: Segment Routing
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Author: Anselme Sawadogo <anselmesawadogo@gmail.com>
 *
 * Copyright (C) 2016 - 2020 Orange Labs http://www.orange.com
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <zebra.h>

#include "printfrr.h"
#include "command.h"
#include "hash.h"
#include "if.h"
#include "if.h"
#include "jhash.h"
#include "libospf.h" /* for ospf interface types */
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "monotime.h"
#include "network.h"
#include "prefix.h"
#include "sockunion.h" /* for inet_aton() */
#include "stream.h"
#include "table.h"
#include "frrevent.h"
#include "vty.h"
#include "zclient.h"
#include "sbuf.h"
#include <lib/json.h>
#include "ospf_errors.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ri.h"
#include "ospfd/ospf_ext.h"
#include "ospfd/ospf_zebra.h"

/*
 * Global variable to manage Segment Routing on this node.
 * Note that all parameter values are stored in network byte order.
 */
static struct ospf_sr_db OspfSR;
static void ospf_sr_register_vty(void);
static inline void del_adj_sid(struct sr_nhlfe nhlfe);
static int ospf_sr_start(struct ospf *ospf);

/*
 * Segment Routing Data Base functions
 */

/* Hash function for Segment Routing entry */
static unsigned int sr_hash(const void *p)
{
	const struct in_addr *rid = p;

	return jhash_1word(rid->s_addr, 0);
}

/* Compare 2 Router ID hash entries based on SR Node */
static bool sr_cmp(const void *p1, const void *p2)
{
	const struct sr_node *srn = p1;
	const struct in_addr *rid = p2;

	return IPV4_ADDR_SAME(&srn->adv_router, rid);
}

/* Functions to remove an SR Link */
static void del_sr_link(void *val)
{
	struct sr_link *srl = (struct sr_link *)val;

	del_adj_sid(srl->nhlfe[0]);
	del_adj_sid(srl->nhlfe[1]);
	XFREE(MTYPE_OSPF_SR_PARAMS, val);
}

/* Functions to remove an SR Prefix */
static void del_sr_pref(void *val)
{
	struct sr_prefix *srp = (struct sr_prefix *)val;

	ospf_zebra_delete_prefix_sid(srp);
	XFREE(MTYPE_OSPF_SR_PARAMS, val);
}

/* Allocate new Segment Routine node */
static struct sr_node *sr_node_new(struct in_addr *rid)
{

	if (rid == NULL)
		return NULL;

	struct sr_node *new;

	/* Allocate Segment Routing node memory */
	new = XCALLOC(MTYPE_OSPF_SR_PARAMS, sizeof(struct sr_node));

	/* Default Algorithm, SRGB and MSD */
	for (int i = 0; i < ALGORITHM_COUNT; i++)
		new->algo[i] = SR_ALGORITHM_UNSET;

	new->srgb.range_size = 0;
	new->srgb.lower_bound = 0;
	new->msd = 0;

	/* Create Link, Prefix and Range TLVs list */
	new->ext_link = list_new();
	new->ext_prefix = list_new();
	new->ext_link->del = del_sr_link;
	new->ext_prefix->del = del_sr_pref;

	IPV4_ADDR_COPY(&new->adv_router, rid);
	new->neighbor = NULL;
	new->instance = 0;

	osr_debug("  |-  Created new SR node for %pI4", &new->adv_router);
	return new;
}

/* Supposed to be used for testing */
struct sr_node *ospf_sr_node_create(struct in_addr *rid)
{
	struct sr_node *srn;

	srn = hash_get(OspfSR.neighbors, (void *)rid, (void *)sr_node_new);

	return srn;
}

/* Delete Segment Routing node */
static void sr_node_del(struct sr_node *srn)
{
	/* Sanity Check */
	if (srn == NULL)
		return;

	osr_debug("  |- Delete SR node for %pI4", &srn->adv_router);

	/* Clean Extended Link */
	list_delete(&srn->ext_link);

	/* Clean Prefix List */
	list_delete(&srn->ext_prefix);

	XFREE(MTYPE_OSPF_SR_PARAMS, srn);
}

/* Get SR Node for a given nexthop */
static struct sr_node *get_sr_node_by_nexthop(struct ospf *ospf,
					      struct in_addr nexthop)
{
	struct ospf_interface *oi = NULL;
	struct ospf_neighbor *nbr = NULL;
	struct listnode *node;
	struct route_node *rn;
	struct sr_node *srn;
	bool found;

	/* Sanity check */
	if (OspfSR.neighbors == NULL)
		return NULL;

	osr_debug("      |-  Search SR-Node for nexthop %pI4", &nexthop);

	/* First, search neighbor Router ID for this nexthop */
	found = false;
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;
			if ((nbr) && (IPV4_ADDR_SAME(&nexthop, &nbr->src))) {
				found = true;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found)
		return NULL;

	osr_debug("      |-  Found nexthop Router ID %pI4", &nbr->router_id);

	/* Then, search SR Node */
	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors, &nbr->router_id);

	return srn;
}

/*
 * Segment Routing Local Block management functions
 */

/**
 * It is necessary to known which label is already allocated to manage the range
 * of SRLB. This is particular useful when an interface flap (goes up / down
 * frequently). Here, SR will release and then allocate label for the Adjacency
 * for each concerned interface. If we don't care, there is a risk to run out of
 * label.
 *
 * For that purpose, a similar principle as already provided to manage chunk of
 * label is proposed. But, here, the label chunk has not a fix range of 64
 * labels that could be easily manage with a single variable of 64 bits size.
 * So, used_mark is used as a bit wise to mark label reserved (bit set) or not
 * (bit unset). Its size is equal to the number of label of the SRLB range round
 * up to 64 bits.
 *
 *  - sr__local_block_init() computes the number of 64 bits variables that are
 *    needed to manage the SRLB range and allocates this number.
 *  - ospf_sr_local_block_request_label() pick up the first available label and
 *    set corresponding bit
 *  - ospf_sr_local_block_release_label() release label by reseting the
 *    corresponding bit and set the next label to the first free position
 */

/**
 * Initialize Segment Routing Local Block from SRDB configuration and reserve
 * block of bits to manage label allocation.
 *
 * @param lower_bound	The lower bound of the SRLB range
 * @param upper_bound	The upper bound of the SRLB range
 *
 * @return		0 on success, -1 otherwise
 */
static int sr_local_block_init(uint32_t lower_bound, uint32_t upper_bound)
{
	struct sr_local_block *srlb = &OspfSR.srlb;
	uint32_t size;

	/* Check if SRLB is not already configured */
	if (srlb->reserved)
		return 0;

	/*
	 * Request SRLB to the label manager. If the allocation fails, return
	 * an error to disable SR until a new SRLB is successfully allocated.
	 */
	size = upper_bound - lower_bound + 1;
	if (ospf_zebra_request_label_range(lower_bound, size)) {
		zlog_err("SR: Error reserving SRLB [%u/%u] %u labels",
			 lower_bound, upper_bound, size);
		return -1;
	}

	osr_debug("SR: Got new SRLB [%u/%u], %u labels", lower_bound,
		  upper_bound, size);

	/* Initialize the SRLB */
	srlb->start = lower_bound;
	srlb->end = upper_bound;
	srlb->current = 0;

	/* Compute the needed Used Mark number and allocate them */
	srlb->max_block = size / SRLB_BLOCK_SIZE;
	if ((size % SRLB_BLOCK_SIZE) != 0)
		srlb->max_block++;
	srlb->used_mark = XCALLOC(MTYPE_OSPF_SR_PARAMS,
				  srlb->max_block * SRLB_BLOCK_SIZE);
	srlb->reserved = true;

	return 0;
}

static int sr_global_block_init(uint32_t start, uint32_t size)
{
	struct sr_global_block *srgb = &OspfSR.srgb;

	/* Check if already configured */
	if (srgb->reserved)
		return 0;

	/* request chunk */
	uint32_t end = start + size - 1;
	if (ospf_zebra_request_label_range(start, size) < 0) {
		zlog_err("SR: Error reserving SRGB [%u/%u], %u labels", start,
			 end, size);
		return -1;
	}

	osr_debug("SR: Got new SRGB [%u/%u], %u labels", start, end, size);

	/* success */
	srgb->start = start;
	srgb->size = size;
	srgb->reserved = true;
	return 0;
}

/**
 * Remove Segment Routing Local Block.
 *
 */
static void sr_local_block_delete(void)
{
	struct sr_local_block *srlb = &OspfSR.srlb;

	/* Check if SRLB is not already delete */
	if (!srlb->reserved)
		return;

	osr_debug("SR (%s): Remove SRLB [%u/%u]", __func__, srlb->start,
		  srlb->end);

	/* First release the label block */
	ospf_zebra_release_label_range(srlb->start, srlb->end);

	/* Then reset SRLB structure */
	if (srlb->used_mark != NULL)
		XFREE(MTYPE_OSPF_SR_PARAMS, srlb->used_mark);

	srlb->reserved = false;
}

/**
 * Remove Segment Routing Global block
 */
static void sr_global_block_delete(void)
{
	struct sr_global_block *srgb = &OspfSR.srgb;

	if (!srgb->reserved)
		return;

	osr_debug("SR (%s): Remove SRGB [%u/%u]", __func__, srgb->start,
		  srgb->start + srgb->size - 1);

	ospf_zebra_release_label_range(srgb->start,
				       srgb->start + srgb->size - 1);

	srgb->reserved = false;
}


/**
 * Request a label from the Segment Routing Local Block.
 *
 * @return	First available label on success or MPLS_INVALID_LABEL if the
 * 		block of labels is full
 */
mpls_label_t ospf_sr_local_block_request_label(void)
{
	struct sr_local_block *srlb = &OspfSR.srlb;
	mpls_label_t label;
	uint32_t index;
	uint32_t pos;
	uint32_t size = srlb->end - srlb->start + 1;

	/* Check if we ran out of available labels */
	if (srlb->current >= size)
		return MPLS_INVALID_LABEL;

	/* Get first available label and mark it used */
	label = srlb->current + srlb->start;
	index = srlb->current / SRLB_BLOCK_SIZE;
	pos = 1ULL << (srlb->current % SRLB_BLOCK_SIZE);
	srlb->used_mark[index] |= pos;

	/* Jump to the next free position */
	srlb->current++;
	pos = srlb->current % SRLB_BLOCK_SIZE;
	while (srlb->current < size) {
		if (pos == 0)
			index++;
		if (!((1ULL << pos) & srlb->used_mark[index]))
			break;
		else {
			srlb->current++;
			pos = srlb->current % SRLB_BLOCK_SIZE;
		}
	}

	if (srlb->current == size)
		zlog_warn(
			"SR: Warning, SRLB is depleted and next label request will fail");

	return label;
}

/**
 * Release label in the Segment Routing Local Block.
 *
 * @param label	Label to be release
 *
 * @return	0 on success or -1 if label falls outside SRLB
 */
int ospf_sr_local_block_release_label(mpls_label_t label)
{
	struct sr_local_block *srlb = &OspfSR.srlb;
	uint32_t index;
	uint32_t pos;

	/* Check that label falls inside the SRLB */
	if ((label < srlb->start) || (label > srlb->end)) {
		flog_warn(EC_OSPF_SR_SID_OVERFLOW,
			  "%s: Returning label %u is outside SRLB [%u/%u]",
			  __func__, label, srlb->start, srlb->end);
		return -1;
	}

	index = (label - srlb->start) / SRLB_BLOCK_SIZE;
	pos = 1ULL << ((label - srlb->start) % SRLB_BLOCK_SIZE);
	srlb->used_mark[index] &= ~pos;
	/* Reset current to the first available position */
	for (index = 0; index < srlb->max_block; index++) {
		if (srlb->used_mark[index] != 0xFFFFFFFFFFFFFFFF) {
			for (pos = 0; pos < SRLB_BLOCK_SIZE; pos++)
				if (!((1ULL << pos) & srlb->used_mark[index])) {
					srlb->current =
						index * SRLB_BLOCK_SIZE + pos;
					break;
				}
			break;
		}
	}

	return 0;
}

/*
 * Segment Routing Initialization functions
 */

/**
 * Thread function to re-attempt connection to the Label Manager and thus be
 * able to start Segment Routing.
 *
 * @param start		Thread structure that contains area as argument
 *
 * @return		1 on success
 */
static void sr_start_label_manager(struct event *start)
{
	struct ospf *ospf;

	ospf = EVENT_ARG(start);

	/* re-attempt to start SR & Label Manager connection */
	ospf_sr_start(ospf);
}

/* Segment Routing starter function */
static int ospf_sr_start(struct ospf *ospf)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;
	struct sr_node *srn;
	int rc = 0;

	osr_debug("SR (%s): Start Segment Routing", __func__);

	/* Initialize self SR Node if not already done */
	if (OspfSR.self == NULL) {
		srn = hash_get(OspfSR.neighbors, (void *)&(ospf->router_id),
			       (void *)sr_node_new);

		/* Complete & Store self SR Node */
		srn->srgb.range_size = OspfSR.srgb.size;
		srn->srgb.lower_bound = OspfSR.srgb.start;
		srn->srlb.lower_bound = OspfSR.srlb.start;
		srn->srlb.range_size = OspfSR.srlb.end - OspfSR.srlb.start + 1;
		srn->algo[0] = OspfSR.algo[0];
		srn->msd = OspfSR.msd;
		OspfSR.self = srn;
	}

	/* Then, start Label Manager if not ready */
	if (!ospf_zebra_label_manager_ready())
		if (ospf_zebra_label_manager_connect() < 0) {
			/* Re-attempt to connect to Label Manager in 1 sec. */
			event_add_timer(master, sr_start_label_manager, ospf, 1,
					&OspfSR.t_start_lm);
			osr_debug("  |- Failed to start the Label Manager");
			return -1;
		}

	/*
	 * Request SRLB & SGRB to the label manager if not already reserved.
	 * If the allocation fails, return an error to disable SR until a new
	 * SRLB and/or SRGB are successfully allocated.
	 */
	if (sr_local_block_init(OspfSR.srlb.start, OspfSR.srlb.end) < 0)
		return -1;

	if (sr_global_block_init(OspfSR.srgb.start, OspfSR.srgb.size) < 0)
		return -1;

	/* SR is UP and ready to flood LSA */
	OspfSR.status = SR_UP;

	/* Set Router Information SR parameters */
	osr_debug("SR: Activate SR for Router Information LSA");

	ospf_router_info_update_sr(true, OspfSR.self);

	/* Update Ext LSA */
	osr_debug("SR: Activate SR for Extended Link/Prefix LSA");

	ospf_ext_update_sr(true);

	osr_debug("SR (%s): Update SR-DB from LSDB", __func__);

	/* Start by looking to Router Info & Extended LSA in lsdb */
	if ((ospf != NULL) && (ospf->backbone != NULL)) {
		LSDB_LOOP (OPAQUE_AREA_LSDB(ospf->backbone), rn, lsa) {
			if (IS_LSA_MAXAGE(lsa) || IS_LSA_SELF(lsa))
				continue;
			int lsa_id =
				GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));
			switch (lsa_id) {
			case OPAQUE_TYPE_ROUTER_INFORMATION_LSA:
				ospf_sr_ri_lsa_update(lsa);
				break;
			case OPAQUE_TYPE_EXTENDED_PREFIX_LSA:
				ospf_sr_ext_prefix_lsa_update(lsa);
				break;
			case OPAQUE_TYPE_EXTENDED_LINK_LSA:
				ospf_sr_ext_link_lsa_update(lsa);
				break;
			default:
				break;
			}
		}
	}

	rc = 1;
	return rc;
}

/* Stop Segment Routing */
static void ospf_sr_stop(void)
{

	if (OspfSR.status == SR_OFF)
		return;

	osr_debug("SR (%s): Stop Segment Routing", __func__);

	/* Disable any re-attempt to connect to Label Manager */
	EVENT_OFF(OspfSR.t_start_lm);

	/* Release SRGB if active */
	sr_global_block_delete();

	/* Release SRLB if active */
	sr_local_block_delete();

	/*
	 * Remove all SR Nodes from the Hash table. Prefix and Link SID will
	 * be remove though list_delete() call. See sr_node_del()
	 */
	hash_clean(OspfSR.neighbors, (void *)sr_node_del);
	OspfSR.self = NULL;
	OspfSR.status = SR_OFF;
	OspfSR.msd = 0;
}

/*
 * Segment Routing initialize function
 *
 * @param - nothing
 *
 * @return 0 if OK, -1 otherwise
 */
int ospf_sr_init(void)
{
	int rc = -1;

	osr_debug("SR (%s): Initialize SR Data Base", __func__);

	memset(&OspfSR, 0, sizeof(OspfSR));
	OspfSR.status = SR_OFF;
	/* Only AREA flooding is supported in this release */
	OspfSR.scope = OSPF_OPAQUE_AREA_LSA;

	/* Initialize Algorithms, SRGB, SRLB and MSD TLVs */
	/* Only Algorithm SPF is supported */
	OspfSR.algo[0] = SR_ALGORITHM_SPF;
	for (int i = 1; i < ALGORITHM_COUNT; i++)
		OspfSR.algo[i] = SR_ALGORITHM_UNSET;

	OspfSR.srgb.size = DEFAULT_SRGB_SIZE;
	OspfSR.srgb.start = DEFAULT_SRGB_LABEL;
	OspfSR.srgb.reserved = false;

	OspfSR.srlb.start = DEFAULT_SRLB_LABEL;
	OspfSR.srlb.end = DEFAULT_SRLB_END;
	OspfSR.srlb.reserved = false;
	OspfSR.msd = 0;

	/* Initialize Hash table for neighbor SR nodes */
	OspfSR.neighbors = hash_create(sr_hash, sr_cmp, "OSPF_SR");
	if (OspfSR.neighbors == NULL)
		return rc;

	/* Register Segment Routing VTY command */
	ospf_sr_register_vty();

	rc = 0;
	return rc;
}

/*
 * Segment Routing termination function
 *
 * @param - nothing
 * @return - nothing
 */
void ospf_sr_term(void)
{

	/* Stop Segment Routing */
	ospf_sr_stop();

	hash_clean_and_free(&OspfSR.neighbors, (void *)sr_node_del);
}

/*
 * Segment Routing finish function
 *
 * @param - nothing
 * @return - nothing
 */
void ospf_sr_finish(void)
{
	/* Stop Segment Routing */
	ospf_sr_stop();
}

/*
 * Following functions are used to manipulate the
 * Next Hop Label Forwarding entry (NHLFE)
 */

/* Compute label from index */
static mpls_label_t index2label(uint32_t index, struct sr_block srgb)
{
	mpls_label_t label;

	label = srgb.lower_bound + index;
	if (label > (srgb.lower_bound + srgb.range_size)) {
		flog_warn(EC_OSPF_SR_SID_OVERFLOW,
			  "%s: SID index %u falls outside SRGB range",
			  __func__, index);
		return MPLS_INVALID_LABEL;
	} else
		return label;
}

/* Get the prefix sid for a specific router id */
mpls_label_t ospf_sr_get_prefix_sid_by_id(struct in_addr *id)
{
	struct sr_node *srn;
	struct sr_prefix *srp;
	mpls_label_t label;

	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors, id);

	if (srn) {
		/*
		 * TODO: Here we assume that the SRGBs are the same,
		 * and that the node's prefix SID is at the head of
		 * the list, probably needs tweaking.
		 */
		srp = listnode_head(srn->ext_prefix);
		label = index2label(srp->sid, srn->srgb);
	} else {
		label = MPLS_INVALID_LABEL;
	}

	return label;
}

/* Get the adjacency sid for a specific 'root' id and 'neighbor' id */
mpls_label_t ospf_sr_get_adj_sid_by_id(struct in_addr *root_id,
				       struct in_addr *neighbor_id)
{
	struct sr_node *srn;
	struct sr_link *srl;
	mpls_label_t label;
	struct listnode *node;

	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors, root_id);

	label = MPLS_INVALID_LABEL;

	if (srn) {
		for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, srl)) {
			if (srl->type == ADJ_SID
			    && srl->remote_id.s_addr == neighbor_id->s_addr) {
				label = srl->sid[0];
				break;
			}
		}
	}

	return label;
}

/* Get neighbor full structure from address */
static struct ospf_neighbor *get_neighbor_by_addr(struct ospf *top,
						  struct in_addr addr)
{
	struct ospf_neighbor *nbr;
	struct ospf_interface *oi;
	struct listnode *node;
	struct route_node *rn;

	/* Sanity Check */
	if (top == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(top->oiflist, node, oi))
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;
			if (!nbr)
				continue;

			if (IPV4_ADDR_SAME(&nbr->address.u.prefix4, &addr) ||
			    IPV4_ADDR_SAME(&nbr->router_id, &addr)) {
				route_unlock_node(rn);
				return nbr;
			}
		}
	return NULL;
}

/* Get OSPF Path from address */
static struct ospf_route *get_nexthop_by_addr(struct ospf *top,
					      struct prefix_ipv4 p)
{
	struct route_node *rn;

	/* Sanity Check */
	if (top == NULL)
		return NULL;

	osr_debug("      |-  Search Nexthop for prefix %pFX",
		  (struct prefix *)&p);

	rn = route_node_lookup(top->new_table, (struct prefix *)&p);

	/*
	 * Check if we found an OSPF route. May be NULL if SPF has not
	 * yet populate routing table for this prefix.
	 */
	if (rn == NULL)
		return NULL;

	route_unlock_node(rn);
	return rn->info;
}

/* Compute NHLFE entry for Extended Link */
static int compute_link_nhlfe(struct sr_link *srl)
{
	struct ospf *top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	struct ospf_neighbor *nh;
	int rc = 0;

	osr_debug("    |-  Compute NHLFE for link %pI4", &srl->itf_addr);

	/* First determine the OSPF Neighbor */
	nh = get_neighbor_by_addr(top, srl->nhlfe[0].nexthop);

	/* Neighbor could be not found when OSPF Adjacency just fire up
	 * because SPF don't yet populate routing table. This NHLFE will
	 * be fixed later when SR SPF schedule will be called.
	 */
	if (nh == NULL)
		return rc;

	osr_debug("    |-  Found nexthop %pI4", &nh->router_id);

	/* Set ifindex for this neighbor */
	srl->nhlfe[0].ifindex = nh->oi->ifp->ifindex;
	srl->nhlfe[1].ifindex = nh->oi->ifp->ifindex;

	/* Update neighbor address for LAN_ADJ_SID */
	if (srl->type == LAN_ADJ_SID) {
		IPV4_ADDR_COPY(&srl->nhlfe[0].nexthop, &nh->src);
		IPV4_ADDR_COPY(&srl->nhlfe[1].nexthop, &nh->src);
	}

	/* Set Input & Output Label */
	if (CHECK_FLAG(srl->flags[0], EXT_SUBTLV_LINK_ADJ_SID_VFLG))
		srl->nhlfe[0].label_in = srl->sid[0];
	else
		srl->nhlfe[0].label_in =
			index2label(srl->sid[0], srl->srn->srgb);
	if (CHECK_FLAG(srl->flags[1], EXT_SUBTLV_LINK_ADJ_SID_VFLG))
		srl->nhlfe[1].label_in = srl->sid[1];
	else
		srl->nhlfe[1].label_in =
			index2label(srl->sid[1], srl->srn->srgb);

	srl->nhlfe[0].label_out = MPLS_LABEL_IMPLICIT_NULL;
	srl->nhlfe[1].label_out = MPLS_LABEL_IMPLICIT_NULL;

	rc = 1;
	return rc;
}

/**
 * Compute output label for the given Prefix-SID.
 *
 * @param srp		Segment Routing Prefix
 * @param srnext	Segment Routing nexthop node
 *
 * @return		MPLS label or MPLS_INVALID_LABEL in case of error
 */
static mpls_label_t sr_prefix_out_label(const struct sr_prefix *srp,
					const struct sr_node *srnext)
{
	/* Check if the nexthop SR Node is the last hop? */
	if (srnext == srp->srn) {
		/* SR-Node doesn't request NO-PHP. Return Implicit NULL label */
		if (!CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_NPFLG))
			return MPLS_LABEL_IMPLICIT_NULL;

		/* SR-Node requests Explicit NULL Label */
		if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_EFLG))
			return MPLS_LABEL_IPV4_EXPLICIT_NULL;
		/* Fallthrough */
	}

	/* Return SID value as MPLS label if it is an Absolute SID */
	if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_VFLG
					   | EXT_SUBTLV_PREFIX_SID_LFLG)) {
		/*
		 * V/L SIDs have local significance, so only adjacent routers
		 * can use them (RFC8665 section #5)
		 */
		if (srp->srn != srnext)
			return MPLS_INVALID_LABEL;
		return srp->sid;
	}

	/* Return MPLS label as SRGB lower bound + SID index as per RFC 8665 */
	return (index2label(srp->sid, srnext->srgb));
}

/*
 * Compute NHLFE entry for Extended Prefix
 *
 * @param srp - Segment Routing Prefix
 *
 * @return -1 if no route is found, 0 if there is no SR route ready
 *         and 1 if success or update
 */
static int compute_prefix_nhlfe(struct sr_prefix *srp)
{
	struct ospf *top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	struct ospf_path *path;
	struct listnode *node;
	struct sr_node *srnext;
	int rc = -1;

	osr_debug("    |-  Compute NHLFE for prefix %pFX",
		  (struct prefix *)&srp->prefv4);


	/* First determine the nexthop */
	srp->route = get_nexthop_by_addr(top, srp->prefv4);

	/* Nexthop could be not found when OSPF Adjacency just fire up
	 * because SPF don't yet populate routing table. This NHLFE will
	 * be fixed later when SR SPF schedule will be called.
	 */
	if (srp->route == NULL)
		return rc;

	/* Compute Input Label with self SRGB */
	srp->label_in = index2label(srp->sid, OspfSR.self->srgb);

	rc = 0;
	for (ALL_LIST_ELEMENTS_RO(srp->route->paths, node, path)) {

		osr_debug("    |-  Process new route via %pI4 for this prefix",
			  &path->nexthop);

		/*
		 * Get SR-Node for this nexthop. Could be not yet available
		 * as Extended Link / Prefix and Router Information are flooded
		 * after LSA Type 1 & 2 which populate the OSPF Route Table
		 */
		srnext = get_sr_node_by_nexthop(top, path->nexthop);
		if (srnext == NULL)
			continue;

		/* And store this information for later update */
		srnext->neighbor = OspfSR.self;
		path->srni.nexthop = srnext;

		/*
		 * SR Node could be known, but SRGB could be not initialize
		 * This is due to the fact that Extended Link / Prefix could
		 * be received before corresponding Router Information LSA
		 */
		if (srnext == NULL || srnext->srgb.lower_bound == 0
		    || srnext->srgb.range_size == 0) {
			osr_debug(
				"    |-  SR-Node %pI4 not ready. Stop process",
				&srnext->adv_router);
			path->srni.label_out = MPLS_INVALID_LABEL;
			continue;
		}

		osr_debug("    |-  Found SRGB %u/%u for next hop SR-Node %pI4",
			  srnext->srgb.range_size, srnext->srgb.lower_bound,
			  &srnext->adv_router);

		/* Compute Output Label with Nexthop SR Node SRGB */
		path->srni.label_out = sr_prefix_out_label(srp, srnext);

		osr_debug("    |-  Computed new labels in: %u out: %u",
			  srp->label_in, path->srni.label_out);
		rc = 1;
	}
	return rc;
}

/* Add new NHLFE entry for Adjacency SID */
static inline void add_adj_sid(struct sr_nhlfe nhlfe)
{
	if (nhlfe.label_in != 0)
		ospf_zebra_send_adjacency_sid(ZEBRA_MPLS_LABELS_ADD, nhlfe);
}

/* Remove NHLFE entry for Adjacency SID */
static inline void del_adj_sid(struct sr_nhlfe nhlfe)
{
	if (nhlfe.label_in != 0)
		ospf_zebra_send_adjacency_sid(ZEBRA_MPLS_LABELS_DELETE, nhlfe);
}

/* Update NHLFE entry for Adjacency SID */
static inline void update_adj_sid(struct sr_nhlfe n1, struct sr_nhlfe n2)
{
	del_adj_sid(n1);
	add_adj_sid(n2);
}

/*
 * Functions to parse and get Extended Link / Prefix
 * TLVs and SubTLVs
 */

/* Extended Link SubTLVs Getter */
static struct sr_link *get_ext_link_sid(struct tlv_header *tlvh, size_t size)
{

	struct sr_link *srl;
	struct ext_tlv_link *link = (struct ext_tlv_link *)tlvh;
	struct ext_subtlv_adj_sid *adj_sid;
	struct ext_subtlv_lan_adj_sid *lan_sid;
	struct ext_subtlv_rmt_itf_addr *rmt_itf;

	struct tlv_header *sub_tlvh;
	uint16_t length = 0, sum = 0, i = 0;

	/* Check TLV size */
	if ((ntohs(tlvh->length) > size)
	    || ntohs(tlvh->length) < EXT_TLV_LINK_SIZE) {
		zlog_warn("Wrong Extended Link TLV size. Abort!");
		return NULL;
	}

	srl = XCALLOC(MTYPE_OSPF_SR_PARAMS, sizeof(struct sr_link));

	/* Initialize TLV browsing */
	length = ntohs(tlvh->length) - EXT_TLV_LINK_SIZE;
	sub_tlvh = (struct tlv_header *)((char *)(tlvh) + TLV_HDR_SIZE
					 + EXT_TLV_LINK_SIZE);
	for (; sum < length && sub_tlvh; sub_tlvh = TLV_HDR_NEXT(sub_tlvh)) {
		switch (ntohs(sub_tlvh->type)) {
		case EXT_SUBTLV_ADJ_SID:
			adj_sid = (struct ext_subtlv_adj_sid *)sub_tlvh;
			srl->type = ADJ_SID;
			i = CHECK_FLAG(adj_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_BFLG)
				    ? 1
				    : 0;
			srl->flags[i] = adj_sid->flags;
			if (CHECK_FLAG(adj_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
				srl->sid[i] = GET_LABEL(ntohl(adj_sid->value));
			else
				srl->sid[i] = ntohl(adj_sid->value);
			IPV4_ADDR_COPY(&srl->nhlfe[i].nexthop, &link->link_id);
			break;
		case EXT_SUBTLV_LAN_ADJ_SID:
			lan_sid = (struct ext_subtlv_lan_adj_sid *)sub_tlvh;
			srl->type = LAN_ADJ_SID;
			i = CHECK_FLAG(lan_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_BFLG)
				    ? 1
				    : 0;
			srl->flags[i] = lan_sid->flags;
			if (CHECK_FLAG(lan_sid->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
				srl->sid[i] = GET_LABEL(ntohl(lan_sid->value));
			else
				srl->sid[i] = ntohl(lan_sid->value);
			IPV4_ADDR_COPY(&srl->nhlfe[i].nexthop,
				       &lan_sid->neighbor_id);
			break;
		case EXT_SUBTLV_RMT_ITF_ADDR:
			rmt_itf = (struct ext_subtlv_rmt_itf_addr *)sub_tlvh;
			IPV4_ADDR_COPY(&srl->nhlfe[0].nexthop, &rmt_itf->value);
			IPV4_ADDR_COPY(&srl->nhlfe[1].nexthop, &rmt_itf->value);
			break;
		default:
			break;
		}
		sum += TLV_SIZE(sub_tlvh);
	}

	IPV4_ADDR_COPY(&srl->itf_addr, &link->link_data);

	osr_debug("  |-  Found primary %u and backup %u Adj/Lan Sid for %pI4",
		  srl->sid[0], srl->sid[1], &srl->itf_addr);

	return srl;
}

/* Extended Prefix SubTLVs Getter */
static struct sr_prefix *get_ext_prefix_sid(struct tlv_header *tlvh,
					    size_t size)
{

	struct sr_prefix *srp;
	struct ext_tlv_prefix *pref = (struct ext_tlv_prefix *)tlvh;
	struct ext_subtlv_prefix_sid *psid;

	struct tlv_header *sub_tlvh;
	uint16_t length = 0, sum = 0;

	/* Check TLV size */
	if ((ntohs(tlvh->length) > size)
	    || ntohs(tlvh->length) < EXT_TLV_PREFIX_SIZE) {
		zlog_warn("Wrong Extended Link TLV size. Abort!");
		return NULL;
	}

	srp = XCALLOC(MTYPE_OSPF_SR_PARAMS, sizeof(struct sr_prefix));

	/* Initialize TLV browsing */
	length = ntohs(tlvh->length) - EXT_TLV_PREFIX_SIZE;
	sub_tlvh = (struct tlv_header *)((char *)(tlvh) + TLV_HDR_SIZE
					 + EXT_TLV_PREFIX_SIZE);
	for (; sum < length && sub_tlvh; sub_tlvh = TLV_HDR_NEXT(sub_tlvh)) {
		switch (ntohs(sub_tlvh->type)) {
		case EXT_SUBTLV_PREFIX_SID:
			psid = (struct ext_subtlv_prefix_sid *)sub_tlvh;
			if (psid->algorithm != SR_ALGORITHM_SPF) {
				flog_err(EC_OSPF_INVALID_ALGORITHM,
					 "SR (%s): Unsupported Algorithm",
					 __func__);
				XFREE(MTYPE_OSPF_SR_PARAMS, srp);
				return NULL;
			}
			srp->type = PREF_SID;
			srp->flags = psid->flags;
			if (CHECK_FLAG(psid->flags, EXT_SUBTLV_PREFIX_SID_VFLG))
				srp->sid = GET_LABEL(ntohl(psid->value));
			else
				srp->sid = ntohl(psid->value);
			IPV4_ADDR_COPY(&srp->prefv4.prefix, &pref->address);
			srp->prefv4.prefixlen = pref->pref_length;
			srp->prefv4.family = AF_INET;
			apply_mask_ipv4(&srp->prefv4);
			break;
		default:
			break;
		}
		sum += TLV_SIZE(sub_tlvh);
	}

	osr_debug("  |-  Found SID %u for prefix %pFX", srp->sid,
		  (struct prefix *)&srp->prefv4);

	return srp;
}

/*
 * Functions to manipulate Segment Routing Link & Prefix structures
 */

/* Compare two Segment Link: return 0 if equal, 1 otherwise */
static inline int sr_link_cmp(struct sr_link *srl1, struct sr_link *srl2)
{
	if ((srl1->sid[0] == srl2->sid[0]) && (srl1->sid[1] == srl2->sid[1])
	    && (srl1->type == srl2->type) && (srl1->flags[0] == srl2->flags[0])
	    && (srl1->flags[1] == srl2->flags[1]))
		return 0;
	else
		return 1;
}

/* Compare two Segment Prefix: return 0 if equal, 1 otherwise */
static inline int sr_prefix_cmp(struct sr_prefix *srp1, struct sr_prefix *srp2)
{
	if ((srp1->sid == srp2->sid) && (srp1->flags == srp2->flags))
		return 0;
	else
		return 1;
}

/* Update Segment Link of given Segment Routing Node */
static void update_ext_link_sid(struct sr_node *srn, struct sr_link *srl,
				uint8_t lsa_flags)
{
	struct listnode *node;
	struct sr_link *lk;
	bool found = false;
	bool config = true;

	/* Sanity check */
	if ((srn == NULL) || (srl == NULL))
		return;

	osr_debug("  |-  Process Extended Link Adj/Lan-SID");

	/* Detect if Adj/Lan_Adj SID must be configured */
	if (!CHECK_FLAG(lsa_flags, OSPF_LSA_SELF)
	    && (CHECK_FLAG(srl->flags[0], EXT_SUBTLV_LINK_ADJ_SID_LFLG)
		|| CHECK_FLAG(srl->flags[1], EXT_SUBTLV_LINK_ADJ_SID_LFLG)))
		config = false;

	/* Search for existing Segment Link */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, lk))
		if (lk->instance == srl->instance) {
			found = true;
			break;
		}

	osr_debug("  |-  %s SR Link 8.0.0.%u for SR node %pI4",
		  found ? "Update" : "Add", GET_OPAQUE_ID(srl->instance),
		  &srn->adv_router);

	/* if not found, add new Segment Link and install NHLFE */
	if (!found) {
		/* Complete SR-Link and add it to SR-Node list */
		srl->srn = srn;
		IPV4_ADDR_COPY(&srl->adv_router, &srn->adv_router);
		listnode_add(srn->ext_link, srl);
		/* Try to set MPLS table */
		if (config && compute_link_nhlfe(srl)) {
			add_adj_sid(srl->nhlfe[0]);
			add_adj_sid(srl->nhlfe[1]);
		}
	} else {
		/* Update SR-Link if they are different */
		if (sr_link_cmp(lk, srl)) {
			/* Try to set MPLS table */
			if (config) {
				if (compute_link_nhlfe(srl)) {
					update_adj_sid(lk->nhlfe[0],
						       srl->nhlfe[0]);
					update_adj_sid(lk->nhlfe[1],
						       srl->nhlfe[1]);
				} else {
					del_adj_sid(lk->nhlfe[0]);
					del_adj_sid(lk->nhlfe[1]);
				}
			}
			/* Replace SR-Link in SR-Node Adjacency List */
			listnode_delete(srn->ext_link, lk);
			XFREE(MTYPE_OSPF_SR_PARAMS, lk);
			srl->srn = srn;
			IPV4_ADDR_COPY(&srl->adv_router, &srn->adv_router);
			listnode_add(srn->ext_link, srl);
		} else {
			/*
			 * This is just an LSA refresh.
			 * Stop processing and free SR Link
			 */
			XFREE(MTYPE_OSPF_SR_PARAMS, srl);
		}
	}
}

/* Update Segment Prefix of given Segment Routing Node */
static void update_ext_prefix_sid(struct sr_node *srn, struct sr_prefix *srp)
{

	struct listnode *node;
	struct sr_prefix *pref;
	bool found = false;

	/* Sanity check */
	if (srn == NULL || srp == NULL)
		return;

	osr_debug("  |-  Process Extended Prefix SID %u", srp->sid);

	/* Process only Global Prefix SID */
	if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_LFLG))
		return;

	/* Search for existing Segment Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, pref))
		if (pref->instance == srp->instance
		    && prefix_same((struct prefix *)&srp->prefv4,
				   &pref->prefv4)) {
			found = true;
			break;
		}

	osr_debug("  |-  %s SR LSA ID 7.0.0.%u for SR node %pI4",
		  found ? "Update" : "Add", GET_OPAQUE_ID(srp->instance),
		  &srn->adv_router);

	/* Complete SR-Prefix */
	srp->srn = srn;
	IPV4_ADDR_COPY(&srp->adv_router, &srn->adv_router);

	/* if not found, add new Segment Prefix and install NHLFE */
	if (!found) {
		/* Add it to SR-Node list ... */
		listnode_add(srn->ext_prefix, srp);
		/* ... and try to set MPLS table */
		if (compute_prefix_nhlfe(srp) == 1)
			ospf_zebra_update_prefix_sid(srp);
	} else {
		/*
		 * An old SR prefix exist. Check if something changes or if it
		 * is just a refresh.
		 */
		if (sr_prefix_cmp(pref, srp)) {
			if (compute_prefix_nhlfe(srp) == 1) {
				ospf_zebra_delete_prefix_sid(pref);
				/* Replace Segment Prefix */
				listnode_delete(srn->ext_prefix, pref);
				XFREE(MTYPE_OSPF_SR_PARAMS, pref);
				listnode_add(srn->ext_prefix, srp);
				ospf_zebra_update_prefix_sid(srp);
			} else {
				/* New NHLFE was not found.
				 * Just free the SR Prefix
				 */
				XFREE(MTYPE_OSPF_SR_PARAMS, srp);
			}
		} else {
			/* This is just an LSA refresh.
			 * Stop processing and free SR Prefix
			 */
			XFREE(MTYPE_OSPF_SR_PARAMS, srp);
		}
	}
}

/*
 * When change the FRR Self SRGB, update the NHLFE Input Label
 * for all Extended Prefix with SID index through hash_iterate()
 */
static void update_in_nhlfe(struct hash_bucket *bucket, void *args)
{
	struct listnode *node;
	struct sr_node *srn = (struct sr_node *)bucket->data;
	struct sr_prefix *srp;

	/* Process Every Extended Prefix for this SR-Node */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {
		/* Process Self SRN only if NO-PHP is requested */
		if ((srn == OspfSR.self)
		    && !CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_NPFLG))
			continue;

		/* Process only SID Index */
		if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_VFLG))
			continue;

		/* First, remove old MPLS table entries ... */
		ospf_zebra_delete_prefix_sid(srp);
		/* ... then compute new input label ... */
		srp->label_in = index2label(srp->sid, OspfSR.self->srgb);
		/* ... and install new MPLS LFIB */
		ospf_zebra_update_prefix_sid(srp);
	}
}

/*
 * When SRGB has changed, update NHLFE Output Label for all Extended Prefix
 * with SID index which use the given SR-Node as nexthop through hash_iterate()
 */
static void update_out_nhlfe(struct hash_bucket *bucket, void *args)
{
	struct listnode *node, *pnode;
	struct sr_node *srn = (struct sr_node *)bucket->data;
	struct sr_node *srnext = (struct sr_node *)args;
	struct sr_prefix *srp;
	struct ospf_path *path;

	/* Skip Self SR-Node */
	if (srn == OspfSR.self)
		return;

	osr_debug("SR (%s): Update Out NHLFE for neighbor SR-Node %pI4",
		  __func__, &srn->adv_router);

	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {
		/* Skip Prefix that has not yet a valid route */
		if (srp->route == NULL)
			continue;

		for (ALL_LIST_ELEMENTS_RO(srp->route->paths, pnode, path)) {
			/* Skip path that has not next SR-Node as nexthop */
			if (path->srni.nexthop != srnext)
				continue;

			/* Compute new Output Label */
			path->srni.label_out = sr_prefix_out_label(srp, srnext);
		}

		/* Finally update MPLS table */
		ospf_zebra_update_prefix_sid(srp);
	}
}

/*
 * Following functions are call when new Segment Routing LSA are received
 *  - Router Information: ospf_sr_ri_lsa_update() & ospf_sr_ri_lsa_delete()
 *  - Extended Link: ospf_sr_ext_link_update() & ospf_sr_ext_link_delete()
 *  - Extended Prefix: ospf_ext_prefix_update() & ospf_sr_ext_prefix_delete()
 */

/* Update Segment Routing from Router Information LSA */
void ospf_sr_ri_lsa_update(struct ospf_lsa *lsa)
{
	struct sr_node *srn;
	struct tlv_header *tlvh;
	struct lsa_header *lsah = lsa->data;
	struct ri_sr_tlv_sid_label_range *ri_srgb = NULL;
	struct ri_sr_tlv_sid_label_range *ri_srlb = NULL;
	struct ri_sr_tlv_sr_algorithm *algo = NULL;
	struct sr_block srgb;
	uint16_t length = 0, sum = 0;
	uint8_t msd = 0;

	osr_debug("SR (%s): Process Router Information LSA 4.0.0.%u from %pI4",
		  __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
		  &lsah->adv_router);

	/* Sanity check */
	if (IS_LSA_SELF(lsa))
		return;

	if (OspfSR.neighbors == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors,
					    &lsah->adv_router);


	/* Collect Router Information Sub TLVs */
	/* Initialize TLV browsing */
	length = lsa->size - OSPF_LSA_HEADER_SIZE;
	srgb.range_size = 0;
	srgb.lower_bound = 0;

	for (tlvh = TLV_HDR_TOP(lsah); (sum < length) && (tlvh != NULL);
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case RI_SR_TLV_SR_ALGORITHM:
			algo = (struct ri_sr_tlv_sr_algorithm *)tlvh;
			break;
		case RI_SR_TLV_SRGB_LABEL_RANGE:
			ri_srgb = (struct ri_sr_tlv_sid_label_range *)tlvh;
			break;
		case RI_SR_TLV_SRLB_LABEL_RANGE:
			ri_srlb = (struct ri_sr_tlv_sid_label_range *)tlvh;
			break;
		case RI_SR_TLV_NODE_MSD:
			msd = ((struct ri_sr_tlv_node_msd *)(tlvh))->value;
			break;
		default:
			break;
		}
		sum += TLV_SIZE(tlvh);
	}

	/* Check if Segment Routing Capabilities has been found */
	if (ri_srgb == NULL) {
		/* Skip Router Information without SR capabilities
		 * advertise by a non SR Node */
		if (srn == NULL) {
			return;
		} else {
			/* Remove SR Node that advertise Router Information
			 * without SR capabilities. This could correspond to a
			 * Node stopping Segment Routing */
			hash_release(OspfSR.neighbors, &(srn->adv_router));
			sr_node_del(srn);
			return;
		}
	}

	/* Check that RI LSA belongs to the correct SR Node */
	if ((srn != NULL) && (srn->instance != 0)
	    && (srn->instance != ntohl(lsah->id.s_addr))) {
		flog_err(EC_OSPF_SR_INVALID_LSA_ID,
			 "SR (%s): Abort! Wrong LSA ID 4.0.0.%u for SR node %pI4/%u",
			 __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			 &lsah->adv_router, srn->instance);
		return;
	}

	/* OK. All things look good. Get SRGB */
	srgb.range_size = GET_RANGE_SIZE(ntohl(ri_srgb->size));
	srgb.lower_bound = GET_LABEL(ntohl(ri_srgb->lower.value));

	/* Check if it is a new SR Node or not */
	if (srn == NULL) {
		/* Get a new SR Node in hash table from Router ID */
		srn = (struct sr_node *)hash_get(OspfSR.neighbors,
						 &lsah->adv_router,
						 (void *)sr_node_new);
		/* update LSA ID */
		srn->instance = ntohl(lsah->id.s_addr);
		/* Copy SRGB */
		srn->srgb.range_size = srgb.range_size;
		srn->srgb.lower_bound = srgb.lower_bound;
	}

	/* Update Algorithm, SRLB and MSD if present */
	if (algo != NULL) {
		int i;
		for (i = 0;
		     i < ntohs(algo->header.length) && i < ALGORITHM_COUNT; i++)
			srn->algo[i] = algo->value[0];
		for (; i < ALGORITHM_COUNT; i++)
			srn->algo[i] = SR_ALGORITHM_UNSET;
	} else {
		srn->algo[0] = SR_ALGORITHM_SPF;
	}
	srn->msd = msd;
	if (ri_srlb != NULL) {
		srn->srlb.range_size = GET_RANGE_SIZE(ntohl(ri_srlb->size));
		srn->srlb.lower_bound = GET_LABEL(ntohl(ri_srlb->lower.value));
	}

	/* Check if SRGB has changed */
	if ((srn->srgb.range_size == srgb.range_size)
	    && (srn->srgb.lower_bound == srgb.lower_bound))
		return;

	/* Copy SRGB */
	srn->srgb.range_size = srgb.range_size;
	srn->srgb.lower_bound = srgb.lower_bound;

	osr_debug("  |- Update SR-Node[%pI4], SRGB[%u/%u], SRLB[%u/%u], Algo[%u], MSD[%u]",
		  &srn->adv_router, srn->srgb.lower_bound, srn->srgb.range_size,
		  srn->srlb.lower_bound, srn->srlb.range_size, srn->algo[0],
		  srn->msd);

	/* ... and NHLFE if it is a neighbor SR node */
	if (srn->neighbor == OspfSR.self)
		hash_iterate(OspfSR.neighbors, update_out_nhlfe, srn);
}

/*
 * Delete SR Node entry in hash table information corresponding to an expired
 * Router Information LSA
 */
void ospf_sr_ri_lsa_delete(struct ospf_lsa *lsa)
{
	struct sr_node *srn;
	struct lsa_header *lsah = lsa->data;

	osr_debug("SR (%s): Remove SR node %pI4 from lsa_id 4.0.0.%u", __func__,
		  &lsah->adv_router, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)));

	/* Sanity check */
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR Data Base", __func__);
		return;
	}

	/* Release Router ID entry in SRDB hash table */
	srn = hash_release(OspfSR.neighbors, &(lsah->adv_router));

	/* Sanity check */
	if (srn == NULL) {
		flog_err(EC_OSPF_SR_NODE_CREATE,
			 "SR (%s): Abort! no entry in SRDB for SR Node %pI4",
			 __func__, &lsah->adv_router);
		return;
	}

	if ((srn->instance != 0) && (srn->instance != ntohl(lsah->id.s_addr))) {
		flog_err(
			EC_OSPF_SR_INVALID_LSA_ID,
			"SR (%s): Abort! Wrong LSA ID 4.0.0.%u for SR node %pI4",
			__func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			&lsah->adv_router);
		return;
	}

	/* Remove SR node */
	sr_node_del(srn);
}

/* Update Segment Routing from Extended Link LSA */
void ospf_sr_ext_link_lsa_update(struct ospf_lsa *lsa)
{
	struct sr_node *srn;
	struct tlv_header *tlvh;
	struct lsa_header *lsah = lsa->data;
	struct sr_link *srl;

	int length;

	osr_debug("SR (%s): Process Extended Link LSA 8.0.0.%u from %pI4",
		  __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
		  &lsah->adv_router);

	/* Sanity check */
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(OspfSR.neighbors,
					 (void *)&(lsah->adv_router),
					 (void *)sr_node_new);

	/* Initialize TLV browsing */
	length = lsa->size - OSPF_LSA_HEADER_SIZE;
	for (tlvh = TLV_HDR_TOP(lsah); length > 0 && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		if (ntohs(tlvh->type) == EXT_TLV_LINK) {
			/* Got Extended Link information */
			srl = get_ext_link_sid(tlvh, length);
			/* Update SID if not null */
			if (srl != NULL) {
				srl->instance = ntohl(lsah->id.s_addr);
				update_ext_link_sid(srn, srl, lsa->flags);
			}
		}
		length -= TLV_SIZE(tlvh);
	}
}

/* Delete Segment Routing from Extended Link LSA */
void ospf_sr_ext_link_lsa_delete(struct ospf_lsa *lsa)
{
	struct listnode *node;
	struct sr_link *srl;
	struct sr_node *srn;
	struct lsa_header *lsah = lsa->data;
	uint32_t instance = ntohl(lsah->id.s_addr);

	osr_debug("SR (%s): Remove Extended Link LSA 8.0.0.%u from %pI4",
		  __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
		  &lsah->adv_router);

	/* Sanity check */
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors,
					    (void *)&(lsah->adv_router));

	/*
	 * SR-Node may be NULL if it has been remove previously when
	 * processing Router Information LSA deletion
	 */
	if (srn == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s): Stop! no entry in SRDB for SR Node %pI4",
			 __func__, &lsah->adv_router);
		return;
	}

	/* Search for corresponding Segment Link */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, srl))
		if (srl->instance == instance)
			break;

	/* Remove Segment Link if found. Note that for Neighbors, only Global
	 * Adj/Lan-Adj SID are stored in the SR-DB */
	if ((srl != NULL) && (srl->instance == instance)) {
		del_adj_sid(srl->nhlfe[0]);
		del_adj_sid(srl->nhlfe[1]);
		listnode_delete(srn->ext_link, srl);
		XFREE(MTYPE_OSPF_SR_PARAMS, srl);
	}
}

/* Add (LAN)Adjacency-SID from Extended Link Information */
void ospf_sr_ext_itf_add(struct ext_itf *exti)
{
	struct sr_node *srn = OspfSR.self;
	struct sr_link *srl;

	osr_debug("SR (%s): Add Extended Link LSA 8.0.0.%u from self", __func__,
		  exti->instance);

	/* Sanity check */
	if (srn == NULL)
		return;

	/* Initialize new Segment Routing Link */
	srl = XCALLOC(MTYPE_OSPF_SR_PARAMS, sizeof(struct sr_link));
	srl->srn = srn;
	srl->adv_router = srn->adv_router;
	srl->itf_addr = exti->link.link_data;
	srl->instance =
		SET_OPAQUE_LSID(OPAQUE_TYPE_EXTENDED_LINK_LSA, exti->instance);
	srl->remote_id = exti->link.link_id;
	switch (exti->stype) {
	case ADJ_SID:
		srl->type = ADJ_SID;
		/* Primary information */
		srl->flags[0] = exti->adj_sid[0].flags;
		if (CHECK_FLAG(exti->adj_sid[0].flags,
			       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
			srl->sid[0] = GET_LABEL(ntohl(exti->adj_sid[0].value));
		else
			srl->sid[0] = ntohl(exti->adj_sid[0].value);
		if (exti->rmt_itf_addr.header.type == 0)
			srl->nhlfe[0].nexthop = exti->link.link_id;
		else
			srl->nhlfe[0].nexthop = exti->rmt_itf_addr.value;
		/* Backup Information if set */
		if (exti->adj_sid[1].header.type == 0)
			break;
		srl->flags[1] = exti->adj_sid[1].flags;
		if (CHECK_FLAG(exti->adj_sid[1].flags,
			       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
			srl->sid[1] = GET_LABEL(ntohl(exti->adj_sid[1].value));
		else
			srl->sid[1] = ntohl(exti->adj_sid[1].value);
		if (exti->rmt_itf_addr.header.type == 0)
			srl->nhlfe[1].nexthop = exti->link.link_id;
		else
			srl->nhlfe[1].nexthop = exti->rmt_itf_addr.value;
		break;
	case LAN_ADJ_SID:
		srl->type = LAN_ADJ_SID;
		/* Primary information */
		srl->flags[0] = exti->lan_sid[0].flags;
		if (CHECK_FLAG(exti->lan_sid[0].flags,
			       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
			srl->sid[0] = GET_LABEL(ntohl(exti->lan_sid[0].value));
		else
			srl->sid[0] = ntohl(exti->lan_sid[0].value);
		if (exti->rmt_itf_addr.header.type == 0)
			srl->nhlfe[0].nexthop = exti->lan_sid[0].neighbor_id;
		else
			srl->nhlfe[0].nexthop = exti->rmt_itf_addr.value;
		/* Backup Information if set */
		if (exti->lan_sid[1].header.type == 0)
			break;
		srl->flags[1] = exti->lan_sid[1].flags;
		if (CHECK_FLAG(exti->lan_sid[1].flags,
			       EXT_SUBTLV_LINK_ADJ_SID_VFLG))
			srl->sid[1] = GET_LABEL(ntohl(exti->lan_sid[1].value));
		else
			srl->sid[1] = ntohl(exti->lan_sid[1].value);
		if (exti->rmt_itf_addr.header.type == 0)
			srl->nhlfe[1].nexthop = exti->lan_sid[1].neighbor_id;
		else
			srl->nhlfe[1].nexthop = exti->rmt_itf_addr.value;
		break;
	case PREF_SID:
	case LOCAL_SID:
		/* Wrong SID Type. Abort! */
		XFREE(MTYPE_OSPF_SR_PARAMS, srl);
		return;
	}

	/* Segment Routing Link is ready, update it */
	update_ext_link_sid(srn, srl, OSPF_LSA_SELF);
}

/* Delete Prefix or (LAN)Adjacency-SID from Extended Link Information */
void ospf_sr_ext_itf_delete(struct ext_itf *exti)
{
	struct listnode *node;
	struct sr_node *srn = OspfSR.self;
	struct sr_prefix *srp = NULL;
	struct sr_link *srl = NULL;
	uint32_t instance;

	osr_debug("SR (%s): Remove Extended LSA %u.0.0.%u from self",
		  __func__, exti->stype == PREF_SID ? 7 : 8, exti->instance);

	/* Sanity check: SR-Node and Extended Prefix/Link list may have been
	 * removed earlier when stopping OSPF or OSPF-SR */
	if (srn == NULL || srn->ext_prefix == NULL || srn->ext_link == NULL)
		return;

	if (exti->stype == PREF_SID) {
		instance = SET_OPAQUE_LSID(OPAQUE_TYPE_EXTENDED_PREFIX_LSA,
					   exti->instance);
		for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp))
			if (srp->instance == instance)
				break;

		/* Uninstall Segment Prefix SID if found */
		if ((srp != NULL) && (srp->instance == instance))
			ospf_zebra_delete_prefix_sid(srp);
	} else {
		/* Search for corresponding Segment Link for self SR-Node */
		instance = SET_OPAQUE_LSID(OPAQUE_TYPE_EXTENDED_LINK_LSA,
					   exti->instance);
		for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, srl))
			if (srl->instance == instance)
				break;

		/* Remove Segment Link if found */
		if ((srl != NULL) && (srl->instance == instance)) {
			del_adj_sid(srl->nhlfe[0]);
			del_adj_sid(srl->nhlfe[1]);
			listnode_delete(srn->ext_link, srl);
			XFREE(MTYPE_OSPF_SR_PARAMS, srl);
		}
	}
}

/* Update Segment Routing from Extended Prefix LSA */
void ospf_sr_ext_prefix_lsa_update(struct ospf_lsa *lsa)
{
	struct sr_node *srn;
	struct tlv_header *tlvh;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct sr_prefix *srp;

	int length;

	osr_debug("SR (%s): Process Extended Prefix LSA 7.0.0.%u from %pI4",
		  __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
		  &lsah->adv_router);

	/* Sanity check */
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Get SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_get(OspfSR.neighbors,
					 (void *)&(lsah->adv_router),
					 (void *)sr_node_new);
	/* Initialize TLV browsing */
	length = lsa->size - OSPF_LSA_HEADER_SIZE;
	for (tlvh = TLV_HDR_TOP(lsah); length > 0 && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		if (ntohs(tlvh->type) == EXT_TLV_LINK) {
			/* Got Extended Link information */
			srp = get_ext_prefix_sid(tlvh, length);
			/* Update SID if not null */
			if (srp != NULL) {
				srp->instance = ntohl(lsah->id.s_addr);
				update_ext_prefix_sid(srn, srp);
			}
		}
		length -= TLV_SIZE(tlvh);
	}
}

/* Delete Segment Routing from Extended Prefix LSA */
void ospf_sr_ext_prefix_lsa_delete(struct ospf_lsa *lsa)
{
	struct listnode *node;
	struct sr_prefix *srp;
	struct sr_node *srn;
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	uint32_t instance = ntohl(lsah->id.s_addr);

	osr_debug("SR (%s): Remove Extended Prefix LSA 7.0.0.%u from %pI4",
		  __func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
		  &lsah->adv_router);

	/* Sanity check */
	if (OspfSR.neighbors == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s): Abort! no valid SR DataBase", __func__);
		return;
	}

	/* Search SR Node in hash table from Router ID */
	srn = (struct sr_node *)hash_lookup(OspfSR.neighbors,
					    (void *)&(lsah->adv_router));

	/*
	 * SR-Node may be NULL if it has been remove previously when
	 * processing Router Information LSA deletion
	 */
	if (srn == NULL) {
		flog_err(EC_OSPF_SR_INVALID_DB,
			 "SR (%s):  Stop! no entry in SRDB for SR Node %pI4",
			 __func__, &lsah->adv_router);
		return;
	}

	/* Search for corresponding Segment Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp))
		if (srp->instance == instance)
			break;

	/* Remove Prefix if found */
	if ((srp != NULL) && (srp->instance == instance)) {
		ospf_zebra_delete_prefix_sid(srp);
		listnode_delete(srn->ext_prefix, srp);
		XFREE(MTYPE_OSPF_SR_PARAMS, srp);
	} else {
		flog_err(
			EC_OSPF_SR_INVALID_DB,
			"SR (%s): Didn't found corresponding SR Prefix 7.0.0.%u for SR Node %pI4",
			__func__, GET_OPAQUE_ID(ntohl(lsah->id.s_addr)),
			&lsah->adv_router);
	}
}

/*
 * Update Prefix SID. Call by ospf_ext_pref_ism_change to
 * complete initial CLI command at startup.
 *
 * @param ifp - Loopback interface
 * @param pref - Prefix address of this interface
 *
 * @return - void
 */
void ospf_sr_update_local_prefix(struct interface *ifp, struct prefix *p)
{
	struct listnode *node;
	struct sr_prefix *srp;

	/* Sanity Check */
	if ((ifp == NULL) || (p == NULL))
		return;

	/*
	 * Search if there is a Segment Prefix that correspond to this
	 * interface or prefix, and update it if found
	 */
	for (ALL_LIST_ELEMENTS_RO(OspfSR.self->ext_prefix, node, srp)) {
		if ((srp->nhlfe.ifindex == ifp->ifindex)
		    || ((IPV4_ADDR_SAME(&srp->prefv4.prefix, &p->u.prefix4))
			&& (srp->prefv4.prefixlen == p->prefixlen))) {

			/* Update Interface & Prefix info */
			srp->nhlfe.ifindex = ifp->ifindex;
			IPV4_ADDR_COPY(&srp->prefv4.prefix, &p->u.prefix4);
			srp->prefv4.prefixlen = p->prefixlen;
			srp->prefv4.family = p->family;
			IPV4_ADDR_COPY(&srp->nhlfe.nexthop, &p->u.prefix4);

			/* OK. Let's Schedule Extended Prefix LSA */
			srp->instance = ospf_ext_schedule_prefix_index(
				ifp, srp->sid, &srp->prefv4, srp->flags);

			osr_debug(
				"  |-  Update Node SID %pFX - %u for self SR Node",
				(struct prefix *)&srp->prefv4, srp->sid);

			/* Install SID if NO-PHP is set and not EXPLICIT-NULL */
			if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_NPFLG)
			    && !CHECK_FLAG(srp->flags,
					   EXT_SUBTLV_PREFIX_SID_EFLG)) {
				srp->label_in = index2label(srp->sid,
							    OspfSR.self->srgb);
				srp->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
				ospf_zebra_update_prefix_sid(srp);
			}
		}
	}
}

/*
 * Following functions are used to update MPLS LFIB after a SPF run
 */

static void ospf_sr_nhlfe_update(struct hash_bucket *bucket, void *args)
{

	struct sr_node *srn = (struct sr_node *)bucket->data;
	struct listnode *node;
	struct sr_prefix *srp;
	bool old;
	int rc;

	osr_debug("  |-  Update Prefix for SR Node %pI4", &srn->adv_router);

	/* Skip Self SR Node */
	if (srn == OspfSR.self)
		return;

	/* Update Extended Prefix */
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {

		/* Keep track of valid route */
		old = srp->route != NULL;

		/* Compute the new NHLFE */
		rc = compute_prefix_nhlfe(srp);

		/* Check computation result */
		switch (rc) {
		/* Routes are not know, remove old NHLFE if any to avoid loop */
		case -1:
			if (old)
				ospf_zebra_delete_prefix_sid(srp);
			break;
		/* Routes exist but are not ready, skip it */
		case 0:
			break;
		/* There is at least one route, update NHLFE */
		case 1:
			ospf_zebra_update_prefix_sid(srp);
			break;
		default:
			break;
		}
	}
}

void ospf_sr_update_task(struct ospf *ospf)
{

	struct timeval start_time, stop_time;

	/* Check ospf and SR status */
	if ((ospf == NULL) || (OspfSR.status != SR_UP))
		return;

	monotime(&start_time);

	osr_debug("SR (%s): Start SPF update", __func__);

	hash_iterate(OspfSR.neighbors, (void (*)(struct hash_bucket *,
						 void *))ospf_sr_nhlfe_update,
		     NULL);

	monotime(&stop_time);

	osr_debug("SR (%s): SPF Processing Time(usecs): %lld", __func__,
		  (stop_time.tv_sec - start_time.tv_sec) * 1000000LL
			  + (stop_time.tv_usec - start_time.tv_usec));
}

/*
 * --------------------------------------
 * Following are vty command functions.
 * --------------------------------------
 */

/*
 * Segment Routing Router configuration
 *
 * Must be centralize as it concerns both Extended Link/Prefix LSA
 * and Router Information LSA. Choose to call it from Extended Prefix
 * write_config() call back.
 *
 * @param vty VTY output
 *
 * @return none
 */
void ospf_sr_config_write_router(struct vty *vty)
{
	struct listnode *node;
	struct sr_prefix *srp;
	uint32_t upper;

	if (OspfSR.status == SR_UP)
		vty_out(vty, " segment-routing on\n");

	upper = OspfSR.srgb.start + OspfSR.srgb.size - 1;
	if ((OspfSR.srgb.start != DEFAULT_SRGB_LABEL)
	    || (OspfSR.srgb.size != DEFAULT_SRGB_SIZE))
		vty_out(vty, " segment-routing global-block %u %u",
			OspfSR.srgb.start, upper);

	if ((OspfSR.srlb.start != DEFAULT_SRLB_LABEL) ||
	    (OspfSR.srlb.end != DEFAULT_SRLB_END)) {
		if ((OspfSR.srgb.start == DEFAULT_SRGB_LABEL) &&
		    (OspfSR.srgb.size == DEFAULT_SRGB_SIZE))
			vty_out(vty, " segment-routing global-block %u %u",
				OspfSR.srgb.start, upper);
		vty_out(vty, " local-block %u %u\n", OspfSR.srlb.start,
			OspfSR.srlb.end);
	} else
		vty_out(vty, "\n");

	if (OspfSR.msd != 0)
		vty_out(vty, " segment-routing node-msd %u\n", OspfSR.msd);

	if (OspfSR.self != NULL) {
		for (ALL_LIST_ELEMENTS_RO(OspfSR.self->ext_prefix, node, srp)) {
			vty_out(vty, " segment-routing prefix %pFX index %u",
				&srp->prefv4, srp->sid);
			if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_EFLG))
				vty_out(vty, " explicit-null\n");
			else if (CHECK_FLAG(srp->flags,
					    EXT_SUBTLV_PREFIX_SID_NPFLG))
				vty_out(vty, " no-php-flag\n");
			else
				vty_out(vty, "\n");
		}
	}
}

DEFUN(ospf_sr_enable,
       ospf_sr_enable_cmd,
       "segment-routing on",
       SR_STR
       "Enable Segment Routing\n")
{

	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (OspfSR.status != SR_OFF)
		return CMD_SUCCESS;

	if (ospf->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"Segment Routing is only supported in default VRF\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	osr_debug("SR: Segment Routing: OFF -> ON");

	/* Start Segment Routing */
	OspfSR.status = SR_ON;
	ospf_sr_start(ospf);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_sr_enable,
       no_ospf_sr_enable_cmd,
       "no segment-routing [on]",
       NO_STR
       SR_STR
       "Disable Segment Routing\n")
{

	if (OspfSR.status == SR_OFF)
		return CMD_SUCCESS;

	osr_debug("SR: Segment Routing: ON -> OFF");

	/* Start by Disabling Extended Link & Prefix LSA */
	ospf_ext_update_sr(false);

	/* then, disable Router Information SR parameters */
	ospf_router_info_update_sr(false, OspfSR.self);

	/* Finally, stop Segment Routing */
	ospf_sr_stop();

	return CMD_SUCCESS;
}

static int ospf_sr_enabled(struct vty *vty)
{
	if (OspfSR.status != SR_OFF)
		return 1;

	if (vty)
		vty_out(vty, "%% OSPF SR is not turned on\n");

	return 0;
}

/* tell if two ranges [r1_lower, r1_upper] and [r2_lower,r2_upper] overlap */
static bool ranges_overlap(uint32_t r1_lower, uint32_t r1_upper,
			   uint32_t r2_lower, uint32_t r2_upper)
{
	return !((r1_upper < r2_lower) || (r1_lower > r2_upper));
}


/* tell if a range is valid */
static bool sr_range_is_valid(uint32_t lower, uint32_t upper, uint32_t min_size)
{
	return (upper >= lower + min_size);
}

/**
 * Update SRGB and/or SRLB using new CLI values.
 *
 * @param gb_lower  Lower bound of the SRGB
 * @param gb_upper  Upper bound of the SRGB
 * @param lb_lower  Lower bound of the SRLB
 * @param lb_upper  Upper bound of the SRLB
 *
 * @return          0 on success, -1 otherwise
 */
static int update_sr_blocks(uint32_t gb_lower, uint32_t gb_upper,
			    uint32_t lb_lower, uint32_t lb_upper)
{

	/* Check if values have changed */
	bool gb_changed, lb_changed;
	uint32_t gb_size = gb_upper - gb_lower + 1;
	uint32_t lb_size = lb_upper - lb_lower + 1;

	gb_changed =
		(OspfSR.srgb.size != gb_size || OspfSR.srgb.start != gb_lower);
	lb_changed =
		(OspfSR.srlb.end != lb_upper || OspfSR.srlb.start != lb_lower);
	if (!gb_changed && !lb_changed)
		return 0;

	/* Check if SR is correctly started i.e. Label Manager connected */
	if (OspfSR.status != SR_UP) {
		OspfSR.srgb.size = gb_size;
		OspfSR.srgb.start = gb_lower;
		OspfSR.srlb.end = lb_upper;
		OspfSR.srlb.start = lb_lower;
		return 0;
	}

	/* Release old SRGB if it has changed and is active. */
	if (gb_changed) {

		sr_global_block_delete();

		/* Set new SRGB values - but do not reserve yet (we need to
		 * release the SRLB too) */
		OspfSR.srgb.size = gb_size;
		OspfSR.srgb.start = gb_lower;
		if (OspfSR.self != NULL) {
			OspfSR.self->srgb.range_size = gb_size;
			OspfSR.self->srgb.lower_bound = gb_lower;
		}
	}
	/* Release old SRLB if it has changed and reserve new block as needed.
	 */
	if (lb_changed) {

		sr_local_block_delete();

		/* Set new SRLB values */
		if (sr_local_block_init(lb_lower, lb_upper) < 0) {
			ospf_sr_stop();
			return -1;
		}
		if (OspfSR.self != NULL) {
			OspfSR.self->srlb.lower_bound = lb_lower;
			OspfSR.self->srlb.range_size = lb_size;
		}
	}

	/*
	 * Try to reserve the new SRGB from the Label Manger. If the
	 * allocation fails, disable SR until new blocks are successfully
	 * allocated.
	 */
	if (gb_changed) {
		if (sr_global_block_init(OspfSR.srgb.start, OspfSR.srgb.size)
		    < 0) {
			ospf_sr_stop();
			return -1;
		}
	}

	/* Update Self SR-Node */
	if (OspfSR.self != NULL) {
		/* SRGB is reserved, set Router Information parameters */
		ospf_router_info_update_sr(true, OspfSR.self);

		/* and update NHLFE entries */
		if (gb_changed)
			hash_iterate(OspfSR.neighbors,
				     (void (*)(struct hash_bucket *,
					       void *))update_in_nhlfe,
				     NULL);

		/* and update (LAN)-Adjacency SID */
		if (lb_changed)
			ospf_ext_link_srlb_update();
	}

	return 0;
}

DEFUN(sr_global_label_range, sr_global_label_range_cmd,
      "segment-routing global-block (16-1048575) (16-1048575) [local-block (16-1048575) (16-1048575)]",
      SR_STR
      "Segment Routing Global Block label range\n"
      "Lower-bound range in decimal (16-1048575)\n"
      "Upper-bound range in decimal (16-1048575)\n"
      "Segment Routing Local Block label range\n"
      "Lower-bound range in decimal (16-1048575)\n"
      "Upper-bound range in decimal (16-1048575)\n")
{
	uint32_t lb_upper, lb_lower;
	uint32_t gb_upper, gb_lower;
	int idx_gb_low = 2, idx_gb_up = 3;
	int idx_lb_low = 5, idx_lb_up = 6;

	/* Get lower and upper bound for mandatory global-block */
	gb_lower = strtoul(argv[idx_gb_low]->arg, NULL, 10);
	gb_upper = strtoul(argv[idx_gb_up]->arg, NULL, 10);

	/* SRLB values are taken from vtysh if there, else use the known ones */
	lb_upper = argc > idx_lb_up ? strtoul(argv[idx_lb_up]->arg, NULL, 10)
				    : OspfSR.srlb.end;
	lb_lower = argc > idx_lb_low ? strtoul(argv[idx_lb_low]->arg, NULL, 10)
				     : OspfSR.srlb.start;

	/* check correctness of input SRGB */
	if (!sr_range_is_valid(gb_lower, gb_upper, MIN_SRGB_SIZE)) {
		vty_out(vty, "Invalid SRGB range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* check correctness of SRLB */
	if (!sr_range_is_valid(lb_lower, lb_upper, MIN_SRLB_SIZE)) {
		vty_out(vty, "Invalid SRLB range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Validate SRGB against SRLB */
	if (ranges_overlap(gb_lower, gb_upper, lb_lower, lb_upper)) {
		vty_out(vty,
			"New SR Global Block (%u/%u) conflicts with Local Block (%u/%u)\n",
			gb_lower, gb_upper, lb_lower, lb_upper);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (update_sr_blocks(gb_lower, gb_upper, lb_lower, lb_upper) < 0)
		return CMD_WARNING_CONFIG_FAILED;
	else
		return CMD_SUCCESS;
}

DEFUN(no_sr_global_label_range, no_sr_global_label_range_cmd,
      "no segment-routing global-block [(16-1048575) (16-1048575) local-block (16-1048575) (16-1048575)]",
      NO_STR SR_STR
      "Segment Routing Global Block label range\n"
      "Lower-bound range in decimal (16-1048575)\n"
      "Upper-bound range in decimal (16-1048575)\n"
      "Segment Routing Local Block label range\n"
      "Lower-bound range in decimal (16-1048575)\n"
      "Upper-bound range in decimal (16-1048575)\n")
{
	if (update_sr_blocks(DEFAULT_SRGB_LABEL, DEFAULT_SRGB_END,
			     DEFAULT_SRLB_LABEL, DEFAULT_SRLB_END)
	    < 0)
		return CMD_WARNING_CONFIG_FAILED;
	else
		return CMD_SUCCESS;
}

DEFUN (sr_node_msd,
       sr_node_msd_cmd,
       "segment-routing node-msd (1-16)",
       SR_STR
       "Maximum Stack Depth for this router\n"
       "Maximum number of label that could be stack (1-16)\n")
{
	uint32_t msd;
	int idx = 1;

	if (!ospf_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* Get MSD */
	argv_find(argv, argc, "(1-16)", &idx);
	msd = strtoul(argv[idx]->arg, NULL, 10);
	if (msd < 1 || msd > MPLS_MAX_LABELS) {
		vty_out(vty, "MSD must be comprise between 1 and %u\n",
			MPLS_MAX_LABELS);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check if value has changed */
	if (OspfSR.msd == msd)
		return CMD_SUCCESS;

	/* Set this router MSD */
	OspfSR.msd = msd;
	if (OspfSR.self != NULL) {
		OspfSR.self->msd = msd;

		/* Set Router Information parameters if SR is UP */
		if (OspfSR.status == SR_UP)
			ospf_router_info_update_sr(true, OspfSR.self);
	}

	return CMD_SUCCESS;
}

DEFUN (no_sr_node_msd,
	no_sr_node_msd_cmd,
	"no segment-routing node-msd [(1-16)]",
	NO_STR
	SR_STR
	"Maximum Stack Depth for this router\n"
	"Maximum number of label that could be stack (1-16)\n")
{

	if (!ospf_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* unset this router MSD */
	OspfSR.msd = 0;
	if (OspfSR.self != NULL) {
		OspfSR.self->msd = 0;

		/* Set Router Information parameters if SR is UP */
		if (OspfSR.status == SR_UP)
			ospf_router_info_update_sr(true, OspfSR.self);
	}

	return CMD_SUCCESS;
}

DEFUN (sr_prefix_sid,
       sr_prefix_sid_cmd,
       "segment-routing prefix A.B.C.D/M index (0-65535) [no-php-flag|explicit-null]",
       SR_STR
       "Prefix SID\n"
       "IPv4 Prefix as A.B.C.D/M\n"
       "SID index for this prefix in decimal (0-65535)\n"
       "Index value inside SRGB (lower_bound < index < upper_bound)\n"
       "Don't request Penultimate Hop Popping (PHP)\n"
       "Upstream neighbor must replace prefix-sid with explicit null label\n")
{
	int idx = 0;
	struct prefix p, pexist;
	uint32_t index;
	struct listnode *node;
	struct sr_prefix *srp, *exist = NULL;
	struct interface *ifp;
	bool no_php_flag = false;
	bool exp_null = false;
	bool index_in_use = false;
	uint8_t desired_flags = 0;

	if (!ospf_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	/* Get network prefix */
	argv_find(argv, argc, "A.B.C.D/M", &idx);
	if (!str2prefix(argv[idx]->arg, &p)) {
		vty_out(vty, "Invalid prefix format %s\n", argv[idx]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get & verify index value */
	argv_find(argv, argc, "(0-65535)", &idx);
	index = strtoul(argv[idx]->arg, NULL, 10);
	if (index > OspfSR.srgb.size - 1) {
		vty_out(vty, "Index %u must be lower than range size %u\n",
			index, OspfSR.srgb.size);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get options */
	no_php_flag = argv_find(argv, argc, "no-php-flag", &idx);
	exp_null = argv_find(argv, argc, "explicit-null", &idx);

	desired_flags |= no_php_flag ? EXT_SUBTLV_PREFIX_SID_NPFLG : 0;
	desired_flags |= exp_null ? EXT_SUBTLV_PREFIX_SID_NPFLG : 0;
	desired_flags |= exp_null ? EXT_SUBTLV_PREFIX_SID_EFLG : 0;

	/* Search for an existing Prefix-SID */
	for (ALL_LIST_ELEMENTS_RO(OspfSR.self->ext_prefix, node, srp)) {
		if (prefix_same((struct prefix *)&srp->prefv4, &p))
			exist = srp;
		if (srp->sid == index) {
			index_in_use = true;
			pexist = p;
		}
	}

	/* done if prefix segment already there with same index and flags */
	if (exist && exist->sid == index && exist->flags == desired_flags)
		return CMD_SUCCESS;

	/* deny if index is already in use by a distinct prefix */
	if (!exist && index_in_use) {
		vty_out(vty, "Index %u is already used by %pFX\n", index,
			&pexist);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* First, remove old NHLFE if installed */
	if (exist && CHECK_FLAG(exist->flags, EXT_SUBTLV_PREFIX_SID_NPFLG)
	    && !CHECK_FLAG(exist->flags, EXT_SUBTLV_PREFIX_SID_EFLG))
		ospf_zebra_delete_prefix_sid(exist);

	/* Create new Extended Prefix to SRDB if not found */
	if (exist == NULL) {
		srp = XCALLOC(MTYPE_OSPF_SR_PARAMS, sizeof(struct sr_prefix));
		IPV4_ADDR_COPY(&srp->prefv4.prefix, &p.u.prefix4);
		srp->prefv4.prefixlen = p.prefixlen;
		srp->prefv4.family = p.family;
		srp->sid = index;
		srp->type = LOCAL_SID;
	} else {
		/* we work on the existing SR prefix */
		srp = exist;
	}

	/* Reset labels to handle flag update */
	srp->label_in = 0;
	srp->nhlfe.label_out = 0;
	srp->sid = index;
	srp->flags = desired_flags;

	/* If NO PHP flag is present, compute NHLFE and set label */
	if (no_php_flag) {
		srp->label_in = index2label(srp->sid, OspfSR.self->srgb);
		srp->nhlfe.label_out = MPLS_LABEL_IMPLICIT_NULL;
	}

	osr_debug("SR (%s): Add new index %u to Prefix %pFX", __func__, index,
		  (struct prefix *)&srp->prefv4);

	/* Get Interface and check if it is a Loopback */
	ifp = if_lookup_prefix(&p, VRF_DEFAULT);
	if (ifp == NULL) {
		/*
		 * Interface could be not yet available i.e. when this
		 * command is in the configuration file, OSPF is not yet
		 * ready. In this case, store the prefix SID for latter
		 * update of this Extended Prefix
		 */
		if (exist == NULL)
			listnode_add(OspfSR.self->ext_prefix, srp);
		zlog_info(
			"Interface for prefix %pFX not found. Deferred LSA flooding",
			&p);
		return CMD_SUCCESS;
	}

	if (!if_is_loopback(ifp)) {
		vty_out(vty, "interface %s is not a Loopback\n", ifp->name);
		XFREE(MTYPE_OSPF_SR_PARAMS, srp);
		return CMD_WARNING_CONFIG_FAILED;
	}
	srp->nhlfe.ifindex = ifp->ifindex;

	/* Add SR Prefix if new */
	if (!exist)
		listnode_add(OspfSR.self->ext_prefix, srp);

	/* Update Prefix SID if SR is UP */
	if (OspfSR.status == SR_UP) {
		if (no_php_flag && !exp_null)
			ospf_zebra_update_prefix_sid(srp);
	} else
		return CMD_SUCCESS;

	/* Finally, update Extended Prefix LSA id SR is UP */
	srp->instance = ospf_ext_schedule_prefix_index(
		ifp, srp->sid, &srp->prefv4, srp->flags);
	if (srp->instance == 0) {
		vty_out(vty, "Unable to set index %u for prefix %pFX\n",
			index, &p);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (no_sr_prefix_sid,
       no_sr_prefix_sid_cmd,
       "no segment-routing prefix A.B.C.D/M [index (0-65535)|no-php-flag|explicit-null]",
       NO_STR
       SR_STR
       "Prefix SID\n"
       "IPv4 Prefix as A.B.C.D/M\n"
       "SID index for this prefix in decimal (0-65535)\n"
       "Index value inside SRGB (lower_bound < index < upper_bound)\n"
       "Don't request Penultimate Hop Popping (PHP)\n"
       "Upstream neighbor must replace prefix-sid with explicit null label\n")
{
	int idx = 0;
	struct prefix p;
	struct listnode *node;
	struct sr_prefix *srp;
	struct interface *ifp;
	bool found = false;
	int rc;

	if (!ospf_sr_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (OspfSR.status != SR_UP)
		return CMD_SUCCESS;

	/* Get network prefix */
	argv_find(argv, argc, "A.B.C.D/M", &idx);
	rc = str2prefix(argv[idx]->arg, &p);
	if (!rc) {
		vty_out(vty, "Invalid prefix format %s\n", argv[idx]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* check that the prefix is already set */
	for (ALL_LIST_ELEMENTS_RO(OspfSR.self->ext_prefix, node, srp))
		if (IPV4_ADDR_SAME(&srp->prefv4.prefix, &p.u.prefix4)
		    && (srp->prefv4.prefixlen == p.prefixlen)) {
			found = true;
			break;
		}

	if (!found) {
		vty_out(vty, "Prefix %s is not found. Abort!\n",
			argv[idx]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	osr_debug("SR (%s): Remove Prefix %pFX with index %u", __func__,
		  (struct prefix *)&srp->prefv4, srp->sid);

	/* Get Interface */
	ifp = if_lookup_by_index(srp->nhlfe.ifindex, VRF_DEFAULT);
	if (ifp == NULL) {
		vty_out(vty, "interface for prefix %s not found.\n",
			argv[idx]->arg);
		/* silently remove from list */
		listnode_delete(OspfSR.self->ext_prefix, srp);
		XFREE(MTYPE_OSPF_SR_PARAMS, srp);
		return CMD_SUCCESS;
	}

	/* Update Extended Prefix LSA */
	if (!ospf_ext_schedule_prefix_index(ifp, 0, NULL, 0)) {
		vty_out(vty, "No corresponding loopback interface. Abort!\n");
		return CMD_WARNING;
	}

	/* Delete NHLFE if NO-PHP is set and EXPLICIT NULL not set */
	if (CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_NPFLG)
	    && !CHECK_FLAG(srp->flags, EXT_SUBTLV_PREFIX_SID_EFLG))
		ospf_zebra_delete_prefix_sid(srp);

	/* OK, all is clean, remove SRP from SRDB */
	listnode_delete(OspfSR.self->ext_prefix, srp);
	XFREE(MTYPE_OSPF_SR_PARAMS, srp);

	return CMD_SUCCESS;
}


static char *sr_op2str(char *buf, size_t size, mpls_label_t label_in,
		       mpls_label_t label_out)
{
	if (size < 24)
		return NULL;

	switch (label_out) {
	case MPLS_LABEL_IMPLICIT_NULL:
		snprintf(buf, size, "Pop(%u)", label_in);
		break;
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
		if (label_in == MPLS_LABEL_IPV4_EXPLICIT_NULL)
			snprintf(buf, size, "no-op.");
		else
			snprintf(buf, size, "Swap(%u, null)", label_in);
		break;
	case MPLS_INVALID_LABEL:
		snprintf(buf, size, "no-op.");
		break;
	default:
		snprintf(buf, size, "Swap(%u, %u)", label_in, label_out);
		break;
	}
	return buf;
}

static void show_sr_prefix(struct sbuf *sbuf, struct json_object *json,
			   struct sr_prefix *srp)
{

	struct listnode *node;
	struct ospf_path *path;
	struct interface *itf;
	json_object *json_route = NULL, *json_obj;
	char pref[19];
	char sid[22];
	char op[32];
	char buf[PREFIX_STRLEN];
	int indent = 0;

	snprintfrr(pref, 19, "%pFX", (struct prefix *)&srp->prefv4);
	snprintf(sid, 22, "SR Pfx (idx %u)", srp->sid);
	if (json) {
		json_object_string_add(json, "prefix", pref);
		json_object_int_add(json, "sid", srp->sid);
		json_object_int_add(json, "inputLabel", srp->label_in);
	} else {
		sbuf_push(sbuf, 0, "%18s  %21s  ", pref, sid);
	}

	/* Check if it is a Local Node SID */
	if (srp->type == LOCAL_SID) {
		itf = if_lookup_by_index(srp->nhlfe.ifindex, VRF_DEFAULT);
		if (json) {
			if (!json_route) {
				json_route = json_object_new_array();
				json_object_object_add(json, "prefixRoute",
						       json_route);
			}
			json_obj = json_object_new_object();
			json_object_int_add(json_obj, "outputLabel",
					    srp->nhlfe.label_out);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_addf(json_obj, "nexthop", "%pI4",
						&srp->nhlfe.nexthop);
			json_object_array_add(json_route, json_obj);
		} else {
			sbuf_push(sbuf, 0, "%20s  %9s  %15s\n",
				  sr_op2str(op, 32, srp->label_in,
					    srp->nhlfe.label_out),
				  itf ? itf->name : "-",
				  inet_ntop(AF_INET, &srp->nhlfe.nexthop,
					    buf, sizeof(buf)));
		}
		return;
	}

	/* Check if we have a valid path for this prefix */
	if (srp->route == NULL) {
		if (!json) {
			sbuf_push(sbuf, 0, "\n");
		}
		return;
	}

	/* Process list of OSPF paths */
	for (ALL_LIST_ELEMENTS_RO(srp->route->paths, node, path)) {
		itf = if_lookup_by_index(path->ifindex, VRF_DEFAULT);
		if (json) {
			if (!json_route) {
				json_route = json_object_new_array();
				json_object_object_add(json, "prefixRoute",
						       json_route);
			}
			json_obj = json_object_new_object();
			json_object_int_add(json_obj, "outputLabel",
					    path->srni.label_out);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_addf(json_obj, "nexthop", "%pI4",
						&path->nexthop);
			json_object_array_add(json_route, json_obj);
		} else {
			sbuf_push(sbuf, indent, "%20s  %9s  %15s\n",
				  sr_op2str(op, 32, srp->label_in,
					    path->srni.label_out),
				  itf ? itf->name : "-",
				  inet_ntop(AF_INET, &path->nexthop, buf,
					    sizeof(buf)));
			/* Offset to align information for ECMP */
			indent = 43;
		}
	}
}

static void show_sr_node(struct vty *vty, struct json_object *json,
			 struct sr_node *srn)
{

	struct listnode *node;
	struct sr_link *srl;
	struct sr_prefix *srp;
	struct interface *itf;
	struct sbuf sbuf;
	char pref[19];
	char sid[22];
	char op[32];
	char buf[PREFIX_STRLEN];
	uint32_t upper;
	json_object *json_node = NULL, *json_algo, *json_obj;
	json_object *json_prefix = NULL, *json_link = NULL;

	/* Sanity Check */
	if (srn == NULL)
		return;

	sbuf_init(&sbuf, NULL, 0);

	if (json) {
		json_node = json_object_new_object();
		json_object_string_addf(json_node, "routerID", "%pI4",
					&srn->adv_router);
		json_object_int_add(json_node, "srgbSize",
				    srn->srgb.range_size);
		json_object_int_add(json_node, "srgbLabel",
				    srn->srgb.lower_bound);
		json_object_int_add(json_node, "srlbSize",
				    srn->srlb.range_size);
		json_object_int_add(json_node, "srlbLabel",
				    srn->srlb.lower_bound);
		json_algo = json_object_new_array();
		json_object_object_add(json_node, "algorithms", json_algo);
		for (int i = 0; i < ALGORITHM_COUNT; i++) {
			if (srn->algo[i] == SR_ALGORITHM_UNSET)
				continue;
			json_obj = json_object_new_object();
			char tmp[12];

			snprintf(tmp, sizeof(tmp), "%d", i);
			json_object_string_add(json_obj, tmp,
					       srn->algo[i] == SR_ALGORITHM_SPF
						       ? "SPF"
						       : "S-SPF");
			json_object_array_add(json_algo, json_obj);
		}
		if (srn->msd != 0)
			json_object_int_add(json_node, "nodeMsd", srn->msd);
	} else {
		sbuf_push(&sbuf, 0, "SR-Node: %pI4", &srn->adv_router);
		upper = srn->srgb.lower_bound + srn->srgb.range_size - 1;
		sbuf_push(&sbuf, 0, "\tSRGB: [%u/%u]",
			  srn->srgb.lower_bound, upper);
		upper = srn->srlb.lower_bound + srn->srlb.range_size - 1;
		sbuf_push(&sbuf, 0, "\tSRLB: [%u/%u]",
			  srn->srlb.lower_bound, upper);
		sbuf_push(&sbuf, 0, "\tAlgo.(s): %s",
			  srn->algo[0] == SR_ALGORITHM_SPF ? "SPF" : "S-SPF");
		for (int i = 1; i < ALGORITHM_COUNT; i++) {
			if (srn->algo[i] == SR_ALGORITHM_UNSET)
				continue;
			sbuf_push(&sbuf, 0, "/%s",
				  srn->algo[i] == SR_ALGORITHM_SPF ? "SPF"
								   : "S-SPF");
		}
		if (srn->msd != 0)
			sbuf_push(&sbuf, 0, "\tMSD: %u", srn->msd);
	}

	if (!json) {
		sbuf_push(&sbuf, 0,
			  "\n\n    Prefix or Link       Node or Adj. SID       Label Operation  Interface          Nexthop\n");
		sbuf_push(&sbuf, 0,
			  "------------------  ---------------------  --------------------  ---------  ---------------\n");
	}
	for (ALL_LIST_ELEMENTS_RO(srn->ext_prefix, node, srp)) {
		if (json) {
			if (!json_prefix) {
				json_prefix = json_object_new_array();
				json_object_object_add(json_node,
						       "extendedPrefix",
						       json_prefix);
			}
			json_obj = json_object_new_object();
			show_sr_prefix(NULL, json_obj, srp);
			json_object_array_add(json_prefix, json_obj);
		} else {
			show_sr_prefix(&sbuf, NULL, srp);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(srn->ext_link, node, srl)) {
		snprintfrr(pref, 19, "%pI4/32", &srl->itf_addr);
		snprintf(sid, 22, "SR Adj. (lbl %u)", srl->sid[0]);
		itf = if_lookup_by_index(srl->nhlfe[0].ifindex, VRF_DEFAULT);
		if (json) {
			if (!json_link) {
				json_link = json_object_new_array();
				json_object_object_add(
					json_node, "extendedLink", json_link);
			}
			/* Primary Link */
			json_obj = json_object_new_object();
			json_object_string_add(json_obj, "prefix", pref);
			json_object_int_add(json_obj, "sid", srl->sid[0]);
			json_object_int_add(json_obj, "inputLabel",
					    srl->nhlfe[0].label_in);
			json_object_int_add(json_obj, "outputLabel",
					    srl->nhlfe[0].label_out);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_addf(json_obj, "nexthop", "%pI4",
						&srl->nhlfe[0].nexthop);
			json_object_array_add(json_link, json_obj);
			/* Backup Link */
			json_obj = json_object_new_object();
			snprintf(sid, 22, "SR Adj. (lbl %u)", srl->sid[1]);
			json_object_string_add(json_obj, "prefix", pref);
			json_object_int_add(json_obj, "sid", srl->sid[1]);
			json_object_int_add(json_obj, "inputLabel",
					    srl->nhlfe[1].label_in);
			json_object_int_add(json_obj, "outputLabel",
					    srl->nhlfe[1].label_out);
			json_object_string_add(json_obj, "interface",
					       itf ? itf->name : "-");
			json_object_string_addf(json_obj, "nexthop", "%pI4",
						&srl->nhlfe[1].nexthop);
			json_object_array_add(json_link, json_obj);
		} else {
			sbuf_push(&sbuf, 0, "%18s  %21s  %20s  %9s  %15s\n",
				  pref, sid,
				  sr_op2str(op, 32, srl->nhlfe[0].label_in,
					    srl->nhlfe[0].label_out),
				  itf ? itf->name : "-",
				  inet_ntop(AF_INET, &srl->nhlfe[0].nexthop,
					    buf, sizeof(buf)));
			snprintf(sid, 22, "SR Adj. (lbl %u)", srl->sid[1]);
			sbuf_push(&sbuf, 0, "%18s  %21s  %20s  %9s  %15s\n",
				  pref, sid,
				  sr_op2str(op, 32, srl->nhlfe[1].label_in,
					    srl->nhlfe[1].label_out),
				  itf ? itf->name : "-",
				  inet_ntop(AF_INET, &srl->nhlfe[1].nexthop,
					  buf, sizeof(buf)));
		}
	}
	if (json)
		json_object_array_add(json, json_node);
	else
		vty_out(vty, "%s\n", sbuf_buf(&sbuf));

	sbuf_free(&sbuf);
}

static void show_vty_srdb(struct hash_bucket *bucket, void *args)
{
	struct vty *vty = (struct vty *)args;
	struct sr_node *srn = (struct sr_node *)bucket->data;

	show_sr_node(vty, NULL, srn);
}

static void show_json_srdb(struct hash_bucket *bucket, void *args)
{
	struct json_object *json = (struct json_object *)args;
	struct sr_node *srn = (struct sr_node *)bucket->data;

	show_sr_node(NULL, json, srn);
}

DEFUN (show_ip_opsf_srdb,
       show_ip_ospf_srdb_cmd,
       "show ip ospf database segment-routing [adv-router A.B.C.D|self-originate] [json]",
       SHOW_STR
       IP_STR
       OSPF_STR
       "Database summary\n"
       "Show Segment Routing Data Base\n"
       "Advertising SR node\n"
       "Advertising SR node ID (as an IP address)\n"
       "Self-originated SR node\n"
       JSON_STR)
{
	int idx = 0;
	struct in_addr rid;
	struct sr_node *srn;
	bool uj = use_json(argc, argv);
	json_object *json = NULL, *json_node_array = NULL;

	if (OspfSR.status == SR_OFF) {
		vty_out(vty, "Segment Routing is disabled on this router\n");
		return CMD_WARNING;
	}

	if (uj) {
		json = json_object_new_object();
		json_node_array = json_object_new_array();
		json_object_string_addf(json, "srdbID", "%pI4",
					&OspfSR.self->adv_router);
		json_object_object_add(json, "srNodes", json_node_array);
	} else {
		vty_out(vty,
			"\n\t\tOSPF Segment Routing database for ID %pI4\n\n",
			&OspfSR.self->adv_router);
	}

	if (argv_find(argv, argc, "self-originate", &idx)) {
		srn = OspfSR.self;
		show_sr_node(vty, json_node_array, srn);
		if (uj)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &rid)) {
			vty_out(vty, "Specified Router ID %s is invalid\n",
				argv[idx]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		/* Get the SR Node from the SRDB */
		srn = (struct sr_node *)hash_lookup(OspfSR.neighbors,
						    (void *)&rid);
		show_sr_node(vty, json_node_array, srn);
		if (uj)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	/* No parameters have been provided, Iterate through all the SRDB */
	if (uj) {
		hash_iterate(OspfSR.neighbors, (void (*)(struct hash_bucket *,
							 void *))show_json_srdb,
			     (void *)json_node_array);
		vty_json(vty, json);
	} else {
		hash_iterate(OspfSR.neighbors, (void (*)(struct hash_bucket *,
							 void *))show_vty_srdb,
			     (void *)vty);
	}
	return CMD_SUCCESS;
}

/* Install new CLI commands */
void ospf_sr_register_vty(void)
{
	install_element(VIEW_NODE, &show_ip_ospf_srdb_cmd);

	install_element(OSPF_NODE, &ospf_sr_enable_cmd);
	install_element(OSPF_NODE, &no_ospf_sr_enable_cmd);
	install_element(OSPF_NODE, &sr_global_label_range_cmd);
	install_element(OSPF_NODE, &no_sr_global_label_range_cmd);
	install_element(OSPF_NODE, &sr_node_msd_cmd);
	install_element(OSPF_NODE, &no_sr_node_msd_cmd);
	install_element(OSPF_NODE, &sr_prefix_sid_cmd);
	install_element(OSPF_NODE, &no_sr_prefix_sid_cmd);
}
