// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of Segment Routing over IPv6 (SRv6) for IS-IS
 * as per RFC 9352
 * https://datatracker.ietf.org/doc/html/rfc9352
 *
 * Copyright (C) 2023 Carmine Scarpitta - University of Rome Tor Vergata
 */

#include <zebra.h>

#include "srv6.h"
#include "termtable.h"
#include "lib/lib_errors.h"

#include "isisd/isisd.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_route.h"
#include "isisd/isis_srv6.h"
#include "isisd/isis_zebra.h"

/* Local variables and functions */
DEFINE_MTYPE_STATIC(ISISD, ISIS_SRV6_SID, "ISIS SRv6 Segment ID");
DEFINE_MTYPE_STATIC(ISISD, ISIS_SRV6_INFO, "ISIS SRv6 information");

/**
 * Fill in SRv6 SID Structure Sub-Sub-TLV with information from an SRv6 SID.
 *
 * @param sid				    SRv6 SID configuration
 * @param structure_subsubtlv	SRv6 SID Structure Sub-Sub-TLV to be updated
 */
void isis_srv6_sid_structure2subsubtlv(
	const struct isis_srv6_sid *sid,
	struct isis_srv6_sid_structure_subsubtlv *structure_subsubtlv)
{
	/* Set Locator Block length */
	structure_subsubtlv->loc_block_len = sid->structure.loc_block_len;

	/* Set Locator Node length */
	structure_subsubtlv->loc_node_len = sid->structure.loc_node_len;

	/* Set Function length */
	structure_subsubtlv->func_len = sid->structure.func_len;

	/* Set Argument length */
	structure_subsubtlv->arg_len = sid->structure.arg_len;
}

/**
 * Fill in SRv6 End SID Sub-TLV with information from an SRv6 SID.
 *
 * @param sid	      SRv6 SID configuration
 * @param sid_subtlv  SRv6 End SID Sub-TLV to be updated
 */
void isis_srv6_end_sid2subtlv(const struct isis_srv6_sid *sid,
			      struct isis_srv6_end_sid_subtlv *sid_subtlv)
{
	/* Set SRv6 SID flags */
	sid_subtlv->flags = sid->flags;

	/* Set SRv6 SID behavior */
	sid_subtlv->behavior = sid->behavior;

	/* Set SRv6 SID value */
	sid_subtlv->sid = sid->sid;
}

/**
 * Fill in SRv6 Locator TLV with information from an SRv6 locator.
 *
 * @param loc	     SRv6 Locator configuration
 * @param loc_tlv    SRv6 Locator TLV to be updated
 */
void isis_srv6_locator2tlv(const struct isis_srv6_locator *loc,
			   struct isis_srv6_locator_tlv *loc_tlv)
{
	/* Set SRv6 Locator metric */
	loc_tlv->metric = loc->metric;

	/* Set SRv6 Locator flags */
	loc_tlv->flags = loc->flags;

	/* Set SRv6 Locator algorithm */
	loc_tlv->algorithm = loc->algorithm;

	/* Set SRv6 Locator prefix */
	loc_tlv->prefix = loc->prefix;
}

/**
 * Unset the SRv6 locator for a given IS-IS area.
 *
 * @param area	IS-IS area
 *
 * @result True on success, False otherwise
 */
bool isis_srv6_locator_unset(struct isis_area *area)
{
	int ret;
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;
	struct isis_srv6_sid *sid;
	struct srv6_adjacency *sra;

	if (strncmp(area->srv6db.config.srv6_locator_name, "",
		    sizeof(area->srv6db.config.srv6_locator_name)) == 0) {
		sr_debug("SRv6 locator not set");
		return true;
	}

	/* Delete SRv6 SIDs */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_sids, node, nnode, sid)) {
		sr_debug(
			"Deleting SRv6 SID (locator %s, sid %pI6) from IS-IS area %s",
			area->srv6db.config.srv6_locator_name, &sid->sid,
			area->area_tag);

		/* Uninstall the SRv6 SID from the forwarding plane through
		 * Zebra */
		isis_zebra_srv6_sid_uninstall(area, sid);

		listnode_delete(area->srv6db.srv6_sids, sid);
		isis_srv6_sid_free(sid);
	}

	/* Uninstall all local Adjacency-SIDs. */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_endx_sids, node, nnode, sra))
		srv6_endx_sid_del(sra);

	/* Inform Zebra that we are releasing the SRv6 locator */
	ret = isis_zebra_srv6_manager_release_locator_chunk(
		area->srv6db.config.srv6_locator_name);
	if (ret < 0)
		return false;

	/* Delete chunks */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_locator_chunks, node, nnode,
			       chunk)) {
		sr_debug(
			"Releasing chunk of locator %s (prefix %pFX) for IS-IS area %s",
			area->srv6db.config.srv6_locator_name, &chunk->prefix,
			area->area_tag);

		listnode_delete(area->srv6db.srv6_locator_chunks, chunk);
		srv6_locator_chunk_free(&chunk);
	}

	/* Clear locator name */
	memset(area->srv6db.config.srv6_locator_name, 0,
	       sizeof(area->srv6db.config.srv6_locator_name));

	/* Regenerate LSPs to advertise that the SRv6 locator no longer exists
	 */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return true;
}

/**
 * Set the interface used to install SRv6 SIDs into the data plane.
 *
 * @param area	IS-IS area
 */
void isis_srv6_interface_set(struct isis_area *area, const char *ifname)
{
	struct listnode *node;
	struct isis_srv6_sid *sid;

	if (!ifname)
		return;

	if (!strncmp(ifname, area->srv6db.config.srv6_ifname, IF_NAMESIZE)) {
		/* The interface has not changed, nothing to do */
		return;
	}

	sr_debug("SRv6 interface for IS-IS area %s changed (old interface: %s, new interface: %s)", area->area_tag, area->srv6db.config.srv6_ifname, ifname);

	/* Walk through all SIDs and uninstall them from the data plane */
	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, node, sid)) {
		sr_debug("Uninstalling SID %pI6 from the data plane", &sid->sid);
		isis_zebra_srv6_sid_uninstall(area, sid);
	}

	strlcpy(area->srv6db.config.srv6_ifname, ifname, sizeof(area->srv6db.config.srv6_ifname));

	if (!if_lookup_by_name(area->srv6db.config.srv6_ifname, VRF_DEFAULT)) {
		sr_debug("Interface %s not yet exist in data plane, deferring SIDs installation until it's created", area->srv6db.config.srv6_ifname);
		return;
	}

	/* Walk through all SIDs and re-install them into the data plane with the newly configured interface */
	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, node, sid)) {
		sr_debug("Installing SID %pI6 from the data plane", &sid->sid);
		isis_zebra_srv6_sid_install(area, sid);
	}
}

/**
 * Encode SID function in the SRv6 SID.
 *
 * @param sid
 * @param func
 * @param offset
 * @param len
 */
static void encode_sid_func(struct in6_addr *sid, uint32_t func, uint8_t offset,
			    uint8_t len)
{
	for (uint8_t idx = 0; idx < len; idx++) {
		uint8_t tidx = offset + idx;
		sid->s6_addr[tidx / 8] &= ~(0x1 << (7 - tidx % 8));
		if (func >> (len - 1 - idx) & 0x1)
			sid->s6_addr[tidx / 8] |= 0x1 << (7 - tidx % 8);
	}
}

static bool sid_exist(struct isis_area *area, const struct in6_addr *sid)
{
	struct listnode *node;
	struct isis_srv6_sid *s;
	struct srv6_adjacency *sra;

	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, node, s))
		if (sid_same(&s->sid, sid))
			return true;
	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_endx_sids, node, sra))
		if (sid_same(&sra->sid, sid))
			return true;
	return false;
}

/**
 * Request a SID from the SRv6 locator.
 *
 * @param area		IS-IS area
 * @param chunk		SRv6 locator chunk
 * @param sid_func	The FUNCTION part of the SID to be allocated (a negative
 * number will allocate the first available SID)
 *
 * @return	First available SID on success or in6addr_any if the SRv6
 * locator chunk is full
 */
static struct in6_addr
srv6_locator_request_sid(struct isis_area *area,
			 struct srv6_locator_chunk *chunk, int sid_func)
{
	struct in6_addr sid;
	uint8_t offset = 0;
	uint8_t func_len = 0;
	uint32_t func_max;
	bool allocated = false;

	if (!area || !chunk)
		return in6addr_any;

	sr_debug("ISIS-SRv6 (%s): requested new SID from locator %s",
		 area->area_tag, chunk->locator_name);

	/* Let's build the SID, step by step. A SID has the following structure
	(defined in RFC 8986): LOCATOR:FUNCTION:ARGUMENT.*/

	/* First, we encode the LOCATOR in the L most significant bits. */
	sid = chunk->prefix.prefix;

	/* The next part of the SID is the FUNCTION. Let's compute the length
	 * and the offset of the FUNCTION in the SID */
	func_len = chunk->function_bits_length;
	offset = chunk->block_bits_length + chunk->node_bits_length;

	/* Then, encode the FUNCTION */
	if (sid_func >= 0) {
		/* SID FUNCTION has been specified. We need to allocate a SID
		 * with the requested FUNCTION. */
		encode_sid_func(&sid, sid_func, offset, func_len);
		if (sid_exist(area, &sid)) {
			zlog_warn(
				"ISIS-SRv6 (%s): the requested SID %pI6 is already used",
				area->area_tag, &sid);
			return sid;
		}
		allocated = true;
	} else {
		/* SID FUNCTION not specified. We need to choose a FUNCTION that
		 * is not already used. So let's iterate through all possible
		 * functions and get the first available one. */
		func_max = (1 << func_len) - 1;
		for (uint32_t func = 1; func < func_max; func++) {
			encode_sid_func(&sid, func, offset, func_len);
			if (sid_exist(area, &sid))
				continue;
			allocated = true;
			break;
		}
	}

	if (!allocated) {
		/* We ran out of available SIDs */
		zlog_warn("ISIS-SRv6 (%s): no SIDs available in locator %s",
			  area->area_tag, chunk->locator_name);
		return in6addr_any;
	}

	sr_debug("ISIS-SRv6 (%s): allocating new SID %pI6", area->area_tag,
		 &sid);

	return sid;
}

/**
 * Allocate an SRv6 SID from an SRv6 locator.
 *
 * @param area		IS-IS area
 * @param chunk		SRv6 locator chunk
 * @param behavior	SRv6 Endpoint Behavior bound to the SID
 *
 * @result the allocated SID on success, NULL otherwise
 */
struct isis_srv6_sid *
isis_srv6_sid_alloc(struct isis_area *area, struct srv6_locator_chunk *chunk,
		    enum srv6_endpoint_behavior_codepoint behavior,
		    int sid_func)
{
	struct isis_srv6_sid *sid = NULL;

	if (!area || !chunk)
		return NULL;

	sid = XCALLOC(MTYPE_ISIS_SRV6_SID, sizeof(struct isis_srv6_sid));

	sid->sid = srv6_locator_request_sid(area, chunk, sid_func);
	if (IPV6_ADDR_SAME(&sid->sid, &in6addr_any)) {
		isis_srv6_sid_free(sid);
		return NULL;
	}

	sid->behavior = behavior;
	sid->structure.loc_block_len = chunk->block_bits_length;
	sid->structure.loc_node_len = chunk->node_bits_length;
	sid->structure.func_len = chunk->function_bits_length;
	sid->structure.arg_len = chunk->argument_bits_length;
	sid->locator = chunk;
	sid->area = area;

	return sid;
}

void isis_srv6_sid_free(struct isis_srv6_sid *sid)
{
	XFREE(MTYPE_ISIS_SRV6_SID, sid);
}

/**
 * Delete all backup SRv6 End.X SIDs.
 *
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
void isis_area_delete_backup_srv6_endx_sids(struct isis_area *area, int level)
{
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_endx_sids, node, nnode, sra))
		if (sra->type == ISIS_SRV6_ADJ_BACKUP &&
		    (sra->adj->level & level))
			srv6_endx_sid_del(sra);
}

/* --- SRv6 End.X SID management functions ------------------- */

/**
 * Add new local End.X SID.
 *
 * @param adj	   IS-IS Adjacency
 * @param backup   True to initialize backup Adjacency SID
 * @param nexthops List of backup nexthops (for backup End.X SIDs only)
 */
void srv6_endx_sid_add_single(struct isis_adjacency *adj, bool backup,
			      struct list *nexthops)
{
	struct isis_circuit *circuit = adj->circuit;
	struct isis_area *area = circuit->area;
	struct srv6_adjacency *sra;
	struct isis_srv6_endx_sid_subtlv *adj_sid;
	struct isis_srv6_lan_endx_sid_subtlv *ladj_sid;
	struct in6_addr nexthop;
	uint8_t flags = 0;
	struct srv6_locator_chunk *chunk;
	uint32_t behavior;

	if (!area || !area->srv6db.srv6_locator_chunks ||
	    list_isempty(area->srv6db.srv6_locator_chunks))
		return;

	sr_debug("ISIS-SRv6 (%s): Add %s End.X SID", area->area_tag,
		 backup ? "Backup" : "Primary");

	/* Determine nexthop IP address */
	if (!circuit->ipv6_router || !adj->ll_ipv6_count)
		return;

	chunk = (struct srv6_locator_chunk *)listgetdata(
		listhead(area->srv6db.srv6_locator_chunks));
	if (!chunk)
		return;

	nexthop = adj->ll_ipv6_addrs[0];

	/* Prepare SRv6 End.X as per RFC9352 section #8.1 */
	if (backup)
		SET_FLAG(flags, EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG);

	if (circuit->ext == NULL)
		circuit->ext = isis_alloc_ext_subtlvs();

	behavior = (CHECK_FLAG(chunk->flags, SRV6_LOCATOR_USID))
			   ? SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID
			   : SRV6_ENDPOINT_BEHAVIOR_END_X;

	sra = XCALLOC(MTYPE_ISIS_SRV6_INFO, sizeof(*sra));
	sra->type = backup ? ISIS_SRV6_ADJ_BACKUP : ISIS_SRV6_ADJ_NORMAL;
	sra->behavior = behavior;
	sra->locator = chunk;
	sra->structure.loc_block_len = chunk->block_bits_length;
	sra->structure.loc_node_len = chunk->node_bits_length;
	sra->structure.func_len = chunk->function_bits_length;
	sra->structure.arg_len = chunk->argument_bits_length;
	sra->nexthop = nexthop;

	sra->sid = srv6_locator_request_sid(area, chunk, -1);
	if (IPV6_ADDR_SAME(&sra->sid, &in6addr_any)) {
		XFREE(MTYPE_ISIS_SRV6_INFO, sra);
		return;
	}

	switch (circuit->circ_type) {
	/* SRv6 LAN End.X SID for Broadcast interface section #8.2 */
	case CIRCUIT_T_BROADCAST:
		ladj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*ladj_sid));
		memcpy(ladj_sid->neighbor_id, adj->sysid,
		       sizeof(ladj_sid->neighbor_id));
		ladj_sid->flags = flags;
		ladj_sid->algorithm = SR_ALGORITHM_SPF;
		ladj_sid->weight = 0;
		ladj_sid->behavior = sra->behavior;
		ladj_sid->sid = sra->sid;
		ladj_sid->subsubtlvs = isis_alloc_subsubtlvs(
			ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID);
		ladj_sid->subsubtlvs->srv6_sid_structure = XCALLOC(
			MTYPE_ISIS_SUBSUBTLV,
			sizeof(*ladj_sid->subsubtlvs->srv6_sid_structure));
		ladj_sid->subsubtlvs->srv6_sid_structure->loc_block_len =
			sra->structure.loc_block_len;
		ladj_sid->subsubtlvs->srv6_sid_structure->loc_node_len =
			sra->structure.loc_node_len;
		ladj_sid->subsubtlvs->srv6_sid_structure->func_len =
			sra->structure.func_len;
		ladj_sid->subsubtlvs->srv6_sid_structure->arg_len =
			sra->structure.arg_len;
		isis_tlvs_add_srv6_lan_endx_sid(circuit->ext, ladj_sid);
		sra->u.lendx_sid = ladj_sid;
		break;
	/* SRv6 End.X SID for Point to Point interface section #8.1 */
	case CIRCUIT_T_P2P:
		adj_sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*adj_sid));
		adj_sid->flags = flags;
		adj_sid->algorithm = SR_ALGORITHM_SPF;
		adj_sid->weight = 0;
		adj_sid->behavior = sra->behavior;
		adj_sid->sid = sra->sid;
		adj_sid->subsubtlvs = isis_alloc_subsubtlvs(
			ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID);
		adj_sid->subsubtlvs->srv6_sid_structure = XCALLOC(
			MTYPE_ISIS_SUBSUBTLV,
			sizeof(*adj_sid->subsubtlvs->srv6_sid_structure));
		adj_sid->subsubtlvs->srv6_sid_structure->loc_block_len =
			sra->structure.loc_block_len;
		adj_sid->subsubtlvs->srv6_sid_structure->loc_node_len =
			sra->structure.loc_node_len;
		adj_sid->subsubtlvs->srv6_sid_structure->func_len =
			sra->structure.func_len;
		adj_sid->subsubtlvs->srv6_sid_structure->arg_len =
			sra->structure.arg_len;
		isis_tlvs_add_srv6_endx_sid(circuit->ext, adj_sid);
		sra->u.endx_sid = adj_sid;
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	/* Add Adjacency-SID in SRDB */
	sra->adj = adj;
	listnode_add(area->srv6db.srv6_endx_sids, sra);
	listnode_add(adj->srv6_endx_sids, sra);

	isis_zebra_srv6_adj_sid_install(sra);
}

/**
 * Add Primary and Backup local SRv6 End.X SID.
 *
 * @param adj	  IS-IS Adjacency
 */
void srv6_endx_sid_add(struct isis_adjacency *adj)
{
	srv6_endx_sid_add_single(adj, false, NULL);
}

/**
 * Delete local SRv6 End.X SID.
 *
 * @param sra	SRv6 Adjacency
 */
void srv6_endx_sid_del(struct srv6_adjacency *sra)
{
	struct isis_circuit *circuit = sra->adj->circuit;
	struct isis_area *area = circuit->area;

	sr_debug("ISIS-SRv6 (%s): Delete SRv6 End.X SID", area->area_tag);

	isis_zebra_srv6_adj_sid_uninstall(sra);

	/* Release dynamic SRv6 SID and remove subTLVs */
	switch (circuit->circ_type) {
	case CIRCUIT_T_BROADCAST:
		isis_tlvs_del_srv6_lan_endx_sid(circuit->ext, sra->u.lendx_sid);
		break;
	case CIRCUIT_T_P2P:
		isis_tlvs_del_srv6_endx_sid(circuit->ext, sra->u.endx_sid);
		break;
	default:
		flog_err(EC_LIB_DEVELOPMENT, "%s: unexpected circuit type: %u",
			 __func__, circuit->circ_type);
		exit(1);
	}

	if (sra->type == ISIS_SRV6_ADJ_BACKUP && sra->backup_nexthops) {
		sra->backup_nexthops->del =
			(void (*)(void *))isis_nexthop_delete;
		list_delete(&sra->backup_nexthops);
	}

	/* Remove Adjacency-SID from the SRDB */
	listnode_delete(area->srv6db.srv6_endx_sids, sra);
	listnode_delete(sra->adj->srv6_endx_sids, sra);
	XFREE(MTYPE_ISIS_SRV6_INFO, sra);
}

/**
 * Lookup SRv6 End.X SID by type.
 *
 * @param adj	  IS-IS Adjacency
 * @param type    SRv6 End.X SID type
 */
struct srv6_adjacency *isis_srv6_endx_sid_find(struct isis_adjacency *adj,
					       enum srv6_adj_type type)
{
	struct srv6_adjacency *sra;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(adj->srv6_endx_sids, node, sra))
		if (sra->type == type)
			return sra;

	return NULL;
}

/**
 * Remove all SRv6 End.X SIDs associated to an adjacency that is going down.
 *
 * @param adj	IS-IS Adjacency
 *
 * @return	0
 */
static int srv6_adj_state_change(struct isis_adjacency *adj)
{
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;

	if (!adj->circuit->area->srv6db.config.enabled)
		return 0;

	if (adj->adj_state == ISIS_ADJ_UP)
		return 0;

	for (ALL_LIST_ELEMENTS(adj->srv6_endx_sids, node, nnode, sra))
		srv6_endx_sid_del(sra);

	return 0;
}

/**
 * When IS-IS Adjacency got one or more IPv6 addresses, add new
 * IPv6 address to corresponding SRv6 End.X SID accordingly.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 * @param global  Indicate if it concerns the Local or Global IPv6 addresses
 *
 * @return	  0
 */
static int srv6_adj_ip_enabled(struct isis_adjacency *adj, int family,
			       bool global)
{
	if (!adj->circuit->area->srv6db.config.enabled || global ||
	    family != AF_INET6)
		return 0;

	srv6_endx_sid_add(adj);

	return 0;
}

/**
 * When IS-IS Adjacency doesn't have any IPv6 addresses anymore,
 * delete the corresponding SRv6 End.X SID(s) accordingly.
 *
 * @param adj	  IS-IS Adjacency
 * @param family  Inet Family (IPv4 or IPv6)
 * @param global  Indicate if it concerns the Local or Global IPv6 addresses
 *
 * @return	  0
 */
static int srv6_adj_ip_disabled(struct isis_adjacency *adj, int family,
				bool global)
{
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;

	if (!adj->circuit->area->srv6db.config.enabled || global ||
	    family != AF_INET6)
		return 0;

	for (ALL_LIST_ELEMENTS(adj->srv6_endx_sids, node, nnode, sra))
		srv6_endx_sid_del(sra);

	return 0;
}

/**
 * Show Segment Routing over IPv6 (SRv6) Node.
 *
 * @param vty	VTY output
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
static void show_node(struct vty *vty, struct isis_area *area, int level)
{
	struct isis_lsp *lsp;
	struct ttable *tt;

	vty_out(vty, " IS-IS %s SRv6-Nodes:\n\n", circuit_t2string(level));

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(
		tt,
		"System ID|Algorithm|SRH Max SL|SRH Max End Pop|SRH Max H.encaps|SRH Max End D");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	frr_each (lspdb, &area->lspdb[level - 1], lsp) {
		struct isis_router_cap *cap;

		if (!lsp->tlvs)
			continue;
		cap = lsp->tlvs->router_cap;
		if (!cap)
			continue;

		ttable_add_row(tt, "%pSY|%s|%u|%u|%u|%u", lsp->hdr.lsp_id,
			       cap->algo[0] == SR_ALGORITHM_SPF ? "SPF"
								: "S-SPF",
			       cap->srv6_msd.max_seg_left_msd,
			       cap->srv6_msd.max_end_pop_msd,
			       cap->srv6_msd.max_h_encaps_msd,
			       cap->srv6_msd.max_end_d_msd);
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	}
	ttable_del(tt);
}

DEFUN(show_srv6_node, show_srv6_node_cmd,
      "show " PROTO_NAME " segment-routing srv6 node",
      SHOW_STR
      PROTO_HELP
      "Segment-Routing\n"
      "Segment-Routing over IPv6 (SRv6)\n"
      "SRv6 node\n")
{
	struct listnode *node, *inode;
	struct isis_area *area;
	struct isis *isis;

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			vty_out(vty, "Area %s:\n",
				area->area_tag ? area->area_tag : "null");
			if (!area->srv6db.config.enabled) {
				vty_out(vty, " SRv6 is disabled\n");
				continue;
			}
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++)
				show_node(vty, area, level);
		}
	}

	return CMD_SUCCESS;
}

int isis_srv6_ifp_up_notify(struct interface *ifp)
{
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);
	struct listnode *node, *node2;
	struct isis_area *area;
	struct isis_srv6_sid *sid;

	if (!isis)
		return 0;

	/* Walk through all areas of the ISIS instance */
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		/* Skip area, if SRv6 is not enabled */
		if (!area->srv6db.config.enabled)
			continue;

		/* Skip area if the interface is not the one configured for SRv6 */
		if (strncmp(area->srv6db.config.srv6_ifname, ifp->name, IF_NAMESIZE))
			continue;

		sr_debug("Interface %s went up. Installing SIDs for area %s in data plane", ifp->name, area->area_tag);

		/* Walk through all SIDs and re-install them into the data plane with the newly configured interface */
		for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, node2, sid)) {
			sr_debug("Installing SID %pI6 from the data plane", &sid->sid);
			isis_zebra_srv6_sid_install(area, sid);
		}
	}

	return 0;
}

/**
 * IS-IS SRv6 initialization for given area.
 *
 * @param area	IS-IS area
 */
void isis_srv6_area_init(struct isis_area *area)
{
	struct isis_srv6_db *srv6db;

	if (!area)
		return;

	srv6db = &area->srv6db;

	sr_debug("ISIS-SRv6 (%s): Initialize Segment Routing SRv6 DB",
		 area->area_tag);

	/* Initialize SRv6 Data Base */
	memset(srv6db, 0, sizeof(*srv6db));
	srv6db->srv6_endx_sids = list_new();

	/* Pull defaults from the YANG module */
#ifndef FABRICD
	srv6db->config.enabled = yang_get_default_bool("%s/enabled", ISIS_SRV6);
	srv6db->config.max_seg_left_msd =
		yang_get_default_uint8("%s/msd/node-msd/max-segs-left",
				       ISIS_SRV6);
	srv6db->config.max_end_pop_msd =
		yang_get_default_uint8("%s/msd/node-msd/max-end-pop", ISIS_SRV6);
	srv6db->config.max_h_encaps_msd =
		yang_get_default_uint8("%s/msd/node-msd/max-h-encaps",
				       ISIS_SRV6);
	srv6db->config.max_end_d_msd =
		yang_get_default_uint8("%s/msd/node-msd/max-end-d", ISIS_SRV6);
	strlcpy(srv6db->config.srv6_ifname, yang_get_default_string("%s/interface", ISIS_SRV6), sizeof(srv6db->config.srv6_ifname));
#else
	srv6db->config.enabled = false;
	srv6db->config.max_seg_left_msd = ISIS_DEFAULT_SRV6_MAX_SEG_LEFT_MSD;
	srv6db->config.max_end_pop_msd = ISIS_DEFAULT_SRV6_MAX_END_POP_MSD;
	srv6db->config.max_h_encaps_msd = ISIS_DEFAULT_SRV6_MAX_H_ENCAPS_MSD;
	srv6db->config.max_end_d_msd = ISIS_DEFAULT_SRV6_MAX_END_D_MSD;
	strlcpy(srv6db->config.srv6_ifname, ISIS_DEFAULT_SRV6_IFNAME, sizeof(srv6db->config.srv6_ifname));
#endif

	/* Initialize SRv6 Locator chunks list */
	srv6db->srv6_locator_chunks = list_new();

	/* Initialize SRv6 SIDs list */
	srv6db->srv6_sids = list_new();
	srv6db->srv6_sids->del = (void (*)(void *))isis_srv6_sid_free;
}

/**
 * Terminate IS-IS SRv6 for the given area.
 *
 * @param area	IS-IS area
 */
void isis_srv6_area_term(struct isis_area *area)
{
	struct isis_srv6_db *srv6db = &area->srv6db;
	struct srv6_adjacency *sra;
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;

	sr_debug("ISIS-SRv6 (%s): Terminate SRv6", area->area_tag);

	/* Uninstall all local SRv6 End.X SIDs */
	if (area->srv6db.config.enabled)
		for (ALL_LIST_ELEMENTS(area->srv6db.srv6_endx_sids, node, nnode,
				       sra))
			srv6_endx_sid_del(sra);

	/* Free SRv6 Locator chunks list */
	for (ALL_LIST_ELEMENTS(srv6db->srv6_locator_chunks, node, nnode, chunk))
		srv6_locator_chunk_free(&chunk);
	list_delete(&srv6db->srv6_locator_chunks);

	/* Free SRv6 SIDs list */
	list_delete(&srv6db->srv6_sids);
	list_delete(&srv6db->srv6_endx_sids);
}

/**
 * IS-IS SRv6 global initialization.
 */
void isis_srv6_init(void)
{
	install_element(VIEW_NODE, &show_srv6_node_cmd);

	/* Register hooks. */
	hook_register(isis_adj_state_change_hook, srv6_adj_state_change);
	hook_register(isis_adj_ip_enabled_hook, srv6_adj_ip_enabled);
	hook_register(isis_adj_ip_disabled_hook, srv6_adj_ip_disabled);
}

/**
 * IS-IS SRv6 global terminate.
 */
void isis_srv6_term(void)
{
	/* Unregister hooks. */
	hook_unregister(isis_adj_state_change_hook, srv6_adj_state_change);
	hook_unregister(isis_adj_ip_enabled_hook, srv6_adj_ip_enabled);
	hook_unregister(isis_adj_ip_disabled_hook, srv6_adj_ip_disabled);
}
