// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of rfc2370.
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
 */

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "frrevent.h"
#include "hash.h"
#include "sockunion.h" /* for inet_aton() */
#include "printfrr.h"

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
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ri.h"
#include "ospfd/ospf_ext.h"
#include "ospfd/ospf_errors.h"

DEFINE_MTYPE_STATIC(OSPFD, OSPF_OPAQUE_FUNCTAB, "OSPF opaque function table");
DEFINE_MTYPE_STATIC(OSPFD, OPAQUE_INFO_PER_TYPE, "OSPF opaque per-type info");
DEFINE_MTYPE_STATIC(OSPFD, OPAQUE_INFO_PER_ID, "OSPF opaque per-ID info");

/*------------------------------------------------------------------------*
 * Following are initialize/terminate functions for Opaque-LSAs handling.
 *------------------------------------------------------------------------*/

#ifdef SUPPORT_OSPF_API
int ospf_apiserver_init(void);
void ospf_apiserver_term(void);
/* Init apiserver? It's disabled by default. */
int ospf_apiserver_enable;
#endif /* SUPPORT_OSPF_API */

static void ospf_opaque_register_vty(void);
static void ospf_opaque_funclist_init(void);
static void ospf_opaque_funclist_term(void);
static void free_opaque_info_per_type_del(void *val);
static void free_opaque_info_per_id(void *val);
static int ospf_opaque_lsa_install_hook(struct ospf_lsa *lsa);
static int ospf_opaque_lsa_delete_hook(struct ospf_lsa *lsa);

void ospf_opaque_init(void)
{
	ospf_opaque_register_vty();
	ospf_opaque_funclist_init();

	if (ospf_mpls_te_init() != 0)
		exit(1);

	/* Segment Routing init */
	if (ospf_sr_init() != 0)
		exit(1);

	if (ospf_router_info_init() != 0)
		exit(1);

	if (ospf_ext_init() != 0)
		exit(1);

#ifdef SUPPORT_OSPF_API
	if ((ospf_apiserver_enable) && (ospf_apiserver_init() != 0))
		exit(1);
#endif /* SUPPORT_OSPF_API */

	return;
}

void ospf_opaque_term(void)
{
	ospf_mpls_te_term();

	ospf_router_info_term();

	ospf_ext_term();

	ospf_sr_term();

#ifdef SUPPORT_OSPF_API
	ospf_apiserver_term();
#endif /* SUPPORT_OSPF_API */

	ospf_opaque_funclist_term();
	return;
}

void ospf_opaque_finish(void)
{
	ospf_mpls_te_finish();

	ospf_router_info_finish();

	ospf_ext_finish();

#ifdef SUPPORT_OSPF_API
	ospf_apiserver_term();
#endif

	ospf_sr_finish();
}

int ospf_opaque_type9_lsa_init(struct ospf_interface *oi)
{
	if (oi->opaque_lsa_self != NULL)
		list_delete(&oi->opaque_lsa_self);

	oi->opaque_lsa_self = list_new();
	oi->opaque_lsa_self->del = free_opaque_info_per_type_del;
	oi->t_opaque_lsa_self = NULL;
	return 0;
}

void ospf_opaque_type9_lsa_term(struct ospf_interface *oi)
{
	EVENT_OFF(oi->t_opaque_lsa_self);
	if (oi->opaque_lsa_self != NULL)
		list_delete(&oi->opaque_lsa_self);
	oi->opaque_lsa_self = NULL;
	return;
}

int ospf_opaque_type10_lsa_init(struct ospf_area *area)
{
	if (area->opaque_lsa_self != NULL)
		list_delete(&area->opaque_lsa_self);

	area->opaque_lsa_self = list_new();
	area->opaque_lsa_self->del = free_opaque_info_per_type_del;
	area->t_opaque_lsa_self = NULL;

#ifdef MONITOR_LSDB_CHANGE
	area->lsdb->new_lsa_hook = ospf_opaque_lsa_install_hook;
	area->lsdb->del_lsa_hook = ospf_opaque_lsa_delete_hook;
#endif /* MONITOR_LSDB_CHANGE */
	return 0;
}

void ospf_opaque_type10_lsa_term(struct ospf_area *area)
{
#ifdef MONITOR_LSDB_CHANGE
	area->lsdb->new_lsa_hook = area->lsdb->del_lsa_hook = NULL;
#endif /* MONITOR_LSDB_CHANGE */

	EVENT_OFF(area->t_opaque_lsa_self);
	if (area->opaque_lsa_self != NULL)
		list_delete(&area->opaque_lsa_self);
	return;
}

int ospf_opaque_type11_lsa_init(struct ospf *top)
{
	if (top->opaque_lsa_self != NULL)
		list_delete(&top->opaque_lsa_self);

	top->opaque_lsa_self = list_new();
	top->opaque_lsa_self->del = free_opaque_info_per_type_del;
	top->t_opaque_lsa_self = NULL;

#ifdef MONITOR_LSDB_CHANGE
	top->lsdb->new_lsa_hook = ospf_opaque_lsa_install_hook;
	top->lsdb->del_lsa_hook = ospf_opaque_lsa_delete_hook;
#endif /* MONITOR_LSDB_CHANGE */
	return 0;
}

void ospf_opaque_type11_lsa_term(struct ospf *top)
{
#ifdef MONITOR_LSDB_CHANGE
	top->lsdb->new_lsa_hook = top->lsdb->del_lsa_hook = NULL;
#endif /* MONITOR_LSDB_CHANGE */

	EVENT_OFF(top->t_opaque_lsa_self);
	if (top->opaque_lsa_self != NULL)
		list_delete(&top->opaque_lsa_self);
	return;
}

static const char *ospf_opaque_type_name(uint8_t opaque_type)
{
	const char *name = "Unknown";

	switch (opaque_type) {
	case OPAQUE_TYPE_WILDCARD: /* This is a special assignment! */
		name = "Wildcard";
		break;
	case OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA:
		name = "Traffic Engineering LSA";
		break;
	case OPAQUE_TYPE_SYCAMORE_OPTICAL_TOPOLOGY_DESC:
		name = "Sycamore optical topology description";
		break;
	case OPAQUE_TYPE_GRACE_LSA:
		name = "Grace-LSA";
		break;
	case OPAQUE_TYPE_INTER_AS_LSA:
		name = "Inter-AS TE-v2 LSA";
		break;
	case OPAQUE_TYPE_ROUTER_INFORMATION_LSA:
		name = "Router Information LSA";
		break;
	case OPAQUE_TYPE_EXTENDED_PREFIX_LSA:
		name = "Extended Prefix Opaque LSA";
		break;
	case OPAQUE_TYPE_EXTENDED_LINK_LSA:
		name = "Extended Link Opaque LSA";
		break;
	default:
		if (OPAQUE_TYPE_RANGE_UNASSIGNED(opaque_type))
			name = "Unassigned";
		else {
			uint32_t bigger_range = opaque_type;
			/*
			 * Get around type-limits warning: comparison is always
			 * true due to limited range of data type
			 */
			if (OPAQUE_TYPE_RANGE_RESERVED(bigger_range))
				name = "Private/Experimental";
		}
		break;
	}
	return name;
}

/*------------------------------------------------------------------------*
 * Following are management functions to store user specified callbacks.
 *------------------------------------------------------------------------*/

struct opaque_info_per_type; /* Forward declaration. */

static void free_opaque_info_per_type(struct opaque_info_per_type *oipt,
				      bool cleanup_owner);

struct ospf_opaque_functab {
	uint8_t opaque_type;
	uint32_t ref_count;

	int (*new_if_hook)(struct interface *ifp);
	int (*del_if_hook)(struct interface *ifp);
	void (*ism_change_hook)(struct ospf_interface *oi, int old_status);
	void (*nsm_change_hook)(struct ospf_neighbor *nbr, int old_status);
	void (*config_write_router)(struct vty *vty);
	void (*config_write_if)(struct vty *vty, struct interface *ifp);
	void (*config_write_debug)(struct vty *vty);
	void (*show_opaque_info)(struct vty *vty, struct json_object *json,
				 struct ospf_lsa *lsa);
	int (*lsa_originator)(void *arg);
	struct ospf_lsa *(*lsa_refresher)(struct ospf_lsa *lsa);
	int (*new_lsa_hook)(struct ospf_lsa *lsa);
	int (*del_lsa_hook)(struct ospf_lsa *lsa);
};

/* Handle LSA-9/10/11 altogether. */
static struct list *ospf_opaque_wildcard_funclist;
static struct list *ospf_opaque_type9_funclist;
static struct list *ospf_opaque_type10_funclist;
static struct list *ospf_opaque_type11_funclist;

static void ospf_opaque_functab_ref(struct ospf_opaque_functab *functab)
{
	functab->ref_count++;
}

static void ospf_opaque_functab_deref(struct ospf_opaque_functab *functab)
{
	assert(functab->ref_count);
	functab->ref_count--;
	if (functab->ref_count == 0)
		XFREE(MTYPE_OSPF_OPAQUE_FUNCTAB, functab);
}

static void ospf_opaque_del_functab(void *val)
{
	struct ospf_opaque_functab *functab = (struct ospf_opaque_functab *)val;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Opaque LSA functab list deletion callback type %u (%p)",
			   __func__, functab->opaque_type, functab);

	ospf_opaque_functab_deref(functab);
	return;
}

static void ospf_opaque_funclist_init(void)
{
	struct list *funclist;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Function list initialize", __func__);

	funclist = ospf_opaque_wildcard_funclist = list_new();
	funclist->del = ospf_opaque_del_functab;

	funclist = ospf_opaque_type9_funclist = list_new();
	funclist->del = ospf_opaque_del_functab;

	funclist = ospf_opaque_type10_funclist = list_new();
	funclist->del = ospf_opaque_del_functab;

	funclist = ospf_opaque_type11_funclist = list_new();
	funclist->del = ospf_opaque_del_functab;
	return;
}

static void ospf_opaque_funclist_term(void)
{
	struct list *funclist;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Function list terminate", __func__);

	funclist = ospf_opaque_wildcard_funclist;
	list_delete(&funclist);

	funclist = ospf_opaque_type9_funclist;
	list_delete(&funclist);

	funclist = ospf_opaque_type10_funclist;
	list_delete(&funclist);

	funclist = ospf_opaque_type11_funclist;
	list_delete(&funclist);
	return;
}

static struct list *ospf_get_opaque_funclist(uint8_t lsa_type)
{
	struct list *funclist = NULL;

	switch (lsa_type) {
	case OPAQUE_TYPE_WILDCARD:
		/* XXX
		 * This is an ugly trick to handle type-9/10/11 LSA altogether.
		 * Yes, "OPAQUE_TYPE_WILDCARD (value 0)" is not an LSA-type, nor
		 * an officially assigned opaque-type.
		 * Though it is possible that the value might be officially used
		 * in the future, we use it internally as a special label, for
		 * now.
		 */
		funclist = ospf_opaque_wildcard_funclist;
		break;
	case OSPF_OPAQUE_LINK_LSA:
		funclist = ospf_opaque_type9_funclist;
		break;
	case OSPF_OPAQUE_AREA_LSA:
		funclist = ospf_opaque_type10_funclist;
		break;
	case OSPF_OPAQUE_AS_LSA:
		funclist = ospf_opaque_type11_funclist;
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, lsa_type);
		break;
	}
	return funclist;
}

/* XXX: such a huge argument list can /not/ be healthy... */
int ospf_register_opaque_functab(
	uint8_t lsa_type, uint8_t opaque_type,
	int (*new_if_hook)(struct interface *ifp),
	int (*del_if_hook)(struct interface *ifp),
	void (*ism_change_hook)(struct ospf_interface *oi, int old_status),
	void (*nsm_change_hook)(struct ospf_neighbor *nbr, int old_status),
	void (*config_write_router)(struct vty *vty),
	void (*config_write_if)(struct vty *vty, struct interface *ifp),
	void (*config_write_debug)(struct vty *vty),
	void (*show_opaque_info)(struct vty *vty, struct json_object *json,
				 struct ospf_lsa *lsa),
	int (*lsa_originator)(void *arg),
	struct ospf_lsa *(*lsa_refresher)(struct ospf_lsa *lsa),
	int (*new_lsa_hook)(struct ospf_lsa *lsa),
	int (*del_lsa_hook)(struct ospf_lsa *lsa))
{
	struct list *funclist;
	struct ospf_opaque_functab *new;

	if ((funclist = ospf_get_opaque_funclist(lsa_type)) == NULL)
		return -1;

	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->opaque_type == opaque_type) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("%s: Opaque LSA functab found type %u, (%p)",
					   __func__, functab->opaque_type,
					   functab);
			break;
		}

	if (functab == NULL)
		new = XCALLOC(MTYPE_OSPF_OPAQUE_FUNCTAB,
			      sizeof(struct ospf_opaque_functab));
	else {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: Re-register Opaque LSA type %u, opaque type %u, (%p)",
				   __func__, lsa_type, opaque_type, functab);
		return 0;
	}

	new->opaque_type = opaque_type;
	new->new_if_hook = new_if_hook;
	new->del_if_hook = del_if_hook;
	new->ism_change_hook = ism_change_hook;
	new->nsm_change_hook = nsm_change_hook;
	new->config_write_router = config_write_router;
	new->config_write_if = config_write_if;
	new->config_write_debug = config_write_debug;
	new->show_opaque_info = show_opaque_info;
	new->lsa_originator = lsa_originator;
	new->lsa_refresher = lsa_refresher;
	new->new_lsa_hook = new_lsa_hook;
	new->del_lsa_hook = del_lsa_hook;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Register Opaque LSA type %u, opaque type %u, (%p)",
			   __func__, lsa_type, opaque_type, new);

	listnode_add(funclist, new);
	ospf_opaque_functab_ref(new);

	return 0;
}

void ospf_delete_opaque_functab(uint8_t lsa_type, uint8_t opaque_type)
{
	struct list *funclist;
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;

	if ((funclist = ospf_get_opaque_funclist(lsa_type)) != NULL)
		for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab)) {
			if (functab->opaque_type == opaque_type) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug("%s: Delete Opaque functab LSA type %u, opaque type %u, (%p)",
						   __func__, lsa_type,
						   opaque_type, functab);

				/* Dequeue listnode entry from the function table
				 * list coreesponding to the opaque LSA type.
				 * Note that the list deletion callback frees
				 * the functab entry memory.
				 */
				listnode_delete(funclist, functab);
				ospf_opaque_functab_deref(functab);
				break;
			}
		}

	return;
}

static struct ospf_opaque_functab *
ospf_opaque_functab_lookup(struct ospf_lsa *lsa)
{
	struct list *funclist;
	struct listnode *node;
	struct ospf_opaque_functab *functab;
	uint8_t key = GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));

	if ((funclist = ospf_get_opaque_funclist(lsa->data->type)) != NULL)
		for (ALL_LIST_ELEMENTS_RO(funclist, node, functab))
			if (functab->opaque_type == key)
				return functab;

	return NULL;
}

/*------------------------------------------------------------------------*
 * Following are management functions for self-originated LSA entries.
 *------------------------------------------------------------------------*/

/*
 * Opaque-LSA control information per opaque-type.
 * Single Opaque-Type may have multiple instances; each of them will be
 * identified by their opaque-id.
 */
struct opaque_info_per_type {
	uint8_t lsa_type;
	uint8_t opaque_type;

	enum { PROC_NORMAL, PROC_SUSPEND } status;

	/*
	 * Thread for (re-)origination scheduling for this opaque-type.
	 *
	 * Initial origination of Opaque-LSAs is controlled by generic
	 * Opaque-LSA handling module so that same opaque-type entries are
	 * called all at once when certain conditions are met.
	 * However, there might be cases that some Opaque-LSA clients need
	 * to (re-)originate their own Opaque-LSAs out-of-sync with others.
	 * This thread is prepared for that specific purpose.
	 */
	struct event *t_opaque_lsa_self;

	/*
	 * Backpointer to an "owner" which is LSA-type dependent.
	 *   type-9:  struct ospf_interface
	 *   type-10: struct ospf_area
	 *   type-11: struct ospf
	 */
	void *owner;

	/* Collection of callback functions for this opaque-type. */
	struct ospf_opaque_functab *functab;

	/* List of Opaque-LSA control information per opaque-id. */
	struct list *id_list;
};

/* Opaque-LSA control information per opaque-id. */
struct opaque_info_per_id {
	uint32_t opaque_id;

	/* Thread for refresh/flush scheduling for this opaque-type/id. */
	struct event *t_opaque_lsa_self;

	/* Backpointer to Opaque-LSA control information per opaque-type. */
	struct opaque_info_per_type *opqctl_type;

	/* Here comes an actual Opaque-LSA entry for this opaque-type/id. */
	struct ospf_lsa *lsa;
};

static struct opaque_info_per_type *
register_opaque_info_per_type(struct ospf_opaque_functab *functab,
			      struct ospf_lsa *new);
static struct opaque_info_per_type *
lookup_opaque_info_by_type(struct ospf_lsa *lsa);
static struct opaque_info_per_id *
register_opaque_info_per_id(struct opaque_info_per_type *oipt,
			    struct ospf_lsa *new);
static struct opaque_info_per_id *
lookup_opaque_info_by_id(struct opaque_info_per_type *oipt,
			 struct ospf_lsa *lsa);
static struct opaque_info_per_id *register_opaque_lsa(struct ospf_lsa *new);


static struct opaque_info_per_type *
register_opaque_info_per_type(struct ospf_opaque_functab *functab,
			      struct ospf_lsa *new)
{
	struct ospf *top;
	struct opaque_info_per_type *oipt;

	oipt = XCALLOC(MTYPE_OPAQUE_INFO_PER_TYPE,
		       sizeof(struct opaque_info_per_type));

	switch (new->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
		oipt->owner = new->oi;
		listnode_add(new->oi->opaque_lsa_self, oipt);
		break;
	case OSPF_OPAQUE_AREA_LSA:
		oipt->owner = new->area;
		listnode_add(new->area->opaque_lsa_self, oipt);
		break;
	case OSPF_OPAQUE_AS_LSA:
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (new->area != NULL && (top = new->area->ospf) == NULL) {
			free_opaque_info_per_type(oipt, true);
			oipt = NULL;
			goto out; /* This case may not exist. */
		}
		oipt->owner = top;
		listnode_add(top->opaque_lsa_self, oipt);
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, new->data->type);
		free_opaque_info_per_type(oipt, true);
		oipt = NULL;
		goto out; /* This case may not exist. */
	}

	oipt->lsa_type = new->data->type;
	oipt->opaque_type = GET_OPAQUE_TYPE(ntohl(new->data->id.s_addr));
	oipt->status = PROC_NORMAL;
	oipt->functab = functab;
	ospf_opaque_functab_ref(functab);
	oipt->id_list = list_new();
	oipt->id_list->del = free_opaque_info_per_id;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Register Opaque info-per-type LSA type %u, opaque type %u, (%p), Functab (%p)",
			   __func__, oipt->lsa_type, oipt->opaque_type, oipt,
			   oipt->functab);

out:
	return oipt;
}

static void free_opaque_info_per_type(struct opaque_info_per_type *oipt,
				      bool cleanup_owner)
{
	struct opaque_info_per_id *oipi;
	struct ospf_lsa *lsa;
	struct listnode *node, *nnode;
	struct list *l;

	/* Control information per opaque-id may still exist. */
	for (ALL_LIST_ELEMENTS(oipt->id_list, node, nnode, oipi)) {
		if ((lsa = oipi->lsa) == NULL)
			continue;
		if (IS_LSA_MAXAGE(lsa))
			continue;
		ospf_opaque_lsa_flush_schedule(lsa);
	}

	EVENT_OFF(oipt->t_opaque_lsa_self);
	list_delete(&oipt->id_list);
	if (cleanup_owner) {
		/* Remove from its owner's self-originated LSA list. */
		switch (oipt->lsa_type) {
		case OSPF_OPAQUE_LINK_LSA:
			l = ((struct ospf_interface *)oipt->owner)
				    ->opaque_lsa_self;
			break;
		case OSPF_OPAQUE_AREA_LSA:
			l = ((struct ospf_area *)oipt->owner)->opaque_lsa_self;
			break;
		case OSPF_OPAQUE_AS_LSA:
			l = ((struct ospf *)oipt->owner)->opaque_lsa_self;
			break;
		default:
			flog_warn(
				EC_OSPF_LSA_UNEXPECTED,
				"free_opaque_info_owner: Unexpected LSA-type(%u)",
				oipt->lsa_type);
			return;
		}
		listnode_delete(l, oipt);
	}

	if (oipt->functab)
		ospf_opaque_functab_deref(oipt->functab);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: Free Opaque info-per-type LSA type %u, opaque type %u, (%p), Functab (%p)",
			   __func__, oipt->lsa_type, oipt->opaque_type, oipt,
			   oipt->functab);

	XFREE(MTYPE_OPAQUE_INFO_PER_TYPE, oipt);
	return;
}

static void free_opaque_info_per_type_del(void *val)
{
	free_opaque_info_per_type((struct opaque_info_per_type *)val, false);
}

static struct opaque_info_per_type *
lookup_opaque_info_by_type(struct ospf_lsa *lsa)
{
	struct ospf *top;
	struct ospf_area *area;
	struct ospf_interface *oi;
	struct list *listtop = NULL;
	struct listnode *node, *nnode;
	struct opaque_info_per_type *oipt = NULL;
	uint8_t key = GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));

	switch (lsa->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
		if ((oi = lsa->oi) != NULL)
			listtop = oi->opaque_lsa_self;
		else
			flog_warn(
				EC_OSPF_LSA,
				"Type-9 Opaque-LSA: Reference to OI is missing?");
		break;
	case OSPF_OPAQUE_AREA_LSA:
		if ((area = lsa->area) != NULL)
			listtop = area->opaque_lsa_self;
		else
			flog_warn(
				EC_OSPF_LSA,
				"Type-10 Opaque-LSA: Reference to AREA is missing?");
		break;
	case OSPF_OPAQUE_AS_LSA:
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if ((area = lsa->area) != NULL && (top = area->ospf) == NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"Type-11 Opaque-LSA: Reference to OSPF is missing?");
			break; /* Unlikely to happen. */
		}
		listtop = top->opaque_lsa_self;
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, lsa->data->type);
		break;
	}

	if (listtop != NULL)
		for (ALL_LIST_ELEMENTS(listtop, node, nnode, oipt))
			if (oipt->opaque_type == key)
				return oipt;

	return NULL;
}

static struct opaque_info_per_id *
register_opaque_info_per_id(struct opaque_info_per_type *oipt,
			    struct ospf_lsa *new)
{
	struct opaque_info_per_id *oipi;

	oipi = XCALLOC(MTYPE_OPAQUE_INFO_PER_ID,
		       sizeof(struct opaque_info_per_id));

	oipi->opaque_id = GET_OPAQUE_ID(ntohl(new->data->id.s_addr));
	oipi->opqctl_type = oipt;
	oipi->lsa = ospf_lsa_lock(new);

	listnode_add(oipt->id_list, oipi);

	return oipi;
}

static void free_opaque_info_per_id(void *val)
{
	struct opaque_info_per_id *oipi = (struct opaque_info_per_id *)val;

	EVENT_OFF(oipi->t_opaque_lsa_self);
	if (oipi->lsa != NULL)
		ospf_lsa_unlock(&oipi->lsa);
	XFREE(MTYPE_OPAQUE_INFO_PER_ID, oipi);
	return;
}

static struct opaque_info_per_id *
lookup_opaque_info_by_id(struct opaque_info_per_type *oipt,
			 struct ospf_lsa *lsa)
{
	struct listnode *node, *nnode;
	struct opaque_info_per_id *oipi;
	uint32_t key = GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr));

	for (ALL_LIST_ELEMENTS(oipt->id_list, node, nnode, oipi))
		if (oipi->opaque_id == key)
			return oipi;

	return NULL;
}

static struct opaque_info_per_id *register_opaque_lsa(struct ospf_lsa *new)
{
	struct ospf_opaque_functab *functab;
	struct opaque_info_per_type *oipt;
	struct opaque_info_per_id *oipi = NULL;

	if ((functab = ospf_opaque_functab_lookup(new)) == NULL)
		goto out;

	if ((oipt = lookup_opaque_info_by_type(new)) == NULL
	    && (oipt = register_opaque_info_per_type(functab, new)) == NULL)
		goto out;

	if ((oipi = register_opaque_info_per_id(oipt, new)) == NULL)
		goto out;

out:
	return oipi;
}

int ospf_opaque_is_owned(struct ospf_lsa *lsa)
{
	struct opaque_info_per_type *oipt = lookup_opaque_info_by_type(lsa);

	return (oipt != NULL && lookup_opaque_info_by_id(oipt, lsa) != NULL);
}

/*
 * Cleanup Link-Local LSAs assocaited with an interface that is being deleted.
 * Since these LSAs are stored in the area link state database (LSDB) as opposed
 * to a separate per-interface, they must be deleted from the area database.
 * Since their flooding scope is solely the deleted OSPF interface, there is no
 * need to attempt to flush them from the routing domain. For link local LSAs
 * originated via the OSPF server API, LSA deletion before interface deletion
 * is required so that the callback can access the OSPF interface address.
 */
void ospf_opaque_type9_lsa_if_cleanup(struct ospf_interface *oi)
{
	struct route_node *rn;
	struct ospf_lsdb *lsdb;
	struct ospf_lsa *lsa;

	lsdb = oi->area->lsdb;
	LSDB_LOOP (OPAQUE_LINK_LSDB(oi->area), rn, lsa)
		/*
		 * While the LSA shouldn't be referenced on any LSA
		 * lists since the flooding scoped is confined to the
		 * interface being deleted, clear the pointer to the
		 * deleted interface to avoid references and set the
		 * age to MAXAGE to avoid flush processing when the LSA
		 * is removed from the interface opaque info list.
		 */
		if (lsa->oi == oi) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug("Delete Type-9 Opaque-LSA on interface delete: [opaque-type=%u, opaque-id=%x]",
					   GET_OPAQUE_TYPE(
						   ntohl(lsa->data->id.s_addr)),
					   GET_OPAQUE_ID(ntohl(
						   lsa->data->id.s_addr)));
			ospf_lsdb_delete(lsdb, lsa);
			lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
			lsa->oi = NULL;
			ospf_lsa_discard(lsa);
		}
}

/*------------------------------------------------------------------------*
 * Following are (vty) configuration functions for Opaque-LSAs handling.
 *------------------------------------------------------------------------*/

DEFUN (capability_opaque,
       capability_opaque_cmd,
       "capability opaque",
       "Enable specific OSPF feature\n"
       "Opaque LSA\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	/* Check that OSPF is using default VRF */
	if (ospf->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"OSPF Opaque LSA is only supported in default VRF\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Turn on the "master switch" of opaque-lsa capability. */
	if (!CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("Opaque capability: OFF -> ON");

		SET_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE);
		ospf_renegotiate_optional_capabilities(ospf);
	}
	return CMD_SUCCESS;
}

DEFUN (ospf_opaque,
       ospf_opaque_cmd,
       "ospf opaque-lsa",
       "OSPF specific commands\n"
       "Enable the Opaque-LSA capability (rfc2370)\n")
{
	return capability_opaque(self, vty, argc, argv);
}

DEFUN (no_capability_opaque,
       no_capability_opaque_cmd,
       "no capability opaque",
       NO_STR
       "Enable specific OSPF feature\n"
       "Opaque LSA\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	/* Turn off the "master switch" of opaque-lsa capability. */
	if (CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("Opaque capability: ON -> OFF");

		UNSET_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE);
		ospf_renegotiate_optional_capabilities(ospf);
	}
	return CMD_SUCCESS;
}

DEFUN (no_ospf_opaque,
       no_ospf_opaque_cmd,
       "no ospf opaque-lsa",
       NO_STR
       "OSPF specific commands\n"
       "Enable the Opaque-LSA capability (rfc2370)\n")
{
	return no_capability_opaque(self, vty, argc, argv);
}

static void ospf_opaque_register_vty(void)
{
	install_element(OSPF_NODE, &capability_opaque_cmd);
	install_element(OSPF_NODE, &no_capability_opaque_cmd);
	install_element(OSPF_NODE, &ospf_opaque_cmd);
	install_element(OSPF_NODE, &no_ospf_opaque_cmd);
	return;
}

/*------------------------------------------------------------------------*
 * Following are collection of user-registered function callers.
 *------------------------------------------------------------------------*/

static int opaque_lsa_new_if_callback(struct list *funclist,
				      struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;
	int rc = -1;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->new_if_hook != NULL)
			if ((*functab->new_if_hook)(ifp) != 0)
				goto out;
	rc = 0;
out:
	return rc;
}

static int opaque_lsa_del_if_callback(struct list *funclist,
				      struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;
	int rc = -1;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->del_if_hook != NULL)
			if ((*functab->del_if_hook)(ifp) != 0)
				goto out;
	rc = 0;
out:
	return rc;
}

static void opaque_lsa_ism_change_callback(struct list *funclist,
					   struct ospf_interface *oi,
					   int old_status)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->ism_change_hook != NULL)
			(*functab->ism_change_hook)(oi, old_status);

	return;
}

static void opaque_lsa_nsm_change_callback(struct list *funclist,
					   struct ospf_neighbor *nbr,
					   int old_status)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->nsm_change_hook != NULL)
			(*functab->nsm_change_hook)(nbr, old_status);
	return;
}

static void opaque_lsa_config_write_router_callback(struct list *funclist,
						    struct vty *vty)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->config_write_router != NULL)
			(*functab->config_write_router)(vty);
	return;
}

static void opaque_lsa_config_write_if_callback(struct list *funclist,
						struct vty *vty,
						struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->config_write_if != NULL)
			(*functab->config_write_if)(vty, ifp);
	return;
}

static void opaque_lsa_config_write_debug_callback(struct list *funclist,
						   struct vty *vty)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->config_write_debug != NULL)
			(*functab->config_write_debug)(vty);
	return;
}

static int opaque_lsa_originate_callback(struct list *funclist,
					 void *lsa_type_dependent)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;
	int rc = -1;

	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->lsa_originator != NULL)
			if ((*functab->lsa_originator)(lsa_type_dependent) != 0)
				goto out;
	rc = 0;
out:
	return rc;
}

static int new_lsa_callback(struct list *funclist, struct ospf_lsa *lsa)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;
	int rc = -1;

	/* This function handles ALL types of LSAs, not only opaque ones. */
	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->new_lsa_hook != NULL)
			if ((*functab->new_lsa_hook)(lsa) != 0)
				goto out;
	rc = 0;
out:
	return rc;
}

static int del_lsa_callback(struct list *funclist, struct ospf_lsa *lsa)
{
	struct listnode *node, *nnode;
	struct ospf_opaque_functab *functab;
	int rc = -1;

	/* This function handles ALL types of LSAs, not only opaque ones. */
	for (ALL_LIST_ELEMENTS(funclist, node, nnode, functab))
		if (functab->del_lsa_hook != NULL)
			if ((*functab->del_lsa_hook)(lsa) != 0)
				goto out;
	rc = 0;
out:
	return rc;
}

/*------------------------------------------------------------------------*
 * Following are glue functions to call Opaque-LSA specific processing.
 *------------------------------------------------------------------------*/

int ospf_opaque_new_if(struct interface *ifp)
{
	struct list *funclist;
	int rc = -1;

	funclist = ospf_opaque_wildcard_funclist;
	if (opaque_lsa_new_if_callback(funclist, ifp) != 0)
		goto out;

	funclist = ospf_opaque_type9_funclist;
	if (opaque_lsa_new_if_callback(funclist, ifp) != 0)
		goto out;

	funclist = ospf_opaque_type10_funclist;
	if (opaque_lsa_new_if_callback(funclist, ifp) != 0)
		goto out;

	funclist = ospf_opaque_type11_funclist;
	if (opaque_lsa_new_if_callback(funclist, ifp) != 0)
		goto out;

	rc = 0;
out:
	return rc;
}

int ospf_opaque_del_if(struct interface *ifp)
{
	struct list *funclist;
	int rc = -1;

	funclist = ospf_opaque_wildcard_funclist;
	if (opaque_lsa_del_if_callback(funclist, ifp) != 0)
		goto out;

	funclist = ospf_opaque_type9_funclist;
	if (opaque_lsa_del_if_callback(funclist, ifp) != 0)
		goto out;

	funclist = ospf_opaque_type10_funclist;
	if (opaque_lsa_del_if_callback(funclist, ifp) != 0)
		goto out;

	funclist = ospf_opaque_type11_funclist;
	if (opaque_lsa_del_if_callback(funclist, ifp) != 0)
		goto out;

	rc = 0;
out:
	return rc;
}

void ospf_opaque_ism_change(struct ospf_interface *oi, int old_status)
{
	struct list *funclist;

	funclist = ospf_opaque_wildcard_funclist;
	opaque_lsa_ism_change_callback(funclist, oi, old_status);

	funclist = ospf_opaque_type9_funclist;
	opaque_lsa_ism_change_callback(funclist, oi, old_status);

	funclist = ospf_opaque_type10_funclist;
	opaque_lsa_ism_change_callback(funclist, oi, old_status);

	funclist = ospf_opaque_type11_funclist;
	opaque_lsa_ism_change_callback(funclist, oi, old_status);

	return;
}

void ospf_opaque_nsm_change(struct ospf_neighbor *nbr, int old_state)
{
	struct ospf *top;
	struct list *funclist;

	if ((top = oi_to_top(nbr->oi)) == NULL)
		goto out;

	if (old_state != NSM_Full && nbr->state == NSM_Full) {
		if (CHECK_FLAG(nbr->options, OSPF_OPTION_O)) {
			if (!CHECK_FLAG(top->opaque,
					OPAQUE_OPERATION_READY_BIT)) {
				if (IS_DEBUG_OSPF_EVENT)
					zlog_debug(
						"Opaque-LSA: Now get operational!");

				SET_FLAG(top->opaque,
					 OPAQUE_OPERATION_READY_BIT);
			}

			ospf_opaque_lsa_originate_schedule(nbr->oi, NULL);
		}
	} else if (old_state == NSM_Full && nbr->state != NSM_Full) {
#ifdef NOTYET
/*
 * If no more opaque-capable full-state neighbor remains in the
 * flooding scope which corresponds to Opaque-LSA type, periodic
 * LS flooding should be stopped.
 */
#endif /* NOTYET */
		;
	}

	funclist = ospf_opaque_wildcard_funclist;
	opaque_lsa_nsm_change_callback(funclist, nbr, old_state);

	funclist = ospf_opaque_type9_funclist;
	opaque_lsa_nsm_change_callback(funclist, nbr, old_state);

	funclist = ospf_opaque_type10_funclist;
	opaque_lsa_nsm_change_callback(funclist, nbr, old_state);

	funclist = ospf_opaque_type11_funclist;
	opaque_lsa_nsm_change_callback(funclist, nbr, old_state);

out:
	return;
}

void ospf_opaque_config_write_router(struct vty *vty, struct ospf *ospf)
{
	struct list *funclist;

	if (CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE))
		vty_out(vty, " capability opaque\n");

	funclist = ospf_opaque_wildcard_funclist;
	opaque_lsa_config_write_router_callback(funclist, vty);

	funclist = ospf_opaque_type9_funclist;
	opaque_lsa_config_write_router_callback(funclist, vty);

	funclist = ospf_opaque_type10_funclist;
	opaque_lsa_config_write_router_callback(funclist, vty);

	funclist = ospf_opaque_type11_funclist;
	opaque_lsa_config_write_router_callback(funclist, vty);

	return;
}

void ospf_opaque_config_write_if(struct vty *vty, struct interface *ifp)
{
	struct list *funclist;

	funclist = ospf_opaque_wildcard_funclist;
	opaque_lsa_config_write_if_callback(funclist, vty, ifp);

	funclist = ospf_opaque_type9_funclist;
	opaque_lsa_config_write_if_callback(funclist, vty, ifp);

	funclist = ospf_opaque_type10_funclist;
	opaque_lsa_config_write_if_callback(funclist, vty, ifp);

	funclist = ospf_opaque_type11_funclist;
	opaque_lsa_config_write_if_callback(funclist, vty, ifp);

	return;
}

void ospf_opaque_config_write_debug(struct vty *vty)
{
	struct list *funclist;

	funclist = ospf_opaque_wildcard_funclist;
	opaque_lsa_config_write_debug_callback(funclist, vty);

	funclist = ospf_opaque_type9_funclist;
	opaque_lsa_config_write_debug_callback(funclist, vty);

	funclist = ospf_opaque_type10_funclist;
	opaque_lsa_config_write_debug_callback(funclist, vty);

	funclist = ospf_opaque_type11_funclist;
	opaque_lsa_config_write_debug_callback(funclist, vty);

	return;
}

void show_opaque_info_detail(struct vty *vty, struct ospf_lsa *lsa,
			     json_object *json)
{
	struct lsa_header *lsah = lsa->data;
	uint32_t lsid = ntohl(lsah->id.s_addr);
	uint8_t opaque_type = GET_OPAQUE_TYPE(lsid);
	uint32_t opaque_id = GET_OPAQUE_ID(lsid);
	struct ospf_opaque_functab *functab;
	json_object *jopaque = NULL;
	int len, lenValid;

	/* Switch output functionality by vty address. */
	if (vty != NULL) {
		if (!json) {
			vty_out(vty, "  Opaque-Type %u (%s)\n", opaque_type,
				ospf_opaque_type_name(opaque_type));
			vty_out(vty, "  Opaque-ID   0x%x\n", opaque_id);

			vty_out(vty, "  Opaque-Info: %u octets of data%s\n",
				ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE,
				VALID_OPAQUE_INFO_LEN(lsah)
					? ""
					: "(Invalid length?)");
		} else {
			json_object_string_add(
				json, "opaqueType",
				ospf_opaque_type_name(opaque_type));
			json_object_int_add(json, "opaqueId", opaque_id);
			len = ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE;
			json_object_int_add(json, "opaqueLength", len);
			lenValid = VALID_OPAQUE_INFO_LEN(lsah);
			json_object_boolean_add(json, "opaqueLengthValid",
						lenValid);
			if (lenValid) {
				jopaque = json_object_new_object();
				json_object_object_add(json, "opaqueValues",
						       jopaque);
			}
		}
	} else {
		zlog_debug("    Opaque-Type %u (%s)", opaque_type,
			   ospf_opaque_type_name(opaque_type));
		zlog_debug("    Opaque-ID   0x%x", opaque_id);

		zlog_debug("    Opaque-Info: %u octets of data%s",
			   ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE,
			   VALID_OPAQUE_INFO_LEN(lsah) ? ""
						       : "(Invalid length?)");
	}

	/* Call individual output functions. */
	if ((functab = ospf_opaque_functab_lookup(lsa)) != NULL)
		if (functab->show_opaque_info != NULL)
			(*functab->show_opaque_info)(vty, jopaque, lsa);

	return;
}

void ospf_opaque_lsa_dump(struct stream *s, uint16_t length)
{
	struct ospf_lsa lsa = {};

	lsa.data = (struct lsa_header *)stream_pnt(s);
	lsa.size = length;
	show_opaque_info_detail(NULL, &lsa, NULL);
	return;
}

static int ospf_opaque_lsa_install_hook(struct ospf_lsa *lsa)
{
	struct list *funclist;
	int rc = -1;

	/*
	 * Some Opaque-LSA user may want to monitor every LSA installation
	 * into the LSDB, regardless with target LSA type.
	 */
	funclist = ospf_opaque_wildcard_funclist;
	if (new_lsa_callback(funclist, lsa) != 0)
		goto out;

	funclist = ospf_opaque_type9_funclist;
	if (new_lsa_callback(funclist, lsa) != 0)
		goto out;

	funclist = ospf_opaque_type10_funclist;
	if (new_lsa_callback(funclist, lsa) != 0)
		goto out;

	funclist = ospf_opaque_type11_funclist;
	if (new_lsa_callback(funclist, lsa) != 0)
		goto out;

	rc = 0;
out:
	return rc;
}

static int ospf_opaque_lsa_delete_hook(struct ospf_lsa *lsa)
{
	struct list *funclist;
	int rc = -1;

	/*
	 * Some Opaque-LSA user may want to monitor every LSA deletion
	 * from the LSDB, regardless with target LSA type.
	 */
	funclist = ospf_opaque_wildcard_funclist;
	if (del_lsa_callback(funclist, lsa) != 0)
		goto out;

	funclist = ospf_opaque_type9_funclist;
	if (del_lsa_callback(funclist, lsa) != 0)
		goto out;

	funclist = ospf_opaque_type10_funclist;
	if (del_lsa_callback(funclist, lsa) != 0)
		goto out;

	funclist = ospf_opaque_type11_funclist;
	if (del_lsa_callback(funclist, lsa) != 0)
		goto out;

	rc = 0;
out:
	return rc;
}

/*------------------------------------------------------------------------*
 * Following are Opaque-LSA origination/refresh management functions.
 *------------------------------------------------------------------------*/

static void ospf_opaque_type9_lsa_originate(struct event *t);
static void ospf_opaque_type10_lsa_originate(struct event *t);
static void ospf_opaque_type11_lsa_originate(struct event *t);
static void ospf_opaque_lsa_reoriginate_resume(struct list *listtop, void *arg);

void ospf_opaque_lsa_originate_schedule(struct ospf_interface *oi, int *delay0)
{
	struct ospf *top;
	struct ospf_area *area;
	struct listnode *node, *nnode;
	struct opaque_info_per_type *oipt;
	int delay = 0;

	if ((top = oi_to_top(oi)) == NULL || (area = oi->area) == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: Invalid argument?", __func__);
		return;
	}

	/* It may not a right time to schedule origination now. */
	if (!CHECK_FLAG(top->opaque, OPAQUE_OPERATION_READY_BIT)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: Not operational.", __func__);
		return; /* This is not an error. */
	}

	if (delay0 != NULL)
		delay = *delay0;

	/*
	 * There might be some entries that have been waiting for triggering
	 * of per opaque-type re-origination get resumed.
	 */
	ospf_opaque_lsa_reoriginate_resume(oi->opaque_lsa_self, (void *)oi);
	ospf_opaque_lsa_reoriginate_resume(area->opaque_lsa_self, (void *)area);
	ospf_opaque_lsa_reoriginate_resume(top->opaque_lsa_self, (void *)top);

	/*
	 * Now, schedule origination of all Opaque-LSAs per opaque-type.
	 */
	if (!list_isempty(ospf_opaque_type9_funclist)
	    && list_isempty(oi->opaque_lsa_self)
	    && oi->t_opaque_lsa_self == NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Schedule Type-9 Opaque-LSA origination in %d ms later.",
				delay);
		oi->t_opaque_lsa_self = NULL;
		event_add_timer_msec(master, ospf_opaque_type9_lsa_originate,
				     oi, delay, &oi->t_opaque_lsa_self);
		delay += top->min_ls_interval;
	}

	if (!list_isempty(ospf_opaque_type10_funclist)
	    && list_isempty(area->opaque_lsa_self)
	    && area->t_opaque_lsa_self == NULL) {
		/*
		 * One AREA may contain multiple OIs, but above 2nd and 3rd
		 * conditions prevent from scheduling the originate function
		 * again and again.
		 */
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Schedule Type-10 Opaque-LSA origination in %d ms later.",
				delay);
		area->t_opaque_lsa_self = NULL;
		event_add_timer_msec(master, ospf_opaque_type10_lsa_originate,
				     area, delay, &area->t_opaque_lsa_self);
		delay += top->min_ls_interval;
	}

	if (!list_isempty(ospf_opaque_type11_funclist)
	    && list_isempty(top->opaque_lsa_self)
	    && top->t_opaque_lsa_self == NULL) {
		/*
		 * One OSPF may contain multiple AREAs, but above 2nd and 3rd
		 * conditions prevent from scheduling the originate function
		 * again and again.
		 */
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Schedule Type-11 Opaque-LSA origination in %d ms later.",
				delay);
		top->t_opaque_lsa_self = NULL;
		event_add_timer_msec(master, ospf_opaque_type11_lsa_originate,
				     top, delay, &top->t_opaque_lsa_self);
		delay += top->min_ls_interval;
	}

	/*
	 * Following section treats a special situation that this node's
	 * opaque capability has changed as "ON -> OFF -> ON".
	 */
	if (!list_isempty(ospf_opaque_type9_funclist)
	    && !list_isempty(oi->opaque_lsa_self)) {
		for (ALL_LIST_ELEMENTS(oi->opaque_lsa_self, node, nnode,
				       oipt)) {
			/*
			 * removed the test for
			 *   (! list_isempty (oipt->id_list))   * Handler is
			 * already active. *
			 * because opaque cababilities ON -> OFF -> ON result in
			 * list_isempty (oipt->id_list)
			 * not being empty.
			 */
			if (oipt->t_opaque_lsa_self
				    != NULL /* Waiting for a thread call. */
			    || oipt->status == PROC_SUSPEND) /* Cannot
								originate
								now. */
				continue;

			ospf_opaque_lsa_reoriginate_schedule(
				(void *)oi, OSPF_OPAQUE_LINK_LSA,
				oipt->opaque_type);
		}
	}

	if (!list_isempty(ospf_opaque_type10_funclist)
	    && !list_isempty(area->opaque_lsa_self)) {
		for (ALL_LIST_ELEMENTS(area->opaque_lsa_self, node, nnode,
				       oipt)) {
			/*
			 * removed the test for
			 *   (! list_isempty (oipt->id_list))   * Handler is
			 * already active. *
			 * because opaque cababilities ON -> OFF -> ON result in
			 * list_isempty (oipt->id_list)
			 * not being empty.
			 */
			if (oipt->t_opaque_lsa_self
				    != NULL /* Waiting for a thread call. */
			    || oipt->status == PROC_SUSPEND) /* Cannot
								originate
								now. */
				continue;

			ospf_opaque_lsa_reoriginate_schedule(
				(void *)area, OSPF_OPAQUE_AREA_LSA,
				oipt->opaque_type);
		}
	}

	if (!list_isempty(ospf_opaque_type11_funclist)
	    && !list_isempty(top->opaque_lsa_self)) {
		for (ALL_LIST_ELEMENTS(top->opaque_lsa_self, node, nnode,
				       oipt)) {
			/*
			 * removed the test for
			 *   (! list_isempty (oipt->id_list))   * Handler is
			 * already active. *
			 * because opaque cababilities ON -> OFF -> ON result in
			 * list_isempty (oipt->id_list)
			 * not being empty.
			 */
			if (oipt->t_opaque_lsa_self
				    != NULL /* Waiting for a thread call. */
			    || oipt->status == PROC_SUSPEND) /* Cannot
								originate
								now. */
				continue;

			ospf_opaque_lsa_reoriginate_schedule((void *)top,
							     OSPF_OPAQUE_AS_LSA,
							     oipt->opaque_type);
		}
	}

	if (delay0 != NULL)
		*delay0 = delay;
}

static void ospf_opaque_type9_lsa_originate(struct event *t)
{
	struct ospf_interface *oi;

	oi = EVENT_ARG(t);
	oi->t_opaque_lsa_self = NULL;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Timer[Type9-LSA]: Originate Opaque-LSAs for OI %s",
			   IF_NAME(oi));

	opaque_lsa_originate_callback(ospf_opaque_type9_funclist, oi);
}

static void ospf_opaque_type10_lsa_originate(struct event *t)
{
	struct ospf_area *area;

	area = EVENT_ARG(t);
	area->t_opaque_lsa_self = NULL;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Timer[Type10-LSA]: Originate Opaque-LSAs for Area %pI4",
			&area->area_id);

	opaque_lsa_originate_callback(ospf_opaque_type10_funclist, area);
}

static void ospf_opaque_type11_lsa_originate(struct event *t)
{
	struct ospf *top;

	top = EVENT_ARG(t);
	top->t_opaque_lsa_self = NULL;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Timer[Type11-LSA]: Originate AS-External Opaque-LSAs");

	opaque_lsa_originate_callback(ospf_opaque_type11_funclist, top);
}

static void ospf_opaque_lsa_reoriginate_resume(struct list *listtop, void *arg)
{
	struct listnode *node, *nnode;
	struct opaque_info_per_type *oipt;
	struct ospf_opaque_functab *functab;

	if (listtop == NULL)
		goto out;

	/*
	 * Pickup oipt entries those which in SUSPEND status, and give
	 * them a chance to start re-origination now.
	 */
	for (ALL_LIST_ELEMENTS(listtop, node, nnode, oipt)) {
		if (oipt->status != PROC_SUSPEND)
			continue;

		oipt->status = PROC_NORMAL;

		if ((functab = oipt->functab) == NULL
		    || functab->lsa_originator == NULL)
			continue;

		if ((*functab->lsa_originator)(arg) != 0) {
			flog_warn(EC_OSPF_LSA, "%s: Failed (opaque-type=%u)",
				  __func__, oipt->opaque_type);
			continue;
		}
	}

out:
	return;
}

struct ospf_lsa *ospf_opaque_lsa_install(struct ospf_lsa *lsa, int rt_recalc)
{
	struct ospf_lsa *new = NULL;
	struct opaque_info_per_type *oipt;
	struct opaque_info_per_id *oipi;
	struct ospf *top;

	/* Don't take "rt_recalc" into consideration for now. */ /* XXX */

	if (!IS_LSA_SELF(lsa)) {
		new = lsa; /* Don't touch this LSA. */
		goto out;
	}

	if (IS_DEBUG_OSPF(lsa, LSA_INSTALL))
		zlog_debug(
			"Install Type-%u Opaque-LSA: [opaque-type=%u, opaque-id=%x]",
			lsa->data->type,
			GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)),
			GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr)));

	/* Replace the existing lsa with the new one. */
	if ((oipt = lookup_opaque_info_by_type(lsa)) != NULL
	    && (oipi = lookup_opaque_info_by_id(oipt, lsa)) != NULL) {
		ospf_lsa_unlock(&oipi->lsa);
		oipi->lsa = ospf_lsa_lock(lsa);
	}
	/* Register the new lsa entry */
	else if (register_opaque_lsa(lsa) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: register_opaque_lsa() ?", __func__);
		goto out;
	}

	/*
	 * Make use of a common mechanism (ospf_lsa_refresh_walker)
	 * for periodic refresh of self-originated Opaque-LSAs.
	 */
	switch (lsa->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
		if ((top = oi_to_top(lsa->oi)) == NULL) {
			/* Above conditions must have passed. */
			flog_warn(EC_OSPF_LSA, "%s: Something wrong?",
				  __func__);
			goto out;
		}
		break;
	case OSPF_OPAQUE_AREA_LSA:
		if (lsa->area == NULL || (top = lsa->area->ospf) == NULL) {
			/* Above conditions must have passed. */
			flog_warn(EC_OSPF_LSA, "%s: Something wrong?",
				  __func__);
			goto out;
		}
		break;
	case OSPF_OPAQUE_AS_LSA:
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (lsa->area != NULL && (top = lsa->area->ospf) == NULL) {
			/* Above conditions must have passed. */
			flog_warn(EC_OSPF_LSA, "%s: Something wrong?",
				  __func__);
			goto out;
		}
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, lsa->data->type);
		goto out;
	}

	ospf_refresher_register_lsa(top, lsa);
	new = lsa;

out:
	return new;
}

struct ospf_lsa *ospf_opaque_lsa_refresh(struct ospf_lsa *lsa)
{
	struct ospf *ospf;
	struct ospf_opaque_functab *functab;
	struct ospf_lsa *new = NULL;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	if ((functab = ospf_opaque_functab_lookup(lsa)) == NULL
	    || functab->lsa_refresher == NULL) {
		/*
		 * Though this LSA seems to have originated on this node, the
		 * handling module for this "lsa-type and opaque-type" was
		 * already deleted sometime ago.
		 * Anyway, this node still has a responsibility to flush this
		 * LSA from the routing domain.
		 */
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("LSA[Type%d:%pI4]: Flush stray Opaque-LSA",
				   lsa->data->type, &lsa->data->id);

		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
		ospf_lsa_flush(ospf, lsa);
	} else
		new = (*functab->lsa_refresher)(lsa);

	return new;
}

/*------------------------------------------------------------------------*
 * Following are re-origination/refresh/flush operations of Opaque-LSAs,
 * triggered by external interventions (vty session, signaling, etc).
 *------------------------------------------------------------------------*/

#define OSPF_OPAQUE_TIMER_ON(T, F, L, V)                                       \
	event_add_timer_msec(master, (F), (L), (V), &(T))

static struct ospf_lsa *pseudo_lsa(struct ospf_interface *oi,
				   struct ospf_area *area, uint8_t lsa_type,
				   uint8_t opaque_type);
static void ospf_opaque_type9_lsa_reoriginate_timer(struct event *t);
static void ospf_opaque_type10_lsa_reoriginate_timer(struct event *t);
static void ospf_opaque_type11_lsa_reoriginate_timer(struct event *t);
static void ospf_opaque_lsa_refresh_timer(struct event *t);

void ospf_opaque_lsa_reoriginate_schedule(void *lsa_type_dependent,
					  uint8_t lsa_type, uint8_t opaque_type)
{
	struct ospf *top = NULL;
	struct ospf_area dummy, *area = NULL;
	struct ospf_interface *oi = NULL;

	struct ospf_lsa *lsa;
	struct opaque_info_per_type *oipt;
	void (*func)(struct event * t) = NULL;
	int delay;

	switch (lsa_type) {
	case OSPF_OPAQUE_LINK_LSA:
		if ((oi = (struct ospf_interface *)lsa_type_dependent)
		    == NULL) {
			flog_warn(EC_OSPF_LSA,
				  "%s: Type-9 Opaque-LSA: Invalid parameter?",
				  __func__);
			goto out;
		}
		if ((top = oi_to_top(oi)) == NULL) {
			flog_warn(EC_OSPF_LSA, "%s: OI(%s) -> TOP?", __func__,
				  IF_NAME(oi));
			goto out;
		}
		if (!list_isempty(ospf_opaque_type9_funclist)
		    && list_isempty(oi->opaque_lsa_self)
		    && oi->t_opaque_lsa_self != NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"Type-9 Opaque-LSA (opaque_type=%u): Common origination for OI(%s) has already started",
				opaque_type, IF_NAME(oi));
			goto out;
		}
		func = ospf_opaque_type9_lsa_reoriginate_timer;
		break;
	case OSPF_OPAQUE_AREA_LSA:
		if ((area = (struct ospf_area *)lsa_type_dependent) == NULL) {
			flog_warn(EC_OSPF_LSA,
				  "%s: Type-10 Opaque-LSA: Invalid parameter?",
				  __func__);
			goto out;
		}
		if ((top = area->ospf) == NULL) {
			flog_warn(EC_OSPF_LSA, "%s: AREA(%pI4) -> TOP?",
				  __func__, &area->area_id);
			goto out;
		}
		if (!list_isempty(ospf_opaque_type10_funclist)
		    && list_isempty(area->opaque_lsa_self)
		    && area->t_opaque_lsa_self != NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"Type-10 Opaque-LSA (opaque_type=%u): Common origination for AREA(%pI4) has already started",
				opaque_type, &area->area_id);
			goto out;
		}
		func = ospf_opaque_type10_lsa_reoriginate_timer;
		break;
	case OSPF_OPAQUE_AS_LSA:
		if ((top = (struct ospf *)lsa_type_dependent) == NULL) {
			flog_warn(EC_OSPF_LSA,
				  "%s: Type-11 Opaque-LSA: Invalid parameter?",
				  __func__);
			goto out;
		}
		if (!list_isempty(ospf_opaque_type11_funclist)
		    && list_isempty(top->opaque_lsa_self)
		    && top->t_opaque_lsa_self != NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"Type-11 Opaque-LSA (opaque_type=%u): Common origination has already started",
				opaque_type);
			goto out;
		}

		/* Fake "area" to pass "ospf" to a lookup function later. */
		dummy.ospf = top;
		area = &dummy;

		func = ospf_opaque_type11_lsa_reoriginate_timer;
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, lsa_type);
		goto out;
	}

	/* It may not a right time to schedule reorigination now. */
	if (!CHECK_FLAG(top->opaque, OPAQUE_OPERATION_READY_BIT)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug("%s: Not operational.", __func__);
		goto out; /* This is not an error. */
	}

	/* Generate a dummy lsa to be passed for a lookup function. */
	lsa = pseudo_lsa(oi, area, lsa_type, opaque_type);
	lsa->vrf_id = VRF_DEFAULT;

	if ((oipt = lookup_opaque_info_by_type(lsa)) == NULL) {
		struct ospf_opaque_functab *functab;
		if ((functab = ospf_opaque_functab_lookup(lsa)) == NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"%s: No associated function?: lsa_type(%u), opaque_type(%u)",
				__func__, lsa_type, opaque_type);
			goto out;
		}
		if ((oipt = register_opaque_info_per_type(functab, lsa))
		    == NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"%s: Cannot get a control info?: lsa_type(%u), opaque_type(%u)",
				__func__, lsa_type, opaque_type);
			goto out;
		}
	}

	if (oipt->t_opaque_lsa_self != NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Type-%u Opaque-LSA has already scheduled to RE-ORIGINATE: [opaque-type=%u]",
				lsa_type,
				GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)));
		goto out;
	}

	/*
	 * Different from initial origination time, in which various conditions
	 * (opaque capability, neighbor status etc) are assured by caller of
	 * the originating function "ospf_opaque_lsa_originate_schedule ()",
	 * it is highly possible that these conditions might not be satisfied
	 * at the time of re-origination function is to be called.
	 */
	delay = top->min_ls_interval; /* XXX */

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Schedule Type-%u Opaque-LSA to RE-ORIGINATE in %d ms later: [opaque-type=%u]",
			lsa_type, delay,
			GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)));

	OSPF_OPAQUE_TIMER_ON(oipt->t_opaque_lsa_self, func, oipt, delay);

out:
	return;
}

static struct ospf_lsa *pseudo_lsa(struct ospf_interface *oi,
				   struct ospf_area *area, uint8_t lsa_type,
				   uint8_t opaque_type)
{
	static struct ospf_lsa lsa = {0};
	static struct lsa_header lsah = {0};
	uint32_t tmp;

	lsa.oi = oi;
	lsa.area = area;
	lsa.data = &lsah;
	lsa.vrf_id = VRF_DEFAULT;

	lsah.type = lsa_type;
	tmp = SET_OPAQUE_LSID(opaque_type, 0); /* Opaque-ID is unused here. */
	lsah.id.s_addr = htonl(tmp);

	return &lsa;
}

static void ospf_opaque_type9_lsa_reoriginate_timer(struct event *t)
{
	struct opaque_info_per_type *oipt;
	struct ospf_opaque_functab *functab;
	struct ospf *top;
	struct ospf_interface *oi;

	oipt = EVENT_ARG(t);

	if ((functab = oipt->functab) == NULL
	    || functab->lsa_originator == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: No associated function?", __func__);
		return;
	}

	oi = (struct ospf_interface *)oipt->owner;
	if ((top = oi_to_top(oi)) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: Something wrong?", __func__);
		return;
	}

	if (!CHECK_FLAG(top->config, OSPF_OPAQUE_CAPABLE) ||
	    !OSPF_IF_PARAM(oi, opaque_capable) || !ospf_if_is_enable(oi) ||
	    ospf_nbr_count_opaque_capable(oi) == 0) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Suspend re-origination of Type-9 Opaque-LSAs (opaque-type=%u) for a while...",
				oipt->opaque_type);

		oipt->status = PROC_SUSPEND;
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Timer[Type9-LSA]: Re-originate Opaque-LSAs (opaque-type=%u) for OI (%s)",
			oipt->opaque_type, IF_NAME(oi));

	(*functab->lsa_originator)(oi);
}

static void ospf_opaque_type10_lsa_reoriginate_timer(struct event *t)
{
	struct opaque_info_per_type *oipt;
	struct ospf_opaque_functab *functab;
	struct listnode *node, *nnode;
	struct ospf *top;
	struct ospf_area *area;
	struct ospf_interface *oi;
	int n;

	oipt = EVENT_ARG(t);

	if ((functab = oipt->functab) == NULL
	    || functab->lsa_originator == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: No associated function?", __func__);
		return;
	}

	area = (struct ospf_area *)oipt->owner;
	if (area == NULL || (top = area->ospf) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: Something wrong?", __func__);
		return;
	}

	/* There must be at least one "opaque-capable, full-state" neighbor. */
	n = 0;
	for (ALL_LIST_ELEMENTS(area->oiflist, node, nnode, oi)) {
		if ((n = ospf_nbr_count_opaque_capable(oi)) > 0)
			break;
	}

	if (n == 0 || !CHECK_FLAG(top->config, OSPF_OPAQUE_CAPABLE)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Suspend re-origination of Type-10 Opaque-LSAs (opaque-type=%u) for a while...",
				oipt->opaque_type);

		oipt->status = PROC_SUSPEND;
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Timer[Type10-LSA]: Re-originate Opaque-LSAs (opaque-type=%u) for Area %pI4",
			oipt->opaque_type, &area->area_id);

	(*functab->lsa_originator)(area);
}

static void ospf_opaque_type11_lsa_reoriginate_timer(struct event *t)
{
	struct opaque_info_per_type *oipt;
	struct ospf_opaque_functab *functab;
	struct ospf *top;

	oipt = EVENT_ARG(t);

	if ((functab = oipt->functab) == NULL
	    || functab->lsa_originator == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: No associated function?", __func__);
		return;
	}

	if ((top = (struct ospf *)oipt->owner) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: Something wrong?", __func__);
		return;
	}

	if (!CHECK_FLAG(top->config, OSPF_OPAQUE_CAPABLE)) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Suspend re-origination of Type-11 Opaque-LSAs (opaque-type=%u) for a while...",
				oipt->opaque_type);

		oipt->status = PROC_SUSPEND;
		return;
	}

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Timer[Type11-LSA]: Re-originate Opaque-LSAs (opaque-type=%u).",
			oipt->opaque_type);

	(*functab->lsa_originator)(top);
}

void ospf_opaque_lsa_refresh_schedule(struct ospf_lsa *lsa0)
{
	struct opaque_info_per_type *oipt;
	struct opaque_info_per_id *oipi;
	struct ospf_lsa *lsa;
	struct ospf *ospf;
	int delay;

	if ((oipt = lookup_opaque_info_by_type(lsa0)) == NULL
	    || (oipi = lookup_opaque_info_by_id(oipt, lsa0)) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: Invalid parameter?", __func__);
		goto out;
	}

	/* Given "lsa0" and current "oipi->lsa" may different, but harmless. */
	if ((lsa = oipi->lsa) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: Something wrong?", __func__);
		goto out;
	}

	if (oipi->t_opaque_lsa_self != NULL) {
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Type-%u Opaque-LSA has already scheduled to REFRESH: [opaque-type=%u, opaque-id=%x]",
				lsa->data->type,
				GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)),
				GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr)));
		goto out;
	}

	if ((lsa0->area != NULL) && (lsa0->area->ospf != NULL))
		ospf = lsa0->area->ospf;
	else
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Delete this lsa from neighbor retransmit-list. */
	switch (lsa->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
	case OSPF_OPAQUE_AREA_LSA:
		ospf_ls_retransmit_delete_nbr_area(lsa->area, lsa);
		break;
	case OSPF_OPAQUE_AS_LSA:
		ospf_ls_retransmit_delete_nbr_as(ospf, lsa);
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, lsa->data->type);
		goto out;
	}

	delay = ospf_lsa_refresh_delay(ospf, lsa);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Schedule Type-%u Opaque-LSA to REFRESH in %d msec later: [opaque-type=%u, opaque-id=%x]",
			   lsa->data->type, delay, GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)),
			   GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr)));

	OSPF_OPAQUE_TIMER_ON(oipi->t_opaque_lsa_self, ospf_opaque_lsa_refresh_timer, oipi, delay);
out:
	return;
}

static void ospf_opaque_lsa_refresh_timer(struct event *t)
{
	struct opaque_info_per_id *oipi;
	struct ospf_opaque_functab *functab;
	struct ospf_lsa *lsa;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("Timer[Opaque-LSA]: (Opaque-LSA Refresh expire)");

	oipi = EVENT_ARG(t);

	if ((lsa = oipi->lsa) != NULL)
		if ((functab = oipi->opqctl_type->functab) != NULL)
			if (functab->lsa_refresher != NULL)
				(*functab->lsa_refresher)(lsa);
}

void ospf_opaque_lsa_flush_schedule(struct ospf_lsa *lsa0)
{
	struct opaque_info_per_type *oipt;
	struct opaque_info_per_id *oipi;
	struct ospf_lsa *lsa;
	struct ospf *top;

	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	if ((oipt = lookup_opaque_info_by_type(lsa0)) == NULL
	    || (oipi = lookup_opaque_info_by_id(oipt, lsa0)) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: Invalid parameter?", __func__);
		goto out;
	}

	/* Given "lsa0" and current "oipi->lsa" may different, but harmless. */
	if ((lsa = oipi->lsa) == NULL) {
		flog_warn(EC_OSPF_LSA, "%s: Something wrong?", __func__);
		goto out;
	}

	if (lsa->opaque_zero_len_delete &&
	    lsa->data->length != htons(sizeof(struct lsa_header))) {
		/* minimize the size of the withdrawal: */
		/*     increment the sequence number and make len just header */
		/*     and update checksum */
		lsa->data->ls_seqnum = lsa_seqnum_increment(lsa);
		lsa->data->length = htons(sizeof(struct lsa_header));
		lsa->data->checksum = 0;
		lsa->data->checksum = ospf_lsa_checksum(lsa->data);
	}

	/* Delete this lsa from neighbor retransmit-list. */
	switch (lsa->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
	case OSPF_OPAQUE_AREA_LSA:
		ospf_ls_retransmit_delete_nbr_area(lsa->area, lsa);
		break;
	case OSPF_OPAQUE_AS_LSA:
		if ((lsa0->area != NULL) && (lsa0->area->ospf != NULL))
			top = lsa0->area->ospf;
		ospf_ls_retransmit_delete_nbr_as(top, lsa);
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, lsa->data->type);
		goto out;
	}

	/* This lsa will be flushed and removed eventually. */
	ospf_lsa_flush(top, lsa);

	/* Dequeue listnode entry from the list. */
	listnode_delete(oipt->id_list, oipi);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Schedule Type-%u Opaque-LSA to FLUSH: [opaque-type=%u, opaque-id=%x]",
			lsa->data->type,
			GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)),
			GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr)));

	/* Disassociate internal control information with the given lsa. */
	free_opaque_info_per_id((void *)oipi);

out:
	return;
}

void ospf_opaque_self_originated_lsa_received(struct ospf_neighbor *nbr,
					      struct ospf_lsa *lsa)
{
	struct ospf *top;

	if ((top = oi_to_top(nbr->oi)) == NULL)
		return;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"LSA[Type%d:%pI4]: processing self-originated Opaque-LSA",
			lsa->data->type, &lsa->data->id);

	/*
	 * Install the stale LSA into the Link State Database, add it to the
	 * MaxAge list, and flush it from the OSPF routing domain. For other
	 * LSA types, the installation is done in the refresh function. It is
	 * done inline here since the opaque refresh function is dynamically
	 * registered when opaque LSAs are originated (which is not the case
	 * for stale LSAs).
	 */
	lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	ospf_lsa_install(
		top, (lsa->data->type == OSPF_OPAQUE_LINK_LSA) ? nbr->oi : NULL,
		lsa);
	ospf_lsa_maxage(top, lsa);

	switch (lsa->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
	case OSPF_OPAQUE_AREA_LSA:
		ospf_flood_through_area(nbr->oi->area, NULL /*inbr*/, lsa);
		break;
	case OSPF_OPAQUE_AS_LSA:
		ospf_flood_through_as(top, NULL /*inbr*/, lsa);
		break;
	default:
		flog_warn(EC_OSPF_LSA_UNEXPECTED, "%s: Unexpected LSA-type(%u)",
			  __func__, lsa->data->type);
		return;
	}
}

/*------------------------------------------------------------------------*
 * Following are util functions; probably be used by Opaque-LSAs only...
 *------------------------------------------------------------------------*/

struct ospf *oi_to_top(struct ospf_interface *oi)
{
	struct ospf *top = NULL;
	struct ospf_area *area;

	if (oi == NULL || (area = oi->area) == NULL
	    || (top = area->ospf) == NULL)
		flog_warn(EC_OSPF_LSA,
			  "Broken relationship for \"OI -> AREA -> OSPF\"?");

	return top;
}
