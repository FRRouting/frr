// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "linklist.h"
#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "plist.h"
#include "filter.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"
#include "ospf6_intra.h"
#include "ospf6_abr.h"
#include "ospf6_asbr.h"
#include "ospf6_zebra.h"
#include "ospf6d.h"
#include "lib/json.h"
#include "ospf6_nssa.h"
#include "ospf6d/ospf6_area_clippy.c"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_AREA,      "OSPF6 area");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_PLISTNAME, "Prefix list name");

int str2area_id(const char *str, uint32_t *area_id, int *area_id_fmt)
{
	char *ep;

	*area_id = htonl(strtoul(str, &ep, 10));
	if (*ep && inet_pton(AF_INET, str, area_id) != 1)
		return -1;

	*area_id_fmt =
		!*ep ? OSPF6_AREA_FMT_DECIMAL : OSPF6_AREA_FMT_DOTTEDQUAD;

	return 0;
}

void area_id2str(char *buf, int len, uint32_t area_id, int area_id_fmt)
{
	if (area_id_fmt == OSPF6_AREA_FMT_DECIMAL)
		snprintf(buf, len, "%u", ntohl(area_id));
	else
		inet_ntop(AF_INET, &area_id, buf, len);
}

int ospf6_area_cmp(void *va, void *vb)
{
	struct ospf6_area *oa = (struct ospf6_area *)va;
	struct ospf6_area *ob = (struct ospf6_area *)vb;
	return (ntohl(oa->area_id) < ntohl(ob->area_id) ? -1 : 1);
}

/* schedule routing table recalculation */
static void ospf6_area_lsdb_hook_add(struct ospf6_lsa *lsa)
{
	switch (ntohs(lsa->header->type)) {

	case OSPF6_LSTYPE_ROUTER:
	case OSPF6_LSTYPE_NETWORK:
		if (IS_OSPF6_DEBUG_EXAMIN_TYPE(lsa->header->type)) {
			zlog_debug("%s Examin LSA %s", __func__, lsa->name);
			zlog_debug(" Schedule SPF Calculation for %s",
				   OSPF6_AREA(lsa->lsdb->data)->name);
		}
		ospf6_spf_schedule(
			OSPF6_PROCESS(OSPF6_AREA(lsa->lsdb->data)->ospf6),
			ospf6_lsadd_to_spf_reason(lsa));
		break;

	case OSPF6_LSTYPE_INTRA_PREFIX:
		ospf6_intra_prefix_lsa_add(lsa);
		break;

	case OSPF6_LSTYPE_INTER_PREFIX:
	case OSPF6_LSTYPE_INTER_ROUTER:
		ospf6_abr_examin_summary(lsa,
					 (struct ospf6_area *)lsa->lsdb->data);
		break;

	case OSPF6_LSTYPE_TYPE_7:
		ospf6_asbr_lsa_add(lsa);
		break;

	default:
		break;
	}
}

static void ospf6_area_lsdb_hook_remove(struct ospf6_lsa *lsa)
{
	switch (ntohs(lsa->header->type)) {
	case OSPF6_LSTYPE_ROUTER:
	case OSPF6_LSTYPE_NETWORK:
		if (IS_OSPF6_DEBUG_EXAMIN_TYPE(lsa->header->type)) {
			zlog_debug("LSA disappearing: %s", lsa->name);
			zlog_debug("Schedule SPF Calculation for %s",
				   OSPF6_AREA(lsa->lsdb->data)->name);
		}
		ospf6_spf_schedule(
			OSPF6_PROCESS(OSPF6_AREA(lsa->lsdb->data)->ospf6),
			ospf6_lsremove_to_spf_reason(lsa));
		break;

	case OSPF6_LSTYPE_INTRA_PREFIX:
		ospf6_intra_prefix_lsa_remove(lsa);
		break;

	case OSPF6_LSTYPE_INTER_PREFIX:
	case OSPF6_LSTYPE_INTER_ROUTER:
		ospf6_abr_examin_summary(lsa,
					 (struct ospf6_area *)lsa->lsdb->data);
		break;
	case OSPF6_LSTYPE_TYPE_7:
		ospf6_asbr_lsa_remove(lsa, NULL);
		break;
	default:
		break;
	}
}

static void ospf6_area_route_hook_add(struct ospf6_route *route)
{
	struct ospf6_area *oa = route->table->scope;
	struct ospf6 *ospf6 = oa->ospf6;
	struct ospf6_route *copy;

	copy = ospf6_route_copy(route);
	ospf6_route_add(copy, ospf6->route_table);
}

static void ospf6_area_route_hook_remove(struct ospf6_route *route)
{
	struct ospf6_area *oa = route->table->scope;
	struct ospf6 *ospf6 = oa->ospf6;
	struct ospf6_route *copy;

	copy = ospf6_route_lookup_identical(route, ospf6->route_table);
	if (copy)
		ospf6_route_remove(copy, ospf6->route_table);
}

static void ospf6_area_stub_update(struct ospf6_area *area)
{

	if (IS_AREA_STUB(area)) {
		if (IS_OSPF6_DEBUG_ORIGINATE(ROUTER))
			zlog_debug("Stubbing out area for area %s", area->name);
		OSPF6_OPT_CLEAR(area->options, OSPF6_OPT_E);
		ospf6_asbr_remove_externals_from_area(area);
	} else if (IS_AREA_ENABLED(area)) {
		if (IS_OSPF6_DEBUG_ORIGINATE(ROUTER))
			zlog_debug("Normal area for area %s", area->name);
		OSPF6_OPT_SET(area->options, OSPF6_OPT_E);
		ospf6_asbr_send_externals_to_area(area);
	}

	OSPF6_ROUTER_LSA_SCHEDULE(area);
}

static int ospf6_area_stub_set(struct ospf6 *ospf6, struct ospf6_area *area)
{
	if (!IS_AREA_STUB(area)) {
		/* Disable NSSA first. */
		ospf6_area_nssa_unset(ospf6, area);

		SET_FLAG(area->flag, OSPF6_AREA_STUB);
		ospf6_area_stub_update(area);
	}

	return 1;
}

void ospf6_area_stub_unset(struct ospf6 *ospf6, struct ospf6_area *area)
{
	if (IS_AREA_STUB(area)) {
		UNSET_FLAG(area->flag, OSPF6_AREA_STUB);
		ospf6_area_stub_update(area);
	}
}

static void ospf6_area_no_summary_set(struct ospf6 *ospf6,
				      struct ospf6_area *area)
{
	if (area) {
		if (!area->no_summary) {
			area->no_summary = 1;
			ospf6_abr_range_reset_cost(ospf6);
			ospf6_abr_prefix_resummarize(ospf6);
		}
	}
}

static void ospf6_area_no_summary_unset(struct ospf6 *ospf6,
					struct ospf6_area *area)
{
	if (area) {
		if (area->no_summary) {
			area->no_summary = 0;
			ospf6_abr_range_reset_cost(ospf6);
			ospf6_abr_prefix_resummarize(ospf6);
		}
	}
}

static void ospf6_nssa_default_originate_set(struct ospf6 *ospf6,
					     struct ospf6_area *area,
					     int metric, int metric_type)
{
	if (!area->nssa_default_originate.enabled) {
		area->nssa_default_originate.enabled = true;
		if (++ospf6->nssa_default_import_check.refcnt == 1) {
			ospf6->nssa_default_import_check.status = false;
			ospf6_zebra_import_default_route(ospf6, false);
		}
	}

	area->nssa_default_originate.metric_value = metric;
	area->nssa_default_originate.metric_type = metric_type;
}

static void ospf6_nssa_default_originate_unset(struct ospf6 *ospf6,
					       struct ospf6_area *area)
{
	if (area->nssa_default_originate.enabled) {
		area->nssa_default_originate.enabled = false;
		if (--ospf6->nssa_default_import_check.refcnt == 0) {
			ospf6->nssa_default_import_check.status = false;
			ospf6_zebra_import_default_route(ospf6, true);
		}
		area->nssa_default_originate.metric_value = -1;
		area->nssa_default_originate.metric_type = -1;
	}
}

/**
 * Make new area structure.
 *
 * @param area_id - ospf6 area ID
 * @param o - ospf6 instance
 * @param df - display format for area ID
 */
struct ospf6_area *ospf6_area_create(uint32_t area_id, struct ospf6 *o, int df)
{
	struct ospf6_area *oa;

	oa = XCALLOC(MTYPE_OSPF6_AREA, sizeof(struct ospf6_area));

	switch (df) {
	case OSPF6_AREA_FMT_DECIMAL:
		snprintf(oa->name, sizeof(oa->name), "%u", ntohl(area_id));
		break;
	default:
	case OSPF6_AREA_FMT_DOTTEDQUAD:
		inet_ntop(AF_INET, &area_id, oa->name, sizeof(oa->name));
		break;
	}

	oa->area_id = area_id;
	oa->if_list = list_new();

	oa->lsdb = ospf6_lsdb_create(oa);
	oa->lsdb->hook_add = ospf6_area_lsdb_hook_add;
	oa->lsdb->hook_remove = ospf6_area_lsdb_hook_remove;
	oa->lsdb_self = ospf6_lsdb_create(oa);
	oa->temp_router_lsa_lsdb = ospf6_lsdb_create(oa);

	oa->spf_table = OSPF6_ROUTE_TABLE_CREATE(AREA, SPF_RESULTS);
	oa->spf_table->scope = oa;
	oa->route_table = OSPF6_ROUTE_TABLE_CREATE(AREA, ROUTES);
	oa->route_table->scope = oa;
	oa->route_table->hook_add = ospf6_area_route_hook_add;
	oa->route_table->hook_remove = ospf6_area_route_hook_remove;

	oa->range_table = OSPF6_ROUTE_TABLE_CREATE(AREA, PREFIX_RANGES);
	oa->range_table->scope = oa;
	oa->nssa_range_table = OSPF6_ROUTE_TABLE_CREATE(AREA, PREFIX_RANGES);
	oa->nssa_range_table->scope = oa;
	oa->summary_prefix = OSPF6_ROUTE_TABLE_CREATE(AREA, SUMMARY_PREFIXES);
	oa->summary_prefix->scope = oa;
	oa->summary_router = OSPF6_ROUTE_TABLE_CREATE(AREA, SUMMARY_ROUTERS);
	oa->summary_router->scope = oa;
	oa->router_lsa_size_limit = 1024 + 256;

	/* set default options */
	if (CHECK_FLAG(o->flag, OSPF6_STUB_ROUTER)) {
		OSPF6_OPT_CLEAR(oa->options, OSPF6_OPT_V6);
		OSPF6_OPT_CLEAR(oa->options, OSPF6_OPT_R);
	} else {
		OSPF6_OPT_SET(oa->options, OSPF6_OPT_V6);
		OSPF6_OPT_SET(oa->options, OSPF6_OPT_R);
	}

	OSPF6_OPT_SET(oa->options, OSPF6_OPT_E);

	SET_FLAG(oa->flag, OSPF6_AREA_ACTIVE);
	SET_FLAG(oa->flag, OSPF6_AREA_ENABLE);

	oa->ospf6 = o;
	listnode_add_sort(o->area_list, oa);

	if (area_id == OSPF_AREA_BACKBONE) {
		o->backbone = oa;
	}

	return oa;
}

void ospf6_area_delete(struct ospf6_area *oa)
{
	struct listnode *n;
	struct ospf6_interface *oi;

	/* The ospf6_interface structs store configuration
	 * information which should not be lost/reset when
	 * deleting an area.
	 * So just detach the interface from the area and
	 * keep it around. */
	for (ALL_LIST_ELEMENTS_RO(oa->if_list, n, oi)) {
		oi->area = NULL;

		struct listnode *node;
		struct listnode *nnode;
		struct ospf6_neighbor *on;

		for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on))
			ospf6_neighbor_delete(on);
	}

	list_delete(&oa->if_list);

	ospf6_lsdb_delete(oa->lsdb);
	ospf6_lsdb_delete(oa->lsdb_self);
	ospf6_lsdb_delete(oa->temp_router_lsa_lsdb);

	ospf6_spf_table_finish(oa->spf_table);
	ospf6_route_table_delete(oa->spf_table);
	ospf6_route_table_delete(oa->route_table);

	ospf6_route_table_delete(oa->range_table);
	ospf6_route_table_delete(oa->nssa_range_table);
	ospf6_route_table_delete(oa->summary_prefix);
	ospf6_route_table_delete(oa->summary_router);

	listnode_delete(oa->ospf6->area_list, oa);
	oa->ospf6 = NULL;

	/* free area */
	XFREE(MTYPE_OSPF6_AREA, oa);
}

struct ospf6_area *ospf6_area_lookup_by_area_id(uint32_t area_id)
{
	struct ospf6_area *oa;
	struct listnode *n, *node, *nnode;
	struct ospf6 *ospf6;

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, n, oa))
			if (oa->area_id == area_id)
				return oa;
	}
	return (struct ospf6_area *)NULL;
}

struct ospf6_area *ospf6_area_lookup(uint32_t area_id, struct ospf6 *ospf6)
{
	struct ospf6_area *oa;
	struct listnode *n;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, n, oa))
		if (oa->area_id == area_id)
			return oa;

	return (struct ospf6_area *)NULL;
}

void ospf6_area_enable(struct ospf6_area *oa)
{
	struct listnode *node, *nnode;
	struct ospf6_interface *oi;

	SET_FLAG(oa->flag, OSPF6_AREA_ENABLE);

	for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi))
		ospf6_interface_enable(oi);
	ospf6_abr_enable_area(oa);
}

void ospf6_area_disable(struct ospf6_area *oa)
{
	struct listnode *node, *nnode;
	struct ospf6_interface *oi;

	UNSET_FLAG(oa->flag, OSPF6_AREA_ENABLE);

	for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi))
		ospf6_interface_disable(oi);

	ospf6_abr_disable_area(oa);
	ospf6_lsdb_remove_all(oa->lsdb);
	ospf6_lsdb_remove_all(oa->lsdb_self);

	ospf6_spf_table_finish(oa->spf_table);
	ospf6_route_remove_all(oa->route_table);

	EVENT_OFF(oa->thread_router_lsa);
	EVENT_OFF(oa->thread_intra_prefix_lsa);
}


void ospf6_area_show(struct vty *vty, struct ospf6_area *oa,
		     json_object *json_areas, bool use_json)
{
	struct listnode *i;
	struct ospf6_interface *oi;
	unsigned long result;
	json_object *json_area;
	json_object *array_interfaces;

	if (use_json) {
		json_area = json_object_new_object();
		json_object_boolean_add(json_area, "areaIsStub",
					IS_AREA_STUB(oa));
		json_object_boolean_add(json_area, "areaIsNSSA",
					IS_AREA_NSSA(oa));
		if (IS_AREA_STUB(oa) || IS_AREA_NSSA(oa)) {
			json_object_boolean_add(json_area, "areaNoSummary",
						oa->no_summary);
		}

		json_object_int_add(json_area, "numberOfAreaScopedLsa",
				    oa->lsdb->count);
		json_object_object_add(
			json_area, "lsaStatistics",
			JSON_OBJECT_NEW_ARRAY(json_object_new_int,
					      oa->lsdb->stats,
					      OSPF6_LSTYPE_SIZE));

		/* Interfaces Attached */
		array_interfaces = json_object_new_array();
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, i, oi))
			json_object_array_add(
				array_interfaces,
				json_object_new_string(oi->interface->name));

		json_object_object_add(json_area, "interfacesAttachedToArea",
				       array_interfaces);

		if (oa->ts_spf.tv_sec || oa->ts_spf.tv_usec) {
			json_object_boolean_true_add(json_area, "spfHasRun");
			result = monotime_since(&oa->ts_spf, NULL);
			if (result / TIMER_SECOND_MICRO > 0) {
				json_object_int_add(
					json_area, "spfLastExecutedSecs",
					result / TIMER_SECOND_MICRO);

				json_object_int_add(
					json_area, "spfLastExecutedMicroSecs",
					result % TIMER_SECOND_MICRO);
			} else {
				json_object_int_add(json_area,
						    "spfLastExecutedSecs", 0);
				json_object_int_add(json_area,
						    "spfLastExecutedMicroSecs",
						    result);
			}
		} else
			json_object_boolean_false_add(json_area, "spfHasRun");


		json_object_object_add(json_areas, oa->name, json_area);

	} else {

		if (!IS_AREA_STUB(oa) && !IS_AREA_NSSA(oa))
			vty_out(vty, " Area %s\n", oa->name);
		else {
			if (oa->no_summary) {
				vty_out(vty, " Area %s[%s, No Summary]\n",
					oa->name,
					IS_AREA_STUB(oa) ? "Stub" : "NSSA");
			} else {
				vty_out(vty, " Area %s[%s]\n", oa->name,
					IS_AREA_STUB(oa) ? "Stub" : "NSSA");
			}
		}
		vty_out(vty, "     Number of Area scoped LSAs is %u\n",
			oa->lsdb->count);

		vty_out(vty, "     Interface attached to this area:");
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, i, oi))
			vty_out(vty, " %s", oi->interface->name);
		vty_out(vty, "\n");

		if (oa->ts_spf.tv_sec || oa->ts_spf.tv_usec) {
			result = monotime_since(&oa->ts_spf, NULL);
			if (result / TIMER_SECOND_MICRO > 0) {
				vty_out(vty,
					"     SPF last executed %ld.%lds ago\n",
					result / TIMER_SECOND_MICRO,
					result % TIMER_SECOND_MICRO);
			} else {
				vty_out(vty,
					"     SPF last executed %ldus ago\n",
					result);
			}
		} else
			vty_out(vty, "SPF has not been run\n");
	}
}

DEFUN (area_range,
       area_range_cmd,
       "area <A.B.C.D|(0-4294967295)> range X:X::X:X/M [<advertise|not-advertise|cost (0-16777215)>]",
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Configured address range\n"
       "Specify IPv6 prefix\n"
       "Advertise\n"
       "Do not advertise\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n")
{
	int idx_ipv4 = 1;
	int idx_ipv6_prefixlen = 3;
	int idx_type = 4;
	int ret;
	struct ospf6_area *oa;
	struct prefix prefix;
	struct ospf6_route *range;
	uint32_t cost;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4]->arg, oa, ospf6);

	ret = str2prefix(argv[idx_ipv6_prefixlen]->arg, &prefix);
	if (ret != 1 || prefix.family != AF_INET6) {
		vty_out(vty, "Malformed argument: %s\n",
			argv[idx_ipv6_prefixlen]->arg);
		return CMD_SUCCESS;
	}

	range = ospf6_route_lookup(&prefix, oa->range_table);
	if (range == NULL) {
		range = ospf6_route_create(ospf6);
		range->type = OSPF6_DEST_TYPE_RANGE;
		range->prefix = prefix;
		range->path.area_id = oa->area_id;
		range->path.cost = OSPF_AREA_RANGE_COST_UNSPEC;
	}

	/* default settings */
	cost = OSPF_AREA_RANGE_COST_UNSPEC;
	UNSET_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);

	if (argc > idx_type) {
		if (strmatch(argv[idx_type]->text, "not-advertise"))
			SET_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE);
		else if (strmatch(argv[idx_type]->text, "cost"))
			cost = strtoul(argv[5]->arg, NULL, 10);
	}

	range->path.u.cost_config = cost;

	if (range->rnode == NULL) {
		ospf6_route_add(range, oa->range_table);
	}

	if (ospf6_check_and_set_router_abr(ospf6)) {
		/* Redo summaries if required */
		ospf6_abr_prefix_resummarize(ospf6);
	}

	return CMD_SUCCESS;
}

DEFUN (no_area_range,
       no_area_range_cmd,
       "no area <A.B.C.D|(0-4294967295)> range X:X::X:X/M [<advertise|not-advertise|cost (0-16777215)>]",
       NO_STR
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Configured address range\n"
       "Specify IPv6 prefix\n"
       "Advertise\n"
       "Do not advertise\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n")
{
	int idx_ipv4 = 2;
	int idx_ipv6 = 4;
	int ret;
	struct ospf6_area *oa;
	struct prefix prefix;
	struct ospf6_route *range, *route;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4]->arg, oa, ospf6);

	ret = str2prefix(argv[idx_ipv6]->arg, &prefix);
	if (ret != 1 || prefix.family != AF_INET6) {
		vty_out(vty, "Malformed argument: %s\n", argv[idx_ipv6]->arg);
		return CMD_SUCCESS;
	}

	range = ospf6_route_lookup(&prefix, oa->range_table);
	if (range == NULL) {
		vty_out(vty, "Range %s does not exists.\n",
			argv[idx_ipv6]->arg);
		return CMD_SUCCESS;
	}

	if (ospf6_check_and_set_router_abr(oa->ospf6)) {
		/* Blow away the aggregated LSA and route */
		SET_FLAG(range->flag, OSPF6_ROUTE_REMOVE);

		/* Redo summaries if required */
		for (route = ospf6_route_head(oa->ospf6->route_table); route;
		     route = ospf6_route_next(route))
			ospf6_abr_originate_summary(route, oa->ospf6);

		/* purge the old aggregated summary LSA */
		ospf6_abr_originate_summary(range, oa->ospf6);
	}
	ospf6_route_remove(range, oa->range_table);

	return CMD_SUCCESS;
}

void ospf6_area_config_write(struct vty *vty, struct ospf6 *ospf6)
{
	struct listnode *node;
	struct ospf6_area *oa;
	struct ospf6_route *range;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
		for (range = ospf6_route_head(oa->range_table); range;
		     range = ospf6_route_next(range)) {
			vty_out(vty, " area %s range %pFX", oa->name,
				&range->prefix);

			if (CHECK_FLAG(range->flag,
				       OSPF6_ROUTE_DO_NOT_ADVERTISE)) {
				vty_out(vty, " not-advertise");
			} else {
				// "advertise" is the default so we do not
				// display it
				if (range->path.u.cost_config
				    != OSPF_AREA_RANGE_COST_UNSPEC)
					vty_out(vty, " cost %d",
						range->path.u.cost_config);
			}
			vty_out(vty, "\n");
		}
		if (IS_AREA_STUB(oa)) {
			if (oa->no_summary)
				vty_out(vty, " area %s stub no-summary\n",
					oa->name);
			else
				vty_out(vty, " area %s stub\n", oa->name);
		}
		if (IS_AREA_NSSA(oa)) {
			vty_out(vty, " area %s nssa", oa->name);
			if (oa->nssa_default_originate.enabled) {
				vty_out(vty, " default-information-originate");
				if (oa->nssa_default_originate.metric_value
				    != -1)
					vty_out(vty, " metric %d",
						oa->nssa_default_originate
							.metric_value);
				if (oa->nssa_default_originate.metric_type
				    != DEFAULT_METRIC_TYPE)
					vty_out(vty, " metric-type 1");
			}
			if (oa->no_summary)
				vty_out(vty, " no-summary");
			vty_out(vty, "\n");
		}
		for (range = ospf6_route_head(oa->nssa_range_table); range;
		     range = ospf6_route_next(range)) {
			vty_out(vty, " area %s nssa range %pFX", oa->name,
				&range->prefix);

			if (CHECK_FLAG(range->flag,
				       OSPF6_ROUTE_DO_NOT_ADVERTISE)) {
				vty_out(vty, " not-advertise");
			} else {
				if (range->path.u.cost_config
				    != OSPF_AREA_RANGE_COST_UNSPEC)
					vty_out(vty, " cost %u",
						range->path.u.cost_config);
			}
			vty_out(vty, "\n");
		}
		if (PREFIX_NAME_IN(oa))
			vty_out(vty, " area %s filter-list prefix %s in\n",
				oa->name, PREFIX_NAME_IN(oa));
		if (PREFIX_NAME_OUT(oa))
			vty_out(vty, " area %s filter-list prefix %s out\n",
				oa->name, PREFIX_NAME_OUT(oa));
		if (IMPORT_NAME(oa))
			vty_out(vty, " area %s import-list %s\n", oa->name,
				IMPORT_NAME(oa));
		if (EXPORT_NAME(oa))
			vty_out(vty, " area %s export-list %s\n", oa->name,
				EXPORT_NAME(oa));
	}
}

DEFUN (area_filter_list,
       area_filter_list_cmd,
       "area <A.B.C.D|(0-4294967295)> filter-list prefix PREFIXLIST6_NAME <in|out>",
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Filter networks between OSPF6 areas\n"
       "Filter prefixes between OSPF6 areas\n"
       "Name of an IPv6 prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
	char *inout = argv[argc - 1]->text;
	char *areaid = argv[1]->arg;
	char *plistname = argv[4]->arg;

	struct ospf6_area *area;
	struct prefix_list *plist;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(areaid, area, ospf6);

	plist = prefix_list_lookup(AFI_IP6, plistname);
	if (strmatch(inout, "in")) {
		PREFIX_LIST_IN(area) = plist;
		XFREE(MTYPE_OSPF6_PLISTNAME, PREFIX_NAME_IN(area));
		PREFIX_NAME_IN(area) =
			XSTRDUP(MTYPE_OSPF6_PLISTNAME, plistname);
	} else {
		PREFIX_LIST_OUT(area) = plist;
		XFREE(MTYPE_OSPF6_PLISTNAME, PREFIX_NAME_OUT(area));
		PREFIX_NAME_OUT(area) =
			XSTRDUP(MTYPE_OSPF6_PLISTNAME, plistname);
	}

	/* Redo summaries if required */
	if (ospf6_check_and_set_router_abr(area->ospf6))
		ospf6_schedule_abr_task(ospf6);

	return CMD_SUCCESS;
}

DEFUN (no_area_filter_list,
       no_area_filter_list_cmd,
       "no area <A.B.C.D|(0-4294967295)> filter-list prefix PREFIXLIST6_NAME <in|out>",
       NO_STR
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Filter networks between OSPF6 areas\n"
       "Filter prefixes between OSPF6 areas\n"
       "Name of an IPv6 prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
	char *inout = argv[argc - 1]->text;
	char *areaid = argv[2]->arg;
	char *plistname = argv[5]->arg;

	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);
	OSPF6_CMD_AREA_GET(areaid, area, ospf6);

	if (strmatch(inout, "in")) {
		if (PREFIX_NAME_IN(area))
			if (!strmatch(PREFIX_NAME_IN(area), plistname))
				return CMD_SUCCESS;

		PREFIX_LIST_IN(area) = NULL;
		XFREE(MTYPE_OSPF6_PLISTNAME, PREFIX_NAME_IN(area));
	} else {
		if (PREFIX_NAME_OUT(area))
			if (!strmatch(PREFIX_NAME_OUT(area), plistname))
				return CMD_SUCCESS;

		XFREE(MTYPE_OSPF6_PLISTNAME, PREFIX_NAME_OUT(area));
		PREFIX_LIST_OUT(area) = NULL;
	}

	/* Redo summaries if required */
	if (ospf6_check_and_set_router_abr(area->ospf6))
		ospf6_schedule_abr_task(ospf6);

	return CMD_SUCCESS;
}

void ospf6_filter_update(struct access_list *access)
{
	struct ospf6_area *oa;
	struct listnode *n, *node, *nnode;
	struct ospf6 *ospf6;

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		bool update = false;

		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, n, oa)) {
			if (IMPORT_NAME(oa)
			    && strcmp(IMPORT_NAME(oa), access->name) == 0) {
				IMPORT_LIST(oa) = access_list_lookup(
					AFI_IP6, IMPORT_NAME(oa));
				update = true;
			}

			if (EXPORT_NAME(oa)
			    && strcmp(EXPORT_NAME(oa), access->name) == 0) {
				EXPORT_LIST(oa) = access_list_lookup(
					AFI_IP6, EXPORT_NAME(oa));
				update = true;
			}
		}

		if (update && ospf6_check_and_set_router_abr(ospf6))
			ospf6_schedule_abr_task(ospf6);
	}
}

void ospf6_plist_update(struct prefix_list *plist)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	struct listnode *n;
	const char *name = prefix_list_name(plist);
	struct ospf6 *ospf6 = NULL;

	if (prefix_list_afi(plist) != AFI_IP6)
		return;

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		bool update = false;

		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, n, oa)) {
			if (PREFIX_NAME_IN(oa)
			    && !strcmp(PREFIX_NAME_IN(oa), name)) {
				PREFIX_LIST_IN(oa) = prefix_list_lookup(
					AFI_IP6, PREFIX_NAME_IN(oa));
				update = true;
			}
			if (PREFIX_NAME_OUT(oa)
			    && !strcmp(PREFIX_NAME_OUT(oa), name)) {
				PREFIX_LIST_OUT(oa) = prefix_list_lookup(
					AFI_IP6, PREFIX_NAME_OUT(oa));
				update = true;
			}
		}

		if (update && ospf6_check_and_set_router_abr(ospf6))
			ospf6_schedule_abr_task(ospf6);
	}
}

DEFUN (area_import_list,
       area_import_list_cmd,
       "area <A.B.C.D|(0-4294967295)> import-list ACCESSLIST6_NAME",
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")
{
	int idx_ipv4 = 1;
	int idx_name = 3;
	struct ospf6_area *area;
	struct access_list *list;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4]->arg, area, ospf6);

	list = access_list_lookup(AFI_IP6, argv[idx_name]->arg);

	IMPORT_LIST(area) = list;

	if (IMPORT_NAME(area))
		free(IMPORT_NAME(area));

	IMPORT_NAME(area) = strdup(argv[idx_name]->arg);
	if (ospf6_check_and_set_router_abr(area->ospf6))
		ospf6_schedule_abr_task(ospf6);

	return CMD_SUCCESS;
}

DEFUN (no_area_import_list,
       no_area_import_list_cmd,
       "no area <A.B.C.D|(0-4294967295)> import-list ACCESSLIST6_NAME",
       NO_STR
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
	int idx_ipv4 = 2;
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4]->arg, area, ospf6);

	IMPORT_LIST(area) = NULL;

	if (IMPORT_NAME(area))
		free(IMPORT_NAME(area));

	IMPORT_NAME(area) = NULL;
	if (ospf6_check_and_set_router_abr(area->ospf6))
		ospf6_schedule_abr_task(ospf6);

	return CMD_SUCCESS;
}

DEFUN (area_export_list,
       area_export_list_cmd,
       "area <A.B.C.D|(0-4294967295)> export-list ACCESSLIST6_NAME",
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
	int idx_ipv4 = 1;
	int idx_name = 3;
	struct ospf6_area *area;
	struct access_list *list;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4]->arg, area, ospf6);

	list = access_list_lookup(AFI_IP6, argv[idx_name]->arg);

	EXPORT_LIST(area) = list;

	if (EXPORT_NAME(area))
		free(EXPORT_NAME(area));

	EXPORT_NAME(area) = strdup(argv[idx_name]->arg);

	/* Redo summaries if required */
	if (ospf6_check_and_set_router_abr(area->ospf6))
		ospf6_schedule_abr_task(ospf6);

	return CMD_SUCCESS;
}

DEFUN (no_area_export_list,
       no_area_export_list_cmd,
       "no area <A.B.C.D|(0-4294967295)> export-list ACCESSLIST6_NAME",
       NO_STR
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
	int idx_ipv4 = 2;
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4]->arg, area, ospf6);

	EXPORT_LIST(area) = NULL;

	if (EXPORT_NAME(area))
		free(EXPORT_NAME(area));

	EXPORT_NAME(area) = NULL;
	if (ospf6_check_and_set_router_abr(area->ospf6))
		ospf6_schedule_abr_task(ospf6);

	return CMD_SUCCESS;
}

static int ipv6_ospf6_spf_tree_common(struct vty *vty, struct ospf6 *ospf6,
				      bool uj)
{
	struct listnode *node;
	struct ospf6_area *oa;
	struct prefix prefix;
	struct ospf6_vertex *root;
	struct ospf6_route *route;
	json_object *json = NULL;
	json_object *json_area = NULL;
	json_object *json_head = NULL;

	if (uj)
		json = json_object_new_object();
	ospf6_linkstate_prefix(ospf6->router_id, htonl(0), &prefix);
	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
		if (uj) {
			json_area = json_object_new_object();
			json_head = json_object_new_object();
		}
		route = ospf6_route_lookup(&prefix, oa->spf_table);
		if (route == NULL) {
			if (uj) {
				json_object_string_add(
					json, oa->name,
					"LS entry for not not found");
				json_object_free(json_head);
				json_object_free(json_area);
			} else
				vty_out(vty,
					"LS entry for root not found in area %s\n",
					oa->name);
			continue;
		}
		root = (struct ospf6_vertex *)route->route_option;
		ospf6_spf_display_subtree(vty, "", 0, root, json_head, uj);

		if (uj) {
			json_object_object_add(json_area, root->name,
					       json_head);
			json_object_object_add(json, oa->name, json_area);
		}
	}

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_spf_tree, show_ipv6_ospf6_spf_tree_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] spf tree [json]",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Shortest Path First calculation\n"
      "Show SPF tree\n" JSON_STR)
{
	struct listnode *node;
	struct ospf6 *ospf6;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			ipv6_ospf6_spf_tree_common(vty, ospf6, uj);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(uj, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static int show_ospf6_area_spf_tree_common(struct vty *vty,
					   struct cmd_token **argv,
					   struct ospf6 *ospf6,
					   uint32_t area_id, int idx_ipv4)
{

	struct ospf6_area *oa;
	struct prefix prefix;
	struct ospf6_vertex *root;
	struct ospf6_route *route;

	ospf6_linkstate_prefix(ospf6->router_id, htonl(0), &prefix);

	oa = ospf6_area_lookup(area_id, ospf6);
	if (oa == NULL) {
		vty_out(vty, "No such Area: %s\n", argv[idx_ipv4]->arg);
		return CMD_SUCCESS;
	}

	route = ospf6_route_lookup(&prefix, oa->spf_table);
	if (route == NULL) {
		vty_out(vty, "LS entry for root not found in area %s\n",
			oa->name);
		return CMD_SUCCESS;
	}
	root = (struct ospf6_vertex *)route->route_option;
	ospf6_spf_display_subtree(vty, "", 0, root, NULL, false);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_area_spf_tree, show_ipv6_ospf6_area_spf_tree_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] area A.B.C.D spf tree",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n" OSPF6_AREA_STR OSPF6_AREA_ID_STR
      "Shortest Path First calculation\n"
      "Show SPF tree\n")
{
	int idx_ipv4 = 4;
	uint32_t area_id;
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0)
		idx_ipv4 += 2;

	if (inet_pton(AF_INET, argv[idx_ipv4]->arg, &area_id) != 1) {
		vty_out(vty, "Malformed Area-ID: %s\n", argv[idx_ipv4]->arg);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			show_ospf6_area_spf_tree_common(vty, argv, ospf6,
							area_id, idx_ipv4);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(false, all_vrf, ospf6);

	return CMD_SUCCESS;
}

static int
show_ospf6_simulate_spf_tree_commen(struct vty *vty, struct cmd_token **argv,
				    struct ospf6 *ospf6, uint32_t router_id,
				    uint32_t area_id, struct prefix prefix,
				    int idx_ipv4, int idx_ipv4_2)
{
	struct ospf6_area *oa;
	struct ospf6_vertex *root;
	struct ospf6_route *route;
	struct ospf6_route_table *spf_table;
	unsigned char tmp_debug_ospf6_spf = 0;

	oa = ospf6_area_lookup(area_id, ospf6);
	if (oa == NULL) {
		vty_out(vty, "No such Area: %s\n", argv[idx_ipv4_2]->arg);
		return CMD_SUCCESS;
	}

	tmp_debug_ospf6_spf = conf_debug_ospf6_spf;
	conf_debug_ospf6_spf = 0;

	spf_table = OSPF6_ROUTE_TABLE_CREATE(NONE, SPF_RESULTS);
	ospf6_spf_calculation(router_id, spf_table, oa);

	conf_debug_ospf6_spf = tmp_debug_ospf6_spf;

	route = ospf6_route_lookup(&prefix, spf_table);
	if (route == NULL) {
		ospf6_spf_table_finish(spf_table);
		ospf6_route_table_delete(spf_table);
		return CMD_SUCCESS;
	}
	root = (struct ospf6_vertex *)route->route_option;
	ospf6_spf_display_subtree(vty, "", 0, root, NULL, false);

	ospf6_spf_table_finish(spf_table);
	ospf6_route_table_delete(spf_table);

	return CMD_SUCCESS;
}

DEFUN(show_ipv6_ospf6_simulate_spf_tree_root,
      show_ipv6_ospf6_simulate_spf_tree_root_cmd,
      "show ipv6 ospf6 [vrf <NAME|all>] simulate spf-tree A.B.C.D area A.B.C.D",
      SHOW_STR IP6_STR OSPF6_STR VRF_CMD_HELP_STR
      "All VRFs\n"
      "Shortest Path First calculation\n"
      "Show SPF tree\n"
      "Specify root's router-id to calculate another router's SPF tree\n"
      "OSPF6 area parameters\n" OSPF6_AREA_ID_STR)
{
	int idx_ipv4 = 5;
	int idx_ipv4_2 = 7;
	uint32_t area_id;
	struct prefix prefix;
	uint32_t router_id;
	struct ospf6 *ospf6;
	struct listnode *node;
	const char *vrf_name = NULL;
	bool all_vrf = false;
	int idx_vrf = 0;

	OSPF6_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);
	if (idx_vrf > 0) {
		idx_ipv4 += 2;
		idx_ipv4_2 += 2;
	}
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &router_id);
	ospf6_linkstate_prefix(router_id, htonl(0), &prefix);

	if (inet_pton(AF_INET, argv[idx_ipv4_2]->arg, &area_id) != 1) {
		vty_out(vty, "Malformed Area-ID: %s\n", argv[idx_ipv4_2]->arg);
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6)) {
		if (all_vrf || strcmp(ospf6->name, vrf_name) == 0) {
			show_ospf6_simulate_spf_tree_commen(
				vty, argv, ospf6, router_id, area_id, prefix,
				idx_ipv4, idx_ipv4_2);
			if (!all_vrf)
				break;
		}
	}

	OSPF6_CMD_CHECK_VRF(false, all_vrf, ospf6);

	return CMD_SUCCESS;
}

DEFUN (ospf6_area_stub,
       ospf6_area_stub_cmd,
       "area <A.B.C.D|(0-4294967295)> stub",
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Configure OSPF6 area as stub\n")
{
	int idx_ipv4_number = 1;
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4_number]->arg, area, ospf6);

	if (!ospf6_area_stub_set(ospf6, area)) {
		vty_out(vty,
			"First deconfigure all virtual link through this area\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ospf6_area_no_summary_unset(ospf6, area);

	return CMD_SUCCESS;
}

DEFUN (ospf6_area_stub_no_summary,
       ospf6_area_stub_no_summary_cmd,
       "area <A.B.C.D|(0-4294967295)> stub no-summary",
       "OSPF6 stub parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Configure OSPF6 area as stub\n"
       "Do not inject inter-area routes into stub\n")
{
	int idx_ipv4_number = 1;
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4_number]->arg, area, ospf6);

	if (!ospf6_area_stub_set(ospf6, area)) {
		vty_out(vty,
			"First deconfigure all virtual link through this area\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ospf6_area_no_summary_set(ospf6, area);

	return CMD_SUCCESS;
}

DEFUN (no_ospf6_area_stub,
       no_ospf6_area_stub_cmd,
       "no area <A.B.C.D|(0-4294967295)> stub",
       NO_STR
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Configure OSPF6 area as stub\n")
{
	int idx_ipv4_number = 2;
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4_number]->arg, area, ospf6);

	ospf6_area_stub_unset(ospf6, area);
	ospf6_area_no_summary_unset(ospf6, area);

	return CMD_SUCCESS;
}

DEFUN (no_ospf6_area_stub_no_summary,
       no_ospf6_area_stub_no_summary_cmd,
       "no area <A.B.C.D|(0-4294967295)> stub no-summary",
       NO_STR
       "OSPF6 area parameters\n"
       "OSPF6 area ID in IP address format\n"
       "OSPF6 area ID as a decimal value\n"
       "Configure OSPF6 area as stub\n"
       "Do not inject inter-area routes into area\n")
{
	int idx_ipv4_number = 2;
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	OSPF6_CMD_AREA_GET(argv[idx_ipv4_number]->arg, area, ospf6);

	ospf6_area_stub_unset(ospf6, area);
	ospf6_area_no_summary_unset(ospf6, area);

	return CMD_SUCCESS;
}

DEFPY(ospf6_area_nssa, ospf6_area_nssa_cmd,
      "area <A.B.C.D|(0-4294967295)>$area_str nssa\
        [{\
	  default-information-originate$dflt_originate [{metric (0-16777214)$mval|metric-type (1-2)$mtype}]\
	  |no-summary$no_summary\
	 }]",
      "OSPF6 area parameters\n"
      "OSPF6 area ID in IP address format\n"
      "OSPF6 area ID as a decimal value\n"
      "Configure OSPF6 area as nssa\n"
      "Originate Type 7 default into NSSA area\n"
      "OSPFv3 default metric\n"
      "OSPFv3 metric\n"
      "OSPFv3 metric type for default routes\n"
      "Set OSPFv3 External Type 1/2 metrics\n"
      "Do not inject inter-area routes into area\n")
{
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);
	OSPF6_CMD_AREA_GET(area_str, area, ospf6);

	if (!ospf6_area_nssa_set(ospf6, area)) {
		vty_out(vty,
			"First deconfigure all virtual link through this area\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (dflt_originate) {
		if (mval_str == NULL)
			mval = -1;
		if (mtype_str == NULL)
			mtype = DEFAULT_METRIC_TYPE;
		ospf6_nssa_default_originate_set(ospf6, area, mval, mtype);
	} else
		ospf6_nssa_default_originate_unset(ospf6, area);

	if (no_summary)
		ospf6_area_no_summary_set(ospf6, area);
	else
		ospf6_area_no_summary_unset(ospf6, area);

	if (ospf6_check_and_set_router_abr(ospf6)) {
		ospf6_abr_defaults_to_stub(ospf6);
		ospf6_abr_nssa_type_7_defaults(ospf6);
	}

	return CMD_SUCCESS;
}

DEFPY(no_ospf6_area_nssa, no_ospf6_area_nssa_cmd,
      "no area <A.B.C.D|(0-4294967295)>$area_str nssa\
        [{\
	  default-information-originate [{metric (0-16777214)|metric-type (1-2)}]\
	  |no-summary\
	 }]",
      NO_STR
      "OSPF6 area parameters\n"
      "OSPF6 area ID in IP address format\n"
      "OSPF6 area ID as a decimal value\n"
      "Configure OSPF6 area as nssa\n"
      "Originate Type 7 default into NSSA area\n"
      "OSPFv3 default metric\n"
      "OSPFv3 metric\n"
      "OSPFv3 metric type for default routes\n"
      "Set OSPFv3 External Type 1/2 metrics\n"
      "Do not inject inter-area routes into area\n")
{
	struct ospf6_area *area;

	VTY_DECLVAR_CONTEXT(ospf6, ospf6);
	OSPF6_CMD_AREA_GET(area_str, area, ospf6);

	ospf6_area_nssa_unset(ospf6, area);
	ospf6_area_no_summary_unset(ospf6, area);
	ospf6_nssa_default_originate_unset(ospf6, area);

	return CMD_SUCCESS;
}


void ospf6_area_init(void)
{
	install_element(VIEW_NODE, &show_ipv6_ospf6_spf_tree_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_area_spf_tree_cmd);
	install_element(VIEW_NODE, &show_ipv6_ospf6_simulate_spf_tree_root_cmd);

	install_element(OSPF6_NODE, &area_range_cmd);
	install_element(OSPF6_NODE, &no_area_range_cmd);
	install_element(OSPF6_NODE, &ospf6_area_stub_no_summary_cmd);
	install_element(OSPF6_NODE, &ospf6_area_stub_cmd);
	install_element(OSPF6_NODE, &no_ospf6_area_stub_no_summary_cmd);
	install_element(OSPF6_NODE, &no_ospf6_area_stub_cmd);


	install_element(OSPF6_NODE, &area_import_list_cmd);
	install_element(OSPF6_NODE, &no_area_import_list_cmd);
	install_element(OSPF6_NODE, &area_export_list_cmd);
	install_element(OSPF6_NODE, &no_area_export_list_cmd);

	install_element(OSPF6_NODE, &area_filter_list_cmd);
	install_element(OSPF6_NODE, &no_area_filter_list_cmd);

	/* "area nssa" commands. */
	install_element(OSPF6_NODE, &ospf6_area_nssa_cmd);
	install_element(OSPF6_NODE, &no_ospf6_area_nssa_cmd);
}

void ospf6_area_interface_delete(struct ospf6_interface *oi)
{
	struct ospf6_area *oa;
	struct listnode *node, *nnode;
	struct ospf6 *ospf6;

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa))
			if (listnode_lookup(oa->if_list, oi))
				listnode_delete(oa->if_list, oi);
	}
}
