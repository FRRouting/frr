/*
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "printfrr.h"
#include "northbound.h"
#include "linklist.h"
#include "log.h"
#include "bfd.h"
#include "filter.h"
#include "plist.h"
#include "spf_backoff.h"
#include "lib_errors.h"
#include "vrf.h"
#include "ldp_sync.h"

#include "isisd/isisd.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_common.h"
#include "isisd/isis_bfd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_redist.h"
#include "isisd/isis_ldp_sync.h"
#include "isisd/isis_dr.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_MPLS_TE,    "ISIS MPLS_TE parameters");
DEFINE_MTYPE_STATIC(ISISD, ISIS_PLIST_NAME, "ISIS prefix-list name");

/*
 * XPath: /frr-isisd:isis/instance
 */
int isis_instance_create(struct nb_cb_create_args *args)
{
	struct isis_area *area;
	const char *area_tag;
	const char *vrf_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	vrf_name = yang_dnode_get_string(args->dnode, "./vrf");
	area_tag = yang_dnode_get_string(args->dnode, "./area-tag");
	isis_global_instance_create(vrf_name);
	area = isis_area_lookup_by_vrf(area_tag, vrf_name);
	if (area)
		return NB_ERR_INCONSISTENCY;

	area = isis_area_create(area_tag, vrf_name);

	/* save area in dnode to avoid looking it up all the time */
	nb_running_set_entry(args->dnode, area);

	return NB_OK;
}

int isis_instance_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	area = nb_running_unset_entry(args->dnode);

	isis_area_destroy(area);
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/is-type
 */
int isis_instance_is_type_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, NULL);
	isis_area_is_type_set(area, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-address
 */
int isis_instance_area_address_create(struct nb_cb_create_args *args)
{
	struct isis_area *area;
	struct area_addr addr, *addrr = NULL, *addrp = NULL;
	struct listnode *node;
	uint8_t buff[255];
	const char *net_title = yang_dnode_get_string(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		area = nb_running_get_entry(args->dnode, NULL, false);
		if (area == NULL)
			return NB_ERR_VALIDATION;
		addr.addr_len = dotformat2buff(buff, net_title);
		memcpy(addr.area_addr, buff, addr.addr_len);
		if (addr.area_addr[addr.addr_len - 1] != 0) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"nsel byte (last byte) in area address must be 0");
			return NB_ERR_VALIDATION;
		}
		if (area->isis->sysid_set) {
			/* Check that the SystemID portions match */
			if (memcmp(area->isis->sysid, GETSYSID((&addr)),
				   ISIS_SYS_ID_LEN)) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"System ID must not change when defining additional area addresses");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
		addrr = XMALLOC(MTYPE_ISIS_AREA_ADDR, sizeof(struct area_addr));
		addrr->addr_len = dotformat2buff(buff, net_title);
		memcpy(addrr->area_addr, buff, addrr->addr_len);
		args->resource->ptr = addrr;
		break;
	case NB_EV_ABORT:
		XFREE(MTYPE_ISIS_AREA_ADDR, args->resource->ptr);
		break;
	case NB_EV_APPLY:
		area = nb_running_get_entry(args->dnode, NULL, true);
		addrr = args->resource->ptr;
		assert(area);

		if (area->isis->sysid_set == 0) {
			/*
			 * First area address - get the SystemID for this router
			 */
			memcpy(area->isis->sysid, GETSYSID(addrr),
			       ISIS_SYS_ID_LEN);
			area->isis->sysid_set = 1;
		} else {
			/* check that we don't already have this address */
			for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node,
						  addrp)) {
				if ((addrp->addr_len + ISIS_SYS_ID_LEN
				     + ISIS_NSEL_LEN)
				    != (addrr->addr_len))
					continue;
				if (!memcmp(addrp->area_addr, addrr->area_addr,
					    addrr->addr_len)) {
					XFREE(MTYPE_ISIS_AREA_ADDR, addrr);
					return NB_OK; /* silent fail */
				}
			}
		}

		/*Forget the systemID part of the address */
		addrr->addr_len -= (ISIS_SYS_ID_LEN + ISIS_NSEL_LEN);
		assert(area->area_addrs); /* to silence scan-build sillyness */
		listnode_add(area->area_addrs, addrr);

		/* only now we can safely generate our LSPs for this area */
		if (listcount(area->area_addrs) > 0) {
			if (area->is_type & IS_LEVEL_1)
				lsp_generate(area, IS_LEVEL_1);
			if (area->is_type & IS_LEVEL_2)
				lsp_generate(area, IS_LEVEL_2);
		}
		break;
	}

	return NB_OK;
}

int isis_instance_area_address_destroy(struct nb_cb_destroy_args *args)
{
	struct area_addr addr, *addrp = NULL;
	struct listnode *node;
	uint8_t buff[255];
	struct isis_area *area;
	const char *net_title;
	struct listnode *cnode;
	struct isis_circuit *circuit;
	int lvl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	net_title = yang_dnode_get_string(args->dnode, NULL);
	addr.addr_len = dotformat2buff(buff, net_title);
	memcpy(addr.area_addr, buff, (int)addr.addr_len);
	area = nb_running_get_entry(args->dnode, NULL, true);

	for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node, addrp)) {
		if ((addrp->addr_len + ISIS_SYS_ID_LEN + 1) == addr.addr_len
		    && !memcmp(addrp->area_addr, addr.area_addr, addr.addr_len))
			break;
	}
	if (!addrp)
		return NB_ERR_INCONSISTENCY;

	listnode_delete(area->area_addrs, addrp);
	XFREE(MTYPE_ISIS_AREA_ADDR, addrp);
	/*
	 * Last area address - reset the SystemID for this router
	 */
	if (listcount(area->area_addrs) == 0) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
				if (circuit->u.bc.is_dr[lvl - 1])
					isis_dr_resign(circuit, lvl);
			}
		memset(area->isis->sysid, 0, ISIS_SYS_ID_LEN);
		area->isis->sysid_set = 0;
		if (IS_DEBUG_EVENTS)
			zlog_debug("Router has no SystemID");
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/dynamic-hostname
 */
int isis_instance_dynamic_hostname_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_dynhostname_set(area, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/attach-send
 */
int isis_instance_attached_send_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	bool attached;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	attached = yang_dnode_get_bool(args->dnode, NULL);
	isis_area_attached_bit_send_set(area, attached);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/attach-receive-ignore
 */
int isis_instance_attached_receive_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	bool attached;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	attached = yang_dnode_get_bool(args->dnode, NULL);
	isis_area_attached_bit_receive_set(area, attached);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/attached
 */
int isis_instance_attached_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/overload
 */
int isis_instance_overload_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	bool overload;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	overload = yang_dnode_get_bool(args->dnode, NULL);
	isis_area_overload_bit_set(area, overload);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/metric-style
 */
int isis_instance_metric_style_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	bool old_metric, new_metric;
	enum isis_metric_style metric_style =
		yang_dnode_get_enum(args->dnode, NULL);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	old_metric = (metric_style == ISIS_WIDE_METRIC) ? false : true;
	new_metric = (metric_style == ISIS_NARROW_METRIC) ? false : true;
	isis_area_metricstyle_set(area, old_metric, new_metric);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/purge-originator
 */
int isis_instance_purge_originator_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->purge_originator = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/mtu
 */
int isis_instance_lsp_mtu_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node;
	struct isis_circuit *circuit;
	uint16_t lsp_mtu = yang_dnode_get_uint16(args->dnode, NULL);
	struct isis_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
		area = nb_running_get_entry(args->dnode, NULL, false);
		if (!area)
			break;
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
			if (circuit->state != C_STATE_INIT
			    && circuit->state != C_STATE_UP)
				continue;
			if (lsp_mtu > isis_circuit_pdu_size(circuit)) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"ISIS area contains circuit %s, which has a maximum PDU size of %zu",
					circuit->interface->name,
					isis_circuit_pdu_size(circuit));
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = nb_running_get_entry(args->dnode, NULL, true);
		isis_area_lsp_mtu_set(area, lsp_mtu);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-1/refresh-interval
 */
int isis_instance_lsp_refresh_interval_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	uint16_t refr_int;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	refr_int = yang_dnode_get_uint16(args->dnode, NULL);
	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_lsp_refresh_set(area, IS_LEVEL_1, refr_int);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-2/refresh-interval
 */
int isis_instance_lsp_refresh_interval_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	uint16_t refr_int;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	refr_int = yang_dnode_get_uint16(args->dnode, NULL);
	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_lsp_refresh_set(area, IS_LEVEL_2, refr_int);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-1/maximum-lifetime
 */
int isis_instance_lsp_maximum_lifetime_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	uint16_t max_lt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	max_lt = yang_dnode_get_uint16(args->dnode, NULL);
	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_max_lsp_lifetime_set(area, IS_LEVEL_1, max_lt);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-2/maximum-lifetime
 */
int isis_instance_lsp_maximum_lifetime_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	uint16_t max_lt;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	max_lt = yang_dnode_get_uint16(args->dnode, NULL);
	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_max_lsp_lifetime_set(area, IS_LEVEL_2, max_lt);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-1/generation-interval
 */
int isis_instance_lsp_generation_interval_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	uint16_t gen_int;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	gen_int = yang_dnode_get_uint16(args->dnode, NULL);
	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lsp_gen_interval[0] = gen_int;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-2/generation-interval
 */
int isis_instance_lsp_generation_interval_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	uint16_t gen_int;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	gen_int = yang_dnode_get_uint16(args->dnode, NULL);
	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lsp_gen_interval[1] = gen_int;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay
 */
void ietf_backoff_delay_apply_finish(struct nb_cb_apply_finish_args *args)
{
	long init_delay = yang_dnode_get_uint16(args->dnode, "./init-delay");
	long short_delay = yang_dnode_get_uint16(args->dnode, "./short-delay");
	long long_delay = yang_dnode_get_uint16(args->dnode, "./long-delay");
	long holddown = yang_dnode_get_uint16(args->dnode, "./hold-down");
	long timetolearn =
		yang_dnode_get_uint16(args->dnode, "./time-to-learn");
	struct isis_area *area = nb_running_get_entry(args->dnode, NULL, true);
	size_t bufsiz = strlen(area->area_tag) + sizeof("IS-IS  Lx");
	char *buf = XCALLOC(MTYPE_TMP, bufsiz);

	snprintf(buf, bufsiz, "IS-IS %s L1", area->area_tag);
	spf_backoff_free(area->spf_delay_ietf[0]);
	area->spf_delay_ietf[0] =
		spf_backoff_new(master, buf, init_delay, short_delay,
				long_delay, holddown, timetolearn);

	snprintf(buf, bufsiz, "IS-IS %s L2", area->area_tag);
	spf_backoff_free(area->spf_delay_ietf[1]);
	area->spf_delay_ietf[1] =
		spf_backoff_new(master, buf, init_delay, short_delay,
				long_delay, holddown, timetolearn);

	XFREE(MTYPE_TMP, buf);
}

int isis_instance_spf_ietf_backoff_delay_create(struct nb_cb_create_args *args)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

int isis_instance_spf_ietf_backoff_delay_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	spf_backoff_free(area->spf_delay_ietf[0]);
	spf_backoff_free(area->spf_delay_ietf[1]);
	area->spf_delay_ietf[0] = NULL;
	area->spf_delay_ietf[1] = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/init-delay
 */
int isis_instance_spf_ietf_backoff_delay_init_delay_modify(
	struct nb_cb_modify_args *args)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/short-delay
 */
int isis_instance_spf_ietf_backoff_delay_short_delay_modify(
	struct nb_cb_modify_args *args)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/long-delay
 */
int isis_instance_spf_ietf_backoff_delay_long_delay_modify(
	struct nb_cb_modify_args *args)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/hold-down
 */
int isis_instance_spf_ietf_backoff_delay_hold_down_modify(
	struct nb_cb_modify_args *args)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/time-to-learn
 */
int isis_instance_spf_ietf_backoff_delay_time_to_learn_modify(
	struct nb_cb_modify_args *args)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/minimum-interval/level-1
 */
int isis_instance_spf_minimum_interval_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->min_spf_interval[0] = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/minimum-interval/level-2
 */
int isis_instance_spf_minimum_interval_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->min_spf_interval[1] = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-isisd:isis/instance/spf/prefix-priorities/critical/access-list-name
 */
int isis_instance_spf_prefix_priorities_critical_access_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	const char *acl_name;
	struct spf_prefix_priority_acl *ppa;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	acl_name = yang_dnode_get_string(args->dnode, NULL);

	ppa = &area->spf_prefix_priorities[SPF_PREFIX_PRIO_CRITICAL];
	XFREE(MTYPE_ISIS_ACL_NAME, ppa->name);
	ppa->name = XSTRDUP(MTYPE_ISIS_ACL_NAME, acl_name);
	ppa->list_v4 = access_list_lookup(AFI_IP, acl_name);
	ppa->list_v6 = access_list_lookup(AFI_IP6, acl_name);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_spf_prefix_priorities_critical_access_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	struct spf_prefix_priority_acl *ppa;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);

	ppa = &area->spf_prefix_priorities[SPF_PREFIX_PRIO_CRITICAL];
	XFREE(MTYPE_ISIS_ACL_NAME, ppa->name);
	ppa->list_v4 = NULL;
	ppa->list_v6 = NULL;
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/prefix-priorities/high/access-list-name
 */
int isis_instance_spf_prefix_priorities_high_access_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	const char *acl_name;
	struct spf_prefix_priority_acl *ppa;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	acl_name = yang_dnode_get_string(args->dnode, NULL);

	ppa = &area->spf_prefix_priorities[SPF_PREFIX_PRIO_HIGH];
	XFREE(MTYPE_ISIS_ACL_NAME, ppa->name);
	ppa->name = XSTRDUP(MTYPE_ISIS_ACL_NAME, acl_name);
	ppa->list_v4 = access_list_lookup(AFI_IP, acl_name);
	ppa->list_v6 = access_list_lookup(AFI_IP6, acl_name);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_spf_prefix_priorities_high_access_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	struct spf_prefix_priority_acl *ppa;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);

	ppa = &area->spf_prefix_priorities[SPF_PREFIX_PRIO_HIGH];
	XFREE(MTYPE_ISIS_ACL_NAME, ppa->name);
	ppa->list_v4 = NULL;
	ppa->list_v6 = NULL;
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/prefix-priorities/medium/access-list-name
 */
int isis_instance_spf_prefix_priorities_medium_access_list_name_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	const char *acl_name;
	struct spf_prefix_priority_acl *ppa;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	acl_name = yang_dnode_get_string(args->dnode, NULL);

	ppa = &area->spf_prefix_priorities[SPF_PREFIX_PRIO_MEDIUM];
	XFREE(MTYPE_ISIS_ACL_NAME, ppa->name);
	ppa->name = XSTRDUP(MTYPE_ISIS_ACL_NAME, acl_name);
	ppa->list_v4 = access_list_lookup(AFI_IP, acl_name);
	ppa->list_v6 = access_list_lookup(AFI_IP6, acl_name);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_spf_prefix_priorities_medium_access_list_name_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	struct spf_prefix_priority_acl *ppa;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);

	ppa = &area->spf_prefix_priorities[SPF_PREFIX_PRIO_MEDIUM];
	XFREE(MTYPE_ISIS_ACL_NAME, ppa->name);
	ppa->list_v4 = NULL;
	ppa->list_v6 = NULL;
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password
 */
void area_password_apply_finish(struct nb_cb_apply_finish_args *args)
{
	const char *password = yang_dnode_get_string(args->dnode, "./password");
	struct isis_area *area = nb_running_get_entry(args->dnode, NULL, true);
	int pass_type = yang_dnode_get_enum(args->dnode, "./password-type");
	uint8_t snp_auth =
		yang_dnode_get_enum(args->dnode, "./authenticate-snp");

	switch (pass_type) {
	case ISIS_PASSWD_TYPE_CLEARTXT:
		isis_area_passwd_cleartext_set(area, IS_LEVEL_1, password,
					       snp_auth);
		break;
	case ISIS_PASSWD_TYPE_HMAC_MD5:
		isis_area_passwd_hmac_md5_set(area, IS_LEVEL_1, password,
					      snp_auth);
		break;
	}
}

int isis_instance_area_password_create(struct nb_cb_create_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

int isis_instance_area_password_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_passwd_unset(area, IS_LEVEL_1);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/password
 */
int isis_instance_area_password_password_modify(struct nb_cb_modify_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/password-type
 */
int isis_instance_area_password_password_type_modify(
	struct nb_cb_modify_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/authenticate-snp
 */
int isis_instance_area_password_authenticate_snp_modify(
	struct nb_cb_modify_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password
 */
void domain_password_apply_finish(struct nb_cb_apply_finish_args *args)
{
	const char *password = yang_dnode_get_string(args->dnode, "./password");
	struct isis_area *area = nb_running_get_entry(args->dnode, NULL, true);
	int pass_type = yang_dnode_get_enum(args->dnode, "./password-type");
	uint8_t snp_auth =
		yang_dnode_get_enum(args->dnode, "./authenticate-snp");

	switch (pass_type) {
	case ISIS_PASSWD_TYPE_CLEARTXT:
		isis_area_passwd_cleartext_set(area, IS_LEVEL_2, password,
					       snp_auth);
		break;
	case ISIS_PASSWD_TYPE_HMAC_MD5:
		isis_area_passwd_hmac_md5_set(area, IS_LEVEL_2, password,
					      snp_auth);
		break;
	}
}

int isis_instance_domain_password_create(struct nb_cb_create_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

int isis_instance_domain_password_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_passwd_unset(area, IS_LEVEL_2);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/password
 */
int isis_instance_domain_password_password_modify(
	struct nb_cb_modify_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/password-type
 */
int isis_instance_domain_password_password_type_modify(
	struct nb_cb_modify_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/authenticate-snp
 */
int isis_instance_domain_password_authenticate_snp_modify(
	struct nb_cb_modify_args *args)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4
 */
void default_info_origin_apply_finish(const struct lyd_node *dnode, int family)
{
	int originate_type = DEFAULT_ORIGINATE;
	unsigned long metric = 0;
	const char *routemap = NULL;
	struct isis_area *area = nb_running_get_entry(dnode, NULL, true);
	int level = yang_dnode_get_enum(dnode, "./level");

	if (yang_dnode_get_bool(dnode, "./always")) {
		originate_type = DEFAULT_ORIGINATE_ALWAYS;
	} else if (family == AF_INET6) {
		zlog_warn(
			"%s: Zebra doesn't implement default-originate for IPv6 yet, so use with care or use default-originate always.",
			__func__);
	}

	if (yang_dnode_exists(dnode, "./metric"))
		metric = yang_dnode_get_uint32(dnode, "./metric");
	if (yang_dnode_exists(dnode, "./route-map"))
		routemap = yang_dnode_get_string(dnode, "./route-map");

	isis_redist_set(area, level, family, DEFAULT_ROUTE, metric, routemap,
			originate_type);
}

void default_info_origin_ipv4_apply_finish(struct nb_cb_apply_finish_args *args)
{
	default_info_origin_apply_finish(args->dnode, AF_INET);
}

void default_info_origin_ipv6_apply_finish(struct nb_cb_apply_finish_args *args)
{
	default_info_origin_apply_finish(args->dnode, AF_INET6);
}

int isis_instance_default_information_originate_ipv4_create(
	struct nb_cb_create_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	int level;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	level = yang_dnode_get_enum(args->dnode, "./level");
	isis_redist_unset(area, level, AF_INET, DEFAULT_ROUTE);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/always
 */
int isis_instance_default_information_originate_ipv4_always_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/route-map
 */
int isis_instance_default_information_originate_ipv4_route_map_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv4_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/metric
 */
int isis_instance_default_information_originate_ipv4_metric_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6
 */
int isis_instance_default_information_originate_ipv6_create(
	struct nb_cb_create_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv6_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	int level;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	level = yang_dnode_get_enum(args->dnode, "./level");
	isis_redist_unset(area, level, AF_INET6, DEFAULT_ROUTE);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/always
 */
int isis_instance_default_information_originate_ipv6_always_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/route-map
 */
int isis_instance_default_information_originate_ipv6_route_map_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv6_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/metric
 */
int isis_instance_default_information_originate_ipv6_metric_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4
 */
void redistribute_apply_finish(const struct lyd_node *dnode, int family)
{
	assert(family == AF_INET || family == AF_INET6);
	int type, level;
	unsigned long metric = 0;
	const char *routemap = NULL;
	struct isis_area *area;

	type = yang_dnode_get_enum(dnode, "./protocol");
	level = yang_dnode_get_enum(dnode, "./level");
	area = nb_running_get_entry(dnode, NULL, true);

	if (yang_dnode_exists(dnode, "./metric"))
		metric = yang_dnode_get_uint32(dnode, "./metric");
	if (yang_dnode_exists(dnode, "./route-map"))
		routemap = yang_dnode_get_string(dnode, "./route-map");

	isis_redist_set(area, level, family, type, metric, routemap, 0);
}

void redistribute_ipv4_apply_finish(struct nb_cb_apply_finish_args *args)
{
	redistribute_apply_finish(args->dnode, AF_INET);
}

void redistribute_ipv6_apply_finish(struct nb_cb_apply_finish_args *args)
{
	redistribute_apply_finish(args->dnode, AF_INET6);
}

int isis_instance_redistribute_ipv4_create(struct nb_cb_create_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	int level, type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	level = yang_dnode_get_enum(args->dnode, "./level");
	type = yang_dnode_get_enum(args->dnode, "./protocol");
	isis_redist_unset(area, level, AF_INET, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4/route-map
 */
int isis_instance_redistribute_ipv4_route_map_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv4_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4/metric
 */
int isis_instance_redistribute_ipv4_metric_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6
 */
int isis_instance_redistribute_ipv6_create(struct nb_cb_create_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv6_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	int level, type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	level = yang_dnode_get_enum(args->dnode, "./level");
	type = yang_dnode_get_enum(args->dnode, "./protocol");
	isis_redist_unset(area, level, AF_INET6, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6/route-map
 */
int isis_instance_redistribute_ipv6_route_map_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv6_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6/metric
 */
int isis_instance_redistribute_ipv6_metric_modify(
	struct nb_cb_modify_args *args)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-multicast
 */
static int isis_multi_topology_common(enum nb_event event,
				      const struct lyd_node *dnode,
				      char *errmsg, size_t errmsg_len,
				      const char *topology, bool create)
{
	struct isis_area *area;
	struct isis_area_mt_setting *setting;
	uint16_t mtid = isis_str2mtid(topology);

	switch (event) {
	case NB_EV_VALIDATE:
		if (mtid == (uint16_t)-1) {
			snprintf(errmsg, errmsg_len, "Unknown topology %s",
				 topology);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = nb_running_get_entry(dnode, NULL, true);
		setting = area_get_mt_setting(area, mtid);
		setting->enabled = create;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);
		break;
	}

	return NB_OK;
}

static int isis_multi_topology_overload_common(enum nb_event event,
					       const struct lyd_node *dnode,
					       const char *topology)
{
	struct isis_area *area;
	struct isis_area_mt_setting *setting;
	uint16_t mtid = isis_str2mtid(topology);

	/* validation is done in isis_multi_topology_common */
	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	setting = area_get_mt_setting(area, mtid);
	setting->overload = yang_dnode_get_bool(dnode, NULL);
	if (setting->enabled)
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);

	return NB_OK;
}

int isis_instance_multi_topology_ipv4_multicast_create(
	struct nb_cb_create_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv4-multicast", true);
}

int isis_instance_multi_topology_ipv4_multicast_destroy(
	struct nb_cb_destroy_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv4-multicast", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload
 */
int isis_instance_multi_topology_ipv4_multicast_overload_modify(
	struct nb_cb_modify_args *args)
{
	return isis_multi_topology_overload_common(args->event, args->dnode,
						   "ipv4-multicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management
 */
int isis_instance_multi_topology_ipv4_management_create(
	struct nb_cb_create_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv4-mgmt", true);
}

int isis_instance_multi_topology_ipv4_management_destroy(
	struct nb_cb_destroy_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv4-mgmt", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management/overload
 */
int isis_instance_multi_topology_ipv4_management_overload_modify(
	struct nb_cb_modify_args *args)
{
	return isis_multi_topology_overload_common(args->event, args->dnode,
						   "ipv4-mgmt");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast
 */
int isis_instance_multi_topology_ipv6_unicast_create(
	struct nb_cb_create_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-unicast", true);
}

int isis_instance_multi_topology_ipv6_unicast_destroy(
	struct nb_cb_destroy_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-unicast", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload
 */
int isis_instance_multi_topology_ipv6_unicast_overload_modify(
	struct nb_cb_modify_args *args)
{
	return isis_multi_topology_overload_common(args->event, args->dnode,
						   "ipv6-unicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast
 */
int isis_instance_multi_topology_ipv6_multicast_create(
	struct nb_cb_create_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-multicast", true);
}

int isis_instance_multi_topology_ipv6_multicast_destroy(
	struct nb_cb_destroy_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-multicast", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload
 */
int isis_instance_multi_topology_ipv6_multicast_overload_modify(
	struct nb_cb_modify_args *args)
{
	return isis_multi_topology_overload_common(args->event, args->dnode,
						   "ipv6-multicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management
 */
int isis_instance_multi_topology_ipv6_management_create(
	struct nb_cb_create_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-mgmt", true);
}

int isis_instance_multi_topology_ipv6_management_destroy(
	struct nb_cb_destroy_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-mgmt", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management/overload
 */
int isis_instance_multi_topology_ipv6_management_overload_modify(
	struct nb_cb_modify_args *args)
{
	return isis_multi_topology_overload_common(args->event, args->dnode,
						   "ipv6-mgmt");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc
 */
int isis_instance_multi_topology_ipv6_dstsrc_create(
	struct nb_cb_create_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-dstsrc", true);
}

int isis_instance_multi_topology_ipv6_dstsrc_destroy(
	struct nb_cb_destroy_args *args)
{
	return isis_multi_topology_common(args->event, args->dnode,
					  args->errmsg, args->errmsg_len,
					  "ipv6-dstsrc", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload
 */
int isis_instance_multi_topology_ipv6_dstsrc_overload_modify(
	struct nb_cb_modify_args *args)
{
	return isis_multi_topology_overload_common(args->event, args->dnode,
						   "ipv6-dstsrc");
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-1/lfa/load-sharing
 */
int isis_instance_fast_reroute_level_1_lfa_load_sharing_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lfa_load_sharing[0] = yang_dnode_get_bool(args->dnode, NULL);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-1/lfa/priority-limit
 */
int isis_instance_fast_reroute_level_1_lfa_priority_limit_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lfa_priority_limit[0] = yang_dnode_get_enum(args->dnode, NULL);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_fast_reroute_level_1_lfa_priority_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lfa_priority_limit[0] = SPF_PREFIX_PRIO_LOW;
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-1/lfa/tiebreaker
 */
int isis_instance_fast_reroute_level_1_lfa_tiebreaker_create(
	struct nb_cb_create_args *args)
{
	struct isis_area *area;
	uint8_t index;
	enum lfa_tiebreaker_type type;
	struct lfa_tiebreaker *tie_b;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	index = yang_dnode_get_uint8(args->dnode, "./index");
	type = yang_dnode_get_enum(args->dnode, "./type");

	tie_b = isis_lfa_tiebreaker_add(area, ISIS_LEVEL1, index, type);
	nb_running_set_entry(args->dnode, tie_b);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_fast_reroute_level_1_lfa_tiebreaker_destroy(
	struct nb_cb_destroy_args *args)
{
	struct lfa_tiebreaker *tie_b;
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	tie_b = nb_running_unset_entry(args->dnode);
	area = tie_b->area;
	isis_lfa_tiebreaker_delete(area, ISIS_LEVEL1, tie_b);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-1/lfa/tiebreaker/type
 */
int isis_instance_fast_reroute_level_1_lfa_tiebreaker_type_modify(
	struct nb_cb_modify_args *args)
{
	struct lfa_tiebreaker *tie_b;
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	tie_b = nb_running_get_entry(args->dnode, NULL, true);
	area = tie_b->area;
	tie_b->type = yang_dnode_get_enum(args->dnode, NULL);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-1/remote-lfa/prefix-list
 */
int isis_instance_fast_reroute_level_1_remote_lfa_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	const char *plist_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	plist_name = yang_dnode_get_string(args->dnode, NULL);

	area->rlfa_plist_name[0] = XSTRDUP(MTYPE_ISIS_PLIST_NAME, plist_name);
	area->rlfa_plist[0] = prefix_list_lookup(AFI_IP, plist_name);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_fast_reroute_level_1_remote_lfa_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);

	XFREE(MTYPE_ISIS_PLIST_NAME, area->rlfa_plist_name[0]);
	area->rlfa_plist[0] = NULL;
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-2/lfa/load-sharing
 */
int isis_instance_fast_reroute_level_2_lfa_load_sharing_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lfa_load_sharing[1] = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-2/lfa/priority-limit
 */
int isis_instance_fast_reroute_level_2_lfa_priority_limit_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lfa_priority_limit[1] = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

int isis_instance_fast_reroute_level_2_lfa_priority_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->lfa_priority_limit[1] = SPF_PREFIX_PRIO_LOW;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-2/lfa/tiebreaker
 */
int isis_instance_fast_reroute_level_2_lfa_tiebreaker_create(
	struct nb_cb_create_args *args)
{
	struct isis_area *area;
	uint8_t index;
	enum lfa_tiebreaker_type type;
	struct lfa_tiebreaker *tie_b;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	index = yang_dnode_get_uint8(args->dnode, "./index");
	type = yang_dnode_get_enum(args->dnode, "./type");

	tie_b = isis_lfa_tiebreaker_add(area, ISIS_LEVEL2, index, type);
	nb_running_set_entry(args->dnode, tie_b);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_fast_reroute_level_2_lfa_tiebreaker_destroy(
	struct nb_cb_destroy_args *args)
{
	struct lfa_tiebreaker *tie_b;
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	tie_b = nb_running_unset_entry(args->dnode);
	area = tie_b->area;
	isis_lfa_tiebreaker_delete(area, ISIS_LEVEL2, tie_b);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-2/lfa/tiebreaker/type
 */
int isis_instance_fast_reroute_level_2_lfa_tiebreaker_type_modify(
	struct nb_cb_modify_args *args)
{
	struct lfa_tiebreaker *tie_b;
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	tie_b = nb_running_get_entry(args->dnode, NULL, true);
	area = tie_b->area;
	tie_b->type = yang_dnode_get_enum(args->dnode, NULL);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-2/remote-lfa/prefix-list
 */
int isis_instance_fast_reroute_level_2_remote_lfa_prefix_list_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	const char *plist_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	plist_name = yang_dnode_get_string(args->dnode, NULL);

	area->rlfa_plist_name[1] = XSTRDUP(MTYPE_ISIS_PLIST_NAME, plist_name);
	area->rlfa_plist[1] = prefix_list_lookup(AFI_IP, plist_name);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_fast_reroute_level_2_remote_lfa_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);

	XFREE(MTYPE_ISIS_PLIST_NAME, area->rlfa_plist_name[1]);
	area->rlfa_plist[1] = NULL;
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/log-adjacency-changes
 */
int isis_instance_log_adjacency_changes_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	bool log = yang_dnode_get_bool(args->dnode, NULL);

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->log_adj_changes = log ? 1 : 0;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/mpls-te
 */
int isis_instance_mpls_te_create(struct nb_cb_create_args *args)
{
	struct listnode *node;
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	if (area->mta == NULL) {

		struct mpls_te_area *new;

		zlog_debug("ISIS-TE(%s): Initialize MPLS Traffic Engineering",
			   area->area_tag);

		new = XCALLOC(MTYPE_ISIS_MPLS_TE, sizeof(struct mpls_te_area));

		/* Initialize MPLS_TE structure */
		new->status = enable;
		new->level = 0;
		new->inter_as = off;
		new->interas_areaid.s_addr = 0;
		new->router_id.s_addr = 0;

		area->mta = new;
	} else {
		area->mta->status = enable;
	}

	/* Update Extended TLVs according to Interface link parameters */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
		isis_link_params_update(circuit, circuit->interface);

	/* Reoriginate STD_TE & GMPLS circuits */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_mpls_te_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node;
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	if (IS_MPLS_TE(area->mta))
		area->mta->status = disable;
	else
		return NB_OK;

	/* Flush LSP if circuit engage */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if (!IS_EXT_TE(circuit->ext))
			continue;

		/* disable MPLS_TE Circuit keeping SR one's */
		if (IS_SUBTLV(circuit->ext, EXT_ADJ_SID))
			circuit->ext->status = EXT_ADJ_SID;
		else if (IS_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID))
			circuit->ext->status = EXT_LAN_ADJ_SID;
		else
			circuit->ext->status = 0;
	}

	/* Reoriginate STD_TE & GMPLS circuits */
	lsp_regenerate_schedule(area, area->is_type, 0);

	zlog_debug("ISIS-TE(%s): Disabled MPLS Traffic Engineering",
		   area->area_tag);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/mpls-te/router-address
 */
int isis_instance_mpls_te_router_address_modify(struct nb_cb_modify_args *args)
{
	struct in_addr value;
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	/* only proceed if MPLS-TE is enabled */
	if (!IS_MPLS_TE(area->mta))
		return NB_OK;

	/* Update Area Router ID */
	yang_dnode_get_ipv4(&value, args->dnode, NULL);
	area->mta->router_id.s_addr = value.s_addr;

	/* And re-schedule LSP update */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_mpls_te_router_address_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	/* only proceed if MPLS-TE is enabled */
	if (!IS_MPLS_TE(area->mta))
		return NB_OK;

	/* Reset Area Router ID */
	area->mta->router_id.s_addr = INADDR_ANY;

	/* And re-schedule LSP update */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/enabled
 */
int isis_instance_segment_routing_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->srdb.config.enabled = yang_dnode_get_bool(args->dnode, NULL);

	if (area->srdb.config.enabled) {
		if (IS_DEBUG_EVENTS)
			zlog_debug("SR: Segment Routing: OFF -> ON");

		isis_sr_start(area);
	} else {
		if (IS_DEBUG_EVENTS)
			zlog_debug("SR: Segment Routing: ON -> OFF");

		isis_sr_stop(area);
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-blocks
 */
int isis_instance_segment_routing_label_blocks_pre_validate(
	struct nb_cb_pre_validate_args *args)
{
	uint32_t srgb_lbound;
	uint32_t srgb_ubound;
	uint32_t srlb_lbound;
	uint32_t srlb_ubound;

	srgb_lbound = yang_dnode_get_uint32(args->dnode, "./srgb/lower-bound");
	srgb_ubound = yang_dnode_get_uint32(args->dnode, "./srgb/upper-bound");
	srlb_lbound = yang_dnode_get_uint32(args->dnode, "./srlb/lower-bound");
	srlb_ubound = yang_dnode_get_uint32(args->dnode, "./srlb/upper-bound");

	/* Check that the block size does not exceed 65535 */
	if ((srgb_ubound - srgb_lbound + 1) > 65535) {
		snprintf(
			args->errmsg, args->errmsg_len,
			"New SR Global Block (%u/%u) exceed the limit of 65535",
			srgb_lbound, srgb_ubound);
		return NB_ERR_VALIDATION;
	}
	if ((srlb_ubound - srlb_lbound + 1) > 65535) {
		snprintf(args->errmsg, args->errmsg_len,
			 "New SR Local Block (%u/%u) exceed the limit of 65535",
			 srlb_lbound, srlb_ubound);
		return NB_ERR_VALIDATION;
	}

	/* Validate SRGB against SRLB */
	if (!((srgb_ubound < srlb_lbound) || (srgb_lbound > srlb_ubound))) {
		snprintf(
			args->errmsg, args->errmsg_len,
			"SR Global Block (%u/%u) conflicts with Local Block (%u/%u)",
			srgb_lbound, srgb_ubound, srlb_lbound, srlb_ubound);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-blocks/srgb
 */

void isis_instance_segment_routing_srgb_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct isis_area *area;
	uint32_t lower_bound, upper_bound;

	area = nb_running_get_entry(args->dnode, NULL, true);
	lower_bound = yang_dnode_get_uint32(args->dnode, "./lower-bound");
	upper_bound = yang_dnode_get_uint32(args->dnode, "./upper-bound");

	isis_sr_cfg_srgb_update(area, lower_bound, upper_bound);
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-blocks/srgb/lower-bound
 */
int isis_instance_segment_routing_srgb_lower_bound_modify(
	struct nb_cb_modify_args *args)
{
	uint32_t lower_bound = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!IS_MPLS_UNRESERVED_LABEL(lower_bound)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid SRGB lower bound: %u", lower_bound);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-blocks/srgb/upper-bound
 */
int isis_instance_segment_routing_srgb_upper_bound_modify(
	struct nb_cb_modify_args *args)
{
	uint32_t upper_bound = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!IS_MPLS_UNRESERVED_LABEL(upper_bound)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid SRGB upper bound: %u", upper_bound);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-blocks/srlb
 */
void isis_instance_segment_routing_srlb_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct isis_area *area;
	uint32_t lower_bound, upper_bound;

	area = nb_running_get_entry(args->dnode, NULL, true);
	lower_bound = yang_dnode_get_uint32(args->dnode, "./lower-bound");
	upper_bound = yang_dnode_get_uint32(args->dnode, "./upper-bound");

	isis_sr_cfg_srlb_update(area, lower_bound, upper_bound);
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-blocks/srlb/lower-bound
 */
int isis_instance_segment_routing_srlb_lower_bound_modify(
	struct nb_cb_modify_args *args)
{
	uint32_t lower_bound = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!IS_MPLS_UNRESERVED_LABEL(lower_bound)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid SRLB lower bound: %u", lower_bound);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-blocks/srlb/upper-bound
 */
int isis_instance_segment_routing_srlb_upper_bound_modify(
	struct nb_cb_modify_args *args)
{
	uint32_t upper_bound = yang_dnode_get_uint32(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!IS_MPLS_UNRESERVED_LABEL(upper_bound)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid SRLB upper bound: %u", upper_bound);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/msd/node-msd
 */
int isis_instance_segment_routing_msd_node_msd_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->srdb.config.msd = yang_dnode_get_uint8(args->dnode, NULL);

	/* Update and regenerate LSP */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_segment_routing_msd_node_msd_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	area->srdb.config.msd = 0;

	/* Update and regenerate LSP */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid
 */
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_create(
	struct nb_cb_create_args *args)
{
	struct isis_area *area;
	struct prefix prefix;
	struct sr_prefix_cfg *pcfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");

	pcfg = isis_sr_cfg_prefix_add(area, &prefix);
	nb_running_set_entry(args->dnode, pcfg);

	return NB_OK;
}

int isis_instance_segment_routing_prefix_sid_map_prefix_sid_destroy(
	struct nb_cb_destroy_args *args)
{
	struct sr_prefix_cfg *pcfg;
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pcfg = nb_running_unset_entry(args->dnode);
	area = pcfg->area;
	isis_sr_cfg_prefix_del(pcfg);
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_segment_routing_prefix_sid_map_prefix_sid_pre_validate(
	struct nb_cb_pre_validate_args *args)
{
	const struct lyd_node *area_dnode;
	struct isis_area *area;
	struct prefix prefix;
	uint32_t srgb_lbound;
	uint32_t srgb_ubound;
	uint32_t srgb_range;
	uint32_t sid;
	enum sr_sid_value_type sid_type;
	struct isis_prefix_sid psid = {};

	yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");
	srgb_lbound = yang_dnode_get_uint32(
		args->dnode, "../../label-blocks/srgb/lower-bound");
	srgb_ubound = yang_dnode_get_uint32(
		args->dnode, "../../label-blocks/srgb/upper-bound");
	sid = yang_dnode_get_uint32(args->dnode, "./sid-value");
	sid_type = yang_dnode_get_enum(args->dnode, "./sid-value-type");

	/* Check for invalid indexes/labels. */
	srgb_range = srgb_ubound - srgb_lbound + 1;
	psid.value = sid;
	switch (sid_type) {
	case SR_SID_VALUE_TYPE_INDEX:
		if (sid >= srgb_range) {
			snprintf(args->errmsg, args->errmsg_len,
				 "SID index %u falls outside local SRGB range",
				 sid);
			return NB_ERR_VALIDATION;
		}
		break;
	case SR_SID_VALUE_TYPE_ABSOLUTE:
		if (!IS_MPLS_UNRESERVED_LABEL(sid)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid absolute SID %u", sid);
			return NB_ERR_VALIDATION;
		}
		SET_FLAG(psid.flags, ISIS_PREFIX_SID_VALUE);
		SET_FLAG(psid.flags, ISIS_PREFIX_SID_LOCAL);
		break;
	}

	/* Check for Prefix-SID collisions. */
	area_dnode = yang_dnode_get_parent(args->dnode, "instance");
	area = nb_running_get_entry(area_dnode, NULL, false);
	if (area) {
		for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVEL2;
			     level++) {
				struct isis_spftree *spftree;
				struct isis_vertex *vertex_psid;

				if (!(area->is_type & level))
					continue;
				spftree = area->spftree[tree][level - 1];
				if (!spftree)
					continue;

				vertex_psid = isis_spf_prefix_sid_lookup(
					spftree, &psid);
				if (vertex_psid
				    && !prefix_same(&vertex_psid->N.ip.p.dest,
						    &prefix)) {
					snprintfrr(
						args->errmsg, args->errmsg_len,
						"Prefix-SID collision detected, SID %s %u is already in use by prefix %pFX (L%u)",
						CHECK_FLAG(
							psid.flags,
							ISIS_PREFIX_SID_VALUE)
							? "label"
							: "index",
						psid.value,
						&vertex_psid->N.ip.p.dest,
						level);
					return NB_ERR_VALIDATION;
				}
			}
		}
	}

	return NB_OK;
}

void isis_instance_segment_routing_prefix_sid_map_prefix_sid_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct sr_prefix_cfg *pcfg;
	struct isis_area *area;

	pcfg = nb_running_get_entry(args->dnode, NULL, true);
	area = pcfg->area;
	lsp_regenerate_schedule(area, area->is_type, 0);
}

/*
 * XPath:
 * /frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/sid-value-type
 */
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_sid_value_type_modify(
	struct nb_cb_modify_args *args)
{
	struct sr_prefix_cfg *pcfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pcfg = nb_running_get_entry(args->dnode, NULL, true);
	pcfg->sid_type = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/sid-value
 */
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_sid_value_modify(
	struct nb_cb_modify_args *args)
{
	struct sr_prefix_cfg *pcfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pcfg = nb_running_get_entry(args->dnode, NULL, true);
	pcfg->sid = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/last-hop-behavior
 */
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_last_hop_behavior_modify(
	struct nb_cb_modify_args *args)
{
	struct sr_prefix_cfg *pcfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pcfg = nb_running_get_entry(args->dnode, NULL, true);
	pcfg->last_hop_behavior = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid/n-flag-clear
 */
int isis_instance_segment_routing_prefix_sid_map_prefix_sid_n_flag_clear_modify(
	struct nb_cb_modify_args *args)
{
	struct sr_prefix_cfg *pcfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pcfg = nb_running_get_entry(args->dnode, NULL, true);
	pcfg->n_flag_clear = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/mpls/ldp-sync
 */
int isis_instance_mpls_ldp_sync_create(struct nb_cb_create_args *args)
{
	struct isis_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
		area = nb_running_get_entry(args->dnode, NULL, false);
		if (area == NULL || area->isis == NULL)
			return NB_ERR_VALIDATION;

		if (area->isis->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync only runs on Default VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = nb_running_get_entry(args->dnode, NULL, true);
		isis_area_ldp_sync_enable(area);
		break;
	}
	return NB_OK;
}

int isis_instance_mpls_ldp_sync_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_area *area;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(args->dnode, NULL, true);
	isis_area_ldp_sync_disable(area);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/mpls/ldp-sync/holddown
 */
int isis_instance_mpls_ldp_sync_holddown_modify(struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	uint16_t holddown;

	switch (args->event) {
	case NB_EV_VALIDATE:
		area = nb_running_get_entry(args->dnode, NULL, false);
		if (area == NULL || area->isis == NULL)
			return NB_ERR_VALIDATION;

		if (area->isis->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync only runs on Default VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = nb_running_get_entry(args->dnode, NULL, true);
		holddown = yang_dnode_get_uint16(args->dnode, NULL);
		isis_area_ldp_sync_set_holddown(area, holddown);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis
 */
int lib_interface_isis_create(struct nb_cb_create_args *args)
{
	struct isis_area *area = NULL;
	struct interface *ifp;
	struct isis_circuit *circuit = NULL;
	const char *area_tag = yang_dnode_get_string(args->dnode, "./area-tag");
	uint32_t min_mtu, actual_mtu;

	switch (args->event) {
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_VALIDATE:
		/* check if interface mtu is sufficient. If the area has not
		 * been created yet, assume default MTU for the area
		 */
		ifp = nb_running_get_entry(args->dnode, NULL, false);
		/* zebra might not know yet about the MTU - nothing we can do */
		if (!ifp || ifp->mtu == 0)
			break;
		actual_mtu =
			if_is_broadcast(ifp) ? ifp->mtu - LLC_LEN : ifp->mtu;

		area = isis_area_lookup(area_tag, ifp->vrf_id);
		if (area)
			min_mtu = area->lsp_mtu;
		else
#ifndef FABRICD
			min_mtu = yang_get_default_uint16(
				"/frr-isisd:isis/instance/lsp/mtu");
#else
			min_mtu = DEFAULT_LSP_MTU;
#endif /* ifndef FABRICD */
		if (actual_mtu < min_mtu) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Interface %s has MTU %u, minimum MTU for the area is %u",
				 ifp->name, actual_mtu, min_mtu);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		circuit = isis_circuit_new(ifp, area_tag);
		nb_running_set_entry(args->dnode, circuit);
		break;
	}

	return NB_OK;
}

int lib_interface_isis_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_unset_entry(args->dnode);

	isis_circuit_del(circuit);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/area-tag
 */
int lib_interface_isis_area_tag_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	struct interface *ifp;
	struct vrf *vrf;
	const char *area_tag, *ifname, *vrfname;

	if (args->event == NB_EV_VALIDATE) {
		/* libyang doesn't like relative paths across module boundaries
		 */
		ifname = yang_dnode_get_string(args->dnode->parent->parent,
					       "./name");
		vrfname = yang_dnode_get_string(args->dnode->parent->parent,
						"./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		assert(vrf);
		ifp = if_lookup_by_name(ifname, vrf->vrf_id);

		if (!ifp)
			return NB_OK;

		circuit = circuit_scan_by_ifp(ifp);
		area_tag = yang_dnode_get_string(args->dnode, NULL);
		if (circuit && circuit->area && circuit->area->area_tag
		    && strcmp(circuit->area->area_tag, area_tag)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "ISIS circuit is already defined on %s",
				 circuit->area->area_tag);
			return NB_ERR_VALIDATION;
		}
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/circuit-type
 */
int lib_interface_isis_circuit_type_modify(struct nb_cb_modify_args *args)
{
	int circ_type = yang_dnode_get_enum(args->dnode, NULL);
	struct isis_circuit *circuit;
	struct interface *ifp;
	struct vrf *vrf;
	const char *ifname, *vrfname;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* libyang doesn't like relative paths across module boundaries
		 */
		ifname = yang_dnode_get_string(args->dnode->parent->parent,
					       "./name");
		vrfname = yang_dnode_get_string(args->dnode->parent->parent,
						"./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		assert(vrf);
		ifp = if_lookup_by_name(ifname, vrf->vrf_id);
		if (!ifp)
			break;

		circuit = circuit_scan_by_ifp(ifp);
		if (circuit && circuit->state == C_STATE_UP
		    && circuit->area->is_type != IS_LEVEL_1_AND_2
		    && circuit->area->is_type != circ_type) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid circuit level for area %s",
				 circuit->area->area_tag);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = nb_running_get_entry(args->dnode, NULL, true);
		isis_circuit_is_type_set(circuit, circ_type);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv4-routing
 */
int lib_interface_isis_ipv4_routing_modify(struct nb_cb_modify_args *args)
{
	bool ipv4, ipv6;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	ipv4 = yang_dnode_get_bool(args->dnode, NULL);
	ipv6 = yang_dnode_get_bool(args->dnode, "../ipv6-routing");
	isis_circuit_af_set(circuit, ipv4, ipv6);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv6-routing
 */
int lib_interface_isis_ipv6_routing_modify(struct nb_cb_modify_args *args)
{
	bool ipv4, ipv6;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	ipv4 = yang_dnode_get_bool(args->dnode, "../ipv4-routing");
	ipv6 = yang_dnode_get_bool(args->dnode, NULL);
	isis_circuit_af_set(circuit, ipv4, ipv6);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring
 */
void lib_interface_isis_bfd_monitoring_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct isis_circuit *circuit;
	bool enabled;
	const char *profile = NULL;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	enabled = yang_dnode_get_bool(args->dnode, "./enabled");

	if (yang_dnode_exists(args->dnode, "./profile"))
		profile = yang_dnode_get_string(args->dnode, "./profile");

	if (enabled) {
		isis_bfd_circuit_param_set(circuit, BFD_DEF_MIN_RX,
					   BFD_DEF_MIN_TX, BFD_DEF_DETECT_MULT,
					   profile, true);
	} else {
		isis_bfd_circuit_cmd(circuit, ZEBRA_BFD_DEST_DEREGISTER);
		bfd_info_free(&circuit->bfd_info);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring/enabled
 */
int lib_interface_isis_bfd_monitoring_enabled_modify(
	struct nb_cb_modify_args *args)
{
	/* Everything done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring/profile
 */
int lib_interface_isis_bfd_monitoring_profile_modify(
	struct nb_cb_modify_args *args)
{
	/* Everything done in apply_finish */
	return NB_OK;
}

int lib_interface_isis_bfd_monitoring_profile_destroy(
	struct nb_cb_destroy_args *args)
{
	/* Everything done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-1
 */
int lib_interface_isis_csnp_interval_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->csnp_interval[0] = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-2
 */
int lib_interface_isis_csnp_interval_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->csnp_interval[1] = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-1
 */
int lib_interface_isis_psnp_interval_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->psnp_interval[0] = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-2
 */
int lib_interface_isis_psnp_interval_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->psnp_interval[1] = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/padding
 */
int lib_interface_isis_hello_padding_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->pad_hellos = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-1
 */
int lib_interface_isis_hello_interval_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	uint32_t interval;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	interval = yang_dnode_get_uint32(args->dnode, NULL);
	circuit->hello_interval[0] = interval;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-2
 */
int lib_interface_isis_hello_interval_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	uint32_t interval;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	interval = yang_dnode_get_uint32(args->dnode, NULL);
	circuit->hello_interval[1] = interval;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1
 */
int lib_interface_isis_hello_multiplier_level_1_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	uint16_t multi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	multi = yang_dnode_get_uint16(args->dnode, NULL);
	circuit->hello_multiplier[0] = multi;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2
 */
int lib_interface_isis_hello_multiplier_level_2_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	uint16_t multi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	multi = yang_dnode_get_uint16(args->dnode, NULL);
	circuit->hello_multiplier[1] = multi;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/metric/level-1
 */
int lib_interface_isis_metric_level_1_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	unsigned int met;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	met = yang_dnode_get_uint32(args->dnode, NULL);
	isis_circuit_metric_set(circuit, IS_LEVEL_1, met);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/metric/level-2
 */
int lib_interface_isis_metric_level_2_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	unsigned int met;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	met = yang_dnode_get_uint32(args->dnode, NULL);
	isis_circuit_metric_set(circuit, IS_LEVEL_2, met);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/priority/level-1
 */
int lib_interface_isis_priority_level_1_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->priority[0] = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/priority/level-2
 */
int lib_interface_isis_priority_level_2_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->priority[1] = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/network-type
 */
int lib_interface_isis_network_type_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	int net_type = yang_dnode_get_enum(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		circuit = nb_running_get_entry(args->dnode, NULL, false);
		if (!circuit)
			break;
		if (circuit->circ_type == CIRCUIT_T_LOOPBACK) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Cannot change network type on loopback interface");
			return NB_ERR_VALIDATION;
		}
		if (net_type == CIRCUIT_T_BROADCAST
		    && circuit->state == C_STATE_UP
		    && !if_is_broadcast(circuit->interface)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Cannot configure non-broadcast interface for broadcast operation");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = nb_running_get_entry(args->dnode, NULL, true);
		isis_circuit_circ_type_set(circuit, net_type);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/passive
 */
int lib_interface_isis_passive_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	struct interface *ifp;
	bool passive = yang_dnode_get_bool(args->dnode, NULL);

	/* validation only applies if we are setting passive to false */
	if (!passive && args->event == NB_EV_VALIDATE) {
		circuit = nb_running_get_entry(args->dnode, NULL, false);
		if (!circuit)
			return NB_OK;
		ifp = circuit->interface;
		if (!ifp)
			return NB_OK;
		if (if_is_loopback(ifp)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Loopback is always passive");
			return NB_ERR_VALIDATION;
		}
	}

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	isis_circuit_passive_set(circuit, passive);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password
 */
int lib_interface_isis_password_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int lib_interface_isis_password_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	isis_circuit_passwd_unset(circuit);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password/password
 */
int lib_interface_isis_password_password_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	const char *password;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	password = yang_dnode_get_string(args->dnode, NULL);
	circuit = nb_running_get_entry(args->dnode, NULL, true);

	isis_circuit_passwd_set(circuit, circuit->passwd.type, password);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password/password-type
 */
int lib_interface_isis_password_password_type_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	uint8_t pass_type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pass_type = yang_dnode_get_enum(args->dnode, NULL);
	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->passwd.type = pass_type;

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake
 */
int lib_interface_isis_disable_three_way_handshake_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->disable_threeway_adj = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-unicast
 */
static int lib_interface_isis_multi_topology_common(
	enum nb_event event, const struct lyd_node *dnode, char *errmsg,
	size_t errmsg_len, uint16_t mtid)
{
	struct isis_circuit *circuit;
	bool value;

	switch (event) {
	case NB_EV_VALIDATE:
		circuit = nb_running_get_entry(dnode, NULL, false);
		if (circuit && circuit->area && circuit->area->oldmetric) {
			snprintf(
				errmsg, errmsg_len,
				"Multi topology IS-IS can only be used with wide metrics");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = nb_running_get_entry(dnode, NULL, true);
		value = yang_dnode_get_bool(dnode, NULL);
		isis_circuit_mt_enabled_set(circuit, mtid, value);
		break;
	}

	return NB_OK;
}

int lib_interface_isis_multi_topology_ipv4_unicast_modify(
	struct nb_cb_modify_args *args)
{
	return lib_interface_isis_multi_topology_common(
		args->event, args->dnode, args->errmsg, args->errmsg_len,
		ISIS_MT_IPV4_UNICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-multicast
 */
int lib_interface_isis_multi_topology_ipv4_multicast_modify(
	struct nb_cb_modify_args *args)
{
	return lib_interface_isis_multi_topology_common(
		args->event, args->dnode, args->errmsg, args->errmsg_len,
		ISIS_MT_IPV4_MULTICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-management
 */
int lib_interface_isis_multi_topology_ipv4_management_modify(
	struct nb_cb_modify_args *args)
{
	return lib_interface_isis_multi_topology_common(
		args->event, args->dnode, args->errmsg, args->errmsg_len,
		ISIS_MT_IPV4_MGMT);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-unicast
 */
int lib_interface_isis_multi_topology_ipv6_unicast_modify(
	struct nb_cb_modify_args *args)
{
	return lib_interface_isis_multi_topology_common(
		args->event, args->dnode, args->errmsg, args->errmsg_len,
		ISIS_MT_IPV6_UNICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-multicast
 */
int lib_interface_isis_multi_topology_ipv6_multicast_modify(
	struct nb_cb_modify_args *args)
{
	return lib_interface_isis_multi_topology_common(
		args->event, args->dnode, args->errmsg, args->errmsg_len,
		ISIS_MT_IPV6_MULTICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-management
 */
int lib_interface_isis_multi_topology_ipv6_management_modify(
	struct nb_cb_modify_args *args)
{
	return lib_interface_isis_multi_topology_common(
		args->event, args->dnode, args->errmsg, args->errmsg_len,
		ISIS_MT_IPV6_MGMT);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc
 */
int lib_interface_isis_multi_topology_ipv6_dstsrc_modify(
	struct nb_cb_modify_args *args)
{
	return lib_interface_isis_multi_topology_common(
		args->event, args->dnode, args->errmsg, args->errmsg_len,
		ISIS_MT_IPV6_DSTSRC);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/mpls/ldp-sync
 */
int lib_interface_isis_mpls_ldp_sync_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	struct ldp_sync_info *ldp_sync_info;
	bool ldp_sync_enable;
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode->parent->parent->parent,
					   NULL, false);
		if (ifp == NULL)
			return NB_ERR_VALIDATION;
		if (if_is_loopback(ifp)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync does not run on loopback interface");
			return NB_ERR_VALIDATION;
		}

		circuit = nb_running_get_entry(args->dnode, NULL, false);
		if (circuit == NULL || circuit->area == NULL)
			break;

		if (circuit->isis->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync only runs on Default VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = nb_running_get_entry(args->dnode, NULL, true);
		ldp_sync_enable = yang_dnode_get_bool(args->dnode, NULL);

		ldp_sync_info = circuit->ldp_sync_info;

		SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
		ldp_sync_info->enabled = ldp_sync_enable;

		if (circuit->area) {
			if (ldp_sync_enable)
				isis_if_ldp_sync_enable(circuit);
			else
				isis_if_ldp_sync_disable(circuit);
		}
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/mpls/holddown
 */
int lib_interface_isis_mpls_holddown_modify(struct nb_cb_modify_args *args)
{
	struct isis_circuit *circuit;
	struct ldp_sync_info *ldp_sync_info;
	uint16_t holddown;
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode->parent->parent->parent,
					   NULL, false);
		if (ifp == NULL)
			return NB_ERR_VALIDATION;
		if (if_is_loopback(ifp)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync does not run on loopback interface");
			return NB_ERR_VALIDATION;
		}

		circuit = nb_running_get_entry(args->dnode, NULL, false);
		if (circuit == NULL || circuit->area == NULL)
			break;

		if (circuit->isis->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync only runs on Default VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = nb_running_get_entry(args->dnode, NULL, true);
		holddown = yang_dnode_get_uint16(args->dnode, NULL);

		ldp_sync_info = circuit->ldp_sync_info;

		SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);
		ldp_sync_info->holddown = holddown;
		break;
	}
	return NB_OK;
}

int lib_interface_isis_mpls_holddown_destroy(struct nb_cb_destroy_args *args)
{
	struct isis_circuit *circuit;
	struct ldp_sync_info *ldp_sync_info;
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode->parent->parent->parent,
					   NULL, false);
		if (ifp == NULL)
			return NB_ERR_VALIDATION;
		if (if_is_loopback(ifp)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync does not run on loopback interface");
			return NB_ERR_VALIDATION;
		}

		circuit = nb_running_get_entry(args->dnode, NULL, false);
		if (circuit == NULL || circuit->area == NULL)
			break;

		if (circuit->isis->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "LDP-Sync only runs on Default VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = nb_running_get_entry(args->dnode, NULL, true);
		ldp_sync_info = circuit->ldp_sync_info;

		UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);

		if (circuit->area)
			isis_if_set_ldp_sync_holddown(circuit);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/lfa/enable
 */
int lib_interface_isis_fast_reroute_level_1_lfa_enable_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->lfa_protection[0] = yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area) {
		if (circuit->lfa_protection[0])
			area->lfa_protected_links[0]++;
		else {
			assert(area->lfa_protected_links[0] > 0);
			area->lfa_protected_links[0]--;
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/lfa/exclude-interface
 */
int lib_interface_isis_fast_reroute_level_1_lfa_exclude_interface_create(
	struct nb_cb_create_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;
	const char *exclude_ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	exclude_ifname = yang_dnode_get_string(args->dnode, NULL);

	isis_lfa_excluded_iface_add(circuit, ISIS_LEVEL1, exclude_ifname);
	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int lib_interface_isis_fast_reroute_level_1_lfa_exclude_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;
	const char *exclude_ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	exclude_ifname = yang_dnode_get_string(args->dnode, NULL);

	isis_lfa_excluded_iface_delete(circuit, ISIS_LEVEL1, exclude_ifname);
	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/remote-lfa/enable
 */
int lib_interface_isis_fast_reroute_level_1_remote_lfa_enable_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->rlfa_protection[0] = yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area) {
		if (circuit->rlfa_protection[0])
			area->rlfa_protected_links[0]++;
		else {
			assert(area->rlfa_protected_links[0] > 0);
			area->rlfa_protected_links[0]--;
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/remote-lfa/maximum-metric
 */
int lib_interface_isis_fast_reroute_level_1_remote_lfa_maximum_metric_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->rlfa_max_metric[0] = yang_dnode_get_uint32(args->dnode, NULL);

	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int lib_interface_isis_fast_reroute_level_1_remote_lfa_maximum_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->rlfa_max_metric[0] = 0;

	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/ti-lfa/enable
 */
int lib_interface_isis_fast_reroute_level_1_ti_lfa_enable_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->tilfa_protection[0] = yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area) {
		if (circuit->tilfa_protection[0])
			area->tilfa_protected_links[0]++;
		else {
			assert(area->tilfa_protected_links[0] > 0);
			area->tilfa_protected_links[0]--;
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-1/ti-lfa/node-protection
 */
int lib_interface_isis_fast_reroute_level_1_ti_lfa_node_protection_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->tilfa_node_protection[0] =
		yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/lfa/enable
 */
int lib_interface_isis_fast_reroute_level_2_lfa_enable_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->lfa_protection[1] = yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area) {
		if (circuit->lfa_protection[1])
			area->lfa_protected_links[1]++;
		else {
			assert(area->lfa_protected_links[1] > 0);
			area->lfa_protected_links[1]--;
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/lfa/exclude-interface
 */
int lib_interface_isis_fast_reroute_level_2_lfa_exclude_interface_create(
	struct nb_cb_create_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;
	const char *exclude_ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	exclude_ifname = yang_dnode_get_string(args->dnode, NULL);

	isis_lfa_excluded_iface_add(circuit, ISIS_LEVEL2, exclude_ifname);
	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int lib_interface_isis_fast_reroute_level_2_lfa_exclude_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;
	const char *exclude_ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	exclude_ifname = yang_dnode_get_string(args->dnode, NULL);

	isis_lfa_excluded_iface_delete(circuit, ISIS_LEVEL2, exclude_ifname);
	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/remote-lfa/enable
 */
int lib_interface_isis_fast_reroute_level_2_remote_lfa_enable_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->rlfa_protection[1] = yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area) {
		if (circuit->rlfa_protection[1])
			area->rlfa_protected_links[1]++;
		else {
			assert(area->rlfa_protected_links[1] > 0);
			area->rlfa_protected_links[1]--;
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/remote-lfa/maximum-metric
 */
int lib_interface_isis_fast_reroute_level_2_remote_lfa_maximum_metric_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->rlfa_max_metric[1] = yang_dnode_get_uint32(args->dnode, NULL);

	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int lib_interface_isis_fast_reroute_level_2_remote_lfa_maximum_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->rlfa_max_metric[1] = 0;

	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/ti-lfa/enable
 */
int lib_interface_isis_fast_reroute_level_2_ti_lfa_enable_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->tilfa_protection[1] = yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area) {
		if (circuit->tilfa_protection[1])
			area->tilfa_protected_links[1]++;
		else {
			assert(area->tilfa_protected_links[1] > 0);
			area->tilfa_protected_links[1]--;
		}

		lsp_regenerate_schedule(area, area->is_type, 0);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-2/ti-lfa/node-protection
 */
int lib_interface_isis_fast_reroute_level_2_ti_lfa_node_protection_modify(
	struct nb_cb_modify_args *args)
{
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(args->dnode, NULL, true);
	circuit->tilfa_node_protection[1] =
		yang_dnode_get_bool(args->dnode, NULL);

	area = circuit->area;
	if (area)
		lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}
