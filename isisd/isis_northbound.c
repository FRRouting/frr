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
#include "northbound.h"
#include "libfrr.h"
#include "linklist.h"
#include "log.h"
#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_te.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_cli.h"
#include "isisd/isis_redist.h"
#include "lib/spf_backoff.h"
#include "lib/lib_errors.h"
#include "lib/vrf.h"

/*
 * XPath: /frr-isisd:isis/instance
 */
static int isis_instance_create(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
{
	struct isis_area *area;
	const char *area_tag;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area_tag = yang_dnode_get_string(dnode, "./area-tag");
	area = isis_area_lookup(area_tag);
	if (area)
		return NB_ERR_INCONSISTENCY;

	area = isis_area_create(area_tag);
	/* save area in dnode to avoid looking it up all the time */
	yang_dnode_set_entry(dnode, area);

	return NB_OK;
}

static int isis_instance_destroy(enum nb_event event,
				const struct lyd_node *dnode)
{
	const char *area_tag;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area_tag = yang_dnode_get_string(dnode, "./area-tag");
	isis_area_destroy(area_tag);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/is-type
 */
static int isis_instance_is_type_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	struct isis_area *area;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	type = yang_dnode_get_enum(dnode, NULL);
	isis_area_is_type_set(area, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-address
 */
static int isis_instance_area_address_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct isis_area *area;
	struct area_addr addr, *addrr = NULL, *addrp = NULL;
	struct listnode *node;
	uint8_t buff[255];
	const char *net_title = yang_dnode_get_string(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		addr.addr_len = dotformat2buff(buff, net_title);
		memcpy(addr.area_addr, buff, addr.addr_len);
		if (addr.area_addr[addr.addr_len - 1] != 0) {
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"nsel byte (last byte) in area address must be 0");
			return NB_ERR_VALIDATION;
		}
		if (isis->sysid_set) {
			/* Check that the SystemID portions match */
			if (memcmp(isis->sysid, GETSYSID((&addr)),
				   ISIS_SYS_ID_LEN)) {
				flog_warn(
					EC_LIB_NB_CB_CONFIG_VALIDATE,
					"System ID must not change when defining additional area addresses");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
		addrr = XMALLOC(MTYPE_ISIS_AREA_ADDR, sizeof(struct area_addr));
		addrr->addr_len = dotformat2buff(buff, net_title);
		memcpy(addrr->area_addr, buff, addrr->addr_len);
		resource->ptr = addrr;
		break;
	case NB_EV_ABORT:
		XFREE(MTYPE_ISIS_AREA_ADDR, resource->ptr);
		break;
	case NB_EV_APPLY:
		area = yang_dnode_get_entry(dnode, true);
		addrr = resource->ptr;

		if (isis->sysid_set == 0) {
			/*
			 * First area address - get the SystemID for this router
			 */
			memcpy(isis->sysid, GETSYSID(addrr), ISIS_SYS_ID_LEN);
			isis->sysid_set = 1;
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

static int isis_instance_area_address_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct area_addr addr, *addrp = NULL;
	struct listnode *node;
	uint8_t buff[255];
	struct isis_area *area;
	const char *net_title;

	if (event != NB_EV_APPLY)
		return NB_OK;

	net_title = yang_dnode_get_string(dnode, NULL);
	addr.addr_len = dotformat2buff(buff, net_title);
	memcpy(addr.area_addr, buff, (int)addr.addr_len);
	area = yang_dnode_get_entry(dnode, true);
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
		memset(isis->sysid, 0, ISIS_SYS_ID_LEN);
		isis->sysid_set = 0;
		if (isis->debugs & DEBUG_EVENTS)
			zlog_debug("Router has no SystemID");
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/dynamic-hostname
 */
static int isis_instance_dynamic_hostname_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	isis_area_dynhostname_set(area, yang_dnode_get_bool(dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/attached
 */
static int isis_instance_attached_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct isis_area *area;
	bool attached;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	attached = yang_dnode_get_bool(dnode, NULL);
	isis_area_attached_bit_set(area, attached);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/overload
 */
static int isis_instance_overload_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct isis_area *area;
	bool overload;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	overload = yang_dnode_get_bool(dnode, NULL);
	isis_area_overload_bit_set(area, overload);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/metric-style
 */
static int isis_instance_metric_style_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct isis_area *area;
	bool old_metric, new_metric;
	enum isis_metric_style metric_style = yang_dnode_get_enum(dnode, NULL);

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	old_metric = (metric_style == ISIS_WIDE_METRIC) ? false : true;
	new_metric = (metric_style == ISIS_NARROW_METRIC) ? false : true;
	isis_area_metricstyle_set(area, old_metric, new_metric);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/purge-originator
 */
static int isis_instance_purge_originator_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	area->purge_originator = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/mtu
 */
static int isis_instance_lsp_mtu_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	struct listnode *node;
	struct isis_circuit *circuit;
	uint16_t lsp_mtu = yang_dnode_get_uint16(dnode, NULL);
	struct isis_area *area;

	switch (event) {
	case NB_EV_VALIDATE:
		area = yang_dnode_get_entry(dnode, false);
		if (!area)
			break;
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
			if (circuit->state != C_STATE_INIT
			    && circuit->state != C_STATE_UP)
				continue;
			if (lsp_mtu > isis_circuit_pdu_size(circuit)) {
				flog_warn(
					EC_LIB_NB_CB_CONFIG_VALIDATE,
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
		area = yang_dnode_get_entry(dnode, true);
		isis_area_lsp_mtu_set(area, lsp_mtu);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/refresh-interval/level-1
 */
static int
isis_instance_lsp_refresh_interval_level_1_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t refr_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	refr_int = yang_dnode_get_uint16(dnode, NULL);
	area = yang_dnode_get_entry(dnode, true);
	isis_area_lsp_refresh_set(area, IS_LEVEL_1, refr_int);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/refresh-interval/level-2
 */
static int
isis_instance_lsp_refresh_interval_level_2_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t refr_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	refr_int = yang_dnode_get_uint16(dnode, NULL);
	area = yang_dnode_get_entry(dnode, true);
	isis_area_lsp_refresh_set(area, IS_LEVEL_2, refr_int);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/maximum-lifetime/level-1
 */
static int
isis_instance_lsp_maximum_lifetime_level_1_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t max_lt;

	if (event != NB_EV_APPLY)
		return NB_OK;

	max_lt = yang_dnode_get_uint16(dnode, NULL);
	area = yang_dnode_get_entry(dnode, true);
	isis_area_max_lsp_lifetime_set(area, IS_LEVEL_1, max_lt);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/maximum-lifetime/level-2
 */
static int
isis_instance_lsp_maximum_lifetime_level_2_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t max_lt;

	if (event != NB_EV_APPLY)
		return NB_OK;

	max_lt = yang_dnode_get_uint16(dnode, NULL);
	area = yang_dnode_get_entry(dnode, true);
	isis_area_max_lsp_lifetime_set(area, IS_LEVEL_2, max_lt);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/generation-interval/level-1
 */
static int isis_instance_lsp_generation_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t gen_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	gen_int = yang_dnode_get_uint16(dnode, NULL);
	area = yang_dnode_get_entry(dnode, true);
	area->lsp_gen_interval[0] = gen_int;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/generation-interval/level-2
 */
static int isis_instance_lsp_generation_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t gen_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	gen_int = yang_dnode_get_uint16(dnode, NULL);
	area = yang_dnode_get_entry(dnode, true);
	area->lsp_gen_interval[1] = gen_int;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay
 */
static void ietf_backoff_delay_apply_finish(const struct lyd_node *dnode)
{
	long init_delay = yang_dnode_get_uint16(dnode, "./init-delay");
	long short_delay = yang_dnode_get_uint16(dnode, "./short-delay");
	long long_delay = yang_dnode_get_uint16(dnode, "./long-delay");
	long holddown = yang_dnode_get_uint16(dnode, "./hold-down");
	long timetolearn = yang_dnode_get_uint16(dnode, "./time-to-learn");
	struct isis_area *area = yang_dnode_get_entry(dnode, true);
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

static int
isis_instance_spf_ietf_backoff_delay_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

static int
isis_instance_spf_ietf_backoff_delay_destroy(enum nb_event event,
					    const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	spf_backoff_free(area->spf_delay_ietf[0]);
	spf_backoff_free(area->spf_delay_ietf[1]);
	area->spf_delay_ietf[0] = NULL;
	area->spf_delay_ietf[1] = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/init-delay
 */
static int isis_instance_spf_ietf_backoff_delay_init_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/short-delay
 */
static int isis_instance_spf_ietf_backoff_delay_short_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/long-delay
 */
static int isis_instance_spf_ietf_backoff_delay_long_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/hold-down
 */
static int isis_instance_spf_ietf_backoff_delay_hold_down_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/time-to-learn
 */
static int isis_instance_spf_ietf_backoff_delay_time_to_learn_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/minimum-interval/level-1
 */
static int
isis_instance_spf_minimum_interval_level_1_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	area->min_spf_interval[0] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/minimum-interval/level-2
 */
static int
isis_instance_spf_minimum_interval_level_2_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	area->min_spf_interval[1] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password
 */
static void area_password_apply_finish(const struct lyd_node *dnode)
{
	const char *password = yang_dnode_get_string(dnode, "./password");
	struct isis_area *area = yang_dnode_get_entry(dnode, true);
	int pass_type = yang_dnode_get_enum(dnode, "./password-type");
	uint8_t snp_auth = yang_dnode_get_enum(dnode, "./authenticate-snp");

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

static int isis_instance_area_password_create(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

static int isis_instance_area_password_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	isis_area_passwd_unset(area, IS_LEVEL_1);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/password
 */
static int
isis_instance_area_password_password_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/password-type
 */
static int
isis_instance_area_password_password_type_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/authenticate-snp
 */
static int isis_instance_area_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password
 */
static void domain_password_apply_finish(const struct lyd_node *dnode)
{
	const char *password = yang_dnode_get_string(dnode, "./password");
	struct isis_area *area = yang_dnode_get_entry(dnode, true);
	int pass_type = yang_dnode_get_enum(dnode, "./password-type");
	uint8_t snp_auth = yang_dnode_get_enum(dnode, "./authenticate-snp");

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

static int isis_instance_domain_password_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

static int isis_instance_domain_password_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	isis_area_passwd_unset(area, IS_LEVEL_2);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/password
 */
static int
isis_instance_domain_password_password_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/password-type
 */
static int
isis_instance_domain_password_password_type_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/authenticate-snp
 */
static int isis_instance_domain_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4
 */
static void default_info_origin_apply_finish(const struct lyd_node *dnode,
					     int family)
{
	int originate_type = DEFAULT_ORIGINATE;
	unsigned long metric = 0;
	const char *routemap = NULL;
	struct isis_area *area = yang_dnode_get_entry(dnode, true);
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
	else if (yang_dnode_exists(dnode, "./route-map"))
		routemap = yang_dnode_get_string(dnode, "./route-map");

	isis_redist_set(area, level, family, DEFAULT_ROUTE, metric, routemap,
			originate_type);
}

static void default_info_origin_ipv4_apply_finish(const struct lyd_node *dnode)
{
	default_info_origin_apply_finish(dnode, AF_INET);
}

static void default_info_origin_ipv6_apply_finish(const struct lyd_node *dnode)
{
	default_info_origin_apply_finish(dnode, AF_INET6);
}

static int isis_instance_default_information_originate_ipv4_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv4_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	level = yang_dnode_get_enum(dnode, "./level");
	isis_redist_unset(area, level, AF_INET, DEFAULT_ROUTE);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/always
 */
static int isis_instance_default_information_originate_ipv4_always_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/route-map
 */
static int isis_instance_default_information_originate_ipv4_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv4_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/metric
 */
static int isis_instance_default_information_originate_ipv4_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv4_metric_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6
 */
static int isis_instance_default_information_originate_ipv6_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv6_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	level = yang_dnode_get_enum(dnode, "./level");
	isis_redist_unset(area, level, AF_INET6, DEFAULT_ROUTE);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/always
 */
static int isis_instance_default_information_originate_ipv6_always_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/route-map
 */
static int isis_instance_default_information_originate_ipv6_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv6_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/metric
 */
static int isis_instance_default_information_originate_ipv6_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv6_metric_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4
 */
static void redistribute_apply_finish(const struct lyd_node *dnode, int family)
{
	assert(family == AF_INET || family == AF_INET6);
	int type, level;
	unsigned long metric = 0;
	const char *routemap = NULL;
	struct isis_area *area;

	type = yang_dnode_get_enum(dnode, "./protocol");
	level = yang_dnode_get_enum(dnode, "./level");
	area = yang_dnode_get_entry(dnode, true);

	if (yang_dnode_exists(dnode, "./metric"))
		metric = yang_dnode_get_uint32(dnode, "./metric");
	else if (yang_dnode_exists(dnode, "./route-map"))
		routemap = yang_dnode_get_string(dnode, "./route-map");

	isis_redist_set(area, level, family, type, metric, routemap, 0);
}

static void redistribute_ipv4_apply_finish(const struct lyd_node *dnode)
{
	redistribute_apply_finish(dnode, AF_INET);
}

static void redistribute_ipv6_apply_finish(const struct lyd_node *dnode)
{
	redistribute_apply_finish(dnode, AF_INET6);
}

static int isis_instance_redistribute_ipv4_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

static int isis_instance_redistribute_ipv4_destroy(enum nb_event event,
						  const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level, type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	level = yang_dnode_get_enum(dnode, "./level");
	type = yang_dnode_get_enum(dnode, "./protocol");
	isis_redist_unset(area, level, AF_INET, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4/route-map
 */
static int
isis_instance_redistribute_ipv4_route_map_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv4_route_map_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4/metric
 */
static int
isis_instance_redistribute_ipv4_metric_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv4_metric_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6
 */
static int isis_instance_redistribute_ipv6_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

static int isis_instance_redistribute_ipv6_destroy(enum nb_event event,
						  const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level, type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	level = yang_dnode_get_enum(dnode, "./level");
	type = yang_dnode_get_enum(dnode, "./protocol");
	isis_redist_unset(area, level, AF_INET6, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6/route-map
 */
static int
isis_instance_redistribute_ipv6_route_map_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv6_route_map_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6/metric
 */
static int
isis_instance_redistribute_ipv6_metric_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv6_metric_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-multicast
 */
static int isis_multi_topology_common(enum nb_event event,
				      const struct lyd_node *dnode,
				      const char *topology, bool create)
{
	struct isis_area *area;
	struct isis_area_mt_setting *setting;
	uint16_t mtid = isis_str2mtid(topology);

	switch (event) {
	case NB_EV_VALIDATE:
		if (mtid == (uint16_t)-1) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Unknown topology %s", topology);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = yang_dnode_get_entry(dnode, true);
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

	area = yang_dnode_get_entry(dnode, true);
	setting = area_get_mt_setting(area, mtid);
	setting->overload = yang_dnode_get_bool(dnode, NULL);
	if (setting->enabled)
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);

	return NB_OK;
}

static int
isis_instance_multi_topology_ipv4_multicast_create(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv4-multicast", true);
}

static int
isis_instance_multi_topology_ipv4_multicast_destroy(enum nb_event event,
						   const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv4-multicast",
					  false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload
 */
static int isis_instance_multi_topology_ipv4_multicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode,
						   "ipv4-multicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management
 */
static int isis_instance_multi_topology_ipv4_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv4-mgmt", true);
}

static int isis_instance_multi_topology_ipv4_management_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv4-mgmt", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management/overload
 */
static int isis_instance_multi_topology_ipv4_management_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode, "ipv4-mgmt");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast
 */
static int
isis_instance_multi_topology_ipv6_unicast_create(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-unicast", true);
}

static int
isis_instance_multi_topology_ipv6_unicast_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-unicast", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload
 */
static int isis_instance_multi_topology_ipv6_unicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode,
						   "ipv6-unicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast
 */
static int
isis_instance_multi_topology_ipv6_multicast_create(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-multicast", true);
}

static int
isis_instance_multi_topology_ipv6_multicast_destroy(enum nb_event event,
						   const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-multicast",
					  false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload
 */
static int isis_instance_multi_topology_ipv6_multicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode,
						   "ipv6-multicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management
 */
static int isis_instance_multi_topology_ipv6_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-mgmt", true);
}

static int isis_instance_multi_topology_ipv6_management_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-mgmt", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management/overload
 */
static int isis_instance_multi_topology_ipv6_management_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode, "ipv6-mgmt");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc
 */
static int
isis_instance_multi_topology_ipv6_dstsrc_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-dstsrc", true);
}

static int
isis_instance_multi_topology_ipv6_dstsrc_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-dstsrc", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload
 */
static int isis_instance_multi_topology_ipv6_dstsrc_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode, "ipv6-dstsrc");
}

/*
 * XPath: /frr-isisd:isis/instance/log-adjacency-changes
 */
static int
isis_instance_log_adjacency_changes_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct isis_area *area;
	bool log = yang_dnode_get_bool(dnode, NULL);

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = yang_dnode_get_entry(dnode, true);
	area->log_adj_changes = log ? 1 : 0;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/mpls-te
 */
static int isis_mpls_te_create(enum nb_event event,
			       const struct lyd_node *dnode,
			       union nb_resource *resource)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	isisMplsTE.status = enable;

	/*
	 * Following code is intended to handle two cases;
	 *
	 * 1) MPLS-TE was disabled at startup time, but now become enabled.
	 * In this case, we must enable MPLS-TE Circuit regarding interface
	 * MPLS_TE flag
	 * 2) MPLS-TE was once enabled then disabled, and now enabled again.
	 */
	for (ALL_LIST_ELEMENTS_RO(isisMplsTE.cir_list, node, circuit)) {
		if (circuit->mtc == NULL || IS_FLOOD_AS(circuit->mtc->type))
			continue;

		if ((circuit->mtc->status == disable)
		    && HAS_LINK_PARAMS(circuit->interface))
			circuit->mtc->status = enable;
		else
			continue;

		/* Reoriginate STD_TE & GMPLS circuits */
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);
	}

	return NB_OK;
}

static int isis_mpls_te_destroy(enum nb_event event,
			       const struct lyd_node *dnode)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	isisMplsTE.status = disable;

	/* Flush LSP if circuit engage */
	for (ALL_LIST_ELEMENTS_RO(isisMplsTE.cir_list, node, circuit)) {
		if (circuit->mtc == NULL || (circuit->mtc->status == disable))
			continue;

		/* disable MPLS_TE Circuit */
		circuit->mtc->status = disable;

		/* Re-originate circuit without STD_TE & GMPLS parameters */
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/mpls-te/router-address
 */
static int isis_mpls_te_router_address_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	struct in_addr value;
	struct listnode *node;
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&value, dnode, NULL);
	isisMplsTE.router_id.s_addr = value.s_addr;
	/* only proceed if MPLS-TE is enabled */
	if (isisMplsTE.status == disable)
		return NB_OK;

	/* Update main Router ID in isis global structure */
	isis->router_id = value.s_addr;
	/* And re-schedule LSP update */
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		if (listcount(area->area_addrs) > 0)
			lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

static int isis_mpls_te_router_address_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct listnode *node;
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	isisMplsTE.router_id.s_addr = INADDR_ANY;
	/* only proceed if MPLS-TE is enabled */
	if (isisMplsTE.status == disable)
		return NB_OK;

	/* Update main Router ID in isis global structure */
	isis->router_id = 0;
	/* And re-schedule LSP update */
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		if (listcount(area->area_addrs) > 0)
			lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis
 */
static int lib_interface_isis_create(enum nb_event event,
				     const struct lyd_node *dnode,
				     union nb_resource *resource)
{
	struct isis_area *area;
	struct interface *ifp;
	struct isis_circuit *circuit;
	const char *area_tag = yang_dnode_get_string(dnode, "./area-tag");

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = isis_area_lookup(area_tag);
	/* The area should have already be created. We are
	 * setting the priority of the global isis area creation
	 * slightly lower, so it should be executed first, but I
	 * cannot rely on that so here I have to check.
	 */
	if (!area) {
		flog_err(
			EC_LIB_NB_CB_CONFIG_APPLY,
			"%s: attempt to create circuit for area %s before the area has been created",
			__func__, area_tag);
		abort();
	}

	ifp = yang_dnode_get_entry(dnode, true);
	circuit = isis_circuit_create(area, ifp);
	assert(circuit->state == C_STATE_CONF || circuit->state == C_STATE_UP);
	yang_dnode_set_entry(dnode, circuit);

	return NB_OK;
}

static int lib_interface_isis_destroy(enum nb_event event,
				     const struct lyd_node *dnode)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	if (!circuit)
		return NB_ERR_INCONSISTENCY;
	/* delete circuit through csm changes */
	switch (circuit->state) {
	case C_STATE_UP:
		isis_csm_state_change(IF_DOWN_FROM_Z, circuit,
				      circuit->interface);
		isis_csm_state_change(ISIS_DISABLE, circuit, circuit->area);
		break;
	case C_STATE_CONF:
		isis_csm_state_change(ISIS_DISABLE, circuit, circuit->area);
		break;
	case C_STATE_INIT:
		isis_csm_state_change(IF_DOWN_FROM_Z, circuit,
				      circuit->interface);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/area-tag
 */
static int lib_interface_isis_area_tag_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	struct isis_circuit *circuit;
	struct interface *ifp;
	struct vrf *vrf;
	const char *area_tag, *ifname, *vrfname;

	if (event == NB_EV_VALIDATE) {
		/* libyang doesn't like relative paths across module boundaries
		 */
		ifname = yang_dnode_get_string(dnode->parent->parent, "./name");
		vrfname = yang_dnode_get_string(dnode->parent->parent, "./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		assert(vrf);
		ifp = if_lookup_by_name(ifname, vrf->vrf_id);
		if (!ifp)
			return NB_OK;
		circuit = circuit_lookup_by_ifp(ifp, isis->init_circ_list);
		area_tag = yang_dnode_get_string(dnode, NULL);
		if (circuit && circuit->area && circuit->area->area_tag
		    && strcmp(circuit->area->area_tag, area_tag)) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
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
static int lib_interface_isis_circuit_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	int circ_type = yang_dnode_get_enum(dnode, NULL);
	struct isis_circuit *circuit;
	struct interface *ifp;
	struct vrf *vrf;
	const char *ifname, *vrfname;

	switch (event) {
	case NB_EV_VALIDATE:
		/* libyang doesn't like relative paths across module boundaries
		 */
		ifname = yang_dnode_get_string(dnode->parent->parent, "./name");
		vrfname = yang_dnode_get_string(dnode->parent->parent, "./vrf");
		vrf = vrf_lookup_by_name(vrfname);
		assert(vrf);
		ifp = if_lookup_by_name(ifname, vrf->vrf_id);
		if (!ifp)
			break;
		circuit = circuit_lookup_by_ifp(ifp, isis->init_circ_list);
		if (circuit && circuit->state == C_STATE_UP
		    && circuit->area->is_type != IS_LEVEL_1_AND_2
		    && circuit->area->is_type != circ_type) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Invalid circuit level for area %s",
				  circuit->area->area_tag);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = yang_dnode_get_entry(dnode, true);
		isis_circuit_is_type_set(circuit, circ_type);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv4-routing
 */
static int lib_interface_isis_ipv4_routing_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	bool ipv4, ipv6;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	ipv4 = yang_dnode_get_bool(dnode, NULL);
	ipv6 = yang_dnode_get_bool(dnode, "../ipv6-routing");
	isis_circuit_af_set(circuit, ipv4, ipv6);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv6-routing
 */
static int lib_interface_isis_ipv6_routing_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	bool ipv4, ipv6;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	ipv4 = yang_dnode_exists(dnode, "../ipv4-routing");
	ipv6 = yang_dnode_get_bool(dnode, NULL);
	isis_circuit_af_set(circuit, ipv4, ipv6);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-1
 */
static int
lib_interface_isis_csnp_interval_level_1_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->csnp_interval[0] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-2
 */
static int
lib_interface_isis_csnp_interval_level_2_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->csnp_interval[1] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-1
 */
static int
lib_interface_isis_psnp_interval_level_1_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->psnp_interval[0] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-2
 */
static int
lib_interface_isis_psnp_interval_level_2_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->psnp_interval[1] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/padding
 */
static int lib_interface_isis_hello_padding_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->pad_hellos = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-1
 */
static int
lib_interface_isis_hello_interval_level_1_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint32_t interval;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	interval = yang_dnode_get_uint32(dnode, NULL);
	circuit->hello_interval[0] = interval;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-2
 */
static int
lib_interface_isis_hello_interval_level_2_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint32_t interval;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	interval = yang_dnode_get_uint32(dnode, NULL);
	circuit->hello_interval[1] = interval;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1
 */
static int
lib_interface_isis_hello_multiplier_level_1_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint16_t multi;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	multi = yang_dnode_get_uint16(dnode, NULL);
	circuit->hello_multiplier[0] = multi;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2
 */
static int
lib_interface_isis_hello_multiplier_level_2_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint16_t multi;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	multi = yang_dnode_get_uint16(dnode, NULL);
	circuit->hello_multiplier[1] = multi;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/metric/level-1
 */
static int
lib_interface_isis_metric_level_1_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct isis_circuit *circuit;
	unsigned int met;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	met = yang_dnode_get_uint32(dnode, NULL);
	isis_circuit_metric_set(circuit, IS_LEVEL_1, met);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/metric/level-2
 */
static int
lib_interface_isis_metric_level_2_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct isis_circuit *circuit;
	unsigned int met;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	met = yang_dnode_get_uint32(dnode, NULL);
	isis_circuit_metric_set(circuit, IS_LEVEL_2, met);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/priority/level-1
 */
static int
lib_interface_isis_priority_level_1_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->priority[0] = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/priority/level-2
 */
static int
lib_interface_isis_priority_level_2_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->priority[1] = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/network-type
 */
static int lib_interface_isis_network_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct isis_circuit *circuit;
	int net_type = yang_dnode_get_enum(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		circuit = yang_dnode_get_entry(dnode, false);
		if (!circuit)
			break;
		if (circuit->circ_type == CIRCUIT_T_LOOPBACK) {
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Cannot change network type on loopback interface");
			return NB_ERR_VALIDATION;
		}
		if (net_type == CIRCUIT_T_BROADCAST
		    && circuit->state == C_STATE_UP
		    && !if_is_broadcast(circuit->interface)) {
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Cannot configure non-broadcast interface for broadcast operation");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = yang_dnode_get_entry(dnode, true);
		isis_circuit_circ_type_set(circuit, net_type);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/passive
 */
static int lib_interface_isis_passive_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct interface *ifp;
	bool passive = yang_dnode_get_bool(dnode, NULL);

	/* validation only applies if we are setting passive to false */
	if (!passive && event == NB_EV_VALIDATE) {
		circuit = yang_dnode_get_entry(dnode, false);
		if (!circuit)
			return NB_OK;
		ifp = circuit->interface;
		if (!ifp)
			return NB_OK;
		if (if_is_loopback(ifp)) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Loopback is always passive");
			return NB_ERR_VALIDATION;
		}
	}

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	if (circuit->state != C_STATE_UP) {
		circuit->is_passive = passive;
	} else {
		area = circuit->area;
		isis_csm_state_change(ISIS_DISABLE, circuit, area);
		circuit->is_passive = passive;
		isis_csm_state_change(ISIS_ENABLE, circuit, area);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password
 */
static int lib_interface_isis_password_create(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	return NB_OK;
}

static int lib_interface_isis_password_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	isis_circuit_passwd_unset(circuit);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password/password
 */
static int
lib_interface_isis_password_password_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct isis_circuit *circuit;
	const char *password;

	if (event != NB_EV_APPLY)
		return NB_OK;

	password = yang_dnode_get_string(dnode, NULL);
	circuit = yang_dnode_get_entry(dnode, true);

	isis_circuit_passwd_set(circuit, circuit->passwd.type, password);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password/password-type
 */
static int
lib_interface_isis_password_password_type_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint8_t pass_type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pass_type = yang_dnode_get_enum(dnode, NULL);
	circuit = yang_dnode_get_entry(dnode, true);
	circuit->passwd.type = pass_type;

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake
 */
static int lib_interface_isis_disable_three_way_handshake_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = yang_dnode_get_entry(dnode, true);
	circuit->disable_threeway_adj = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-unicast
 */
static int lib_interface_isis_multi_topology_common(
	enum nb_event event, const struct lyd_node *dnode, uint16_t mtid)
{
	struct isis_circuit *circuit;
	bool value;

	switch (event) {
	case NB_EV_VALIDATE:
		circuit = yang_dnode_get_entry(dnode, false);
		if (circuit && circuit->area && circuit->area->oldmetric) {
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Multi topology IS-IS can only be used with wide metrics");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		circuit = yang_dnode_get_entry(dnode, true);
		value = yang_dnode_get_bool(dnode, NULL);
		isis_circuit_mt_enabled_set(circuit, mtid, value);
		break;
	}

	return NB_OK;
}

static int lib_interface_isis_multi_topology_ipv4_unicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV4_UNICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-multicast
 */
static int lib_interface_isis_multi_topology_ipv4_multicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV4_MULTICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-management
 */
static int lib_interface_isis_multi_topology_ipv4_management_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV4_MGMT);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-unicast
 */
static int lib_interface_isis_multi_topology_ipv6_unicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV6_UNICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-multicast
 */
static int lib_interface_isis_multi_topology_ipv6_multicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV6_MULTICAST);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-management
 */
static int lib_interface_isis_multi_topology_ipv6_management_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV6_MGMT);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc
 */
static int lib_interface_isis_multi_topology_ipv6_dstsrc_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV6_DSTSRC);
}

/*
 * NOTIFICATIONS
 */
static void notif_prep_instance_hdr(const char *xpath,
				    const struct isis_area *area,
				    const char *routing_instance,
				    struct list *args)
{
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/routing-instance", xpath);
	data = yang_data_new_string(xpath_arg, routing_instance);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/routing-protocol-name",
		 xpath);
	data = yang_data_new_string(xpath_arg, area->area_tag);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/isis-level", xpath);
	data = yang_data_new_enum(xpath_arg, area->is_type);
	listnode_add(args, data);
}

static void notif_prepr_iface_hdr(const char *xpath,
				  const struct isis_circuit *circuit,
				  struct list *args)
{
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-name", xpath);
	data = yang_data_new_string(xpath_arg, circuit->interface->name);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-level", xpath);
	data = yang_data_new_enum(xpath_arg, circuit->is_type);
	listnode_add(args, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/extended-circuit-id", xpath);
	/* we do not seem to have the extended version of the circuit_id */
	data = yang_data_new_uint32(xpath_arg, (uint32_t)circuit->circuit_id);
	listnode_add(args, data);
}

/*
 * XPath:
 * /frr-isisd:database-overload
 */
void isis_notif_db_overload(const struct isis_area *area, bool overload)
{
	const char *xpath = "/frr-isisd:database-overload";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/overload", xpath);
	data = yang_data_new_enum(xpath_arg, !!overload);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:lsp-too-large
 */
void isis_notif_lsp_too_large(const struct isis_circuit *circuit,
			      uint32_t pdu_size, const char *lsp_id)
{
	const char *xpath = "/frr-isisd:lsp-too-large";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/pdu-size", xpath);
	data = yang_data_new_uint32(xpath_arg, pdu_size);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:if-state-change
 */
void isis_notif_if_state_change(const struct isis_circuit *circuit, bool down)
{
	const char *xpath = "/frr-isisd:if-state-change";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	data = yang_data_new_enum(xpath_arg, !!down);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:corrupted-lsp-detected
 */
void isis_notif_corrupted_lsp(const struct isis_area *area, const char *lsp_id)
{
	const char *xpath = "/frr-isisd:corrupted-lsp-detected";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:attempt-to-exceed-max-sequence
 */
void isis_notif_lsp_exceed_max(const struct isis_area *area, const char *lsp_id)
{
	const char *xpath = "/frr-isisd:attempt-to-exceed-max-sequence";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:max-area-addresses-mismatch
 */
void isis_notif_max_area_addr_mismatch(const struct isis_circuit *circuit,
				       uint8_t max_area_addrs,
				       const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:max-area-addresses-mismatch";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/max-area-addresses", xpath);
	data = yang_data_new_uint8(xpath_arg, max_area_addrs);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:authentication-type-failure
 */
void isis_notif_authentication_type_failure(const struct isis_circuit *circuit,
					    const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:authentication-type-failure";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:authentication-failure
 */
void isis_notif_authentication_failure(const struct isis_circuit *circuit,
				       const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:authentication-failure";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:adjacency-state-change
 */
void isis_notif_adj_state_change(const struct isis_adjacency *adj,
				 int new_state, const char *reason)
{
	const char *xpath = "/frr-isisd:adjacency-state-change";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_circuit *circuit = adj->circuit;
	struct isis_area *area = circuit->area;
	struct isis_dynhn *dyn = dynhn_find_by_id(adj->sysid);

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	if (dyn) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor", xpath);
		data = yang_data_new_string(xpath_arg, dyn->hostname);
		listnode_add(arguments, data);
	}
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-system-id", xpath);
	data = yang_data_new_string(xpath_arg, sysid_print(adj->sysid));
	listnode_add(arguments, data);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	switch (new_state) {
	case ISIS_ADJ_DOWN:
		data = yang_data_new_string(xpath_arg, "down");
		break;
	case ISIS_ADJ_UP:
		data = yang_data_new_string(xpath_arg, "up");
		break;
	case ISIS_ADJ_INITIALIZING:
		data = yang_data_new_string(xpath_arg, "init");
		break;
	default:
		data = yang_data_new_string(xpath_arg, "failed");
	}
	listnode_add(arguments, data);
	if (new_state == ISIS_ADJ_DOWN) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/reason", xpath);
		data = yang_data_new_string(xpath_arg, reason);
		listnode_add(arguments, data);
	}

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:rejected-adjacency
 */
void isis_notif_reject_adjacency(const struct isis_circuit *circuit,
				 const char *reason, const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:rejected-adjacency";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/reason", xpath);
	data = yang_data_new_string(xpath_arg, reason);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:area-mismatch
 */
void isis_notif_area_mismatch(const struct isis_circuit *circuit,
			      const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:area-mismatch";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:lsp-received
 */
void isis_notif_lsp_received(const struct isis_circuit *circuit,
			     const char *lsp_id, uint32_t seqno,
			     uint32_t timestamp, const char *sys_id)
{
	const char *xpath = "/frr-isisd:lsp-received";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/sequence", xpath);
	data = yang_data_new_uint32(xpath_arg, seqno);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/received-timestamp", xpath);
	data = yang_data_new_uint32(xpath_arg, timestamp);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-system-id", xpath);
	data = yang_data_new_string(xpath_arg, sys_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:lsp-generation
 */
void isis_notif_lsp_gen(const struct isis_area *area, const char *lsp_id,
			uint32_t seqno, uint32_t timestamp)
{
	const char *xpath = "/frr-isisd:lsp-generation";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/sequence", xpath);
	data = yang_data_new_uint32(xpath_arg, seqno);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/send-timestamp", xpath);
	data = yang_data_new_uint32(xpath_arg, timestamp);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:id-len-mismatch
 */
void isis_notif_id_len_mismatch(const struct isis_circuit *circuit,
				uint8_t rcv_id_len, const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:id-len-mismatch";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/pdu-field-len", xpath);
	data = yang_data_new_uint8(xpath_arg, rcv_id_len);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:version-skew
 */
void isis_notif_version_skew(const struct isis_circuit *circuit,
			     uint8_t version, const char *raw_pdu)
{
	const char *xpath = "/frr-isisd:version-skew";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/protocol-version", xpath);
	data = yang_data_new_uint8(xpath_arg, version);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:lsp-error-detected
 */
void isis_notif_lsp_error(const struct isis_circuit *circuit,
			  const char *lsp_id, const char *raw_pdu,
			  __attribute__((unused)) uint32_t offset,
			  __attribute__((unused)) uint8_t tlv_type)
{
	const char *xpath = "/frr-isisd:lsp-error-detected";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/raw-pdu", xpath);
	data = yang_data_new(xpath_arg, raw_pdu);
	listnode_add(arguments, data);
	/* ignore offset and tlv_type which cannot be set properly */

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:sequence-number-skipped
 */
void isis_notif_seqno_skipped(const struct isis_circuit *circuit,
			      const char *lsp_id)
{
	const char *xpath = "/frr-isisd:sequence-number-skipped";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath:
 * /frr-isisd:own-lsp-purge
 */
void isis_notif_own_lsp_purge(const struct isis_circuit *circuit,
			      const char *lsp_id)
{
	const char *xpath = "/frr-isisd:own-lsp-purge";
	struct list *arguments = yang_data_list_new();
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;
	struct isis_area *area = circuit->area;

	notif_prep_instance_hdr(xpath, area, "default", arguments);
	notif_prepr_iface_hdr(xpath, circuit, arguments);
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/lsp-id", xpath);
	data = yang_data_new_string(xpath_arg, lsp_id);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/* clang-format off */
const struct frr_yang_module_info frr_isisd_info = {
	.name = "frr-isisd",
	.nodes = {
		{
			.xpath = "/frr-isisd:isis/instance",
			.cbs.create = isis_instance_create,
			.cbs.destroy = isis_instance_destroy,
			.cbs.cli_show = cli_show_router_isis,
			.priority = NB_DFLT_PRIORITY - 1,
		},
		{
			.xpath = "/frr-isisd:isis/instance/is-type",
			.cbs.modify = isis_instance_is_type_modify,
			.cbs.cli_show = cli_show_isis_is_type,
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-address",
			.cbs.create = isis_instance_area_address_create,
			.cbs.destroy = isis_instance_area_address_destroy,
			.cbs.cli_show = cli_show_isis_area_address,
		},
		{
			.xpath = "/frr-isisd:isis/instance/dynamic-hostname",
			.cbs.modify = isis_instance_dynamic_hostname_modify,
			.cbs.cli_show = cli_show_isis_dynamic_hostname,
		},
		{
			.xpath = "/frr-isisd:isis/instance/attached",
			.cbs.modify = isis_instance_attached_modify,
			.cbs.cli_show = cli_show_isis_attached,
		},
		{
			.xpath = "/frr-isisd:isis/instance/overload",
			.cbs.modify = isis_instance_overload_modify,
			.cbs.cli_show = cli_show_isis_overload,
		},
		{
			.xpath = "/frr-isisd:isis/instance/metric-style",
			.cbs.modify = isis_instance_metric_style_modify,
			.cbs.cli_show = cli_show_isis_metric_style,
		},
		{
			.xpath = "/frr-isisd:isis/instance/purge-originator",
			.cbs.modify = isis_instance_purge_originator_modify,
			.cbs.cli_show = cli_show_isis_purge_origin,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/mtu",
			.cbs.modify = isis_instance_lsp_mtu_modify,
			.cbs.cli_show = cli_show_isis_lsp_mtu,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/refresh-interval",
			.cbs.cli_show = cli_show_isis_lsp_ref_interval,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/refresh-interval/level-1",
			.cbs.modify = isis_instance_lsp_refresh_interval_level_1_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/refresh-interval/level-2",
			.cbs.modify = isis_instance_lsp_refresh_interval_level_2_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime",
			.cbs.cli_show = cli_show_isis_lsp_max_lifetime,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime/level-1",
			.cbs.modify = isis_instance_lsp_maximum_lifetime_level_1_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime/level-2",
			.cbs.modify = isis_instance_lsp_maximum_lifetime_level_2_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/generation-interval",
			.cbs.cli_show = cli_show_isis_lsp_gen_interval,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/generation-interval/level-1",
			.cbs.modify = isis_instance_lsp_generation_interval_level_1_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/generation-interval/level-2",
			.cbs.modify = isis_instance_lsp_generation_interval_level_2_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay",
			.cbs.create = isis_instance_spf_ietf_backoff_delay_create,
			.cbs.destroy = isis_instance_spf_ietf_backoff_delay_destroy,
			.cbs.apply_finish = ietf_backoff_delay_apply_finish,
			.cbs.cli_show = cli_show_isis_spf_ietf_backoff,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/init-delay",
			.cbs.modify = isis_instance_spf_ietf_backoff_delay_init_delay_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/short-delay",
			.cbs.modify = isis_instance_spf_ietf_backoff_delay_short_delay_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/long-delay",
			.cbs.modify = isis_instance_spf_ietf_backoff_delay_long_delay_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/hold-down",
			.cbs.modify = isis_instance_spf_ietf_backoff_delay_hold_down_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/ietf-backoff-delay/time-to-learn",
			.cbs.modify = isis_instance_spf_ietf_backoff_delay_time_to_learn_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval",
			.cbs.cli_show = cli_show_isis_spf_min_interval,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval/level-1",
			.cbs.modify = isis_instance_spf_minimum_interval_level_1_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/spf/minimum-interval/level-2",
			.cbs.modify = isis_instance_spf_minimum_interval_level_2_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password",
			.cbs.create = isis_instance_area_password_create,
			.cbs.destroy = isis_instance_area_password_destroy,
			.cbs.apply_finish = area_password_apply_finish,
			.cbs.cli_show = cli_show_isis_area_pwd,
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/password",
			.cbs.modify = isis_instance_area_password_password_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/password-type",
			.cbs.modify = isis_instance_area_password_password_type_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-password/authenticate-snp",
			.cbs.modify = isis_instance_area_password_authenticate_snp_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password",
			.cbs.create = isis_instance_domain_password_create,
			.cbs.destroy = isis_instance_domain_password_destroy,
			.cbs.apply_finish = domain_password_apply_finish,
			.cbs.cli_show = cli_show_isis_domain_pwd,
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/password",
			.cbs.modify = isis_instance_domain_password_password_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/password-type",
			.cbs.modify = isis_instance_domain_password_password_type_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/domain-password/authenticate-snp",
			.cbs.modify = isis_instance_domain_password_authenticate_snp_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4",
			.cbs.create = isis_instance_default_information_originate_ipv4_create,
			.cbs.destroy = isis_instance_default_information_originate_ipv4_destroy,
			.cbs.apply_finish = default_info_origin_ipv4_apply_finish,
			.cbs.cli_show = cli_show_isis_def_origin_ipv4,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/always",
			.cbs.modify = isis_instance_default_information_originate_ipv4_always_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/route-map",
			.cbs.modify = isis_instance_default_information_originate_ipv4_route_map_modify,
			.cbs.destroy = isis_instance_default_information_originate_ipv4_route_map_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/metric",
			.cbs.modify = isis_instance_default_information_originate_ipv4_metric_modify,
			.cbs.destroy = isis_instance_default_information_originate_ipv4_metric_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6",
			.cbs.create = isis_instance_default_information_originate_ipv6_create,
			.cbs.destroy = isis_instance_default_information_originate_ipv6_destroy,
			.cbs.apply_finish = default_info_origin_ipv6_apply_finish,
			.cbs.cli_show = cli_show_isis_def_origin_ipv6,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/always",
			.cbs.modify = isis_instance_default_information_originate_ipv6_always_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/route-map",
			.cbs.modify = isis_instance_default_information_originate_ipv6_route_map_modify,
			.cbs.destroy = isis_instance_default_information_originate_ipv6_route_map_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/metric",
			.cbs.modify = isis_instance_default_information_originate_ipv6_metric_modify,
			.cbs.destroy = isis_instance_default_information_originate_ipv6_metric_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4",
			.cbs.create = isis_instance_redistribute_ipv4_create,
			.cbs.destroy = isis_instance_redistribute_ipv4_destroy,
			.cbs.apply_finish = redistribute_ipv4_apply_finish,
			.cbs.cli_show = cli_show_isis_redistribute_ipv4,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/route-map",
			.cbs.modify = isis_instance_redistribute_ipv4_route_map_modify,
			.cbs.destroy = isis_instance_redistribute_ipv4_route_map_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/metric",
			.cbs.modify = isis_instance_redistribute_ipv4_metric_modify,
			.cbs.destroy = isis_instance_redistribute_ipv4_metric_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6",
			.cbs.create = isis_instance_redistribute_ipv6_create,
			.cbs.destroy = isis_instance_redistribute_ipv6_destroy,
			.cbs.apply_finish = redistribute_ipv6_apply_finish,
			.cbs.cli_show = cli_show_isis_redistribute_ipv6,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/route-map",
			.cbs.modify = isis_instance_redistribute_ipv6_route_map_modify,
			.cbs.destroy = isis_instance_redistribute_ipv6_route_map_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/metric",
			.cbs.modify = isis_instance_redistribute_ipv6_metric_modify,
			.cbs.destroy = isis_instance_redistribute_ipv6_metric_destroy,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast",
			.cbs.create = isis_instance_multi_topology_ipv4_multicast_create,
			.cbs.destroy = isis_instance_multi_topology_ipv4_multicast_destroy,
			.cbs.cli_show = cli_show_isis_mt_ipv4_multicast,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload",
			.cbs.modify = isis_instance_multi_topology_ipv4_multicast_overload_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management",
			.cbs.create = isis_instance_multi_topology_ipv4_management_create,
			.cbs.destroy = isis_instance_multi_topology_ipv4_management_destroy,
			.cbs.cli_show = cli_show_isis_mt_ipv4_mgmt,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management/overload",
			.cbs.modify = isis_instance_multi_topology_ipv4_management_overload_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast",
			.cbs.create = isis_instance_multi_topology_ipv6_unicast_create,
			.cbs.destroy = isis_instance_multi_topology_ipv6_unicast_destroy,
			.cbs.cli_show = cli_show_isis_mt_ipv6_unicast,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload",
			.cbs.modify = isis_instance_multi_topology_ipv6_unicast_overload_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast",
			.cbs.create = isis_instance_multi_topology_ipv6_multicast_create,
			.cbs.destroy = isis_instance_multi_topology_ipv6_multicast_destroy,
			.cbs.cli_show = cli_show_isis_mt_ipv6_multicast,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload",
			.cbs.modify = isis_instance_multi_topology_ipv6_multicast_overload_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management",
			.cbs.create = isis_instance_multi_topology_ipv6_management_create,
			.cbs.destroy = isis_instance_multi_topology_ipv6_management_destroy,
			.cbs.cli_show = cli_show_isis_mt_ipv6_mgmt,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management/overload",
			.cbs.modify = isis_instance_multi_topology_ipv6_management_overload_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc",
			.cbs.create = isis_instance_multi_topology_ipv6_dstsrc_create,
			.cbs.destroy = isis_instance_multi_topology_ipv6_dstsrc_destroy,
			.cbs.cli_show = cli_show_isis_mt_ipv6_dstsrc,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload",
			.cbs.modify = isis_instance_multi_topology_ipv6_dstsrc_overload_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/log-adjacency-changes",
			.cbs.modify = isis_instance_log_adjacency_changes_modify,
			.cbs.cli_show = cli_show_isis_log_adjacency,
		},
		{
			.xpath = "/frr-isisd:isis/mpls-te",
			.cbs.create = isis_mpls_te_create,
			.cbs.destroy = isis_mpls_te_destroy,
			.cbs.cli_show = cli_show_isis_mpls_te,
		},
		{
			.xpath = "/frr-isisd:isis/mpls-te/router-address",
			.cbs.modify = isis_mpls_te_router_address_modify,
			.cbs.destroy = isis_mpls_te_router_address_destroy,
			.cbs.cli_show = cli_show_isis_mpls_te_router_addr,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis",
			.cbs.create = lib_interface_isis_create,
			.cbs.destroy = lib_interface_isis_destroy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/area-tag",
			.cbs.modify = lib_interface_isis_area_tag_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/circuit-type",
			.cbs.modify = lib_interface_isis_circuit_type_modify,
			.cbs.cli_show = cli_show_ip_isis_circ_type,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv4-routing",
			.cbs.modify = lib_interface_isis_ipv4_routing_modify,
			.cbs.cli_show = cli_show_ip_isis_ipv4,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv6-routing",
			.cbs.modify = lib_interface_isis_ipv6_routing_modify,
			.cbs.cli_show = cli_show_ip_isis_ipv6,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval",
			.cbs.cli_show = cli_show_ip_isis_csnp_interval,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-1",
			.cbs.modify = lib_interface_isis_csnp_interval_level_1_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-2",
			.cbs.modify = lib_interface_isis_csnp_interval_level_2_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval",
			.cbs.cli_show = cli_show_ip_isis_psnp_interval,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-1",
			.cbs.modify = lib_interface_isis_psnp_interval_level_1_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-2",
			.cbs.modify = lib_interface_isis_psnp_interval_level_2_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/padding",
			.cbs.modify = lib_interface_isis_hello_padding_modify,
			.cbs.cli_show = cli_show_ip_isis_hello_padding,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval",
			.cbs.cli_show = cli_show_ip_isis_hello_interval,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-1",
			.cbs.modify = lib_interface_isis_hello_interval_level_1_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-2",
			.cbs.modify = lib_interface_isis_hello_interval_level_2_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier",
			.cbs.cli_show = cli_show_ip_isis_hello_multi,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1",
			.cbs.modify = lib_interface_isis_hello_multiplier_level_1_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2",
			.cbs.modify = lib_interface_isis_hello_multiplier_level_2_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric",
			.cbs.cli_show = cli_show_ip_isis_metric,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric/level-1",
			.cbs.modify = lib_interface_isis_metric_level_1_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/metric/level-2",
			.cbs.modify = lib_interface_isis_metric_level_2_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority",
			.cbs.cli_show = cli_show_ip_isis_priority,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority/level-1",
			.cbs.modify = lib_interface_isis_priority_level_1_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/priority/level-2",
			.cbs.modify = lib_interface_isis_priority_level_2_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/network-type",
			.cbs.modify = lib_interface_isis_network_type_modify,
			.cbs.cli_show = cli_show_ip_isis_network_type,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/passive",
			.cbs.modify = lib_interface_isis_passive_modify,
			.cbs.cli_show = cli_show_ip_isis_passive,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password",
			.cbs.create = lib_interface_isis_password_create,
			.cbs.destroy = lib_interface_isis_password_destroy,
			.cbs.cli_show = cli_show_ip_isis_password,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password/password",
			.cbs.modify = lib_interface_isis_password_password_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password/password-type",
			.cbs.modify = lib_interface_isis_password_password_type_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake",
			.cbs.modify = lib_interface_isis_disable_three_way_handshake_modify,
			.cbs.cli_show = cli_show_ip_isis_threeway_shake,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-unicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv4_unicast_modify,
			.cbs.cli_show = cli_show_ip_isis_mt_ipv4_unicast,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-multicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv4_multicast_modify,
			.cbs.cli_show = cli_show_ip_isis_mt_ipv4_multicast,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-management",
			.cbs.modify = lib_interface_isis_multi_topology_ipv4_management_modify,
			.cbs.cli_show = cli_show_ip_isis_mt_ipv4_mgmt,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-unicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_unicast_modify,
			.cbs.cli_show = cli_show_ip_isis_mt_ipv6_unicast,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-multicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_multicast_modify,
			.cbs.cli_show = cli_show_ip_isis_mt_ipv6_multicast,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-management",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_management_modify,
			.cbs.cli_show = cli_show_ip_isis_mt_ipv6_mgmt,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_dstsrc_modify,
			.cbs.cli_show = cli_show_ip_isis_mt_ipv6_dstsrc,
		},
		{
			.xpath = NULL,
		},
	}
};
