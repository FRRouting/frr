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
#include "linklist.h"
#include "log.h"
#include "bfd.h"
#include "spf_backoff.h"
#include "lib_errors.h"
#include "vrf.h"

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
#include "isisd/isis_te.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_redist.h"

/*
 * XPath: /frr-isisd:isis/instance
 */
int isis_instance_create(enum nb_event event, const struct lyd_node *dnode,
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
	nb_running_set_entry(dnode, area);

	return NB_OK;
}

int isis_instance_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_unset_entry(dnode);
	isis_area_destroy(area->area_tag);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/is-type
 */
int isis_instance_is_type_modify(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource)
{
	struct isis_area *area;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, NULL);
	isis_area_is_type_set(area, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-address
 */
int isis_instance_area_address_create(enum nb_event event,
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
		area = nb_running_get_entry(dnode, NULL, true);
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

int isis_instance_area_address_destroy(enum nb_event event,
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
	area = nb_running_get_entry(dnode, NULL, true);
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
int isis_instance_dynamic_hostname_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	isis_area_dynhostname_set(area, yang_dnode_get_bool(dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/attached
 */
int isis_instance_attached_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	struct isis_area *area;
	bool attached;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	attached = yang_dnode_get_bool(dnode, NULL);
	isis_area_attached_bit_set(area, attached);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/overload
 */
int isis_instance_overload_modify(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	struct isis_area *area;
	bool overload;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	overload = yang_dnode_get_bool(dnode, NULL);
	isis_area_overload_bit_set(area, overload);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/metric-style
 */
int isis_instance_metric_style_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource)
{
	struct isis_area *area;
	bool old_metric, new_metric;
	enum isis_metric_style metric_style = yang_dnode_get_enum(dnode, NULL);

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	old_metric = (metric_style == ISIS_WIDE_METRIC) ? false : true;
	new_metric = (metric_style == ISIS_NARROW_METRIC) ? false : true;
	isis_area_metricstyle_set(area, old_metric, new_metric);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/purge-originator
 */
int isis_instance_purge_originator_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	area->purge_originator = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/mtu
 */
int isis_instance_lsp_mtu_modify(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource)
{
	struct listnode *node;
	struct isis_circuit *circuit;
	uint16_t lsp_mtu = yang_dnode_get_uint16(dnode, NULL);
	struct isis_area *area;

	switch (event) {
	case NB_EV_VALIDATE:
		area = nb_running_get_entry(dnode, NULL, false);
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
		area = nb_running_get_entry(dnode, NULL, true);
		isis_area_lsp_mtu_set(area, lsp_mtu);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/refresh-interval/level-1
 */
int isis_instance_lsp_refresh_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t refr_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	refr_int = yang_dnode_get_uint16(dnode, NULL);
	area = nb_running_get_entry(dnode, NULL, true);
	isis_area_lsp_refresh_set(area, IS_LEVEL_1, refr_int);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/refresh-interval/level-2
 */
int isis_instance_lsp_refresh_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t refr_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	refr_int = yang_dnode_get_uint16(dnode, NULL);
	area = nb_running_get_entry(dnode, NULL, true);
	isis_area_lsp_refresh_set(area, IS_LEVEL_2, refr_int);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/maximum-lifetime/level-1
 */
int isis_instance_lsp_maximum_lifetime_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t max_lt;

	if (event != NB_EV_APPLY)
		return NB_OK;

	max_lt = yang_dnode_get_uint16(dnode, NULL);
	area = nb_running_get_entry(dnode, NULL, true);
	isis_area_max_lsp_lifetime_set(area, IS_LEVEL_1, max_lt);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/maximum-lifetime/level-2
 */
int isis_instance_lsp_maximum_lifetime_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t max_lt;

	if (event != NB_EV_APPLY)
		return NB_OK;

	max_lt = yang_dnode_get_uint16(dnode, NULL);
	area = nb_running_get_entry(dnode, NULL, true);
	isis_area_max_lsp_lifetime_set(area, IS_LEVEL_2, max_lt);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/generation-interval/level-1
 */
int isis_instance_lsp_generation_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t gen_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	gen_int = yang_dnode_get_uint16(dnode, NULL);
	area = nb_running_get_entry(dnode, NULL, true);
	area->lsp_gen_interval[0] = gen_int;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/generation-interval/level-2
 */
int isis_instance_lsp_generation_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;
	uint16_t gen_int;

	if (event != NB_EV_APPLY)
		return NB_OK;

	gen_int = yang_dnode_get_uint16(dnode, NULL);
	area = nb_running_get_entry(dnode, NULL, true);
	area->lsp_gen_interval[1] = gen_int;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay
 */
void ietf_backoff_delay_apply_finish(const struct lyd_node *dnode)
{
	long init_delay = yang_dnode_get_uint16(dnode, "./init-delay");
	long short_delay = yang_dnode_get_uint16(dnode, "./short-delay");
	long long_delay = yang_dnode_get_uint16(dnode, "./long-delay");
	long holddown = yang_dnode_get_uint16(dnode, "./hold-down");
	long timetolearn = yang_dnode_get_uint16(dnode, "./time-to-learn");
	struct isis_area *area = nb_running_get_entry(dnode, NULL, true);
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

int isis_instance_spf_ietf_backoff_delay_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

int isis_instance_spf_ietf_backoff_delay_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
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
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/short-delay
 */
int isis_instance_spf_ietf_backoff_delay_short_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/long-delay
 */
int isis_instance_spf_ietf_backoff_delay_long_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/hold-down
 */
int isis_instance_spf_ietf_backoff_delay_hold_down_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/time-to-learn
 */
int isis_instance_spf_ietf_backoff_delay_time_to_learn_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* All the work is done in the apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/minimum-interval/level-1
 */
int isis_instance_spf_minimum_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	area->min_spf_interval[0] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/minimum-interval/level-2
 */
int isis_instance_spf_minimum_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	area->min_spf_interval[1] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password
 */
void area_password_apply_finish(const struct lyd_node *dnode)
{
	const char *password = yang_dnode_get_string(dnode, "./password");
	struct isis_area *area = nb_running_get_entry(dnode, NULL, true);
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

int isis_instance_area_password_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

int isis_instance_area_password_destroy(enum nb_event event,
					const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	isis_area_passwd_unset(area, IS_LEVEL_1);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/password
 */
int isis_instance_area_password_password_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/password-type
 */
int isis_instance_area_password_password_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/authenticate-snp
 */
int isis_instance_area_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password
 */
void domain_password_apply_finish(const struct lyd_node *dnode)
{
	const char *password = yang_dnode_get_string(dnode, "./password");
	struct isis_area *area = nb_running_get_entry(dnode, NULL, true);
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

int isis_instance_domain_password_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

int isis_instance_domain_password_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	isis_area_passwd_unset(area, IS_LEVEL_2);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/password
 */
int isis_instance_domain_password_password_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/password-type
 */
int isis_instance_domain_password_password_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* actual setting is done in apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/authenticate-snp
 */
int isis_instance_domain_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
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

void default_info_origin_ipv4_apply_finish(const struct lyd_node *dnode)
{
	default_info_origin_apply_finish(dnode, AF_INET);
}

void default_info_origin_ipv6_apply_finish(const struct lyd_node *dnode)
{
	default_info_origin_apply_finish(dnode, AF_INET6);
}

int isis_instance_default_information_originate_ipv4_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv4_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	level = yang_dnode_get_enum(dnode, "./level");
	isis_redist_unset(area, level, AF_INET, DEFAULT_ROUTE);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/always
 */
int isis_instance_default_information_originate_ipv4_always_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/route-map
 */
int isis_instance_default_information_originate_ipv4_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv4_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/metric
 */
int isis_instance_default_information_originate_ipv4_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6
 */
int isis_instance_default_information_originate_ipv6_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv6_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	level = yang_dnode_get_enum(dnode, "./level");
	isis_redist_unset(area, level, AF_INET6, DEFAULT_ROUTE);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/always
 */
int isis_instance_default_information_originate_ipv6_always_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/route-map
 */
int isis_instance_default_information_originate_ipv6_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

int isis_instance_default_information_originate_ipv6_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by default_info_origin_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/metric
 */
int isis_instance_default_information_originate_ipv6_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
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

void redistribute_ipv4_apply_finish(const struct lyd_node *dnode)
{
	redistribute_apply_finish(dnode, AF_INET);
}

void redistribute_ipv6_apply_finish(const struct lyd_node *dnode)
{
	redistribute_apply_finish(dnode, AF_INET6);
}

int isis_instance_redistribute_ipv4_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv4_destroy(enum nb_event event,
					    const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level, type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	level = yang_dnode_get_enum(dnode, "./level");
	type = yang_dnode_get_enum(dnode, "./protocol");
	isis_redist_unset(area, level, AF_INET, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4/route-map
 */
int isis_instance_redistribute_ipv4_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv4_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4/metric
 */
int isis_instance_redistribute_ipv4_metric_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6
 */
int isis_instance_redistribute_ipv6_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv6_destroy(enum nb_event event,
					    const struct lyd_node *dnode)
{
	struct isis_area *area;
	int level, type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	level = yang_dnode_get_enum(dnode, "./level");
	type = yang_dnode_get_enum(dnode, "./protocol");
	isis_redist_unset(area, level, AF_INET6, type);

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6/route-map
 */
int isis_instance_redistribute_ipv6_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

int isis_instance_redistribute_ipv6_route_map_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* It's all done by redistribute_apply_finish */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6/metric
 */
int isis_instance_redistribute_ipv6_metric_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
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
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv4-multicast", true);
}

int isis_instance_multi_topology_ipv4_multicast_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv4-multicast",
					  false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload
 */
int isis_instance_multi_topology_ipv4_multicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode,
						   "ipv4-multicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management
 */
int isis_instance_multi_topology_ipv4_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv4-mgmt", true);
}

int isis_instance_multi_topology_ipv4_management_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv4-mgmt", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management/overload
 */
int isis_instance_multi_topology_ipv4_management_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode, "ipv4-mgmt");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast
 */
int isis_instance_multi_topology_ipv6_unicast_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-unicast", true);
}

int isis_instance_multi_topology_ipv6_unicast_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-unicast", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload
 */
int isis_instance_multi_topology_ipv6_unicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode,
						   "ipv6-unicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast
 */
int isis_instance_multi_topology_ipv6_multicast_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-multicast", true);
}

int isis_instance_multi_topology_ipv6_multicast_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-multicast",
					  false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload
 */
int isis_instance_multi_topology_ipv6_multicast_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode,
						   "ipv6-multicast");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management
 */
int isis_instance_multi_topology_ipv6_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-mgmt", true);
}

int isis_instance_multi_topology_ipv6_management_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-mgmt", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management/overload
 */
int isis_instance_multi_topology_ipv6_management_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode, "ipv6-mgmt");
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc
 */
int isis_instance_multi_topology_ipv6_dstsrc_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_common(event, dnode, "ipv6-dstsrc", true);
}

int isis_instance_multi_topology_ipv6_dstsrc_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return isis_multi_topology_common(event, dnode, "ipv6-dstsrc", false);
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload
 */
int isis_instance_multi_topology_ipv6_dstsrc_overload_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return isis_multi_topology_overload_common(event, dnode, "ipv6-dstsrc");
}

/*
 * XPath: /frr-isisd:isis/instance/log-adjacency-changes
 */
int isis_instance_log_adjacency_changes_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct isis_area *area;
	bool log = yang_dnode_get_bool(dnode, NULL);

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	area->log_adj_changes = log ? 1 : 0;

	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/mpls-te
 */
int isis_instance_mpls_te_create(enum nb_event event,
				 const struct lyd_node *dnode,
				 union nb_resource *resource)
{
	struct listnode *node;
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
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

int isis_instance_mpls_te_destroy(enum nb_event event,
				  const struct lyd_node *dnode)
{
	struct listnode *node;
	struct isis_area *area;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
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
int isis_instance_mpls_te_router_address_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct in_addr value;
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
	/* only proceed if MPLS-TE is enabled */
	if (!IS_MPLS_TE(area->mta))
		return NB_OK;

	/* Update Area Router ID */
	yang_dnode_get_ipv4(&value, dnode, NULL);
	area->mta->router_id.s_addr = value.s_addr;

	/* And re-schedule LSP update */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return NB_OK;
}

int isis_instance_mpls_te_router_address_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	struct isis_area *area;

	if (event != NB_EV_APPLY)
		return NB_OK;

	area = nb_running_get_entry(dnode, NULL, true);
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
 * XPath: /frr-interface:lib/interface/frr-isisd:isis
 */
int lib_interface_isis_create(enum nb_event event, const struct lyd_node *dnode,
			      union nb_resource *resource)
{
	struct isis_area *area;
	struct interface *ifp;
	struct isis_circuit *circuit;
	const char *area_tag = yang_dnode_get_string(dnode, "./area-tag");
	uint32_t min_mtu, actual_mtu;

	switch (event) {
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_VALIDATE:
		/* check if interface mtu is sufficient. If the area has not
		 * been created yet, assume default MTU for the area
		 */
		ifp = nb_running_get_entry(dnode, NULL, false);
		/* zebra might not know yet about the MTU - nothing we can do */
		if (!ifp || ifp->mtu == 0)
			break;
		actual_mtu =
			if_is_broadcast(ifp) ? ifp->mtu - LLC_LEN : ifp->mtu;
		area = isis_area_lookup(area_tag);
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
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Interface %s has MTU %" PRIu32
				  ", minimum MTU for the area is %" PRIu32 "",
				  ifp->name, actual_mtu, min_mtu);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_APPLY:
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

		ifp = nb_running_get_entry(dnode, NULL, true);
		circuit = isis_circuit_create(area, ifp);
		assert(circuit
		       && (circuit->state == C_STATE_CONF
			   || circuit->state == C_STATE_UP));
		nb_running_set_entry(dnode, circuit);
		break;
	}

	return NB_OK;
}

int lib_interface_isis_destroy(enum nb_event event,
			       const struct lyd_node *dnode)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_unset_entry(dnode);
	if (!circuit)
		return NB_ERR_INCONSISTENCY;
	if (circuit->state == C_STATE_UP || circuit->state == C_STATE_CONF)
		isis_csm_state_change(ISIS_DISABLE, circuit, circuit->area);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/area-tag
 */
int lib_interface_isis_area_tag_modify(enum nb_event event,
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
int lib_interface_isis_circuit_type_modify(enum nb_event event,
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
		circuit = nb_running_get_entry(dnode, NULL, true);
		isis_circuit_is_type_set(circuit, circ_type);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv4-routing
 */
int lib_interface_isis_ipv4_routing_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	bool ipv4, ipv6;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	ipv4 = yang_dnode_get_bool(dnode, NULL);
	ipv6 = yang_dnode_get_bool(dnode, "../ipv6-routing");
	isis_circuit_af_set(circuit, ipv4, ipv6);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv6-routing
 */
int lib_interface_isis_ipv6_routing_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	bool ipv4, ipv6;
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	ipv4 = yang_dnode_exists(dnode, "../ipv4-routing");
	ipv6 = yang_dnode_get_bool(dnode, NULL);
	isis_circuit_af_set(circuit, ipv4, ipv6);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring
 */
int lib_interface_isis_bfd_monitoring_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct isis_circuit *circuit;
	bool bfd_monitoring;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	bfd_monitoring = yang_dnode_get_bool(dnode, NULL);

	if (bfd_monitoring) {
		isis_bfd_circuit_param_set(circuit, BFD_DEF_MIN_RX,
					   BFD_DEF_MIN_TX, BFD_DEF_DETECT_MULT,
					   true);
	} else {
		isis_bfd_circuit_cmd(circuit, ZEBRA_BFD_DEST_DEREGISTER);
		bfd_info_free(&circuit->bfd_info);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-1
 */
int lib_interface_isis_csnp_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->csnp_interval[0] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/csnp-interval/level-2
 */
int lib_interface_isis_csnp_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->csnp_interval[1] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-1
 */
int lib_interface_isis_psnp_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->psnp_interval[0] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/psnp-interval/level-2
 */
int lib_interface_isis_psnp_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->psnp_interval[1] = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/padding
 */
int lib_interface_isis_hello_padding_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->pad_hellos = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-1
 */
int lib_interface_isis_hello_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint32_t interval;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	interval = yang_dnode_get_uint32(dnode, NULL);
	circuit->hello_interval[0] = interval;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/interval/level-2
 */
int lib_interface_isis_hello_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint32_t interval;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	interval = yang_dnode_get_uint32(dnode, NULL);
	circuit->hello_interval[1] = interval;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1
 */
int lib_interface_isis_hello_multiplier_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint16_t multi;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	multi = yang_dnode_get_uint16(dnode, NULL);
	circuit->hello_multiplier[0] = multi;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2
 */
int lib_interface_isis_hello_multiplier_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint16_t multi;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	multi = yang_dnode_get_uint16(dnode, NULL);
	circuit->hello_multiplier[1] = multi;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/metric/level-1
 */
int lib_interface_isis_metric_level_1_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct isis_circuit *circuit;
	unsigned int met;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	met = yang_dnode_get_uint32(dnode, NULL);
	isis_circuit_metric_set(circuit, IS_LEVEL_1, met);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/metric/level-2
 */
int lib_interface_isis_metric_level_2_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct isis_circuit *circuit;
	unsigned int met;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	met = yang_dnode_get_uint32(dnode, NULL);
	isis_circuit_metric_set(circuit, IS_LEVEL_2, met);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/priority/level-1
 */
int lib_interface_isis_priority_level_1_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->priority[0] = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/priority/level-2
 */
int lib_interface_isis_priority_level_2_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->priority[1] = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/network-type
 */
int lib_interface_isis_network_type_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct isis_circuit *circuit;
	int net_type = yang_dnode_get_enum(dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		circuit = nb_running_get_entry(dnode, NULL, false);
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
		circuit = nb_running_get_entry(dnode, NULL, true);
		isis_circuit_circ_type_set(circuit, net_type);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/passive
 */
int lib_interface_isis_passive_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource)
{
	struct isis_circuit *circuit;
	struct isis_area *area;
	struct interface *ifp;
	bool passive = yang_dnode_get_bool(dnode, NULL);

	/* validation only applies if we are setting passive to false */
	if (!passive && event == NB_EV_VALIDATE) {
		circuit = nb_running_get_entry(dnode, NULL, false);
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

	circuit = nb_running_get_entry(dnode, NULL, true);
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
int lib_interface_isis_password_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource)
{
	return NB_OK;
}

int lib_interface_isis_password_destroy(enum nb_event event,
					const struct lyd_node *dnode)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
	isis_circuit_passwd_unset(circuit);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password/password
 */
int lib_interface_isis_password_password_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct isis_circuit *circuit;
	const char *password;

	if (event != NB_EV_APPLY)
		return NB_OK;

	password = yang_dnode_get_string(dnode, NULL);
	circuit = nb_running_get_entry(dnode, NULL, true);

	isis_circuit_passwd_set(circuit, circuit->passwd.type, password);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password/password-type
 */
int lib_interface_isis_password_password_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;
	uint8_t pass_type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	pass_type = yang_dnode_get_enum(dnode, NULL);
	circuit = nb_running_get_entry(dnode, NULL, true);
	circuit->passwd.type = pass_type;

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake
 */
int lib_interface_isis_disable_three_way_handshake_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct isis_circuit *circuit;

	if (event != NB_EV_APPLY)
		return NB_OK;

	circuit = nb_running_get_entry(dnode, NULL, true);
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
		circuit = nb_running_get_entry(dnode, NULL, false);
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
		circuit = nb_running_get_entry(dnode, NULL, true);
		value = yang_dnode_get_bool(dnode, NULL);
		isis_circuit_mt_enabled_set(circuit, mtid, value);
		break;
	}

	return NB_OK;
}

int lib_interface_isis_multi_topology_ipv4_unicast_modify(
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
int lib_interface_isis_multi_topology_ipv4_multicast_modify(
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
int lib_interface_isis_multi_topology_ipv4_management_modify(
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
int lib_interface_isis_multi_topology_ipv6_unicast_modify(
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
int lib_interface_isis_multi_topology_ipv6_multicast_modify(
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
int lib_interface_isis_multi_topology_ipv6_management_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV6_MGMT);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc
 */
int lib_interface_isis_multi_topology_ipv6_dstsrc_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return lib_interface_isis_multi_topology_common(event, dnode,
							ISIS_MT_IPV6_DSTSRC);
}
