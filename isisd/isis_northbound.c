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
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_delete(enum nb_event event,
				const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/is-type
 */
static int isis_instance_is_type_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-address
 */
static int isis_instance_area_address_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_area_address_delete(enum nb_event event,
					     const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/dynamic-hostname
 */
static int isis_instance_dynamic_hostname_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/attached
 */
static int isis_instance_attached_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_attached_delete(enum nb_event event,
					 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/overload
 */
static int isis_instance_overload_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_overload_delete(enum nb_event event,
					 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/metric-style
 */
static int isis_instance_metric_style_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/purge-originator
 */
static int isis_instance_purge_originator_create(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_purge_originator_delete(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/mtu
 */
static int isis_instance_lsp_mtu_modify(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/generation-interval/level-1
 */
static int isis_instance_lsp_generation_interval_level_1_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/generation-interval/level-2
 */
static int isis_instance_lsp_generation_interval_level_2_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay
 */
static int
isis_instance_spf_ietf_backoff_delay_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_spf_ietf_backoff_delay_delete(enum nb_event event,
					    const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/init-delay
 */
static int isis_instance_spf_ietf_backoff_delay_init_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/short-delay
 */
static int isis_instance_spf_ietf_backoff_delay_short_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/long-delay
 */
static int isis_instance_spf_ietf_backoff_delay_long_delay_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/hold-down
 */
static int isis_instance_spf_ietf_backoff_delay_hold_down_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay/time-to-learn
 */
static int isis_instance_spf_ietf_backoff_delay_time_to_learn_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password
 */
static int isis_instance_area_password_create(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_area_password_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/area-password/authenticate-snp
 */
static int isis_instance_area_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password
 */
static int isis_instance_domain_password_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_domain_password_delete(enum nb_event event,
						const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password/authenticate-snp
 */
static int isis_instance_domain_password_authenticate_snp_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4
 */
static int isis_instance_default_information_originate_ipv4_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv4_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/always
 */
static int isis_instance_default_information_originate_ipv4_always_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv4_always_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/route-map
 */
static int isis_instance_default_information_originate_ipv4_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv4_route_map_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv4/metric
 */
static int isis_instance_default_information_originate_ipv4_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv4_metric_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6
 */
static int isis_instance_default_information_originate_ipv6_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv6_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/always
 */
static int isis_instance_default_information_originate_ipv6_always_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv6_always_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/route-map
 */
static int isis_instance_default_information_originate_ipv6_route_map_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv6_route_map_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate/ipv6/metric
 */
static int isis_instance_default_information_originate_ipv6_metric_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_default_information_originate_ipv6_metric_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv4
 */
static int isis_instance_redistribute_ipv4_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_redistribute_ipv4_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv4_route_map_delete(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv4_metric_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/ipv6
 */
static int isis_instance_redistribute_ipv6_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_redistribute_ipv6_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv6_route_map_delete(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_redistribute_ipv6_metric_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-multicast
 */
static int
isis_instance_multi_topology_ipv4_multicast_create(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_multi_topology_ipv4_multicast_delete(enum nb_event event,
						   const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload
 */
static int isis_instance_multi_topology_ipv4_multicast_overload_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv4_multicast_overload_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management
 */
static int isis_instance_multi_topology_ipv4_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv4_management_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv4-management/overload
 */
static int isis_instance_multi_topology_ipv4_management_overload_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv4_management_overload_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast
 */
static int
isis_instance_multi_topology_ipv6_unicast_create(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_multi_topology_ipv6_unicast_delete(enum nb_event event,
						 const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload
 */
static int isis_instance_multi_topology_ipv6_unicast_overload_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv6_unicast_overload_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast
 */
static int
isis_instance_multi_topology_ipv6_multicast_create(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_multi_topology_ipv6_multicast_delete(enum nb_event event,
						   const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload
 */
static int isis_instance_multi_topology_ipv6_multicast_overload_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv6_multicast_overload_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management
 */
static int isis_instance_multi_topology_ipv6_management_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv6_management_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-management/overload
 */
static int isis_instance_multi_topology_ipv6_management_overload_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv6_management_overload_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc
 */
static int
isis_instance_multi_topology_ipv6_dstsrc_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_multi_topology_ipv6_dstsrc_delete(enum nb_event event,
						const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload
 */
static int isis_instance_multi_topology_ipv6_dstsrc_overload_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_instance_multi_topology_ipv6_dstsrc_overload_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/instance/log-adjacency-changes
 */
static int
isis_instance_log_adjacency_changes_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int
isis_instance_log_adjacency_changes_delete(enum nb_event event,
					   const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/mpls-te
 */
static int isis_mpls_te_create(enum nb_event event,
			       const struct lyd_node *dnode,
			       union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_mpls_te_delete(enum nb_event event,
			       const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-isisd:isis/mpls-te/router-address
 */
static int isis_mpls_te_router_address_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int isis_mpls_te_router_address_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis
 */
static int lib_interface_isis_create(enum nb_event event,
				     const struct lyd_node *dnode,
				     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_isis_delete(enum nb_event event,
				     const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/area-tag
 */
static int lib_interface_isis_area_tag_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/circuit-type
 */
static int lib_interface_isis_circuit_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv4-routing
 */
static int lib_interface_isis_ipv4_routing_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_isis_ipv4_routing_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv6-routing
 */
static int lib_interface_isis_ipv6_routing_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_isis_ipv6_routing_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/padding
 */
static int lib_interface_isis_hello_padding_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/network-type
 */
static int lib_interface_isis_network_type_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_isis_network_type_delete(enum nb_event event,
						  const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/passive
 */
static int lib_interface_isis_passive_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_isis_passive_delete(enum nb_event event,
					     const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password
 */
static int lib_interface_isis_password_create(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_isis_password_delete(enum nb_event event,
					      const struct lyd_node *dnode)
{
	/* TODO: implement me. */
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
	/* TODO: implement me. */
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
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake
 */
static int lib_interface_isis_disable_three_way_handshake_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

static int lib_interface_isis_disable_three_way_handshake_delete(
	enum nb_event event, const struct lyd_node *dnode)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-unicast
 */
static int lib_interface_isis_multi_topology_ipv4_unicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-multicast
 */
static int lib_interface_isis_multi_topology_ipv4_multicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-management
 */
static int lib_interface_isis_multi_topology_ipv4_management_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-unicast
 */
static int lib_interface_isis_multi_topology_ipv6_unicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-multicast
 */
static int lib_interface_isis_multi_topology_ipv6_multicast_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-management
 */
static int lib_interface_isis_multi_topology_ipv6_management_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc
 */
static int lib_interface_isis_multi_topology_ipv6_dstsrc_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	/* TODO: implement me. */
	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_isisd_info = {
	.name = "frr-isisd",
	.nodes = {
		{
			.xpath = "/frr-isisd:isis/instance",
			.cbs.create = isis_instance_create,
			.cbs.delete = isis_instance_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/is-type",
			.cbs.modify = isis_instance_is_type_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/area-address",
			.cbs.create = isis_instance_area_address_create,
			.cbs.delete = isis_instance_area_address_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/dynamic-hostname",
			.cbs.modify = isis_instance_dynamic_hostname_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/attached",
			.cbs.create = isis_instance_attached_create,
			.cbs.delete = isis_instance_attached_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/overload",
			.cbs.create = isis_instance_overload_create,
			.cbs.delete = isis_instance_overload_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/metric-style",
			.cbs.modify = isis_instance_metric_style_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/purge-originator",
			.cbs.create = isis_instance_purge_originator_create,
			.cbs.delete = isis_instance_purge_originator_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/mtu",
			.cbs.modify = isis_instance_lsp_mtu_modify,
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
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime/level-1",
			.cbs.modify = isis_instance_lsp_maximum_lifetime_level_1_modify,
		},
		{
			.xpath = "/frr-isisd:isis/instance/lsp/maximum-lifetime/level-2",
			.cbs.modify = isis_instance_lsp_maximum_lifetime_level_2_modify,
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
			.cbs.delete = isis_instance_spf_ietf_backoff_delay_delete,
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
			.cbs.delete = isis_instance_area_password_delete,
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
			.cbs.delete = isis_instance_domain_password_delete,
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
			.cbs.delete = isis_instance_default_information_originate_ipv4_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/always",
			.cbs.create = isis_instance_default_information_originate_ipv4_always_create,
			.cbs.delete = isis_instance_default_information_originate_ipv4_always_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/route-map",
			.cbs.modify = isis_instance_default_information_originate_ipv4_route_map_modify,
			.cbs.delete = isis_instance_default_information_originate_ipv4_route_map_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv4/metric",
			.cbs.modify = isis_instance_default_information_originate_ipv4_metric_modify,
			.cbs.delete = isis_instance_default_information_originate_ipv4_metric_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6",
			.cbs.create = isis_instance_default_information_originate_ipv6_create,
			.cbs.delete = isis_instance_default_information_originate_ipv6_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/always",
			.cbs.create = isis_instance_default_information_originate_ipv6_always_create,
			.cbs.delete = isis_instance_default_information_originate_ipv6_always_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/route-map",
			.cbs.modify = isis_instance_default_information_originate_ipv6_route_map_modify,
			.cbs.delete = isis_instance_default_information_originate_ipv6_route_map_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/default-information-originate/ipv6/metric",
			.cbs.modify = isis_instance_default_information_originate_ipv6_metric_modify,
			.cbs.delete = isis_instance_default_information_originate_ipv6_metric_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4",
			.cbs.create = isis_instance_redistribute_ipv4_create,
			.cbs.delete = isis_instance_redistribute_ipv4_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/route-map",
			.cbs.modify = isis_instance_redistribute_ipv4_route_map_modify,
			.cbs.delete = isis_instance_redistribute_ipv4_route_map_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv4/metric",
			.cbs.modify = isis_instance_redistribute_ipv4_metric_modify,
			.cbs.delete = isis_instance_redistribute_ipv4_metric_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6",
			.cbs.create = isis_instance_redistribute_ipv6_create,
			.cbs.delete = isis_instance_redistribute_ipv6_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/route-map",
			.cbs.modify = isis_instance_redistribute_ipv6_route_map_modify,
			.cbs.delete = isis_instance_redistribute_ipv6_route_map_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/redistribute/ipv6/metric",
			.cbs.modify = isis_instance_redistribute_ipv6_metric_modify,
			.cbs.delete = isis_instance_redistribute_ipv6_metric_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast",
			.cbs.create = isis_instance_multi_topology_ipv4_multicast_create,
			.cbs.delete = isis_instance_multi_topology_ipv4_multicast_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-multicast/overload",
			.cbs.create = isis_instance_multi_topology_ipv4_multicast_overload_create,
			.cbs.delete = isis_instance_multi_topology_ipv4_multicast_overload_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management",
			.cbs.create = isis_instance_multi_topology_ipv4_management_create,
			.cbs.delete = isis_instance_multi_topology_ipv4_management_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv4-management/overload",
			.cbs.create = isis_instance_multi_topology_ipv4_management_overload_create,
			.cbs.delete = isis_instance_multi_topology_ipv4_management_overload_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast",
			.cbs.create = isis_instance_multi_topology_ipv6_unicast_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_unicast_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-unicast/overload",
			.cbs.create = isis_instance_multi_topology_ipv6_unicast_overload_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_unicast_overload_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast",
			.cbs.create = isis_instance_multi_topology_ipv6_multicast_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_multicast_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-multicast/overload",
			.cbs.create = isis_instance_multi_topology_ipv6_multicast_overload_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_multicast_overload_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management",
			.cbs.create = isis_instance_multi_topology_ipv6_management_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_management_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-management/overload",
			.cbs.create = isis_instance_multi_topology_ipv6_management_overload_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_management_overload_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc",
			.cbs.create = isis_instance_multi_topology_ipv6_dstsrc_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_dstsrc_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/multi-topology/ipv6-dstsrc/overload",
			.cbs.create = isis_instance_multi_topology_ipv6_dstsrc_overload_create,
			.cbs.delete = isis_instance_multi_topology_ipv6_dstsrc_overload_delete,
		},
		{
			.xpath = "/frr-isisd:isis/instance/log-adjacency-changes",
			.cbs.create = isis_instance_log_adjacency_changes_create,
			.cbs.delete = isis_instance_log_adjacency_changes_delete,
		},
		{
			.xpath = "/frr-isisd:isis/mpls-te",
			.cbs.create = isis_mpls_te_create,
			.cbs.delete = isis_mpls_te_delete,
		},
		{
			.xpath = "/frr-isisd:isis/mpls-te/router-address",
			.cbs.modify = isis_mpls_te_router_address_modify,
			.cbs.delete = isis_mpls_te_router_address_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis",
			.cbs.create = lib_interface_isis_create,
			.cbs.delete = lib_interface_isis_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/area-tag",
			.cbs.modify = lib_interface_isis_area_tag_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/circuit-type",
			.cbs.modify = lib_interface_isis_circuit_type_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv4-routing",
			.cbs.create = lib_interface_isis_ipv4_routing_create,
			.cbs.delete = lib_interface_isis_ipv4_routing_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/ipv6-routing",
			.cbs.create = lib_interface_isis_ipv6_routing_create,
			.cbs.delete = lib_interface_isis_ipv6_routing_delete,
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
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-1",
			.cbs.modify = lib_interface_isis_hello_multiplier_level_1_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/hello/multiplier/level-2",
			.cbs.modify = lib_interface_isis_hello_multiplier_level_2_modify,
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
			.cbs.delete = lib_interface_isis_network_type_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/passive",
			.cbs.create = lib_interface_isis_passive_create,
			.cbs.delete = lib_interface_isis_passive_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/password",
			.cbs.create = lib_interface_isis_password_create,
			.cbs.delete = lib_interface_isis_password_delete,
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
			.cbs.create = lib_interface_isis_disable_three_way_handshake_create,
			.cbs.delete = lib_interface_isis_disable_three_way_handshake_delete,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-unicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv4_unicast_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-multicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv4_multicast_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv4-management",
			.cbs.modify = lib_interface_isis_multi_topology_ipv4_management_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-unicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_unicast_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-multicast",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_multicast_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-management",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_management_modify,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-isisd:isis/multi-topology/ipv6-dstsrc",
			.cbs.modify = lib_interface_isis_multi_topology_ipv6_dstsrc_modify,
		},
		{
			.xpath = NULL,
		},
	}
};
