// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frrscript encoders and decoders for data structures in Zebra
 * Copyright (C) 2021 Donald Lee
 */

#include "zebra.h"

#include "zebra_script.h"

#ifdef HAVE_SCRIPTING

void zebra_script_init(void)
{
	frrscript_names_add_function_name(ZEBRA_ON_RIB_PROCESS_HOOK_CALL);
}

void zebra_script_destroy(void)
{
	frrscript_names_destroy();
}

void lua_pushnh_grp(lua_State *L, const struct nh_grp *nh_grp)
{
	lua_newtable(L);
	lua_pushinteger(L, nh_grp->id);
	lua_setfield(L, -2, "id");
	lua_pushinteger(L, nh_grp->weight);
	lua_setfield(L, -2, "weight");
}

void lua_pushzebra_dplane_ctx(lua_State *L, const struct zebra_dplane_ctx *ctx)
{

	lua_newtable(L);
	lua_pushinteger(L, dplane_ctx_get_op(ctx));
	lua_setfield(L, -2, "zd_op");
	lua_pushinteger(L, dplane_ctx_get_status(ctx));
	lua_setfield(L, -2, "zd_status");
	lua_pushinteger(L, dplane_ctx_get_provider(ctx));
	lua_setfield(L, -2, "zd_provider");
	lua_pushinteger(L, dplane_ctx_get_vrf(ctx));
	lua_setfield(L, -2, "zd_vrf_id");
	lua_pushinteger(L, dplane_ctx_get_table(ctx));
	lua_setfield(L, -2, "zd_table_id");
	lua_pushstring(L, dplane_ctx_get_ifname(ctx));
	lua_setfield(L, -2, "zd_ifname");
	lua_pushinteger(L, dplane_ctx_get_ifindex(ctx));
	lua_setfield(L, -2, "zd_ifindex");

	switch (dplane_ctx_get_op(ctx)) {
	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
	case DPLANE_OP_PIC_NH_INSTALL:
	case DPLANE_OP_PIC_NH_UPDATE:
	case DPLANE_OP_PIC_NH_DELETE:
		/* rinfo */
		lua_newtable(L);
		{
			lua_pushprefix(L, dplane_ctx_get_dest(ctx));
			lua_setfield(L, -2, "zd_dest");
			const struct prefix *src_pfx = dplane_ctx_get_src(ctx);

			if (src_pfx) {
				lua_pushprefix(L, src_pfx);
				lua_setfield(L, -2, "zd_src");
			}
			lua_pushinteger(L, dplane_ctx_get_afi(ctx));
			lua_setfield(L, -2, "zd_afi");
			lua_pushinteger(L, dplane_ctx_get_safi(ctx));
			lua_setfield(L, -2, "zd_safi");
			lua_pushinteger(L, dplane_ctx_get_type(ctx));
			lua_setfield(L, -2, "zd_type");
			lua_pushinteger(L, dplane_ctx_get_old_type(ctx));
			lua_setfield(L, -2, "zd_old_type");
			lua_pushinteger(L, dplane_ctx_get_tag(ctx));
			lua_setfield(L, -2, "zd_tag");
			lua_pushinteger(L, dplane_ctx_get_old_tag(ctx));
			lua_setfield(L, -2, "zd_old_tag");
			lua_pushinteger(L, dplane_ctx_get_metric(ctx));
			lua_setfield(L, -2, "zd_metric");
			lua_pushinteger(L, dplane_ctx_get_old_metric(ctx));
			lua_setfield(L, -2, "zd_old_metric");
			lua_pushinteger(L, dplane_ctx_get_instance(ctx));
			lua_setfield(L, -2, "zd_instance");
			lua_pushinteger(L, dplane_ctx_get_old_instance(ctx));
			lua_setfield(L, -2, "zd_old_instance");
			lua_pushinteger(L, dplane_ctx_get_distance(ctx));
			lua_setfield(L, -2, "zd_distance");
			lua_pushinteger(L, dplane_ctx_get_old_distance(ctx));
			lua_setfield(L, -2, "zd_old_distance");
			lua_pushinteger(L, dplane_ctx_get_mtu(ctx));
			lua_setfield(L, -2, "zd_mtu");
			lua_pushinteger(L, dplane_ctx_get_nh_mtu(ctx));
			lua_setfield(L, -2, "zd_nexthop_mtu");
			/* nhe */
			lua_newtable(L);
			{
				lua_pushinteger(L, dplane_ctx_get_nhe_id(ctx));
				lua_setfield(L, -2, "id");
				lua_pushinteger(L,
						dplane_ctx_get_old_nhe_id(ctx));
				lua_setfield(L, -2, "old_id");
				lua_pushinteger(L, dplane_ctx_get_nhe_afi(ctx));
				lua_setfield(L, -2, "afi");
				lua_pushinteger(L,
						dplane_ctx_get_nhe_vrf_id(ctx));
				lua_setfield(L, -2, "vrf_id");
				lua_pushinteger(L,
						dplane_ctx_get_nhe_type(ctx));
				lua_setfield(L, -2, "type");
				lua_pushnexthop_group(
					L, dplane_ctx_get_nhe_ng(ctx));
				lua_setfield(L, -2, "ng");
				lua_pushnh_grp(L,
					       dplane_ctx_get_nhe_nh_grp(ctx));
				lua_setfield(L, -2, "nh_grp");
				lua_pushinteger(
					L,
					dplane_ctx_get_nhe_nh_grp_count(ctx));
				lua_setfield(L, -2, "nh_grp_count");
			}
			lua_setfield(L, -2, "nhe");
			lua_pushinteger(L, dplane_ctx_get_nhg_id(ctx));
			lua_setfield(L, -2, "zd_nhg_id");
			lua_pushnexthop_group(L, dplane_ctx_get_ng(ctx));
			lua_setfield(L, -2, "zd_ng");
			lua_pushnexthop_group(L, dplane_ctx_get_backup_ng(ctx));
			lua_setfield(L, -2, "backup_ng");
			lua_pushnexthop_group(L, dplane_ctx_get_old_ng(ctx));
			lua_setfield(L, -2, "zd_old_ng");
			lua_pushnexthop_group(
				L, dplane_ctx_get_old_backup_ng(ctx));
			lua_setfield(L, -2, "old_backup_ng");
		}
		lua_setfield(L, -2, "rinfo");
		break;
	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
	case DPLANE_OP_LSP_NOTIFY:
		lua_pushinteger(L, (int)dplane_ctx_get_in_label(ctx));
		lua_setfield(L, -2, "label");
		break;
	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
		/* pw*/
		lua_newtable(L);
		{
			lua_pushinteger(L, dplane_ctx_get_pw_type(ctx));
			lua_setfield(L, -2, "type");
			lua_pushinteger(L, dplane_ctx_get_pw_af(ctx));
			lua_setfield(L, -2, "af");
			lua_pushinteger(L, dplane_ctx_get_pw_status(ctx));
			lua_setfield(L, -2, "status");
			lua_pushinteger(L, dplane_ctx_get_pw_flags(ctx));
			lua_setfield(L, -2, "flags");
			lua_pushinteger(L, dplane_ctx_get_pw_local_label(ctx));
			lua_setfield(L, -2, "local_label");
			lua_pushinteger(L, dplane_ctx_get_pw_remote_label(ctx));
			lua_setfield(L, -2, "remote_label");
		}
		lua_setfield(L, -2, "pw");
		break;
	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
		/* nothing to encode */
		break;
	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		/* macinfo */
		lua_newtable(L);
		{
			lua_pushinteger(L, dplane_ctx_mac_get_vlan(ctx));
			lua_setfield(L, -2, "vid");
			lua_pushinteger(L, dplane_ctx_mac_get_br_ifindex(ctx));
			lua_setfield(L, -2, "br_ifindex");
			lua_pushethaddr(L, dplane_ctx_mac_get_addr(ctx));
			lua_setfield(L, -2, "mac");
			lua_pushinaddr(L, dplane_ctx_mac_get_vtep_ip(ctx));
			lua_setfield(L, -2, "vtep_ip");
			lua_pushinteger(L, dplane_ctx_mac_is_sticky(ctx));
			lua_setfield(L, -2, "is_sticky");
			lua_pushinteger(L, dplane_ctx_mac_get_nhg_id(ctx));
			lua_setfield(L, -2, "nhg_id");
			lua_pushinteger(L,
					dplane_ctx_mac_get_update_flags(ctx));
			lua_setfield(L, -2, "update_flags");
		}
		lua_setfield(L, -2, "macinfo");
		break;
	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
		/* rule */
		lua_newtable(L);
		{
			lua_pushinteger(L, dplane_ctx_rule_get_sock(ctx));
			lua_setfield(L, -2, "sock");
			lua_pushinteger(L, dplane_ctx_rule_get_unique(ctx));
			lua_setfield(L, -2, "unique");
			lua_pushinteger(L, dplane_ctx_rule_get_seq(ctx));
			lua_setfield(L, -2, "seq");
			lua_pushstring(L, dplane_ctx_rule_get_ifname(ctx));
			lua_setfield(L, -2, "ifname");
			lua_pushinteger(L, dplane_ctx_rule_get_priority(ctx));
			lua_setfield(L, -2, "priority");
			lua_pushinteger(L,
					dplane_ctx_rule_get_old_priority(ctx));
			lua_setfield(L, -2, "old_priority");
			lua_pushinteger(L, dplane_ctx_rule_get_table(ctx));
			lua_setfield(L, -2, "table");
			lua_pushinteger(L, dplane_ctx_rule_get_old_table(ctx));
			lua_setfield(L, -2, "old_table");
			lua_pushinteger(L, dplane_ctx_rule_get_filter_bm(ctx));
			lua_setfield(L, -2, "filter_bm");
			lua_pushinteger(L,
					dplane_ctx_rule_get_old_filter_bm(ctx));
			lua_setfield(L, -2, "old_filter_bm");
			lua_pushinteger(L, dplane_ctx_rule_get_fwmark(ctx));
			lua_setfield(L, -2, "fwmark");
			lua_pushinteger(L, dplane_ctx_rule_get_old_fwmark(ctx));
			lua_setfield(L, -2, "old_fwmark");
			lua_pushinteger(L, dplane_ctx_rule_get_dsfield(ctx));
			lua_setfield(L, -2, "dsfield");
			lua_pushinteger(L,
					dplane_ctx_rule_get_old_dsfield(ctx));
			lua_setfield(L, -2, "old_dsfield");
			lua_pushinteger(L, dplane_ctx_rule_get_ipproto(ctx));
			lua_setfield(L, -2, "ip_proto");
			lua_pushinteger(L,
					dplane_ctx_rule_get_old_ipproto(ctx));
			lua_setfield(L, -2, "old_ip_proto");
			lua_pushprefix(L, dplane_ctx_rule_get_src_ip(ctx));
			lua_setfield(L, -2, "src_ip");
			lua_pushprefix(L, dplane_ctx_rule_get_old_src_ip(ctx));
			lua_setfield(L, -2, "old_src_ip");
			lua_pushprefix(L, dplane_ctx_rule_get_dst_ip(ctx));
			lua_setfield(L, -2, "dst_ip");
			lua_pushprefix(L, dplane_ctx_rule_get_old_dst_ip(ctx));
			lua_setfield(L, -2, "old_dst_ip");
		}
		lua_setfield(L, -2, "rule");
		break;
	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE: {
		struct zebra_pbr_iptable iptable;

		dplane_ctx_get_pbr_iptable(ctx, &iptable);
		/* iptable  */
		lua_newtable(L);
		{
			lua_pushinteger(L, iptable.sock);
			lua_setfield(L, -2, "sock");
			lua_pushinteger(L, iptable.vrf_id);
			lua_setfield(L, -2, "vrf_id");
			lua_pushinteger(L, iptable.unique);
			lua_setfield(L, -2, "unique");
			lua_pushinteger(L, iptable.type);
			lua_setfield(L, -2, "type");
			lua_pushinteger(L, iptable.filter_bm);
			lua_setfield(L, -2, "filter_bm");
			lua_pushinteger(L, iptable.fwmark);
			lua_setfield(L, -2, "fwmark");
			lua_pushinteger(L, iptable.action);
			lua_setfield(L, -2, "action");
			lua_pushinteger(L, iptable.pkt_len_min);
			lua_setfield(L, -2, "pkt_len_min");
			lua_pushinteger(L, iptable.pkt_len_max);
			lua_setfield(L, -2, "pkt_len_max");
			lua_pushinteger(L, iptable.tcp_flags);
			lua_setfield(L, -2, "tcp_flags");
			lua_pushinteger(L, iptable.dscp_value);
			lua_setfield(L, -2, "dscp_value");
			lua_pushinteger(L, iptable.fragment);
			lua_setfield(L, -2, "fragment");
			lua_pushinteger(L, iptable.protocol);
			lua_setfield(L, -2, "protocol");
			lua_pushinteger(L, iptable.nb_interface);
			lua_setfield(L, -2, "nb_interface");
			lua_pushinteger(L, iptable.flow_label);
			lua_setfield(L, -2, "flow_label");
			lua_pushinteger(L, iptable.family);
			lua_setfield(L, -2, "family");
			lua_pushstring(L, iptable.ipset_name);
			lua_setfield(L, -2, "ipset_name");
		}
		lua_setfield(L, -2, "iptable");
		break;
	}
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE: {
		struct zebra_pbr_ipset ipset;

		dplane_ctx_get_pbr_ipset(ctx, &ipset);
		/* ipset */
		lua_newtable(L);
		{
			lua_pushinteger(L, ipset.sock);
			lua_setfield(L, -2, "sock");
			lua_pushinteger(L, ipset.vrf_id);
			lua_setfield(L, -2, "vrf_id");
			lua_pushinteger(L, ipset.unique);
			lua_setfield(L, -2, "unique");
			lua_pushinteger(L, ipset.type);
			lua_setfield(L, -2, "type");
			lua_pushinteger(L, ipset.family);
			lua_setfield(L, -2, "family");
			lua_pushstring(L, ipset.ipset_name);
			lua_setfield(L, -2, "ipset_name");
		}
		lua_setfield(L, -2, "ipset");
		break;
	}
	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
		/* neigh */
		lua_newtable(L);
		{
			lua_pushipaddr(L, dplane_ctx_neigh_get_ipaddr(ctx));
			lua_setfield(L, -2, "ip_addr");
			/* link */
			lua_newtable(L);
			{
				lua_pushethaddr(L,
						dplane_ctx_neigh_get_mac(ctx));
				lua_setfield(L, -2, "mac");
				lua_pushipaddr(
					L, dplane_ctx_neigh_get_link_ip(ctx));
				lua_setfield(L, -2, "ip_addr");
			}
			lua_setfield(L, -2, "link");
			lua_pushinteger(L, dplane_ctx_neigh_get_flags(ctx));
			lua_setfield(L, -2, "flags");
			lua_pushinteger(L, dplane_ctx_neigh_get_state(ctx));
			lua_setfield(L, -2, "state");
			lua_pushinteger(L,
					dplane_ctx_neigh_get_update_flags(ctx));
			lua_setfield(L, -2, "update_flags");
		}
		lua_setfield(L, -2, "neigh");
		break;
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
		break;
	case DPLANE_OP_BR_PORT_UPDATE:
		/* br_port */
		lua_newtable(L);
		{
			lua_pushinteger(
				L, dplane_ctx_get_br_port_sph_filter_cnt(ctx));
			lua_setfield(L, -2, "sph_filter_cnt");
			lua_pushinteger(L, dplane_ctx_get_br_port_flags(ctx));
			lua_setfield(L, -2, "flags");
			lua_pushinteger(
				L, dplane_ctx_get_br_port_backup_nhg_id(ctx));
			lua_setfield(L, -2, "backup_nhg_id");
		}
		lua_setfield(L, -2, "br_port");
		break;
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		/* neightable */
		lua_newtable(L);
		{
			lua_pushinteger(L,
					dplane_ctx_neightable_get_family(ctx));
			lua_setfield(L, -2, "family");
			lua_pushinteger(
				L, dplane_ctx_neightable_get_app_probes(ctx));
			lua_setfield(L, -2, "app_probes");
			lua_pushinteger(
				L, dplane_ctx_neightable_get_mcast_probes(ctx));
			lua_setfield(L, -2, "ucast_probes");
			lua_pushinteger(
				L, dplane_ctx_neightable_get_ucast_probes(ctx));
			lua_setfield(L, -2, "mcast_probes");
		}
		lua_setfield(L, -2, "neightable");
		break;
	case DPLANE_OP_GRE_SET:
		/* gre */
		lua_newtable(L);
		{
			lua_pushinteger(L,
					dplane_ctx_gre_get_link_ifindex(ctx));
			lua_setfield(L, -2, "link_ifindex");
			lua_pushinteger(L, dplane_ctx_gre_get_mtu(ctx));
			lua_setfield(L, -2, "mtu");
		}
		lua_setfield(L, -2, "gre");
		break;

	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
		/* Not currently handled */
	case DPLANE_OP_INTF_NETCONFIG: /*NYI*/
	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
	case DPLANE_OP_NONE:
	case DPLANE_OP_STARTUP_STAGE:
	case DPLANE_OP_VLAN_INSTALL:
		break;
	} /* Dispatch by op code */
}

#endif /* HAVE_SCRIPTING */
