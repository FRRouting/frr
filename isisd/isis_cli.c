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

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "northbound_cli.h"
#include "libfrr.h"
#include "yang.h"
#include "lib/linklist.h"
#include "isisd/isisd.h"
#include "isisd/isis_cli.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"

#ifndef VTYSH_EXTRACT_PL
#include "isisd/isis_cli_clippy.c"
#endif

#ifndef FABRICD

/*
 * XPath: /frr-isisd:isis/instance
 */
DEFPY_NOSH(router_isis, router_isis_cmd, "router isis WORD$tag",
	   ROUTER_STR
	   "ISO IS-IS\n"
	   "ISO Routing area tag\n")
{
	int ret;
	char base_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN,
		 "/frr-isisd:isis/instance[area-tag='%s']", tag);
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	/* default value in yang for is-type is level-1, but in FRR
	 * the first instance is assigned is-type level-1-2. We
	 * need to make sure to set it in the yang model so that it
	 * is consistent with what FRR sees.
	 */
	if (listcount(isis->area_list) == 0)
		nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY,
				      "level-1-2");
	ret = nb_cli_apply_changes(vty, base_xpath);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(ISIS_NODE, base_xpath);

	return ret;
}

DEFPY(no_router_isis, no_router_isis_cmd, "no router isis WORD$tag",
      NO_STR ROUTER_STR
      "ISO IS-IS\n"
      "ISO Routing area tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	struct listnode *node, *nnode;
	struct isis_circuit *circuit = NULL;
	struct isis_area *area = NULL;

	area = isis_area_lookup(tag);
	if (!area) {
		vty_out(vty, "ISIS area %s not found.\n", tag);
		return CMD_ERR_NOTHING_TODO;
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_DELETE, NULL);
	if (area->circuit_list && listcount(area->circuit_list)) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, node, nnode,
				       circuit)) {
			/* add callbacks to delete each of the circuits listed
			 */
			const char *vrf_name =
				vrf_lookup_by_id(circuit->interface->vrf_id)
					->name;
			snprintf(
				temp_xpath, XPATH_MAXLEN,
				"/frr-interface:lib/interface[name='%s'][vrf='%s']/frr-isisd:isis",
				circuit->interface->name, vrf_name);
			nb_cli_enqueue_change(vty, temp_xpath, NB_OP_DELETE,
					      NULL);
		}
	}

	return nb_cli_apply_changes(
		vty, "/frr-isisd:isis/instance[area-tag='%s']", tag);
}

void cli_show_router_isis(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, "!\n");
	vty_out(vty, "router isis %s\n",
		yang_dnode_get_string(dnode, "./area-tag"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv4-routing
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv6-routing
 * XPath: /frr-isisd:isis/instance
 */
DEFPY(ip_router_isis, ip_router_isis_cmd, "ip router isis WORD$tag",
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "IS-IS routing protocol\n"
      "Routing process tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	const char *circ_type;
	struct isis_area *area;

	/* area will be created if it is not present. make sure the yang model
	 * is synced with FRR and call the appropriate NB cb.
	 */
	area = isis_area_lookup(tag);
	if (!area) {
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']", tag);
		nb_cli_enqueue_change(vty, temp_xpath, NB_OP_CREATE, tag);
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']/is-type",
			 tag);
		nb_cli_enqueue_change(
			vty, temp_xpath, NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2" : NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv4-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/circuit-type", NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2"
							: "level-1");
	} else {
		/* area exists, circuit type defaults to its area's is_type */
		switch (area->is_type) {
		case IS_LEVEL_1:
			circ_type = "level-1";
			break;
		case IS_LEVEL_2:
			circ_type = "level-2";
			break;
		case IS_LEVEL_1_AND_2:
			circ_type = "level-1-2";
			break;
		}
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv4-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/circuit-type",
				      NB_OP_MODIFY, circ_type);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(ip6_router_isis, ip6_router_isis_cmd, "ipv6 router isis WORD$tag",
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "IS-IS routing protocol\n"
      "Routing process tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	const char *circ_type;
	struct isis_area *area;

	/* area will be created if it is not present. make sure the yang model
	 * is synced with FRR and call the appropriate NB cb.
	 */
	area = isis_area_lookup(tag);
	if (!area) {
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']", tag);
		nb_cli_enqueue_change(vty, temp_xpath, NB_OP_CREATE, tag);
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-isisd:isis/instance[area-tag='%s']/is-type",
			 tag);
		nb_cli_enqueue_change(
			vty, temp_xpath, NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2" : NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv6-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/circuit-type", NB_OP_MODIFY,
			listcount(isis->area_list) == 0 ? "level-1-2"
							: "level-1");
	} else {
		/* area exists, circuit type defaults to its area's is_type */
		switch (area->is_type) {
		case IS_LEVEL_1:
			circ_type = "level-1";
			break;
		case IS_LEVEL_2:
			circ_type = "level-2";
			break;
		case IS_LEVEL_1_AND_2:
			circ_type = "level-1-2";
			break;
		}
		nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv6-routing",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/circuit-type",
				      NB_OP_MODIFY, circ_type);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_ip_router_isis, no_ip_router_isis_cmd,
      "no <ip|ipv6>$ip router isis [WORD]$tag",
      NO_STR
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "IP router interface commands\n"
      "IS-IS routing protocol\n"
      "Routing process tag\n")
{
	const struct lyd_node *dnode =
		yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);
	struct interface *ifp;
	struct isis_circuit *circuit = NULL;

	/* check for the existance of a circuit */
	if (dnode) {
		ifp = yang_dnode_get_entry(dnode, false);
		if (ifp)
			circuit = circuit_scan_by_ifp(ifp);
	}

	/* if both ipv4 and ipv6 are off delete the interface isis container too
	 */
	if (!strncmp(ip, "ipv6", strlen("ipv6"))) {
		if (circuit && !circuit->ip_router)
			nb_cli_enqueue_change(vty, "./frr-isisd:isis",
					      NB_OP_DELETE, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-isisd:isis/ipv6-routing",
					      NB_OP_DELETE, NULL);
	} else { /* no ipv4  */
		if (circuit && !circuit->ipv6_router)
			nb_cli_enqueue_change(vty, "./frr-isisd:isis",
					      NB_OP_DELETE, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-isisd:isis/ipv4-routing",
					      NB_OP_DELETE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_ipv4(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " ip router isis %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

void cli_show_ip_isis_ipv6(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " ipv6 router isis %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

/*
 * XPath: /frr-isisd:isis/instance/area-address
 */
DEFPY(net, net_cmd, "[no] net WORD",
      "Remove an existing Network Entity Title for this process\n"
      "A Network Entity Title for this process (OSI only)\n"
      "XX.XXXX. ... .XXX.XX  Network entity title (NET)\n")
{
	nb_cli_enqueue_change(vty, "./area-address",
			      no ? NB_OP_DELETE : NB_OP_CREATE, net);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_area_address(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " net %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/is-type
 */
DEFPY(is_type, is_type_cmd, "is-type <level-1|level-1-2|level-2-only>$level",
      "IS Level for this routing process (OSI only)\n"
      "Act as a station router only\n"
      "Act as both a station router and an area router\n"
      "Act as an area router only\n")
{
	nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY,
			      strmatch(level, "level-2-only") ? "level-2"
							      : level);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_is_type, no_is_type_cmd,
      "no is-type [<level-1|level-1-2|level-2-only>]",
      NO_STR
      "IS Level for this routing process (OSI only)\n"
      "Act as a station router only\n"
      "Act as both a station router and an area router\n"
      "Act as an area router only\n")
{
	const char *value = NULL;
	const struct lyd_node *dnode =
		yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);
	struct isis_area *area = yang_dnode_get_entry(dnode, false);

	/*
	 * Put the is-type back to defaults:
	 * - level-1-2 on first area
	 * - level-1 for the rest
	 */
	if (area && listgetdata(listhead(isis->area_list)) == area)
		value = "level-1-2";
	else
		value = NULL;
	nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_is_type(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	int is_type = yang_dnode_get_enum(dnode, NULL);

	switch (is_type) {
	case IS_LEVEL_1:
		vty_out(vty, " is-type level-1\n");
		break;
	case IS_LEVEL_2:
		vty_out(vty, " is-type level-2-only\n");
		break;
	case IS_LEVEL_1_AND_2:
		vty_out(vty, " is-type level-1-2\n");
		break;
	}
}

/*
 * XPath: /frr-isisd:isis/instance/dynamic-hostname
 */
DEFPY(dynamic_hostname, dynamic_hostname_cmd, "[no] hostname dynamic",
      NO_STR
      "Dynamic hostname for IS-IS\n"
      "Dynamic hostname\n")
{
	nb_cli_enqueue_change(vty, "./dynamic-hostname", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_dynamic_hostname(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " hostname dynamic\n");
}

/*
 * XPath: /frr-isisd:isis/instance/overload
 */
DEFPY(set_overload_bit, set_overload_bit_cmd, "[no] set-overload-bit",
      "Reset overload bit to accept transit traffic\n"
      "Set overload bit to avoid any transit traffic\n")
{
	nb_cli_enqueue_change(vty, "./overload",
			      no ? NB_OP_DELETE : NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_overload(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults)
{
	vty_out(vty, " set-overload-bit\n");
}

/*
 * XPath: /frr-isisd:isis/instance/attached
 */
DEFPY(set_attached_bit, set_attached_bit_cmd, "[no] set-attached-bit",
      "Reset attached bit\n"
      "Set attached bit to identify as L1/L2 router for inter-area traffic\n")
{
	nb_cli_enqueue_change(vty, "./attached",
			      no ? NB_OP_DELETE : NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_attached(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults)
{
	vty_out(vty, " set-attached-bit\n");
}

/*
 * XPath: /frr-isisd:isis/instance/metric-style
 */
DEFPY(metric_style, metric_style_cmd,
	  "metric-style <narrow|transition|wide>$style",
      "Use old-style (ISO 10589) or new-style packet formats\n"
      "Use old style of TLVs with narrow metric\n"
      "Send and accept both styles of TLVs during transition\n"
      "Use new style of TLVs to carry wider metric\n")
{
	nb_cli_enqueue_change(vty, "./metric-style", NB_OP_MODIFY, style);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_metric_style, no_metric_style_cmd,
	  "no metric-style [narrow|transition|wide]",
	  NO_STR
	  "Use old-style (ISO 10589) or new-style packet formats\n"
      "Use old style of TLVs with narrow metric\n"
      "Send and accept both styles of TLVs during transition\n"
      "Use new style of TLVs to carry wider metric\n")
{
	nb_cli_enqueue_change(vty, "./metric-style", NB_OP_MODIFY, "narrow");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_metric_style(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	int metric = yang_dnode_get_enum(dnode, NULL);

	switch (metric) {
	case ISIS_NARROW_METRIC:
		vty_out(vty, " metric-style narrow\n");
		break;
	case ISIS_WIDE_METRIC:
		vty_out(vty, " metric-style wide\n");
		break;
	case ISIS_TRANSITION_METRIC:
		vty_out(vty, " metric-style transition\n");
		break;
	}
}

/*
 * XPath: /frr-isisd:isis/instance/area-password
 */
DEFPY(area_passwd, area_passwd_cmd,
      "area-password <clear|md5>$pwd_type WORD$pwd [authenticate snp <send-only|validate>$snp]",
      "Configure the authentication password for an area\n"
      "Clear-text authentication type\n"
      "MD5 authentication type\n"
      "Level-wide password\n"
      "Authentication\n"
      "SNP PDUs\n"
      "Send but do not check PDUs on receiving\n"
      "Send and check PDUs on receiving\n")
{
	nb_cli_enqueue_change(vty, "./area-password", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./area-password/password", NB_OP_MODIFY,
			      pwd);
	nb_cli_enqueue_change(vty, "./area-password/password-type",
			      NB_OP_MODIFY, pwd_type);
	nb_cli_enqueue_change(vty, "./area-password/authenticate-snp",
			      NB_OP_MODIFY, snp ? snp : "none");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_area_pwd(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults)
{
	const char *snp;

	vty_out(vty, " area-password %s %s",
		yang_dnode_get_string(dnode, "./password-type"),
		yang_dnode_get_string(dnode, "./password"));
	snp = yang_dnode_get_string(dnode, "./authenticate-snp");
	if (!strmatch("none", snp))
		vty_out(vty, " authenticate snp %s", snp);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password
 */
DEFPY(domain_passwd, domain_passwd_cmd,
      "domain-password <clear|md5>$pwd_type WORD$pwd [authenticate snp <send-only|validate>$snp]",
      "Set the authentication password for a routing domain\n"
      "Clear-text authentication type\n"
      "MD5 authentication type\n"
      "Level-wide password\n"
      "Authentication\n"
      "SNP PDUs\n"
      "Send but do not check PDUs on receiving\n"
      "Send and check PDUs on receiving\n")
{
	nb_cli_enqueue_change(vty, "./domain-password", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./domain-password/password", NB_OP_MODIFY,
			      pwd);
	nb_cli_enqueue_change(vty, "./domain-password/password-type",
			      NB_OP_MODIFY, pwd_type);
	nb_cli_enqueue_change(vty, "./domain-password/authenticate-snp",
			      NB_OP_MODIFY, snp ? snp : "none");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_area_passwd, no_area_passwd_cmd,
      "no <area-password|domain-password>$cmd",
      NO_STR
      "Configure the authentication password for an area\n"
      "Set the authentication password for a routing domain\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DELETE, NULL);

	return nb_cli_apply_changes(vty, "./%s", cmd);
}

void cli_show_isis_domain_pwd(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *snp;

	vty_out(vty, " domain-password %s %s",
		yang_dnode_get_string(dnode, "./password-type"),
		yang_dnode_get_string(dnode, "./password"));
	snp = yang_dnode_get_string(dnode, "./authenticate-snp");
	if (!strmatch("none", snp))
		vty_out(vty, " authenticate snp %s", snp);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/generation-interval
 */
DEFPY(lsp_gen_interval, lsp_gen_interval_cmd,
      "lsp-gen-interval [level-1|level-2]$level (1-120)$val",
      "Minimum interval between regenerating same LSP\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_lsp_gen_interval, no_lsp_gen_interval_cmd,
      "no lsp-gen-interval [level-1|level-2]$level [(1-120)]",
      NO_STR
      "Minimum interval between regenerating same LSP\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_lsp_gen_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " lsp-gen-interval %s\n", l1);
	else {
		vty_out(vty, " lsp-gen-interval level-1 %s\n", l1);
		vty_out(vty, " lsp-gen-interval level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/refresh-interval
 */
DEFPY(lsp_refresh_interval, lsp_refresh_interval_cmd,
      "lsp-refresh-interval [level-1|level-2]$level (1-65235)$val",
      "LSP refresh interval\n"
      "LSP refresh interval for Level 1 only\n"
      "LSP refresh interval for Level 2 only\n"
      "LSP refresh interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_lsp_refresh_interval, no_lsp_refresh_interval_cmd,
      "no lsp-refresh-interval [level-1|level-2]$level [(1-65235)]",
      NO_STR
      "LSP refresh interval\n"
      "LSP refresh interval for Level 1 only\n"
      "LSP refresh interval for Level 2 only\n"
      "LSP refresh interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_lsp_ref_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " lsp-refresh-interval %s\n", l1);
	else {
		vty_out(vty, " lsp-refresh-interval level-1 %s\n", l1);
		vty_out(vty, " lsp-refresh-interval level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/maximum-lifetime
 */
DEFPY(max_lsp_lifetime, max_lsp_lifetime_cmd,
      "max-lsp-lifetime [level-1|level-2]$level (350-65535)$val",
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime for Level 1 only\n"
      "Maximum LSP lifetime for Level 2 only\n"
      "LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_max_lsp_lifetime, no_max_lsp_lifetime_cmd,
      "no max-lsp-lifetime [level-1|level-2]$level [(350-65535)]",
      NO_STR
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime for Level 1 only\n"
      "Maximum LSP lifetime for Level 2 only\n"
      "LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_lsp_max_lifetime(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " max-lsp-lifetime %s\n", l1);
	else {
		vty_out(vty, " max-lsp-lifetime level-1 %s\n", l1);
		vty_out(vty, " max-lsp-lifetime level-2 %s\n", l2);
	}
}

void isis_cli_init(void)
{
	install_element(CONFIG_NODE, &router_isis_cmd);
	install_element(CONFIG_NODE, &no_router_isis_cmd);

	install_element(INTERFACE_NODE, &ip_router_isis_cmd);
	install_element(INTERFACE_NODE, &ip6_router_isis_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_isis_cmd);

	install_element(ISIS_NODE, &net_cmd);

	install_element(ISIS_NODE, &is_type_cmd);
	install_element(ISIS_NODE, &no_is_type_cmd);

	install_element(ISIS_NODE, &dynamic_hostname_cmd);

	install_element(ISIS_NODE, &set_overload_bit_cmd);
	install_element(ISIS_NODE, &set_attached_bit_cmd);

	install_element(ISIS_NODE, &metric_style_cmd);
	install_element(ISIS_NODE, &no_metric_style_cmd);

	install_element(ISIS_NODE, &area_passwd_cmd);
	install_element(ISIS_NODE, &domain_passwd_cmd);
	install_element(ISIS_NODE, &no_area_passwd_cmd);

	install_element(ISIS_NODE, &lsp_gen_interval_cmd);
	install_element(ISIS_NODE, &no_lsp_gen_interval_cmd);
	install_element(ISIS_NODE, &lsp_refresh_interval_cmd);
	install_element(ISIS_NODE, &no_lsp_refresh_interval_cmd);
	install_element(ISIS_NODE, &max_lsp_lifetime_cmd);
	install_element(ISIS_NODE, &no_max_lsp_lifetime_cmd);
}

#endif /* ifndef FABRICD */
