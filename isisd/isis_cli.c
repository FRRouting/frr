// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
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
#include "isisd/isis_nb.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_flex_algo.h"

#include "isisd/isis_cli_clippy.c"

#ifndef FABRICD

/*
 * XPath: /frr-isisd:isis/instance
 */
DEFPY_YANG_NOSH(router_isis, router_isis_cmd,
		"router isis WORD$tag [vrf NAME$vrf_name]",
		ROUTER_STR
		"ISO IS-IS\n"
		"ISO Routing area tag\n" VRF_CMD_HELP_STR)
{
	int ret;
	char base_xpath[XPATH_MAXLEN];

	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;

	snprintf(base_xpath, XPATH_MAXLEN,
		 "/frr-isisd:isis/instance[area-tag='%s'][vrf='%s']", tag,
		 vrf_name);
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, "%s", base_xpath);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(ISIS_NODE, base_xpath);

	return ret;
}

DEFPY_YANG(no_router_isis, no_router_isis_cmd,
	   "no router isis WORD$tag [vrf NAME$vrf_name]",
	   NO_STR ROUTER_STR
	   "ISO IS-IS\n"
	   "ISO Routing area tag\n" VRF_CMD_HELP_STR)
{
	if (!vrf_name)
		vrf_name = VRF_DEFAULT_NAME;

	if (!yang_dnode_existsf(
		    vty->candidate_config->dnode,
		    "/frr-isisd:isis/instance[area-tag='%s'][vrf='%s']", tag,
		    vrf_name)) {
		vty_out(vty, "ISIS area %s not found.\n", tag);
		return CMD_ERR_NOTHING_TODO;
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes_clear_pending(
		vty, "/frr-isisd:isis/instance[area-tag='%s'][vrf='%s']", tag,
		vrf_name);
}

void cli_show_router_isis(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	const char *vrf = NULL;

	vrf = yang_dnode_get_string(dnode, "vrf");

	vty_out(vty, "!\n");
	vty_out(vty, "router isis %s",
		yang_dnode_get_string(dnode, "area-tag"));
	if (!strmatch(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", yang_dnode_get_string(dnode, "vrf"));
	vty_out(vty, "\n");
}

void cli_show_router_isis_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv4-routing
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/ipv6-routing
 * XPath: /frr-isisd:isis/instance
 */
DEFPY_YANG(ip_router_isis, ip_router_isis_cmd,
	   "ip router isis WORD$tag",
	   "Interface Internet Protocol config commands\n"
	   "IP router interface commands\n"
	   "IS-IS routing protocol\n"
	   "Routing process tag\n")
{
	nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag", NB_OP_MODIFY,
			      tag);
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv4-routing",
			      NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_HIDDEN(ip_router_isis, ip_router_isis_vrf_cmd,
	     "ip router isis WORD$tag vrf NAME$vrf_name",
	     "Interface Internet Protocol config commands\n"
	     "IP router interface commands\n"
	     "IS-IS routing protocol\n"
	     "Routing process tag\n" VRF_CMD_HELP_STR)

DEFPY_YANG(ip6_router_isis, ip6_router_isis_cmd,
	   "ipv6 router isis WORD$tag",
	   "Interface Internet Protocol config commands\n"
	   "IP router interface commands\n"
	   "IS-IS routing protocol\n"
	   "Routing process tag\n")
{
	nb_cli_enqueue_change(vty, "./frr-isisd:isis", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/area-tag", NB_OP_MODIFY,
			      tag);
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/ipv6-routing",
			      NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_HIDDEN(ip6_router_isis, ip6_router_isis_vrf_cmd,
	     "ipv6 router isis WORD$tag vrf NAME$vrf_name",
	     "Interface Internet Protocol config commands\n"
	     "IP router interface commands\n"
	     "IS-IS routing protocol\n"
	     "Routing process tag\n" VRF_CMD_HELP_STR)

DEFPY_YANG(no_ip_router_isis, no_ip_router_isis_cmd,
	   "no <ip|ipv6>$ip router isis [WORD]$tag",
	   NO_STR
	   "Interface Internet Protocol config commands\n"
	   "IP router interface commands\n"
	   "IP router interface commands\n"
	   "IS-IS routing protocol\n"
	   "Routing process tag\n")
{
	const struct lyd_node *dnode;

	dnode = yang_dnode_getf(vty->candidate_config->dnode,
				"%s/frr-isisd:isis", VTY_CURR_XPATH);
	if (!dnode)
		return CMD_SUCCESS;

	/*
	 * If both ipv4 and ipv6 are off delete the interface isis container.
	 */
	if (strmatch(ip, "ipv6")) {
		if (!yang_dnode_get_bool(dnode, "ipv4-routing"))
			nb_cli_enqueue_change(vty, "./frr-isisd:isis",
					      NB_OP_DESTROY, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-isisd:isis/ipv6-routing",
					      NB_OP_MODIFY, "false");
	} else {
		if (!yang_dnode_get_bool(dnode, "ipv6-routing"))
			nb_cli_enqueue_change(vty, "./frr-isisd:isis",
					      NB_OP_DESTROY, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-isisd:isis/ipv4-routing",
					      NB_OP_MODIFY, "false");
	}

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_HIDDEN(no_ip_router_isis, no_ip_router_isis_vrf_cmd,
	     "no <ip|ipv6>$ip router isis WORD$tag vrf NAME$vrf_name",
	     NO_STR
	     "Interface Internet Protocol config commands\n"
	     "IP router interface commands\n"
	     "IP router interface commands\n"
	     "IS-IS routing protocol\n"
	     "Routing process tag\n"
	     VRF_CMD_HELP_STR)

void cli_show_ip_isis_ipv4(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " ip router isis %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

void cli_show_ip_isis_ipv6(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " ipv6 router isis %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring
 */
DEFPY_YANG(isis_bfd,
      isis_bfd_cmd,
      "[no] isis bfd",
      NO_STR PROTO_HELP
      "Enable BFD support\n")
{
	const struct lyd_node *dnode;

	dnode = yang_dnode_getf(vty->candidate_config->dnode,
				"%s/frr-isisd:isis", VTY_CURR_XPATH);
	if (dnode == NULL) {
		vty_out(vty, "ISIS is not enabled on this circuit\n");
		return CMD_SUCCESS;
	}

	nb_cli_enqueue_change(vty, "./frr-isisd:isis/bfd-monitoring/enabled",
			      NB_OP_MODIFY, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/bfd-monitoring/profile
 */
DEFPY_YANG(isis_bfd_profile,
      isis_bfd_profile_cmd,
      "[no] isis bfd profile BFDPROF$profile",
      NO_STR PROTO_HELP
      "Enable BFD support\n"
      "Use a pre-configured profile\n"
      "Profile name\n")
{
	const struct lyd_node *dnode;

	dnode = yang_dnode_getf(vty->candidate_config->dnode,
				"%s/frr-isisd:isis", VTY_CURR_XPATH);
	if (dnode == NULL) {
		vty_out(vty, "ISIS is not enabled on this circuit\n");
		return CMD_SUCCESS;
	}

	if (no)
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/bfd-monitoring/profile",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/bfd-monitoring/profile",
				      NB_OP_MODIFY, profile);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_bfd_monitoring(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, "enabled")) {
		if (show_defaults)
			vty_out(vty, " no isis bfd\n");
	} else {
		vty_out(vty, " isis bfd\n");
	}

	if (yang_dnode_exists(dnode, "profile"))
		vty_out(vty, " isis bfd profile %s\n",
			yang_dnode_get_string(dnode, "profile"));
}

/*
 * XPath: /frr-isisd:isis/instance/area-address
 */
DEFPY_YANG(net, net_cmd, "[no] net WORD",
      "Remove an existing Network Entity Title for this process\n"
      "A Network Entity Title for this process (OSI only)\n"
      "XX.XXXX. ... .XXX.XX  Network entity title (NET)\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, XPATH_MAXLEN, "./area-address[.='%s']", net);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_area_address(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " net %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/is-type
 */
DEFPY_YANG(is_type, is_type_cmd, "is-type <level-1|level-1-2|level-2-only>$level",
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

DEFPY_YANG(no_is_type, no_is_type_cmd,
      "no is-type [<level-1|level-1-2|level-2-only>]",
      NO_STR
      "IS Level for this routing process (OSI only)\n"
      "Act as a station router only\n"
      "Act as both a station router and an area router\n"
      "Act as an area router only\n")
{
	nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_is_type(struct vty *vty, const struct lyd_node *dnode,
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
DEFPY_YANG(dynamic_hostname, dynamic_hostname_cmd, "[no] hostname dynamic",
      NO_STR
      "Dynamic hostname for IS-IS\n"
      "Dynamic hostname\n")
{
	nb_cli_enqueue_change(vty, "./dynamic-hostname", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_dynamic_hostname(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " hostname dynamic\n");
}

/*
 * XPath: /frr-isisd:isis/instance/overload
 */
DEFPY_YANG(set_overload_bit, set_overload_bit_cmd, "[no] set-overload-bit",
      "Reset overload bit to accept transit traffic\n"
      "Set overload bit to avoid any transit traffic\n")
{
	nb_cli_enqueue_change(vty, "./overload/enabled", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_overload(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " set-overload-bit\n");
}

/*
 * XPath: /frr-isisd:isis/instance/overload/on-startup
 */
DEFPY_YANG(set_overload_bit_on_startup, set_overload_bit_on_startup_cmd,
	   "set-overload-bit on-startup (0-86400)$val",
	   "Set overload bit to avoid any transit traffic\n"
	   "Set overload bit on startup\n"
	   "Set overload time in seconds\n")
{
	nb_cli_enqueue_change(vty, "./overload/on-startup", NB_OP_MODIFY,
			      val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_overload_bit_on_startup, no_set_overload_bit_on_startup_cmd,
	   "no set-overload-bit on-startup [(0-86400)$val]",
	   NO_STR
	   "Reset overload bit to accept transit traffic\n"
	   "Set overload bit on startup\n"
	   "Set overload time in seconds\n")
{
	nb_cli_enqueue_change(vty, "./overload/on-startup", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_overload_on_startup(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, " set-overload-bit on-startup %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/advertise-high-metrics
 */
DEFPY_YANG(advertise_high_metrics, advertise_high_metrics_cmd,
	   "[no] advertise-high-metrics",
	   NO_STR "Advertise high metric value on all interfaces\n")
{
	nb_cli_enqueue_change(vty, "./advertise-high-metrics", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_advertise_high_metrics(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " advertise-high-metrics\n");
	else if (show_defaults)
		vty_out(vty, " no advertise-high-metrics\n");
}

/*
 * XPath: /frr-isisd:isis/instance/attach-send
 */
DEFPY_YANG(attached_bit_send, attached_bit_send_cmd, "[no] attached-bit send",
	   "Reset attached bit\n"
	   "Set attached bit for inter-area traffic\n"
	   "Set attached bit in LSP sent to L1 router\n")
{
	nb_cli_enqueue_change(vty, "./attach-send", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_attached_send(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " attached-bit send\n");
}

/*
 * XPath: /frr-isisd:isis/instance/attach-receive-ignore
 */
DEFPY_YANG(
	attached_bit_receive_ignore, attached_bit_receive_ignore_cmd,
	"[no] attached-bit receive ignore",
	"Reset attached bit\n"
	"Set attach bit for inter-area traffic\n"
	"If LSP received with attached bit set, create default route to neighbor\n"
	"Do not process attached bit\n")
{
	nb_cli_enqueue_change(vty, "./attach-receive-ignore", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_attached_receive(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " attached-bit receive ignore\n");
}

/*
 * XPath: /frr-isisd:isis/instance/metric-style
 */
DEFPY_YANG(metric_style, metric_style_cmd,
      "metric-style <narrow|transition|wide>$style",
      "Use old-style (ISO 10589) or new-style packet formats\n"
      "Use old style of TLVs with narrow metric\n"
      "Send and accept both styles of TLVs during transition\n"
      "Use new style of TLVs to carry wider metric\n")
{
	nb_cli_enqueue_change(vty, "./metric-style", NB_OP_MODIFY, style);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_metric_style, no_metric_style_cmd,
      "no metric-style [narrow|transition|wide]",
      NO_STR
      "Use old-style (ISO 10589) or new-style packet formats\n"
      "Use old style of TLVs with narrow metric\n"
      "Send and accept both styles of TLVs during transition\n"
      "Use new style of TLVs to carry wider metric\n")
{
	nb_cli_enqueue_change(vty, "./metric-style", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_metric_style(struct vty *vty, const struct lyd_node *dnode,
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
DEFPY_YANG(area_passwd, area_passwd_cmd,
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

void cli_show_isis_area_pwd(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults)
{
	const char *snp;

	vty_out(vty, " area-password %s %s",
		yang_dnode_get_string(dnode, "password-type"),
		yang_dnode_get_string(dnode, "password"));
	snp = yang_dnode_get_string(dnode, "authenticate-snp");
	if (!strmatch("none", snp))
		vty_out(vty, " authenticate snp %s", snp);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-isisd:isis/instance/domain-password
 */
DEFPY_YANG(domain_passwd, domain_passwd_cmd,
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

DEFPY_YANG(no_area_passwd, no_area_passwd_cmd,
      "no <area-password|domain-password>$cmd",
      NO_STR
      "Configure the authentication password for an area\n"
      "Set the authentication password for a routing domain\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./%s", cmd);
}

void cli_show_isis_domain_pwd(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *snp;

	vty_out(vty, " domain-password %s %s",
		yang_dnode_get_string(dnode, "password-type"),
		yang_dnode_get_string(dnode, "password"));
	snp = yang_dnode_get_string(dnode, "authenticate-snp");
	if (!strmatch("none", snp))
		vty_out(vty, " authenticate snp %s", snp);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-1/generation-interval
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-2/generation-interval
 */
DEFPY_YANG(lsp_gen_interval, lsp_gen_interval_cmd,
      "lsp-gen-interval [level-1|level-2]$level (1-120)$val",
      "Minimum interval between regenerating same LSP\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-1/generation-interval",
			NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-2/generation-interval",
			NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_lsp_gen_interval, no_lsp_gen_interval_cmd,
      "no lsp-gen-interval [level-1|level-2]$level [(1-120)]",
      NO_STR
      "Minimum interval between regenerating same LSP\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-1/generation-interval",
			NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-2/generation-interval",
			NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-1/refresh-interval
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-2/refresh-interval
 */
DEFPY_YANG(lsp_refresh_interval, lsp_refresh_interval_cmd,
      "lsp-refresh-interval [level-1|level-2]$level (1-65235)$val",
      "LSP refresh interval\n"
      "LSP refresh interval for Level 1 only\n"
      "LSP refresh interval for Level 2 only\n"
      "LSP refresh interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/refresh-interval",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/refresh-interval",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_lsp_refresh_interval, no_lsp_refresh_interval_cmd,
      "no lsp-refresh-interval [level-1|level-2]$level [(1-65235)]",
      NO_STR
      "LSP refresh interval\n"
      "LSP refresh interval for Level 1 only\n"
      "LSP refresh interval for Level 2 only\n"
      "LSP refresh interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/refresh-interval",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/refresh-interval",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-1/maximum-lifetime
 * XPath: /frr-isisd:isis/instance/lsp/timers/level-1/maximum-lifetime
 */

DEFPY_YANG(max_lsp_lifetime, max_lsp_lifetime_cmd,
      "max-lsp-lifetime [level-1|level-2]$level (350-65535)$val",
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime for Level 1 only\n"
      "Maximum LSP lifetime for Level 2 only\n"
      "LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/maximum-lifetime",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/maximum-lifetime",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_max_lsp_lifetime, no_max_lsp_lifetime_cmd,
      "no max-lsp-lifetime [level-1|level-2]$level [(350-65535)]",
      NO_STR
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime for Level 1 only\n"
      "Maximum LSP lifetime for Level 2 only\n"
      "LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/maximum-lifetime",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/maximum-lifetime",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* unified LSP timers command
 * XPath: /frr-isisd:isis/instance/lsp/timers
 */

DEFPY_YANG(lsp_timers, lsp_timers_cmd,
      "lsp-timers [level-1|level-2]$level gen-interval (1-120)$gen refresh-interval (1-65235)$refresh max-lifetime (350-65535)$lifetime",
      "LSP-related timers\n"
      "LSP-related timers for Level 1 only\n"
      "LSP-related timers for Level 2 only\n"
      "Minimum interval between regenerating same LSP\n"
      "Generation interval in seconds\n"
      "LSP refresh interval\n"
      "LSP refresh interval in seconds\n"
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1")) {
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-1/generation-interval",
			NB_OP_MODIFY, gen_str);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/refresh-interval",
				      NB_OP_MODIFY, refresh_str);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/maximum-lifetime",
				      NB_OP_MODIFY, lifetime_str);
	}
	if (!level || strmatch(level, "level-2")) {
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-2/generation-interval",
			NB_OP_MODIFY, gen_str);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/refresh-interval",
				      NB_OP_MODIFY, refresh_str);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/maximum-lifetime",
				      NB_OP_MODIFY, lifetime_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_lsp_timers, no_lsp_timers_cmd,
      "no lsp-timers [level-1|level-2]$level [gen-interval (1-120) refresh-interval (1-65235) max-lifetime (350-65535)]",
      NO_STR
      "LSP-related timers\n"
      "LSP-related timers for Level 1 only\n"
      "LSP-related timers for Level 2 only\n"
      "Minimum interval between regenerating same LSP\n"
      "Generation interval in seconds\n"
      "LSP refresh interval\n"
      "LSP refresh interval in seconds\n"
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1")) {
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-1/generation-interval",
			NB_OP_MODIFY, NULL);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/refresh-interval",
				      NB_OP_MODIFY, NULL);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-1/maximum-lifetime",
				      NB_OP_MODIFY, NULL);
	}
	if (!level || strmatch(level, "level-2")) {
		nb_cli_enqueue_change(
			vty, "./lsp/timers/level-2/generation-interval",
			NB_OP_MODIFY, NULL);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/refresh-interval",
				      NB_OP_MODIFY, NULL);
		nb_cli_enqueue_change(vty,
				      "./lsp/timers/level-2/maximum-lifetime",
				      NB_OP_MODIFY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_lsp_timers(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *l1_refresh =
		yang_dnode_get_string(dnode, "level-1/refresh-interval");
	const char *l2_refresh =
		yang_dnode_get_string(dnode, "level-2/refresh-interval");
	const char *l1_lifetime =
		yang_dnode_get_string(dnode, "level-1/maximum-lifetime");
	const char *l2_lifetime =
		yang_dnode_get_string(dnode, "level-2/maximum-lifetime");
	const char *l1_gen =
		yang_dnode_get_string(dnode, "level-1/generation-interval");
	const char *l2_gen =
		yang_dnode_get_string(dnode, "level-2/generation-interval");
	if (strmatch(l1_refresh, l2_refresh)
	    && strmatch(l1_lifetime, l2_lifetime) && strmatch(l1_gen, l2_gen))
		vty_out(vty,
			" lsp-timers gen-interval %s refresh-interval %s max-lifetime %s\n",
			l1_gen, l1_refresh, l1_lifetime);
	else {
		vty_out(vty,
			" lsp-timers level-1 gen-interval %s refresh-interval %s max-lifetime %s\n",
			l1_gen, l1_refresh, l1_lifetime);
		vty_out(vty,
			" lsp-timers level-2 gen-interval %s refresh-interval %s max-lifetime %s\n",
			l2_gen, l2_refresh, l2_lifetime);
	}
}

/*
 * XPath: /frr-isisd:isis/instance/lsp/mtu
 */
DEFPY_YANG(area_lsp_mtu, area_lsp_mtu_cmd, "lsp-mtu (128-4352)$val",
      "Configure the maximum size of generated LSPs\n"
      "Maximum size of generated LSPs\n")
{
	nb_cli_enqueue_change(vty, "./lsp/mtu", NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_area_lsp_mtu, no_area_lsp_mtu_cmd, "no lsp-mtu [(128-4352)]",
      NO_STR
      "Configure the maximum size of generated LSPs\n"
      "Maximum size of generated LSPs\n")
{
	nb_cli_enqueue_change(vty, "./lsp/mtu", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_lsp_mtu(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " lsp-mtu %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/advertise-passive-only
 */
DEFPY_YANG(advertise_passive_only, advertise_passive_only_cmd,
	   "[no] advertise-passive-only",
	   NO_STR "Advertise prefixes of passive interfaces only\n")
{
	nb_cli_enqueue_change(vty, "./advertise-passive-only", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_advertise_passive_only(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " advertise-passive-only\n");
}

/*
 * XPath: /frr-isisd:isis/instance/spf/minimum-interval
 */
DEFPY_YANG(spf_interval, spf_interval_cmd,
      "spf-interval [level-1|level-2]$level (1-120)$val",
      "Minimum interval between SPF calculations\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval between consecutive SPFs in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_spf_interval, no_spf_interval_cmd,
      "no spf-interval [level-1|level-2]$level [(1-120)]",
      NO_STR
      "Minimum interval between SPF calculations\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval between consecutive SPFs in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_spf_min_interval(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "level-1");
	const char *l2 = yang_dnode_get_string(dnode, "level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " spf-interval %s\n", l1);
	else {
		vty_out(vty, " spf-interval level-1 %s\n", l1);
		vty_out(vty, " spf-interval level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-isisd:isis/instance/spf/ietf-backoff-delay
 */
DEFPY_YANG(spf_delay_ietf, spf_delay_ietf_cmd,
      "spf-delay-ietf init-delay (0-60000) short-delay (0-60000) long-delay (0-60000) holddown (0-60000) time-to-learn (0-60000)",
      "IETF SPF delay algorithm\n"
      "Delay used while in QUIET state\n"
      "Delay used while in QUIET state in milliseconds\n"
      "Delay used while in SHORT_WAIT state\n"
      "Delay used while in SHORT_WAIT state in milliseconds\n"
      "Delay used while in LONG_WAIT\n"
      "Delay used while in LONG_WAIT state in milliseconds\n"
      "Time with no received IGP events before considering IGP stable\n"
      "Time with no received IGP events before considering IGP stable (in milliseconds)\n"
      "Maximum duration needed to learn all the events related to a single failure\n"
      "Maximum duration needed to learn all the events related to a single failure (in milliseconds)\n")
{
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay", NB_OP_CREATE,
			      NULL);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/init-delay",
			      NB_OP_MODIFY, init_delay_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/short-delay",
			      NB_OP_MODIFY, short_delay_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/long-delay",
			      NB_OP_MODIFY, long_delay_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/hold-down",
			      NB_OP_MODIFY, holddown_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/time-to-learn",
			      NB_OP_MODIFY, time_to_learn_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_spf_delay_ietf, no_spf_delay_ietf_cmd,
      "no spf-delay-ietf [init-delay (0-60000) short-delay (0-60000) long-delay (0-60000) holddown (0-60000) time-to-learn (0-60000)]",
      NO_STR
      "IETF SPF delay algorithm\n"
      "Delay used while in QUIET state\n"
      "Delay used while in QUIET state in milliseconds\n"
      "Delay used while in SHORT_WAIT state\n"
      "Delay used while in SHORT_WAIT state in milliseconds\n"
      "Delay used while in LONG_WAIT\n"
      "Delay used while in LONG_WAIT state in milliseconds\n"
      "Time with no received IGP events before considering IGP stable\n"
      "Time with no received IGP events before considering IGP stable (in milliseconds)\n"
      "Maximum duration needed to learn all the events related to a single failure\n"
      "Maximum duration needed to learn all the events related to a single failure (in milliseconds)\n")
{
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_spf_ietf_backoff(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty,
		" spf-delay-ietf init-delay %s short-delay %s long-delay %s holddown %s time-to-learn %s\n",
		yang_dnode_get_string(dnode, "init-delay"),
		yang_dnode_get_string(dnode, "short-delay"),
		yang_dnode_get_string(dnode, "long-delay"),
		yang_dnode_get_string(dnode, "hold-down"),
		yang_dnode_get_string(dnode, "time-to-learn"));
}

/*
 * XPath: /frr-isisd:isis/instance/spf/prefix-priorities/medium/access-list-name
 */
DEFPY_YANG(spf_prefix_priority, spf_prefix_priority_cmd,
      "spf prefix-priority <critical|high|medium>$priority ACCESSLIST_NAME$acl_name",
      "SPF configuration\n"
      "Configure a prefix priority list\n"
      "Specify critical priority prefixes\n"
      "Specify high priority prefixes\n"
      "Specify medium priority prefixes\n"
      "Access-list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, XPATH_MAXLEN,
		 "./spf/prefix-priorities/%s/access-list-name", priority);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, acl_name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_spf_prefix_priority, no_spf_prefix_priority_cmd,
      "no spf prefix-priority <critical|high|medium>$priority [ACCESSLIST_NAME]",
      NO_STR
      "SPF configuration\n"
      "Configure a prefix priority list\n"
      "Specify critical priority prefixes\n"
      "Specify high priority prefixes\n"
      "Specify medium priority prefixes\n"
      "Access-list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, XPATH_MAXLEN,
		 "./spf/prefix-priorities/%s/access-list-name", priority);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_spf_prefix_priority(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, " spf prefix-priority %s %s\n",
		dnode->parent->schema->name,
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/purge-originator
 */
DEFPY_YANG(area_purge_originator, area_purge_originator_cmd, "[no] purge-originator",
      NO_STR "Use the RFC 6232 purge-originator\n")
{
	nb_cli_enqueue_change(vty, "./purge-originator", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_purge_origin(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " purge-originator\n");
}


/*
 * XPath: /frr-isisd:isis/instance/admin-group-send-zero
 */
DEFPY_YANG(isis_admin_group_send_zero, isis_admin_group_send_zero_cmd,
	   "[no] admin-group-send-zero",
	   NO_STR
	   "Allow sending the default admin-group value of 0x00000000.\n")
{
	nb_cli_enqueue_change(vty, "./admin-group-send-zero", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_admin_group_send_zero(struct vty *vty,
					 const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " admin-group-send-zero\n");
}


/*
 * XPath: /frr-isisd:isis/instance/asla-legacy-flag
 */
DEFPY_HIDDEN(isis_asla_legacy_flag, isis_asla_legacy_flag_cmd,
	     "[no] asla-legacy-flag",
	     NO_STR "Set the legacy flag (aka. L-FLAG) in the ASLA Sub-TLV.\n")
{
	nb_cli_enqueue_change(vty, "./asla-legacy-flag", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_asla_legacy_flag(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " asla-legacy-flag\n");
}

/*
 * XPath: /frr-isisd:isis/instance/mpls-te
 */
DEFPY_YANG(isis_mpls_te_on, isis_mpls_te_on_cmd, "mpls-te on",
      MPLS_TE_STR "Enable the MPLS-TE functionality\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te", NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_mpls_te_on, no_isis_mpls_te_on_cmd, "no mpls-te [on]",
      NO_STR
      "Disable the MPLS-TE functionality\n"
      "Disable the MPLS-TE functionality\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_mpls_te(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " mpls-te on\n");
}

/*
 * XPath: /frr-isisd:isis/instance/mpls-te/router-address
 */
DEFPY_YANG(isis_mpls_te_router_addr, isis_mpls_te_router_addr_cmd,
      "mpls-te router-address A.B.C.D",
      MPLS_TE_STR
      "Stable IP address of the advertising router\n"
      "MPLS-TE router address in IPv4 address format\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te/router-address",
			      NB_OP_MODIFY, router_address_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_mpls_te_router_addr, no_isis_mpls_te_router_addr_cmd,
      "no mpls-te router-address [A.B.C.D]",
      NO_STR MPLS_TE_STR
      "Delete IP address of the advertising router\n"
      "MPLS-TE router address in IPv4 address format\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te/router-address",
			      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_mpls_te_router_addr(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, " mpls-te router-address %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/mpls-te/router-address-v6
 */
DEFPY_YANG(isis_mpls_te_router_addr_v6, isis_mpls_te_router_addr_v6_cmd,
      "mpls-te router-address ipv6 X:X::X:X",
      MPLS_TE_STR
      "Stable IP address of the advertising router\n"
      "IPv6 address\n"
      "MPLS-TE router address in IPv6 address format\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te/router-address-v6", NB_OP_MODIFY,
			      ipv6_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_mpls_te_router_addr_v6, no_isis_mpls_te_router_addr_v6_cmd,
      "no mpls-te router-address ipv6 [X:X::X:X]",
      NO_STR MPLS_TE_STR
      "Delete IP address of the advertising router\n"
      "IPv6 address\n"
      "MPLS-TE router address in IPv6 address format\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te/router-address-v6", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_mpls_te_router_addr_ipv6(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " mpls-te router-address ipv6 %s\n",
		yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG(isis_mpls_te_inter_as, isis_mpls_te_inter_as_cmd,
      "[no] mpls-te inter-as [level-1|level-1-2|level-2-only]",
      NO_STR MPLS_TE_STR
      "Configure MPLS-TE Inter-AS support\n"
      "AREA native mode self originate INTER-AS LSP with L1 only flooding scope\n"
      "AREA native mode self originate INTER-AS LSP with L1 and L2 flooding scope\n"
      "AS native mode self originate INTER-AS LSP with L2 only flooding scope\n")
{
	vty_out(vty, "MPLS-TE Inter-AS is not yet supported\n");
	return CMD_SUCCESS;
}

/*
 * XPath: /frr-isisd:isis/instance/mpls-te/export
 */
DEFPY_YANG(isis_mpls_te_export, isis_mpls_te_export_cmd, "mpls-te export",
      MPLS_TE_STR "Enable export of MPLS-TE Link State information\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te/export", NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_mpls_te_export, no_isis_mpls_te_export_cmd,
      "no mpls-te export",
      NO_STR MPLS_TE_STR
      "Disable export of MPLS-TE  Link State information\n")
{
	nb_cli_enqueue_change(vty, "./mpls-te/export", NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_mpls_te_export(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " mpls-te export\n");
}

/*
 * XPath: /frr-isisd:isis/instance/default-information-originate
 */
DEFPY_YANG(isis_default_originate, isis_default_originate_cmd,
      "[no] default-information originate <ipv4|ipv6>$ip <level-1|level-2>$level [always]$always [{metric (0-16777215)$metric|route-map RMAP_NAME$rmap}]",
      NO_STR
      "Control distribution of default information\n"
      "Distribute a default route\n"
      "Distribute default route for IPv4\n"
      "Distribute default route for IPv6\n"
      "Distribute default route into level-1\n"
      "Distribute default route into level-2\n"
      "Always advertise default route\n"
      "Metric for default route\n"
      "IS-IS default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./always", NB_OP_MODIFY,
				      always ? "true" : "false");
		nb_cli_enqueue_change(vty, "./route-map",
				      rmap ? NB_OP_MODIFY : NB_OP_DESTROY,
				      rmap ? rmap : NULL);
		nb_cli_enqueue_change(vty, "./metric", NB_OP_MODIFY,
				      metric_str ? metric_str : NULL);
		if (strmatch(ip, "ipv6") && !always) {
			vty_out(vty,
				"Zebra doesn't implement default-originate for IPv6 yet\n");
			vty_out(vty,
				"so use with care or use default-originate always.\n");
		}
	}

	return nb_cli_apply_changes(
		vty, "./default-information-originate/%s[level='%s']", ip,
		level);
}

static void vty_print_def_origin(struct vty *vty, const struct lyd_node *dnode,
				 const char *family, const char *level,
				 bool show_defaults)
{
	vty_out(vty, " default-information originate %s %s", family, level);
	if (yang_dnode_get_bool(dnode, "always"))
		vty_out(vty, " always");

	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "route-map"));
	if (show_defaults || !yang_dnode_is_default(dnode, "metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "metric"));

	vty_out(vty, "\n");
}

void cli_show_isis_def_origin_ipv4(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *level = yang_dnode_get_string(dnode, "level");

	vty_print_def_origin(vty, dnode, "ipv4", level, show_defaults);
}

void cli_show_isis_def_origin_ipv6(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *level = yang_dnode_get_string(dnode, "level");

	vty_print_def_origin(vty, dnode, "ipv6", level, show_defaults);
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute
 */
DEFPY_YANG(isis_redistribute, isis_redistribute_cmd,
      "[no] redistribute <ipv4$ip " PROTO_IP_REDIST_STR "$proto|ipv6$ip "
      PROTO_IP6_REDIST_STR "$proto> <level-1|level-2>$level"
      "[{metric (0-16777215)|route-map RMAP_NAME$route_map}]",
      NO_STR REDIST_STR
      "Redistribute IPv4 routes\n"
      PROTO_IP_REDIST_HELP
      "Redistribute IPv6 routes\n"
      PROTO_IP6_REDIST_HELP
      "Redistribute into level-1\n"
      "Redistribute into level-2\n"
      "Metric for redistributed routes\n"
      "IS-IS default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map",
				      route_map ? NB_OP_MODIFY : NB_OP_DESTROY,
				      route_map ? route_map : NULL);
		nb_cli_enqueue_change(vty, "./metric", NB_OP_MODIFY,
				      metric_str ? metric_str : NULL);
	}

	return nb_cli_apply_changes(
		vty, "./redistribute/%s[protocol='%s'][level='%s']", ip, proto,
		level);
}

/*
 * XPath: /frr-isisd:isis/instance/redistribute/table
 */
DEFPY_YANG(isis_redistribute_table, isis_redistribute_table_cmd,
	   "[no] redistribute <ipv4|ipv6>$ip table (1-65535)$table"
	   "<level-1|level-2>$level [{metric (0-16777215)|route-map WORD}]",
	   NO_STR REDIST_STR "Redistribute IPv4 routes\n"
			     "Redistribute IPv6 routes\n"
			     "Non-main Kernel Routing Table\n"
			     "Table Id\n"
			     "Redistribute into level-1\n"
			     "Redistribute into level-2\n"
			     "Metric for redistributed routes\n"
			     "IS-IS default metric\n"
			     "Route map reference\n"
			     "Pointer to route-map entries\n")
{
	struct isis_redist_table_present_args rtda = {};
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 128];
	int rv;

	rtda.rtda_table = table_str;
	rtda.rtda_ip = ip;
	rtda.rtda_level = level;

	if (no) {
		if (!isis_redist_table_is_present(vty, &rtda))
			return CMD_WARNING_CONFIG_FAILED;

		snprintf(xpath, sizeof(xpath), "./table[table='%s']", table_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		rv = nb_cli_apply_changes(vty,
					  "./redistribute/%s[protocol='table'][level='%s']",
					  ip, level);
		if (rv == CMD_SUCCESS) {
			if (isis_redist_table_get_first(vty, &rtda) > 0)
				return CMD_SUCCESS;
			nb_cli_enqueue_change(vty, "./table", NB_OP_DESTROY,
					      NULL);
			nb_cli_apply_changes(vty,
					     "./redistribute/%s[protocol='table'][level='%s']",
					     ip, level);
		}
		return CMD_SUCCESS;
	}
	if (isis_redist_table_is_present(vty, &rtda))
		return CMD_SUCCESS;

	snprintf(xpath, sizeof(xpath), "./table[table='%s']", table_str);
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_entry, sizeof(xpath_entry), "%s/route-map", xpath);
	nb_cli_enqueue_change(vty, xpath_entry,
			      route_map ? NB_OP_MODIFY : NB_OP_DESTROY,
			      route_map ? route_map : NULL);
	snprintf(xpath_entry, sizeof(xpath_entry), "%s/metric", xpath);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_MODIFY,
			      metric_str ? metric_str : NULL);
	return nb_cli_apply_changes(vty,
				    "./redistribute/%s[protocol='table'][level='%s']",
				    ip, level);
}

static void vty_print_redistribute(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults, const char *family,
				   bool table)
{
	const char *level;
	const char *protocol = NULL;
	const char *routemap = NULL;
	uint16_t tableid;

	if (table) {
		level = yang_dnode_get_string(dnode, "../level");
		tableid = yang_dnode_get_uint16(dnode, "table");
		vty_out(vty, " redistribute %s table %d ", family, tableid);
	} else {
		protocol = yang_dnode_get_string(dnode, "protocol");
		if (!table && strmatch(protocol, "table"))
			return;
		level = yang_dnode_get_string(dnode, "level");
		vty_out(vty, " redistribute %s %s ", family, protocol);
	}
	vty_out(vty, "%s", level);
	if (show_defaults || !yang_dnode_is_default(dnode, "metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "%s", "metric"));

	if (yang_dnode_exists(dnode, "route-map"))
		routemap = yang_dnode_get_string(dnode, "route-map");
	if (routemap)
		vty_out(vty, " route-map %s", routemap);
	vty_out(vty, "\n");
}

void cli_show_isis_redistribute_ipv4(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_print_redistribute(vty, dnode, show_defaults, "ipv4", false);
}

void cli_show_isis_redistribute_ipv6(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_print_redistribute(vty, dnode, show_defaults, "ipv6", false);
}

void cli_show_isis_redistribute_ipv4_table(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_print_redistribute(vty, dnode, show_defaults, "ipv4", true);
}

void cli_show_isis_redistribute_ipv6_table(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_print_redistribute(vty, dnode, show_defaults, "ipv6", true);
}

int cli_cmp_isis_redistribute_table(const struct lyd_node *dnode1,
				    const struct lyd_node *dnode2)
{
	uint16_t table1 = yang_dnode_get_uint16(dnode1, "table");
	uint16_t table2 = yang_dnode_get_uint16(dnode2, "table");

	return table1 - table2;
}

/*
 * XPath: /frr-isisd:isis/instance/multi-topology
 */
DEFPY_YANG(
	isis_topology, isis_topology_cmd,
	"[no] topology <standard|ipv4-unicast|ipv4-mgmt|ipv6-unicast|ipv4-multicast|ipv6-multicast|ipv6-mgmt|ipv6-dstsrc>$topology [overload]$overload",
	NO_STR
	"Configure IS-IS topologies\n"
	"standard topology\n"
	"IPv4 unicast topology\n"
	"IPv4 management topology\n"
	"IPv6 unicast topology\n"
	"IPv4 multicast topology\n"
	"IPv6 multicast topology\n"
	"IPv6 management topology\n"
	"IPv6 dst-src topology\n"
	"Set overload bit for topology\n")
{
	char base_xpath[XPATH_MAXLEN];

	/* Since standard is not configurable it is not present in the
	 * YANG model, so we need to validate it here
	 */
	if (strmatch(topology, "standard") ||
	    strmatch(topology, "ipv4-unicast")) {
		vty_out(vty,
			"Cannot configure IPv4 unicast (Standard) topology\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(topology, "ipv4-mgmt"))
		snprintf(base_xpath, XPATH_MAXLEN,
			 "./multi-topology/ipv4-management");
	else if (strmatch(topology, "ipv6-mgmt"))
		snprintf(base_xpath, XPATH_MAXLEN,
			 "./multi-topology/ipv6-management");
	else
		snprintf(base_xpath, XPATH_MAXLEN, "./multi-topology/%s",
			 topology);

	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./overload", NB_OP_MODIFY,
				      overload ? "true" : "false");
	}

	return nb_cli_apply_changes(vty, "%s", base_xpath);
}

void cli_show_isis_mt_ipv4_multicast(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, " topology ipv4-multicast");
	if (yang_dnode_get_bool(dnode, "overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_isis_mt_ipv4_mgmt(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " topology ipv4-mgmt");
	if (yang_dnode_get_bool(dnode, "overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_isis_mt_ipv6_unicast(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " topology ipv6-unicast");
	if (yang_dnode_get_bool(dnode, "overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_isis_mt_ipv6_multicast(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, " topology ipv6-multicast");
	if (yang_dnode_get_bool(dnode, "overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_isis_mt_ipv6_mgmt(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " topology ipv6-mgmt");
	if (yang_dnode_get_bool(dnode, "overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_isis_mt_ipv6_dstsrc(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, " topology ipv6-dstsrc");
	if (yang_dnode_get_bool(dnode, "overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/enabled
 */
DEFPY_YANG (isis_sr_enable,
       isis_sr_enable_cmd,
       "segment-routing on",
       SR_STR
       "Enable Segment Routing\n")
{
	nb_cli_enqueue_change(vty, "./segment-routing/enabled", NB_OP_MODIFY,
			      "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_isis_sr_enable,
       no_isis_sr_enable_cmd,
       "no segment-routing [on]",
       NO_STR
       SR_STR
       "Disable Segment Routing\n")
{
	nb_cli_enqueue_change(vty, "./segment-routing/enabled", NB_OP_MODIFY,
			      "false");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_sr_enabled(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " segment-routing on\n");
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/label-block
 */

DEFPY_YANG(
	isis_sr_global_block_label_range, isis_sr_global_block_label_range_cmd,
	"segment-routing global-block (16-1048575)$gb_lower_bound (16-1048575)$gb_upper_bound [local-block (16-1048575)$lb_lower_bound (16-1048575)$lb_upper_bound]",
	SR_STR
	"Segment Routing Global Block label range\n"
	"The lower bound of the global block\n"
	"The upper bound of the global block (block size may not exceed 65535)\n"
	"Segment Routing Local Block label range\n"
	"The lower bound of the local block\n"
	"The upper bound of the local block (block size may not exceed 65535)\n")
{
	nb_cli_enqueue_change(vty,
			      "./segment-routing/label-blocks/srgb/lower-bound",
			      NB_OP_MODIFY, gb_lower_bound_str);
	nb_cli_enqueue_change(vty,
			      "./segment-routing/label-blocks/srgb/upper-bound",
			      NB_OP_MODIFY, gb_upper_bound_str);

	nb_cli_enqueue_change(
		vty, "./segment-routing/label-blocks/srlb/lower-bound",
		NB_OP_MODIFY, lb_lower_bound ? lb_lower_bound_str : NULL);
	nb_cli_enqueue_change(
		vty, "./segment-routing/label-blocks/srlb/upper-bound",
		NB_OP_MODIFY, lb_upper_bound ? lb_upper_bound_str : NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_sr_global_block_label_range,
	no_isis_sr_global_block_label_range_cmd,
	"no segment-routing global-block [(16-1048575) (16-1048575) local-block (16-1048575) (16-1048575)]",
	NO_STR SR_STR
	"Segment Routing Global Block label range\n"
	"The lower bound of the global block\n"
	"The upper bound of the global block (block size may not exceed 65535)\n"
	"Segment Routing Local Block label range\n"
	"The lower bound of the local block\n"
	"The upper bound of the local block (block size may not exceed 65535)\n")
{
	nb_cli_enqueue_change(vty,
			      "./segment-routing/label-blocks/srgb/lower-bound",
			      NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty,
			      "./segment-routing/label-blocks/srgb/upper-bound",
			      NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty,
			      "./segment-routing/label-blocks/srlb/lower-bound",
			      NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty,
			      "./segment-routing/label-blocks/srlb/upper-bound",
			      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_label_blocks(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " segment-routing global-block %s %s",
		yang_dnode_get_string(dnode, "srgb/lower-bound"),
		yang_dnode_get_string(dnode, "srgb/upper-bound"));
	if (!yang_dnode_is_default(dnode, "srlb/lower-bound")
	    || !yang_dnode_is_default(dnode, "srlb/upper-bound"))
		vty_out(vty, " local-block %s %s",
			yang_dnode_get_string(dnode, "srlb/lower-bound"),
			yang_dnode_get_string(dnode, "srlb/upper-bound"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/msd/node-msd
 */
DEFPY_YANG (isis_sr_node_msd,
       isis_sr_node_msd_cmd,
       "segment-routing node-msd (1-16)$msd",
       SR_STR
       "Maximum Stack Depth for this router\n"
       "Maximum number of label that can be stack (1-16)\n")
{
	nb_cli_enqueue_change(vty, "./segment-routing/msd/node-msd",
			      NB_OP_MODIFY, msd_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_isis_sr_node_msd,
       no_isis_sr_node_msd_cmd,
       "no segment-routing node-msd [(1-16)]",
       NO_STR
       SR_STR
       "Maximum Stack Depth for this router\n"
       "Maximum number of label that can be stack (1-16)\n")
{
	nb_cli_enqueue_change(vty, "./segment-routing/msd/node-msd",
			      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_node_msd(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults)
{
	vty_out(vty, " segment-routing node-msd %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing/prefix-sid-map/prefix-sid
 */
DEFPY_YANG (isis_sr_prefix_sid,
       isis_sr_prefix_sid_cmd,
       "segment-routing prefix\
          <A.B.C.D/M|X:X::X:X/M>$prefix\
	  <absolute$sid_type (16-1048575)$sid_value|index$sid_type (0-65535)$sid_value>\
	  [<no-php-flag|explicit-null>$lh_behavior] [n-flag-clear$n_flag_clear]",
       SR_STR
       "Prefix SID\n"
       "IPv4 Prefix\n"
       "IPv6 Prefix\n"
       "Specify the absolute value of Prefix Segment ID\n"
       "The Prefix Segment ID value\n"
       "Specify the index of Prefix Segment ID\n"
       "The Prefix Segment ID index\n"
       "Don't request Penultimate Hop Popping (PHP)\n"
       "Upstream neighbor must replace prefix-sid with explicit null label\n"
       "Not a node SID\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./sid-value-type", NB_OP_MODIFY, sid_type);
	nb_cli_enqueue_change(vty, "./sid-value", NB_OP_MODIFY, sid_value_str);
	if (lh_behavior) {
		const char *value;

		if (strmatch(lh_behavior, "no-php-flag"))
			value = "no-php";
		else if (strmatch(lh_behavior, "explicit-null"))
			value = "explicit-null";
		else
			value = "php";

		nb_cli_enqueue_change(vty, "./last-hop-behavior", NB_OP_MODIFY,
				      value);
	} else
		nb_cli_enqueue_change(vty, "./last-hop-behavior", NB_OP_MODIFY,
				      NULL);
	nb_cli_enqueue_change(vty, "./n-flag-clear", NB_OP_MODIFY,
			      n_flag_clear ? "true" : "false");

	return nb_cli_apply_changes(
		vty, "./segment-routing/prefix-sid-map/prefix-sid[prefix='%s']",
		prefix_str);
}

DEFPY_YANG (no_isis_sr_prefix_sid,
       no_isis_sr_prefix_sid_cmd,
       "no segment-routing prefix <A.B.C.D/M|X:X::X:X/M>$prefix\
         [<absolute$sid_type (16-1048575)|index (0-65535)> [<no-php-flag|explicit-null>]]\
	 [n-flag-clear]",
       NO_STR
       SR_STR
       "Prefix SID\n"
       "IPv4 Prefix\n"
       "IPv6 Prefix\n"
       "Specify the absolute value of Prefix Segment ID\n"
       "The Prefix Segment ID value\n"
       "Specify the index of Prefix Segment ID\n"
       "The Prefix Segment ID index\n"
       "Don't request Penultimate Hop Popping (PHP)\n"
       "Upstream neighbor must replace prefix-sid with explicit null label\n"
       "Not a node SID\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(
		vty, "./segment-routing/prefix-sid-map/prefix-sid[prefix='%s']",
		prefix_str);
}

void cli_show_isis_prefix_sid(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *prefix;
	const char *lh_behavior;
	const char *sid_value_type;
	const char *sid_value;
	bool n_flag_clear;

	prefix = yang_dnode_get_string(dnode, "prefix");
	lh_behavior = yang_dnode_get_string(dnode, "last-hop-behavior");
	sid_value_type = yang_dnode_get_string(dnode, "sid-value-type");
	sid_value = yang_dnode_get_string(dnode, "sid-value");
	n_flag_clear = yang_dnode_get_bool(dnode, "n-flag-clear");

	vty_out(vty, " segment-routing prefix %s", prefix);
	if (strmatch(sid_value_type, "absolute"))
		vty_out(vty, " absolute");
	else
		vty_out(vty, " index");
	vty_out(vty, " %s", sid_value);
	if (strmatch(lh_behavior, "no-php"))
		vty_out(vty, " no-php-flag");
	else if (strmatch(lh_behavior, "explicit-null"))
		vty_out(vty, " explicit-null");
	if (n_flag_clear)
		vty_out(vty, " n-flag-clear");
	vty_out(vty, "\n");
}

#ifndef FABRICD
/*
 * XPath:
 * /frr-isisd:isis/instance/segment-routing/algorithm-prefix-sids/algorithm-prefix-sid
 */
DEFPY_YANG(
	isis_sr_prefix_sid_algorithm, isis_sr_prefix_sid_algorithm_cmd,
	"segment-routing prefix <A.B.C.D/M|X:X::X:X/M>$prefix\
              algorithm (128-255)$algorithm\
              <absolute$sid_type (16-1048575)$sid_value|index$sid_type (0-65535)$sid_value>\
              [<no-php-flag|explicit-null>$lh_behavior] [n-flag-clear$n_flag_clear]",
	SR_STR
	"Prefix SID\n"
	"IPv4 Prefix\n"
	"IPv6 Prefix\n"
	"Algorithm Specific Prefix SID Configuration\n"
	"Algorithm number\n"
	"Specify the absolute value of Prefix Segment ID\n"
	"The Prefix Segment ID value\n"
	"Specify the index of Prefix Segment ID\n"
	"The Prefix Segment ID index\n"
	"Don't request Penultimate Hop Popping (PHP)\n"
	"Upstream neighbor must replace prefix-sid with explicit null label\n"
	"Not a node SID\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./sid-value-type", NB_OP_MODIFY, sid_type);
	nb_cli_enqueue_change(vty, "./sid-value", NB_OP_MODIFY, sid_value_str);
	if (lh_behavior) {
		const char *value;

		if (strmatch(lh_behavior, "no-php-flag"))
			value = "no-php";
		else if (strmatch(lh_behavior, "explicit-null"))
			value = "explicit-null";
		else
			value = "php";

		nb_cli_enqueue_change(vty, "./last-hop-behavior", NB_OP_MODIFY,
				      value);
	} else
		nb_cli_enqueue_change(vty, "./last-hop-behavior", NB_OP_MODIFY,
				      NULL);
	nb_cli_enqueue_change(vty, "./n-flag-clear", NB_OP_MODIFY,
			      n_flag_clear ? "true" : "false");

	return nb_cli_apply_changes(
		vty,
		"./segment-routing/algorithm-prefix-sids/algorithm-prefix-sid[prefix='%s'][algo='%s']",
		prefix_str, algorithm_str);
}

DEFPY_YANG(
	no_isis_sr_prefix_algorithm_sid, no_isis_sr_prefix_sid_algorithm_cmd,
	"no segment-routing prefix <A.B.C.D/M|X:X::X:X/M>$prefix\
              algorithm (128-255)$algorithm\
              [<absolute$sid_type (16-1048575)|index (0-65535)> [<no-php-flag|explicit-null>]]\
              [n-flag-clear]",
	NO_STR SR_STR
	"Prefix SID\n"
	"IPv4 Prefix\n"
	"IPv6 Prefix\n"
	"Algorithm Specific Prefix SID Configuration\n"
	"Algorithm number\n"
	"Specify the absolute value of Prefix Segment ID\n"
	"The Prefix Segment ID value\n"
	"Specify the index of Prefix Segment ID\n"
	"The Prefix Segment ID index\n"
	"Don't request Penultimate Hop Popping (PHP)\n"
	"Upstream neighbor must replace prefix-sid with explicit null label\n"
	"Not a node SID\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(
		vty,
		"./segment-routing/algorithm-prefix-sids/algorithm-prefix-sid[prefix='%s'][algo='%s']",
		prefix_str, algorithm_str);
	return CMD_SUCCESS;
}
#endif /* ifndef FABRICD */

void cli_show_isis_prefix_sid_algorithm(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	const char *prefix;
	const char *lh_behavior;
	const char *sid_value_type;
	const char *sid_value;
	bool n_flag_clear;
	uint8_t algorithm;

	prefix = yang_dnode_get_string(dnode, "prefix");
	sid_value_type = yang_dnode_get_string(dnode, "sid-value-type");
	sid_value = yang_dnode_get_string(dnode, "sid-value");
	algorithm = yang_dnode_get_uint8(dnode, "algo");
	lh_behavior = yang_dnode_get_string(dnode, "last-hop-behavior");
	n_flag_clear = yang_dnode_get_bool(dnode, "n-flag-clear");

	vty_out(vty, " segment-routing prefix %s", prefix);
	vty_out(vty, " algorithm %u", algorithm);
	if (strmatch(sid_value_type, "absolute"))
		vty_out(vty, " absolute");
	else
		vty_out(vty, " index");
	vty_out(vty, " %s", sid_value);

	if (strmatch(lh_behavior, "no-php"))
		vty_out(vty, " no-php-flag");
	else if (strmatch(lh_behavior, "explicit-null"))
		vty_out(vty, " explicit-null");
	if (n_flag_clear)
		vty_out(vty, " n-flag-clear");
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/locator
 */
DEFPY (isis_srv6_locator,
       isis_srv6_locator_cmd,
       "[no] locator NAME$loc_name",
       NO_STR
       "Specify SRv6 locator\n"
       "Specify SRv6 locator\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./locator", NB_OP_DESTROY, loc_name);
	else
		nb_cli_enqueue_change(vty, "./locator", NB_OP_MODIFY, loc_name);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_srv6_locator(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, "  locator %s\n", yang_dnode_get_string(dnode, NULL));
}

void cli_show_isis_srv6_locator_end(struct vty *vty,
				    const struct lyd_node *dnode)
{
	vty_out(vty, " exit\n");
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/enabled
 */
DEFPY_YANG_NOSH (isis_srv6_enable,
       isis_srv6_enable_cmd,
       "segment-routing srv6",
       SR_STR
       "Enable Segment Routing over IPv6 (SRv6)\n")
{
	int ret;
	char xpath[XPATH_MAXLEN + 37];

	snprintf(xpath, sizeof(xpath), "%s/segment-routing-srv6",
		 VTY_CURR_XPATH);

	nb_cli_enqueue_change(vty, "./segment-routing-srv6/enabled",
			      NB_OP_MODIFY, "true");

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(ISIS_SRV6_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_isis_srv6_enable,
       no_isis_srv6_enable_cmd,
       "no segment-routing srv6",
       NO_STR
       SR_STR
       "Disable Segment Routing over IPv6 (SRv6)\n")
{
	nb_cli_enqueue_change(vty, "./segment-routing-srv6", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_srv6_enabled(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " segment-routing srv6\n");
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd
 */
DEFPY_YANG_NOSH (isis_srv6_node_msd,
       isis_srv6_node_msd_cmd,
       "[no] node-msd",
       NO_STR
       "Segment Routing over IPv6 (SRv6) Maximum SRv6 SID Depths\n")
{
	int ret = CMD_SUCCESS;
	char xpath[XPATH_MAXLEN + 37];

	snprintf(xpath, sizeof(xpath), "%s/msd/node-msd", VTY_CURR_XPATH);

	if (no) {
		nb_cli_enqueue_change(vty, "./msd/node_msd/max-segs-left",
				      NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, "./msd/node_msd/end-pop",
				      NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, "./msd/node_msd/h-encaps",
				      NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, "./msd/node_msd/end-d",
				      NB_OP_DESTROY, NULL);
		ret = nb_cli_apply_changes(vty, NULL);
	} else
		VTY_PUSH_XPATH(ISIS_SRV6_NODE_MSD_NODE, xpath);

	return ret;
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-segs-left
 */
DEFPY (isis_srv6_node_msd_max_segs_left,
       isis_srv6_node_msd_max_segs_left_cmd,
       "[no] max-segs-left (0-255)$max_segs_left",
       NO_STR
       "Specify Maximum Segments Left MSD\n"
       "Specify Maximum Segments Left MSD\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./max-segs-left", NB_OP_DESTROY,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./max-segs-left", NB_OP_MODIFY,
				      max_segs_left_str);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-end-pop
 */
DEFPY (isis_srv6_node_msd_max_end_pop,
       isis_srv6_node_msd_max_end_pop_cmd,
       "[no] max-end-pop (0-255)$max_end_pop",
       NO_STR
       "Specify Maximum End Pop MSD\n"
       "Specify Maximum End Pop MSD\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./max-end-pop", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./max-end-pop", NB_OP_MODIFY,
				      max_end_pop_str);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-h-encaps
 */
DEFPY (isis_srv6_node_msd_max_h_encaps,
       isis_srv6_node_msd_max_h_encaps_cmd,
       "[no] max-h-encaps (0-255)$max_h_encaps",
       NO_STR
       "Specify Maximum H.Encaps MSD\n"
       "Specify Maximum H.Encaps MSD\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./max-h-encaps", NB_OP_DESTROY,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./max-h-encaps", NB_OP_MODIFY,
				      max_h_encaps_str);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/msd/node-msd/max-end-d
 */
DEFPY (isis_srv6_node_msd_max_end_d,
       isis_srv6_node_msd_max_end_d_cmd,
       "[no] max-end-d (0-255)$max_end_d",
       NO_STR
       "Specify Maximum End D MSD\n"
       "Specify Maximum End D MSD\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./max-end-d", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./max-end-d", NB_OP_MODIFY,
				      max_end_d_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_srv6_node_msd(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, "  node-msd\n");
	if (yang_dnode_get_uint8(dnode, "max-segs-left") !=
	    yang_get_default_uint8("%s/msd/node-msd/max-segs-left", ISIS_SRV6))
		vty_out(vty, "   max-segs-left %u\n",
			yang_dnode_get_uint8(dnode, "max-segs-left"));
	if (yang_dnode_get_uint8(dnode, "max-end-pop") !=
	    yang_get_default_uint8("%s/msd/node-msd/max-end-pop", ISIS_SRV6))
		vty_out(vty, "   max-end-pop %u\n",
			yang_dnode_get_uint8(dnode, "max-end-pop"));
	if (yang_dnode_get_uint8(dnode, "max-h-encaps") !=
	    yang_get_default_uint8("%s/msd/node-msd/max-h-encaps", ISIS_SRV6))
		vty_out(vty, "   max-h-encaps %u\n",
			yang_dnode_get_uint8(dnode, "max-h-encaps"));
	if (yang_dnode_get_uint8(dnode, "max-end-d") !=
	    yang_get_default_uint8("%s/msd/node-msd/max-end-d", ISIS_SRV6))
		vty_out(vty, "   max-end-d %u\n",
			yang_dnode_get_uint8(dnode, "max-end-d"));
}

/*
 * XPath: /frr-isisd:isis/instance/segment-routing-srv6/interface
 */
DEFPY (isis_srv6_interface,
       isis_srv6_interface_cmd,
       "[no] interface WORD$interface",
       NO_STR
       "Interface for Segment Routing over IPv6 (SRv6)\n"
       "Interface for Segment Routing over IPv6 (SRv6)\n")
{
	if (no) {
		nb_cli_enqueue_change(vty, "./interface",
				      NB_OP_MODIFY, NULL);
	} else {
		nb_cli_enqueue_change(vty, "./interface",
				      NB_OP_MODIFY, interface);
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_srv6_interface(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, "  interface %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-{1,2}/lfa/priority-limit
 */
DEFPY_YANG (isis_frr_lfa_priority_limit,
       isis_frr_lfa_priority_limit_cmd,
       "[no] fast-reroute priority-limit <critical|high|medium>$priority [<level-1|level-2>$level]",
       NO_STR
       "Configure Fast ReRoute\n"
       "Limit backup computation up to the prefix priority\n"
       "Compute for critical priority prefixes only\n"
       "Compute for critical & high priority prefixes\n"
       "Compute for critical, high & medium priority prefixes\n"
       "Set priority-limit for level-1 only\n"
       "Set priority-limit for level-2 only\n")
{
	if (!level || strmatch(level, "level-1")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./fast-reroute/level-1/lfa/priority-limit",
				NB_OP_DESTROY, NULL);
		} else {
			nb_cli_enqueue_change(
				vty,
				"./fast-reroute/level-1/lfa/priority-limit",
				NB_OP_CREATE, priority);
		}
	}
	if (!level || strmatch(level, "level-2")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./fast-reroute/level-2/lfa/priority-limit",
				NB_OP_DESTROY, NULL);
		} else {
			nb_cli_enqueue_change(
				vty,
				"./fast-reroute/level-2/lfa/priority-limit",
				NB_OP_CREATE, priority);
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_frr_lfa_priority_limit(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, " fast-reroute priority-limit %s %s\n",
		yang_dnode_get_string(dnode, NULL),
		dnode->parent->parent->schema->name);
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-{1,2}/lfa/tiebreaker
 */
DEFPY_YANG (isis_frr_lfa_tiebreaker,
       isis_frr_lfa_tiebreaker_cmd,
       "[no] fast-reroute lfa\
          tiebreaker <downstream|lowest-backup-metric|node-protecting>$type\
	  index (1-255)$index\
	  [<level-1|level-2>$level]",
       NO_STR
       "Configure Fast ReRoute\n"
       "LFA configuration\n"
       "Configure tiebreaker for multiple backups\n"
       "Prefer backup path via downstream node\n"
       "Prefer backup path with lowest total metric\n"
       "Prefer node protecting backup path\n"
       "Set preference order among tiebreakers\n"
       "Index\n"
       "Configure tiebreaker for level-1 only\n"
       "Configure tiebreaker for level-2 only\n")
{
	char xpath[XPATH_MAXLEN];

	if (!level || strmatch(level, "level-1")) {
		if (no) {
			snprintf(
				xpath, XPATH_MAXLEN,
				"./fast-reroute/level-1/lfa/tiebreaker[index='%s']",
				index_str);
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		} else {
			snprintf(
				xpath, XPATH_MAXLEN,
				"./fast-reroute/level-1/lfa/tiebreaker[index='%s']/type",
				index_str);
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, type);
		}
	}
	if (!level || strmatch(level, "level-2")) {
		if (no) {
			snprintf(
				xpath, XPATH_MAXLEN,
				"./fast-reroute/level-2/lfa/tiebreaker[index='%s']",
				index_str);
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		} else {
			snprintf(
				xpath, XPATH_MAXLEN,
				"./fast-reroute/level-2/lfa/tiebreaker[index='%s']/type",
				index_str);
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, type);
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_frr_lfa_tiebreaker(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " fast-reroute lfa tiebreaker %s index %s %s\n",
		yang_dnode_get_string(dnode, "type"),
		yang_dnode_get_string(dnode, "index"),
		dnode->parent->parent->schema->name);
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-{1,2}/lfa/load-sharing
 */
DEFPY_YANG (isis_frr_lfa_load_sharing,
       isis_frr_lfa_load_sharing_cmd,
       "[no] fast-reroute load-sharing disable [<level-1|level-2>$level]",
       NO_STR
       "Configure Fast ReRoute\n"
       "Load share prefixes across multiple backups\n"
       "Disable load sharing\n"
       "Disable load sharing for level-1 only\n"
       "Disable load sharing for level-2 only\n")
{
	if (!level || strmatch(level, "level-1")) {
		if (no) {
			nb_cli_enqueue_change(
				vty, "./fast-reroute/level-1/lfa/load-sharing",
				NB_OP_MODIFY, "true");
		} else {
			nb_cli_enqueue_change(
				vty, "./fast-reroute/level-1/lfa/load-sharing",
				NB_OP_MODIFY, "false");
		}
	}
	if (!level || strmatch(level, "level-2")) {
		if (no) {
			nb_cli_enqueue_change(
				vty, "./fast-reroute/level-2/lfa/load-sharing",
				NB_OP_MODIFY, "true");
		} else {
			nb_cli_enqueue_change(
				vty, "./fast-reroute/level-2/lfa/load-sharing",
				NB_OP_MODIFY, "false");
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_frr_lfa_load_sharing(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " fast-reroute load-sharing disable %s\n",
		dnode->parent->parent->schema->name);
}

/*
 * XPath: /frr-isisd:isis/instance/fast-reroute/level-{1,2}/remote-lfa/prefix-list
 */
DEFPY_YANG (isis_frr_remote_lfa_plist,
       isis_frr_remote_lfa_plist_cmd,
       "fast-reroute remote-lfa prefix-list WORD$plist [<level-1|level-2>$level]",
       "Configure Fast ReRoute\n"
       "Enable remote LFA related configuration\n"
       "Filter PQ node router ID based on prefix list\n"
       "Prefix-list name\n"
       "Enable router ID filtering for level-1 only\n"
       "Enable router ID filtering for level-2 only\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./fast-reroute/level-1/remote-lfa/prefix-list",
			NB_OP_MODIFY, plist);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./fast-reroute/level-2/remote-lfa/prefix-list",
			NB_OP_MODIFY, plist);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_isis_frr_remote_lfa_plist,
       no_isis_frr_remote_lfa_plist_cmd,
       "no fast-reroute remote-lfa prefix-list [WORD] [<level-1|level-2>$level]",
       NO_STR
       "Configure Fast ReRoute\n"
       "Enable remote LFA related configuration\n"
       "Filter PQ node router ID based on prefix list\n"
       "Prefix-list name\n"
       "Enable router ID filtering for level-1 only\n"
       "Enable router ID filtering for level-2 only\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./fast-reroute/level-1/remote-lfa/prefix-list",
			NB_OP_DESTROY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./fast-reroute/level-2/remote-lfa/prefix-list",
			NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_frr_remote_lfa_plist(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, " fast-reroute remote-lfa prefix-list %s %s\n",
		yang_dnode_get_string(dnode, NULL),
		dnode->parent->parent->schema->name);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/passive
 */
DEFPY_YANG(isis_passive, isis_passive_cmd, "[no] isis passive",
      NO_STR
      "IS-IS routing protocol\n"
      "Configure the passive mode for interface\n")
{
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/passive", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_passive(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis passive\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/password
 */

DEFPY_YANG(isis_passwd, isis_passwd_cmd, "isis password <md5|clear>$type WORD$pwd",
      "IS-IS routing protocol\n"
      "Configure the authentication password for a circuit\n"
      "HMAC-MD5 authentication\n"
      "Cleartext password\n"
      "Circuit password\n")
{
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/password", NB_OP_CREATE,
			      NULL);
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/password/password",
			      NB_OP_MODIFY, pwd);
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/password/password-type",
			      NB_OP_MODIFY, type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_passwd, no_isis_passwd_cmd, "no isis password [<md5|clear> WORD]",
      NO_STR
      "IS-IS routing protocol\n"
      "Configure the authentication password for a circuit\n"
      "HMAC-MD5 authentication\n"
      "Cleartext password\n"
      "Circuit password\n")
{
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/password", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_password(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, " isis password %s %s\n",
		yang_dnode_get_string(dnode, "password-type"),
		yang_dnode_get_string(dnode, "password"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/metric
 */
DEFPY_YANG(isis_metric, isis_metric_cmd,
      "isis metric [level-1|level-2]$level (0-16777215)$met",
      "IS-IS routing protocol\n"
      "Set default metric for circuit\n"
      "Specify metric for level-1 routing\n"
      "Specify metric for level-2 routing\n"
      "Default metric value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/metric/level-1",
				      NB_OP_MODIFY, met_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/metric/level-2",
				      NB_OP_MODIFY, met_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_metric, no_isis_metric_cmd,
      "no isis metric [level-1|level-2]$level [(0-16777215)]",
      NO_STR
      "IS-IS routing protocol\n"
      "Set default metric for circuit\n"
      "Specify metric for level-1 routing\n"
      "Specify metric for level-2 routing\n"
      "Default metric value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/metric/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/metric/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_metric(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "level-1");
	const char *l2 = yang_dnode_get_string(dnode, "level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " isis metric %s\n", l1);
	else {
		vty_out(vty, " isis metric level-1 %s\n", l1);
		vty_out(vty, " isis metric level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/interval
 */
DEFPY_YANG(isis_hello_interval, isis_hello_interval_cmd,
      "isis hello-interval [level-1|level-2]$level (1-600)$intv",
      "IS-IS routing protocol\n"
      "Set Hello interval\n"
      "Specify hello-interval for level-1 IIHs\n"
      "Specify hello-interval for level-2 IIHs\n"
      "Holdtime 1 seconds, interval depends on multiplier\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/hello/interval/level-1",
				      NB_OP_MODIFY, intv_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/hello/interval/level-2",
				      NB_OP_MODIFY, intv_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_hello_interval, no_isis_hello_interval_cmd,
      "no isis hello-interval [level-1|level-2]$level [(1-600)]",
      NO_STR
      "IS-IS routing protocol\n"
      "Set Hello interval\n"
      "Specify hello-interval for level-1 IIHs\n"
      "Specify hello-interval for level-2 IIHs\n"
      "Holdtime 1 second, interval depends on multiplier\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/hello/interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/hello/interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_hello_interval(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "level-1");
	const char *l2 = yang_dnode_get_string(dnode, "level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " isis hello-interval %s\n", l1);
	else {
		vty_out(vty, " isis hello-interval level-1 %s\n", l1);
		vty_out(vty, " isis hello-interval level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/multiplier
 */
DEFPY_YANG(isis_hello_multiplier, isis_hello_multiplier_cmd,
      "isis hello-multiplier [level-1|level-2]$level (2-100)$mult",
      "IS-IS routing protocol\n"
      "Set multiplier for Hello holding time\n"
      "Specify hello multiplier for level-1 IIHs\n"
      "Specify hello multiplier for level-2 IIHs\n"
      "Hello multiplier value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/hello/multiplier/level-1",
			NB_OP_MODIFY, mult_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/hello/multiplier/level-2",
			NB_OP_MODIFY, mult_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_hello_multiplier, no_isis_hello_multiplier_cmd,
      "no isis hello-multiplier [level-1|level-2]$level [(2-100)]",
      NO_STR
      "IS-IS routing protocol\n"
      "Set multiplier for Hello holding time\n"
      "Specify hello multiplier for level-1 IIHs\n"
      "Specify hello multiplier for level-2 IIHs\n"
      "Hello multiplier value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/hello/multiplier/level-1",
			NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./frr-isisd:isis/hello/multiplier/level-2",
			NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_hello_multi(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "level-1");
	const char *l2 = yang_dnode_get_string(dnode, "level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " isis hello-multiplier %s\n", l1);
	else {
		vty_out(vty, " isis hello-multiplier level-1 %s\n", l1);
		vty_out(vty, " isis hello-multiplier level-2 %s\n", l2);
	}
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/disable-three-way-handshake
 */
DEFPY_YANG(isis_threeway_adj, isis_threeway_adj_cmd, "[no] isis three-way-handshake",
      NO_STR
      "IS-IS commands\n"
      "Enable/Disable three-way handshake\n")
{
	nb_cli_enqueue_change(vty,
			      "./frr-isisd:isis/disable-three-way-handshake",
			      NB_OP_MODIFY, no ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_threeway_shake(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis three-way-handshake\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/hello/padding
 */
DEFPY_YANG(isis_hello_padding, isis_hello_padding_cmd,
	   "[no] isis hello padding [during-adjacency-formation]$padding_type",
	   NO_STR
	   "IS-IS routing protocol\n"
	   "Type of padding for IS-IS hello packets\n"
	   "Pad hello packets\n"
	   "Add padding to hello packets during adjacency formation only.\n")
{
	if (no) {
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/hello/padding",
				      NB_OP_MODIFY, "disabled");
	} else {
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/hello/padding",
				      NB_OP_MODIFY,
				      padding_type ? padding_type : "always");
	}
	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_hello_padding(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	int hello_padding_type = yang_dnode_get_enum(dnode, NULL);
	if (hello_padding_type == ISIS_HELLO_PADDING_DISABLED)
		vty_out(vty, " no");
	vty_out(vty, " isis hello padding");
	if (hello_padding_type == ISIS_HELLO_PADDING_DURING_ADJACENCY_FORMATION)
		vty_out(vty, " during-adjacency-formation");
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/csnp-interval
 */
DEFPY_YANG(csnp_interval, csnp_interval_cmd,
      "isis csnp-interval (1-600)$intv [level-1|level-2]$level",
      "IS-IS routing protocol\n"
      "Set CSNP interval in seconds\n"
      "CSNP interval value\n"
      "Specify interval for level-1 CSNPs\n"
      "Specify interval for level-2 CSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/csnp-interval/level-1",
				      NB_OP_MODIFY, intv_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/csnp-interval/level-2",
				      NB_OP_MODIFY, intv_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_csnp_interval, no_csnp_interval_cmd,
      "no isis csnp-interval [(1-600)] [level-1|level-2]$level",
      NO_STR
      "IS-IS routing protocol\n"
      "Set CSNP interval in seconds\n"
      "CSNP interval value\n"
      "Specify interval for level-1 CSNPs\n"
      "Specify interval for level-2 CSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/csnp-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/csnp-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_csnp_interval(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "level-1");
	const char *l2 = yang_dnode_get_string(dnode, "level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " isis csnp-interval %s\n", l1);
	else {
		vty_out(vty, " isis csnp-interval %s level-1\n", l1);
		vty_out(vty, " isis csnp-interval %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/psnp-interval
 */
DEFPY_YANG(psnp_interval, psnp_interval_cmd,
      "isis psnp-interval (1-120)$intv [level-1|level-2]$level",
      "IS-IS routing protocol\n"
      "Set PSNP interval in seconds\n"
      "PSNP interval value\n"
      "Specify interval for level-1 PSNPs\n"
      "Specify interval for level-2 PSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/psnp-interval/level-1",
				      NB_OP_MODIFY, intv_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/psnp-interval/level-2",
				      NB_OP_MODIFY, intv_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_psnp_interval, no_psnp_interval_cmd,
      "no isis psnp-interval [(1-120)] [level-1|level-2]$level",
      NO_STR
      "IS-IS routing protocol\n"
      "Set PSNP interval in seconds\n"
      "PSNP interval value\n"
      "Specify interval for level-1 PSNPs\n"
      "Specify interval for level-2 PSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/psnp-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-isisd:isis/psnp-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_psnp_interval(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "level-1");
	const char *l2 = yang_dnode_get_string(dnode, "level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " isis psnp-interval %s\n", l1);
	else {
		vty_out(vty, " isis psnp-interval %s level-1\n", l1);
		vty_out(vty, " isis psnp-interval %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/multi-topology
 */
DEFPY_YANG(circuit_topology, circuit_topology_cmd,
      "[no] isis topology<standard|ipv4-unicast|ipv4-mgmt|ipv6-unicast|ipv4-multicast|ipv6-multicast|ipv6-mgmt|ipv6-dstsrc>$topology",
      NO_STR
      "IS-IS routing protocol\n"
      "Configure interface IS-IS topologies\n"
      "Standard topology\n"
      "IPv4 unicast topology\n"
      "IPv4 management topology\n"
      "IPv6 unicast topology\n"
      "IPv4 multicast topology\n"
      "IPv6 multicast topology\n"
      "IPv6 management topology\n"
      "IPv6 dst-src topology\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_MODIFY, no ? "false" : "true");

	if (strmatch(topology, "ipv4-mgmt"))
		return nb_cli_apply_changes(
			vty, "./frr-isisd:isis/multi-topology/ipv4-management");
	else if (strmatch(topology, "ipv6-mgmt"))
		return nb_cli_apply_changes(
			vty, "./frr-isisd:isis/multi-topology/ipv6-management");
	if (strmatch(topology, "ipv4-unicast"))
		return nb_cli_apply_changes(
			vty, "./frr-isisd:isis/multi-topology/standard");
	else
		return nb_cli_apply_changes(
			vty, "./frr-isisd:isis/multi-topology/%s", topology);
}

void cli_show_ip_isis_mt_standard(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis topology standard\n");
}

void cli_show_ip_isis_mt_ipv4_multicast(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis topology ipv4-multicast\n");
}

void cli_show_ip_isis_mt_ipv4_mgmt(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis topology ipv4-mgmt\n");
}

void cli_show_ip_isis_mt_ipv6_unicast(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis topology ipv6-unicast\n");
}

void cli_show_ip_isis_mt_ipv6_multicast(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis topology ipv6-multicast\n");
}

void cli_show_ip_isis_mt_ipv6_mgmt(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis topology ipv6-mgmt\n");
}

void cli_show_ip_isis_mt_ipv6_dstsrc(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " isis topology ipv6-dstsrc\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/circuit-type
 */
DEFPY_YANG(isis_circuit_type, isis_circuit_type_cmd,
      "isis circuit-type <level-1|level-1-2|level-2-only>$type",
      "IS-IS routing protocol\n"
      "Configure circuit type for interface\n"
      "Level-1 only adjacencies are formed\n"
      "Level-1-2 adjacencies are formed\n"
      "Level-2 only adjacencies are formed\n")
{
	nb_cli_enqueue_change(
		vty, "./frr-isisd:isis/circuit-type", NB_OP_MODIFY,
		strmatch(type, "level-2-only") ? "level-2" : type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_circuit_type, no_isis_circuit_type_cmd,
      "no isis circuit-type [level-1|level-1-2|level-2-only]",
      NO_STR
      "IS-IS routing protocol\n"
      "Configure circuit type for interface\n"
      "Level-1 only adjacencies are formed\n"
      "Level-1-2 adjacencies are formed\n"
      "Level-2 only adjacencies are formed\n")
{
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/circuit-type",
			      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_circ_type(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	int level = yang_dnode_get_enum(dnode, NULL);

	switch (level) {
	case IS_LEVEL_1:
		vty_out(vty, " isis circuit-type level-1\n");
		break;
	case IS_LEVEL_2:
		vty_out(vty, " isis circuit-type level-2-only\n");
		break;
	case IS_LEVEL_1_AND_2:
		vty_out(vty, " isis circuit-type level-1-2\n");
		break;
	}
}

static int ag_change(struct vty *vty, int argc, struct cmd_token **argv,
		     const char *xpath_base, bool no, int start_idx)
{
	char xpath[XPATH_MAXLEN];

	for (int i = start_idx; i < argc; i++) {
		snprintf(xpath, XPATH_MAXLEN, "%s[.='%s']", xpath_base,
			 argv[i]->arg);
		nb_cli_enqueue_change(vty, xpath,
				      no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

static int ag_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = (struct vty *)arg;

	vty_out(vty, " %s", yang_dnode_get_string(dnode, "."));
	return YANG_ITER_CONTINUE;
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/network-type
 */
DEFPY_YANG(isis_network, isis_network_cmd, "[no] isis network point-to-point",
      NO_STR
      "IS-IS routing protocol\n"
      "Set network type\n"
      "point-to-point network type\n")
{
	nb_cli_enqueue_change(vty, "./frr-isisd:isis/network-type",
			      NB_OP_MODIFY,
			      no ? "broadcast" : "point-to-point");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_network_type(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_enum(dnode, NULL) != CIRCUIT_T_P2P)
		vty_out(vty, " no");

	vty_out(vty, " isis network point-to-point\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/priority
 */
DEFPY_YANG(isis_priority, isis_priority_cmd,
      "isis priority (0-127)$prio [level-1|level-2]$level",
      "IS-IS routing protocol\n"
      "Set priority for Designated Router election\n"
      "Priority value\n"
      "Specify priority for level-1 routing\n"
      "Specify priority for level-2 routing\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/priority/level-1",
				      NB_OP_MODIFY, prio_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/priority/level-2",
				      NB_OP_MODIFY, prio_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_isis_priority, no_isis_priority_cmd,
      "no isis priority [(0-127)] [level-1|level-2]$level",
      NO_STR
      "IS-IS routing protocol\n"
      "Set priority for Designated Router election\n"
      "Priority value\n"
      "Specify priority for level-1 routing\n"
      "Specify priority for level-2 routing\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/priority/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-isisd:isis/priority/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_isis_priority(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "level-1");
	const char *l2 = yang_dnode_get_string(dnode, "level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " isis priority %s\n", l1);
	else {
		vty_out(vty, " isis priority %s level-1\n", l1);
		vty_out(vty, " isis priority %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/fast-reroute
 */
void cli_show_ip_isis_frr(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	bool l1_enabled, l2_enabled;
	bool l1_node_protection, l2_node_protection;
	bool l1_link_fallback, l2_link_fallback;

	/* Classic LFA */
	l1_enabled = yang_dnode_get_bool(dnode, "level-1/lfa/enable");
	l2_enabled = yang_dnode_get_bool(dnode, "level-2/lfa/enable");

	if (l1_enabled || l2_enabled) {
		if (l1_enabled == l2_enabled) {
			vty_out(vty, " isis fast-reroute lfa\n");
			vty_out(vty, "\n");
		} else {
			if (l1_enabled)
				vty_out(vty,
					" isis fast-reroute lfa level-1\n");
			if (l2_enabled)
				vty_out(vty,
					" isis fast-reroute lfa level-2\n");
		}
	}

	/* Remote LFA */
	l1_enabled = yang_dnode_get_bool(dnode, "level-1/remote-lfa/enable");
	l2_enabled = yang_dnode_get_bool(dnode, "level-2/remote-lfa/enable");

	if (l1_enabled || l2_enabled) {
		if (l1_enabled == l2_enabled) {
			vty_out(vty,
				" isis fast-reroute remote-lfa tunnel mpls-ldp\n");
			vty_out(vty, "\n");
		} else {
			if (l1_enabled)
				vty_out(vty,
					" isis fast-reroute remote-lfa tunnel mpls-ldp level-1\n");
			if (l2_enabled)
				vty_out(vty,
					" isis fast-reroute remote-lfa tunnel mpls-ldp level-2\n");
		}
	}

	/* TI-LFA */
	l1_enabled = yang_dnode_get_bool(dnode, "level-1/ti-lfa/enable");
	l2_enabled = yang_dnode_get_bool(dnode, "level-2/ti-lfa/enable");
	l1_node_protection =
		yang_dnode_get_bool(dnode, "level-1/ti-lfa/node-protection");
	l2_node_protection =
		yang_dnode_get_bool(dnode, "level-2/ti-lfa/node-protection");
	l1_link_fallback =
		yang_dnode_get_bool(dnode, "level-1/ti-lfa/link-fallback");
	l2_link_fallback =
		yang_dnode_get_bool(dnode, "level-2/ti-lfa/link-fallback");


	if (l1_enabled || l2_enabled) {
		if (l1_enabled == l2_enabled
		    && l1_node_protection == l2_node_protection
		    && l1_link_fallback == l2_link_fallback) {
			vty_out(vty, " isis fast-reroute ti-lfa");
			if (l1_node_protection)
				vty_out(vty, " node-protection");
			if (l1_link_fallback)
				vty_out(vty, " link-fallback");
			vty_out(vty, "\n");
		} else {
			if (l1_enabled) {
				vty_out(vty,
					" isis fast-reroute ti-lfa level-1");
				if (l1_node_protection)
					vty_out(vty, " node-protection");
				if (l1_link_fallback)
					vty_out(vty, " link-fallback");
				vty_out(vty, "\n");
			}
			if (l2_enabled) {
				vty_out(vty,
					" isis fast-reroute ti-lfa level-2");
				if (l2_node_protection)
					vty_out(vty, " node-protection");
				if (l2_link_fallback)
					vty_out(vty, " link-fallback");
				vty_out(vty, "\n");
			}
		}
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-{1,2}/lfa/enable
 */
DEFPY(isis_lfa, isis_lfa_cmd,
      "[no] isis fast-reroute lfa [level-1|level-2]$level",
      NO_STR
      "IS-IS routing protocol\n"
      "Interface IP Fast-reroute configuration\n"
      "Enable LFA computation\n"
      "Enable LFA computation for Level 1 only\n"
      "Enable LFA computation for Level 2 only\n")
{
	if (!level || strmatch(level, "level-1")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/lfa/enable",
				NB_OP_MODIFY, "false");
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/lfa/enable",
				NB_OP_MODIFY, "true");
		}
	}
	if (!level || strmatch(level, "level-2")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/lfa/enable",
				NB_OP_MODIFY, "false");
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/lfa/enable",
				NB_OP_MODIFY, "true");
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-{1,2}/lfa/exclude-interface
 */
DEFPY(isis_lfa_exclude_interface, isis_lfa_exclude_interface_cmd,
      "[no] isis fast-reroute lfa [level-1|level-2]$level exclude interface IFNAME$ifname",
      NO_STR
      "IS-IS routing protocol\n"
      "Interface IP Fast-reroute configuration\n"
      "Enable LFA computation\n"
      "Enable LFA computation for Level 1 only\n"
      "Enable LFA computation for Level 2 only\n"
      "FRR exclusion information\n"
      "Exclude an interface from computation\n"
      "Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	if (!level || strmatch(level, "level-1")) {
		snprintf(xpath, sizeof(xpath),
			 "./frr-isisd:isis/fast-reroute/level-1/lfa/exclude-interface[.='%s']",
			 ifname);

		if (no)
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		else
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	}
	if (!level || strmatch(level, "level-2")) {
		snprintf(xpath, sizeof(xpath),
			 "./frr-isisd:isis/fast-reroute/level-2/lfa/exclude-interface[.='%s']",
			 ifname);

		if (no)
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		else
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_frr_lfa_exclude_interface(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, " isis fast-reroute lfa %s exclude interface %s\n",
		dnode->parent->parent->schema->name,
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-{1,2}/remote-lfa/enable
 */
DEFPY(isis_remote_lfa, isis_remote_lfa_cmd,
      "[no] isis fast-reroute remote-lfa tunnel mpls-ldp [level-1|level-2]$level",
      NO_STR
      "IS-IS routing protocol\n"
      "Interface IP Fast-reroute configuration\n"
      "Enable remote LFA computation\n"
      "Enable remote LFA computation using tunnels\n"
      "Use MPLS LDP tunnel to reach the remote LFA node\n"
      "Enable LFA computation for Level 1 only\n"
      "Enable LFA computation for Level 2 only\n")
{
	if (!level || strmatch(level, "level-1")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/remote-lfa/enable",
				NB_OP_MODIFY, "false");
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/remote-lfa/enable",
				NB_OP_MODIFY, "true");
		}
	}
	if (!level || strmatch(level, "level-2")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/remote-lfa/enable",
				NB_OP_MODIFY, "false");
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/remote-lfa/enable",
				NB_OP_MODIFY, "true");
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-{1,2}/remote-lfa/maximum-metric
 */
DEFPY(isis_remote_lfa_max_metric, isis_remote_lfa_max_metric_cmd,
      "[no] isis fast-reroute remote-lfa maximum-metric (1-16777215)$metric [level-1|level-2]$level",
      NO_STR
      "IS-IS routing protocol\n"
      "Interface IP Fast-reroute configuration\n"
      "Enable remote LFA computation\n"
      "Limit remote LFA node selection within the metric\n"
      "Value of the metric\n"
      "Enable LFA computation for Level 1 only\n"
      "Enable LFA computation for Level 2 only\n")
{
	if (!level || strmatch(level, "level-1")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/remote-lfa/maximum-metric",
				NB_OP_DESTROY, NULL);
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/remote-lfa/maximum-metric",
				NB_OP_MODIFY, metric_str);
		}
	}
	if (!level || strmatch(level, "level-2")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/remote-lfa/maximum-metric",
				NB_OP_DESTROY, NULL);
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/remote-lfa/maximum-metric",
				NB_OP_MODIFY, metric_str);
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_frr_remote_lfa_max_metric(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, " isis fast-reroute remote-lfa maximum-metric %s %s\n",
		yang_dnode_get_string(dnode, NULL),
		dnode->parent->parent->schema->name);
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/fast-reroute/level-{1,2}/ti-lfa/enable
 */
DEFPY(isis_ti_lfa, isis_ti_lfa_cmd,
      "[no] isis fast-reroute ti-lfa [level-1|level-2]$level [node-protection$node_protection [link-fallback$link_fallback]]",
      NO_STR
      "IS-IS routing protocol\n"
      "Interface IP Fast-reroute configuration\n"
      "Enable TI-LFA computation\n"
      "Enable TI-LFA computation for Level 1 only\n"
      "Enable TI-LFA computation for Level 2 only\n"
      "Protect against node failures\n"
      "Enable link-protection fallback\n")
{
	if (!level || strmatch(level, "level-1")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/ti-lfa/enable",
				NB_OP_MODIFY, "false");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/ti-lfa/node-protection",
				NB_OP_MODIFY, "false");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/ti-lfa/link-fallback",
				NB_OP_MODIFY, "false");
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/ti-lfa/enable",
				NB_OP_MODIFY, "true");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/ti-lfa/node-protection",
				NB_OP_MODIFY,
				node_protection ? "true" : "false");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-1/ti-lfa/link-fallback",
				NB_OP_MODIFY, link_fallback ? "true" : "false");
		}
	}
	if (!level || strmatch(level, "level-2")) {
		if (no) {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/ti-lfa/enable",
				NB_OP_MODIFY, "false");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/ti-lfa/node-protection",
				NB_OP_MODIFY, "false");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/ti-lfa/link-fallback",
				NB_OP_MODIFY, "false");
		} else {
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/ti-lfa/enable",
				NB_OP_MODIFY, "true");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/ti-lfa/node-protection",
				NB_OP_MODIFY,
				node_protection ? "true" : "false");
			nb_cli_enqueue_change(
				vty,
				"./frr-isisd:isis/fast-reroute/level-2/ti-lfa/link-fallback",
				NB_OP_MODIFY, link_fallback ? "true" : "false");
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-isisd:isis/instance/log-adjacency-changes
 */
DEFPY_YANG(log_adj_changes, log_adj_changes_cmd, "[no] log-adjacency-changes",
      NO_STR "Log changes in adjacency state\n")
{
	nb_cli_enqueue_change(vty, "./log-adjacency-changes", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_log_adjacency(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " log-adjacency-changes\n");
}

/*
 * XPath: /frr-isisd:isis/instance/log-pdu-drops
 */
DEFPY_YANG(log_pdu_drops, log_pdu_drops_cmd, "[no] log-pdu-drops",
	   NO_STR "Log any dropped PDUs\n")
{
	nb_cli_enqueue_change(vty, "./log-pdu-drops", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_log_pdu_drops(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " log-pdu-drops\n");
}

/*
 * XPath: /frr-isisd:isis/instance/mpls/ldp-sync
 */
DEFPY(isis_mpls_ldp_sync, isis_mpls_ldp_sync_cmd, "mpls ldp-sync",
      MPLS_STR MPLS_LDP_SYNC_STR)
{
	nb_cli_enqueue_change(vty, "./mpls/ldp-sync", NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_isis_mpls_ldp_sync, no_isis_mpls_ldp_sync_cmd, "no mpls ldp-sync",
      NO_STR MPLS_STR NO_MPLS_LDP_SYNC_STR)
{
	nb_cli_enqueue_change(vty, "./mpls/ldp-sync", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_mpls_ldp_sync(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " mpls ldp-sync\n");
}

DEFPY(isis_mpls_ldp_sync_holddown, isis_mpls_ldp_sync_holddown_cmd,
      "mpls ldp-sync holddown (0-10000)",
      MPLS_STR MPLS_LDP_SYNC_STR
      "Time to wait for LDP-SYNC to occur before restoring interface metric\n"
      "Time in seconds\n")
{
	nb_cli_enqueue_change(vty, "./mpls/ldp-sync/holddown", NB_OP_MODIFY,
			      holddown_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_isis_mpls_ldp_sync_holddown, no_isis_mpls_ldp_sync_holddown_cmd,
      "no mpls ldp-sync holddown [<(1-10000)>]",
      NO_STR MPLS_STR MPLS_LDP_SYNC_STR NO_MPLS_LDP_SYNC_HOLDDOWN_STR "Time in seconds\n")
{
	nb_cli_enqueue_change(vty, "./mpls/ldp-sync/holddown", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_mpls_ldp_sync_holddown(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, " mpls ldp-sync holddown %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-interface:lib/interface/frr-isisd:isis/mpls/ldp-sync
 */
DEFPY(isis_mpls_if_ldp_sync, isis_mpls_if_ldp_sync_cmd,
      "[no] isis mpls ldp-sync",
      NO_STR "IS-IS routing protocol\n" MPLS_STR MPLS_LDP_SYNC_STR)
{
	const struct lyd_node *dnode;

	dnode = yang_dnode_getf(vty->candidate_config->dnode,
				"%s/frr-isisd:isis", VTY_CURR_XPATH);
	if (dnode == NULL) {
		vty_out(vty, "ISIS is not enabled on this circuit\n");
		return CMD_SUCCESS;
	}

	nb_cli_enqueue_change(vty, "./frr-isisd:isis/mpls/ldp-sync",
			      NB_OP_MODIFY, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}


void cli_show_isis_mpls_if_ldp_sync(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " isis mpls ldp-sync\n");
}

DEFPY(isis_mpls_if_ldp_sync_holddown, isis_mpls_if_ldp_sync_holddown_cmd,
      "isis mpls ldp-sync holddown (0-10000)",
      "IS-IS routing protocol\n" MPLS_STR MPLS_LDP_SYNC_STR
      "Time to wait for LDP-SYNC to occur before restoring interface metric\n"
      "Time in seconds\n")
{
	const struct lyd_node *dnode;

	dnode = yang_dnode_getf(vty->candidate_config->dnode,
				"%s/frr-isisd:isis", VTY_CURR_XPATH);
	if (dnode == NULL) {
		vty_out(vty, "ISIS is not enabled on this circuit\n");
		return CMD_SUCCESS;
	}

	nb_cli_enqueue_change(vty, "./frr-isisd:isis/mpls/holddown",
			      NB_OP_MODIFY, holddown_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_isis_mpls_if_ldp_sync_holddown, no_isis_mpls_if_ldp_sync_holddown_cmd,
      "no isis mpls ldp-sync holddown [<(1-10000)>]",
      NO_STR "IS-IS routing protocol\n" MPLS_STR NO_MPLS_LDP_SYNC_STR
	      NO_MPLS_LDP_SYNC_HOLDDOWN_STR "Time in seconds\n")
{
	const struct lyd_node *dnode;

	dnode = yang_dnode_getf(vty->candidate_config->dnode,
				"%s/frr-isisd:isis", VTY_CURR_XPATH);
	if (dnode == NULL) {
		vty_out(vty, "ISIS is not enabled on this circuit\n");
		return CMD_SUCCESS;
	}

	nb_cli_enqueue_change(vty, "./frr-isisd:isis/mpls/holddown",
			      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_mpls_if_ldp_sync_holddown(struct vty *vty,
					     const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " isis mpls ldp-sync holddown %s\n",
		yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG_NOSH(flex_algo, flex_algo_cmd, "flex-algo (128-255)$algorithm",
		"Flexible Algorithm\n"
		"Flexible Algorithm Number\n")
{
	int ret;
	char xpath[XPATH_MAXLEN + 37];

	snprintf(xpath, sizeof(xpath),
		 "%s/flex-algos/flex-algo[flex-algo='%ld']", VTY_CURR_XPATH,
		 algorithm);

	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(
		vty, "./flex-algos/flex-algo[flex-algo='%ld']", algorithm);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(ISIS_FLEX_ALGO_NODE, xpath);

	return ret;
}

DEFPY_YANG(no_flex_algo, no_flex_algo_cmd, "no flex-algo (128-255)$algorithm",
	   NO_STR
	   "Flexible Algorithm\n"
	   "Flexible Algorithm Number\n")
{
	char xpath[XPATH_MAXLEN + 37];

	snprintf(xpath, sizeof(xpath),
		 "%s/flex-algos/flex-algo[flex-algo='%ld']", VTY_CURR_XPATH,
		 algorithm);

	if (!yang_dnode_exists(vty->candidate_config->dnode, xpath)) {
		vty_out(vty, "ISIS flex-algo %ld isn't exist.\n", algorithm);
		return CMD_ERR_NO_MATCH;
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes_clear_pending(
		vty, "./flex-algos/flex-algo[flex-algo='%ld']", algorithm);
}

DEFPY_YANG(advertise_definition, advertise_definition_cmd,
	   "[no] advertise-definition",
	   NO_STR "Advertise Local Flexible Algorithm\n")
{
	nb_cli_enqueue_change(vty, "./advertise-definition",
			      no ? NB_OP_DESTROY : NB_OP_CREATE,
			      no ? NULL : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(affinity_include_any, affinity_include_any_cmd,
	   "[no] affinity include-any NAME...",
	   NO_STR
	   "Affinity configuration\n"
	   "Any Include with\n"
	   "Include NAME list\n")
{
	const char *xpath = "./affinity-include-anies/affinity-include-any";

	return ag_change(vty, argc, argv, xpath, no, no ? 3 : 2);
}

DEFPY_YANG(affinity_include_all, affinity_include_all_cmd,
	   "[no] affinity include-all NAME...",
	   NO_STR
	   "Affinity configuration\n"
	   "All Include with\n"
	   "Include NAME list\n")
{
	const char *xpath = "./affinity-include-alls/affinity-include-all";

	return ag_change(vty, argc, argv, xpath, no, no ? 3 : 2);
}

DEFPY_YANG(affinity_exclude_any, affinity_exclude_any_cmd,
	   "[no] affinity exclude-any NAME...",
	   NO_STR
	   "Affinity configuration\n"
	   "Any Exclude with\n"
	   "Exclude NAME list\n")
{
	const char *xpath = "./affinity-exclude-anies/affinity-exclude-any";

	return ag_change(vty, argc, argv, xpath, no, no ? 3 : 2);
}

DEFPY_YANG(prefix_metric, prefix_metric_cmd, "[no] prefix-metric",
	   NO_STR "Use Flex-Algo Prefix Metric\n")
{
	nb_cli_enqueue_change(vty, "./prefix-metric",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(dplane_sr_mpls, dplane_sr_mpls_cmd, "[no] dataplane sr-mpls",
	   NO_STR
	   "Advertise and participate in the specified Data-Planes\n"
	   "Advertise and participate in SR-MPLS data-plane\n")
{
	nb_cli_enqueue_change(vty, "./dplane-sr-mpls",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_HIDDEN(dplane_srv6, dplane_srv6_cmd, "[no] dataplane srv6",
	     NO_STR
	     "Advertise and participate in the specified Data-Planes\n"
	     "Advertise and participate in SRv6 data-plane\n")
{

	nb_cli_enqueue_change(vty, "./dplane-srv6",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_HIDDEN(dplane_ip, dplane_ip_cmd, "[no] dataplane ip",
	     NO_STR
	     "Advertise and participate in the specified Data-Planes\n"
	     "Advertise and participate in IP data-plane\n")
{
	nb_cli_enqueue_change(vty, "./dplane-ip",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(metric_type, metric_type_cmd,
	   "[no] metric-type [igp$igp|te$te|delay$delay]",
	   NO_STR
	   "Metric-type used by flex-algo calculation\n"
	   "Use IGP metric (default)\n"
	   "Use Delay as metric\n"
	   "Use Traffic Engineering metric\n")
{
	const char *type = NULL;

	if (igp) {
		type = "igp";
	} else if (te) {
		type = "te-default";
	} else if (delay) {
		type = "min-uni-link-delay";
	} else {
		vty_out(vty, "Error: unknown metric type\n");
		return CMD_SUCCESS;
	}

	if (!igp)
		vty_out(vty,
			"Warning: this version can advertise a Flex-Algorithm Definition (FAD) with the %s metric.\n"
			"However, participation in a Flex-Algorithm with such a metric is not yet supported.\n",
			type);

	nb_cli_enqueue_change(vty, "./metric-type",
			      no ? NB_OP_DESTROY : NB_OP_MODIFY,
			      no ? NULL : type);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(priority, priority_cmd, "[no] priority (0-255)$priority",
	   NO_STR
	   "Flex-Algo definition priority\n"
	   "Priority value\n")
{
	nb_cli_enqueue_change(vty, "./priority",
			      no ? NB_OP_DESTROY : NB_OP_MODIFY,
			      no ? NULL : priority_str);
	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_isis_flex_algo(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	uint32_t algorithm;
	enum flex_algo_metric_type metric_type;
	uint32_t priority;
	char type_str[10];

	algorithm = yang_dnode_get_uint32(dnode, "flex-algo");
	vty_out(vty, " flex-algo %u\n", algorithm);

	if (yang_dnode_exists(dnode, "advertise-definition"))
		vty_out(vty, "  advertise-definition\n");

	if (yang_dnode_exists(dnode, "dplane-sr-mpls"))
		vty_out(vty, "  dataplane sr-mpls\n");
	if (yang_dnode_exists(dnode, "dplane-srv6"))
		vty_out(vty, "  dataplane srv6\n");
	if (yang_dnode_exists(dnode, "dplane-ip"))
		vty_out(vty, "  dataplane ip\n");

	if (yang_dnode_exists(dnode, "prefix-metric"))
		vty_out(vty, "  prefix-metric\n");

	if (yang_dnode_exists(dnode, "metric-type")) {
		metric_type = yang_dnode_get_enum(dnode, "metric-type");
		if (metric_type != MT_IGP) {
			flex_algo_metric_type_print(type_str, sizeof(type_str),
						    metric_type);
			vty_out(vty, "  metric-type %s\n", type_str);
		}
	}

	if (yang_dnode_exists(dnode, "priority")) {
		priority = yang_dnode_get_uint32(dnode, "priority");
		if (priority != FLEX_ALGO_PRIO_DEFAULT)
			vty_out(vty, "  priority %u\n", priority);
	}

	if (yang_dnode_exists(dnode,
			      "./affinity-include-alls/affinity-include-all")) {
		vty_out(vty, "  affinity include-all");
		yang_dnode_iterate(
			ag_iter_cb, vty, dnode,
			"./affinity-include-alls/affinity-include-all");
		vty_out(vty, "\n");
	}

	if (yang_dnode_exists(
		    dnode, "./affinity-include-anies/affinity-include-any")) {
		vty_out(vty, "  affinity include-any");
		yang_dnode_iterate(
			ag_iter_cb, vty, dnode,
			"./affinity-include-anies/affinity-include-any");
		vty_out(vty, "\n");
	}

	if (yang_dnode_exists(
		    dnode, "./affinity-exclude-anies/affinity-exclude-any")) {
		vty_out(vty, "  affinity exclude-any");
		yang_dnode_iterate(
			ag_iter_cb, vty, dnode,
			"./affinity-exclude-anies/affinity-exclude-any");
		vty_out(vty, "\n");
	}
}

void cli_show_isis_flex_algo_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, " !\n");
}


void isis_cli_init(void)
{
	install_element(CONFIG_NODE, &router_isis_cmd);
	install_element(CONFIG_NODE, &no_router_isis_cmd);

	install_element(INTERFACE_NODE, &ip_router_isis_cmd);
	install_element(INTERFACE_NODE, &ip_router_isis_vrf_cmd);
	install_element(INTERFACE_NODE, &ip6_router_isis_cmd);
	install_element(INTERFACE_NODE, &ip6_router_isis_vrf_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_isis_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_isis_vrf_cmd);
	install_element(INTERFACE_NODE, &isis_bfd_cmd);
	install_element(INTERFACE_NODE, &isis_bfd_profile_cmd);

	install_element(ISIS_NODE, &net_cmd);

	install_element(ISIS_NODE, &is_type_cmd);
	install_element(ISIS_NODE, &no_is_type_cmd);

	install_element(ISIS_NODE, &dynamic_hostname_cmd);

	install_element(ISIS_NODE, &set_overload_bit_cmd);
	install_element(ISIS_NODE, &set_overload_bit_on_startup_cmd);
	install_element(ISIS_NODE, &no_set_overload_bit_on_startup_cmd);

	install_element(ISIS_NODE, &attached_bit_send_cmd);
	install_element(ISIS_NODE, &attached_bit_receive_ignore_cmd);

	install_element(ISIS_NODE, &metric_style_cmd);
	install_element(ISIS_NODE, &no_metric_style_cmd);

	install_element(ISIS_NODE, &advertise_high_metrics_cmd);

	install_element(ISIS_NODE, &area_passwd_cmd);
	install_element(ISIS_NODE, &domain_passwd_cmd);
	install_element(ISIS_NODE, &no_area_passwd_cmd);

	install_element(ISIS_NODE, &lsp_gen_interval_cmd);
	install_element(ISIS_NODE, &no_lsp_gen_interval_cmd);
	install_element(ISIS_NODE, &lsp_refresh_interval_cmd);
	install_element(ISIS_NODE, &no_lsp_refresh_interval_cmd);
	install_element(ISIS_NODE, &max_lsp_lifetime_cmd);
	install_element(ISIS_NODE, &no_max_lsp_lifetime_cmd);
	install_element(ISIS_NODE, &lsp_timers_cmd);
	install_element(ISIS_NODE, &no_lsp_timers_cmd);
	install_element(ISIS_NODE, &area_lsp_mtu_cmd);
	install_element(ISIS_NODE, &no_area_lsp_mtu_cmd);
	install_element(ISIS_NODE, &advertise_passive_only_cmd);

	install_element(ISIS_NODE, &spf_interval_cmd);
	install_element(ISIS_NODE, &no_spf_interval_cmd);
	install_element(ISIS_NODE, &spf_prefix_priority_cmd);
	install_element(ISIS_NODE, &no_spf_prefix_priority_cmd);
	install_element(ISIS_NODE, &spf_delay_ietf_cmd);
	install_element(ISIS_NODE, &no_spf_delay_ietf_cmd);

	install_element(ISIS_NODE, &area_purge_originator_cmd);

	install_element(ISIS_NODE, &isis_admin_group_send_zero_cmd);
	install_element(ISIS_NODE, &isis_asla_legacy_flag_cmd);

	install_element(ISIS_NODE, &isis_mpls_te_on_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_te_on_cmd);
	install_element(ISIS_NODE, &isis_mpls_te_router_addr_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_te_router_addr_cmd);
	install_element(ISIS_NODE, &isis_mpls_te_router_addr_v6_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_te_router_addr_v6_cmd);
	install_element(ISIS_NODE, &isis_mpls_te_inter_as_cmd);
	install_element(ISIS_NODE, &isis_mpls_te_export_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_te_export_cmd);

	install_element(ISIS_NODE, &isis_default_originate_cmd);
	install_element(ISIS_NODE, &isis_redistribute_cmd);
	install_element(ISIS_NODE, &isis_redistribute_table_cmd);

	install_element(ISIS_NODE, &isis_topology_cmd);

	install_element(ISIS_NODE, &isis_sr_enable_cmd);
	install_element(ISIS_NODE, &no_isis_sr_enable_cmd);
	install_element(ISIS_NODE, &isis_sr_global_block_label_range_cmd);
	install_element(ISIS_NODE, &no_isis_sr_global_block_label_range_cmd);
	install_element(ISIS_NODE, &isis_sr_node_msd_cmd);
	install_element(ISIS_NODE, &no_isis_sr_node_msd_cmd);
	install_element(ISIS_NODE, &isis_sr_prefix_sid_cmd);
	install_element(ISIS_NODE, &no_isis_sr_prefix_sid_cmd);
#ifndef FABRICD
	install_element(ISIS_NODE, &isis_sr_prefix_sid_algorithm_cmd);
	install_element(ISIS_NODE, &no_isis_sr_prefix_sid_algorithm_cmd);
#endif /* ifndef FABRICD */
	install_element(ISIS_NODE, &isis_frr_lfa_priority_limit_cmd);
	install_element(ISIS_NODE, &isis_frr_lfa_tiebreaker_cmd);
	install_element(ISIS_NODE, &isis_frr_lfa_load_sharing_cmd);
	install_element(ISIS_NODE, &isis_frr_remote_lfa_plist_cmd);
	install_element(ISIS_NODE, &no_isis_frr_remote_lfa_plist_cmd);

	install_element(ISIS_NODE, &isis_srv6_enable_cmd);
	install_element(ISIS_NODE, &no_isis_srv6_enable_cmd);
	install_element(ISIS_SRV6_NODE, &isis_srv6_locator_cmd);
	install_element(ISIS_SRV6_NODE, &isis_srv6_node_msd_cmd);
	install_element(ISIS_SRV6_NODE, &isis_srv6_interface_cmd);
	install_element(ISIS_SRV6_NODE_MSD_NODE,
			&isis_srv6_node_msd_max_segs_left_cmd);
	install_element(ISIS_SRV6_NODE_MSD_NODE,
			&isis_srv6_node_msd_max_end_pop_cmd);
	install_element(ISIS_SRV6_NODE_MSD_NODE,
			&isis_srv6_node_msd_max_h_encaps_cmd);
	install_element(ISIS_SRV6_NODE_MSD_NODE,
			&isis_srv6_node_msd_max_end_d_cmd);

	install_element(INTERFACE_NODE, &isis_passive_cmd);

	install_element(INTERFACE_NODE, &isis_passwd_cmd);
	install_element(INTERFACE_NODE, &no_isis_passwd_cmd);

	install_element(INTERFACE_NODE, &isis_metric_cmd);
	install_element(INTERFACE_NODE, &no_isis_metric_cmd);

	install_element(INTERFACE_NODE, &isis_hello_interval_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_interval_cmd);

	install_element(INTERFACE_NODE, &isis_hello_multiplier_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_multiplier_cmd);

	install_element(INTERFACE_NODE, &isis_threeway_adj_cmd);

	install_element(INTERFACE_NODE, &isis_hello_padding_cmd);

	install_element(INTERFACE_NODE, &csnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_csnp_interval_cmd);

	install_element(INTERFACE_NODE, &psnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_psnp_interval_cmd);

	install_element(INTERFACE_NODE, &circuit_topology_cmd);

	install_element(INTERFACE_NODE, &isis_circuit_type_cmd);
	install_element(INTERFACE_NODE, &no_isis_circuit_type_cmd);

	install_element(INTERFACE_NODE, &isis_network_cmd);

	install_element(INTERFACE_NODE, &isis_priority_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_cmd);

	install_element(INTERFACE_NODE, &isis_lfa_cmd);
	install_element(INTERFACE_NODE, &isis_lfa_exclude_interface_cmd);
	install_element(INTERFACE_NODE, &isis_remote_lfa_cmd);
	install_element(INTERFACE_NODE, &isis_remote_lfa_max_metric_cmd);
	install_element(INTERFACE_NODE, &isis_ti_lfa_cmd);

	install_element(ISIS_NODE, &log_adj_changes_cmd);
	install_element(ISIS_NODE, &log_pdu_drops_cmd);

	install_element(ISIS_NODE, &isis_mpls_ldp_sync_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_ldp_sync_cmd);
	install_element(ISIS_NODE, &isis_mpls_ldp_sync_holddown_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_ldp_sync_holddown_cmd);
	install_element(INTERFACE_NODE, &isis_mpls_if_ldp_sync_cmd);
	install_element(INTERFACE_NODE, &isis_mpls_if_ldp_sync_holddown_cmd);
	install_element(INTERFACE_NODE, &no_isis_mpls_if_ldp_sync_holddown_cmd);

	install_element(ISIS_NODE, &flex_algo_cmd);
	install_element(ISIS_NODE, &no_flex_algo_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &advertise_definition_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &affinity_include_any_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &affinity_include_all_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &affinity_exclude_any_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &dplane_sr_mpls_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &dplane_srv6_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &dplane_ip_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &prefix_metric_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &metric_type_cmd);
	install_element(ISIS_FLEX_ALGO_NODE, &priority_cmd);
}

#endif /* ifndef FABRICD */
