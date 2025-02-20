// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP daemon CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound_cli.h"

#include "eigrp_structs.h"
#include "eigrpd.h"
#include "eigrp_zebra.h"
#include "eigrp_cli.h"

#include "eigrpd/eigrp_cli_clippy.c"

/*
 * XPath: /frr-eigrpd:eigrpd/instance
 */
DEFPY_YANG_NOSH(
	router_eigrp,
	router_eigrp_cmd,
	"router eigrp (1-65535)$as [vrf NAME]",
	ROUTER_STR
	EIGRP_STR
	AS_STR
	VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];
	int rv;

	snprintf(xpath, sizeof(xpath),
		 "/frr-eigrpd:eigrpd/instance[asn='%s'][vrf='%s']",
		 as_str, vrf ? vrf : VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(EIGRP_NODE, xpath);

	return rv;
}

DEFPY_YANG(
	no_router_eigrp,
	no_router_eigrp_cmd,
	"no router eigrp (1-65535)$as [vrf NAME]",
	NO_STR
	ROUTER_STR
	EIGRP_STR
	AS_STR
	VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-eigrpd:eigrpd/instance[asn='%s'][vrf='%s']",
		 as_str, vrf ? vrf : VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

void eigrp_cli_show_header(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	const char *asn = yang_dnode_get_string(dnode, "asn");
	const char *vrf = yang_dnode_get_string(dnode, "vrf");

	vty_out(vty, "router eigrp %s", asn);
	if (strcmp(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf);
	vty_out(vty, "\n");
}

void eigrp_cli_show_end_header(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/router-id
 */
DEFPY_YANG(
	eigrp_router_id,
	eigrp_router_id_cmd,
	"eigrp router-id A.B.C.D$addr",
	EIGRP_STR
	"Router ID for this EIGRP process\n"
	"EIGRP Router-ID in IP address format\n")
{
	nb_cli_enqueue_change(vty, "./router-id", NB_OP_MODIFY, addr_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_router_id,
	no_eigrp_router_id_cmd,
	"no eigrp router-id [A.B.C.D]",
	NO_STR
	EIGRP_STR
	"Router ID for this EIGRP process\n"
	"EIGRP Router-ID in IP address format\n")
{
	nb_cli_enqueue_change(vty, "./router-id", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_router_id(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *router_id = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " eigrp router-id %s\n", router_id);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/passive-interface
 */
DEFPY_YANG(
	eigrp_passive_interface,
	eigrp_passive_interface_cmd,
	"[no] passive-interface IFNAME",
	NO_STR
	"Suppress routing updates on an interface\n"
	"Interface to suppress on\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./passive-interface[.='%s']", ifname);

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_passive_interface(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	const char *ifname = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " passive-interface %s\n", ifname);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/active-time
 */
DEFPY_YANG(
	eigrp_timers_active,
	eigrp_timers_active_cmd,
	"timers active-time <(1-65535)$timer|disabled$disabled>",
	"Adjust routing timers\n"
	"Time limit for active state\n"
	"Active state time limit in seconds\n"
	"Disable time limit for active state\n")
{
	if (disabled)
		nb_cli_enqueue_change(vty, "./active-time", NB_OP_MODIFY, "0");
	else
		nb_cli_enqueue_change(vty, "./active-time",
				      NB_OP_MODIFY, timer_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_timers_active,
	no_eigrp_timers_active_cmd,
	"no timers active-time [<(1-65535)|disabled>]",
	NO_STR
	"Adjust routing timers\n"
	"Time limit for active state\n"
	"Active state time limit in seconds\n"
	"Disable time limit for active state\n")
{
	nb_cli_enqueue_change(vty, "./active-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_active_time(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	const char *timer = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " timers active-time %s\n", timer);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/variance
 */
DEFPY_YANG(
	eigrp_variance,
	eigrp_variance_cmd,
	"variance (1-128)$variance",
	"Control load balancing variance\n"
	"Metric variance multiplier\n")
{
	nb_cli_enqueue_change(vty, "./variance", NB_OP_MODIFY, variance_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_variance,
	no_eigrp_variance_cmd,
	"no variance [(1-128)]",
	NO_STR
	"Control load balancing variance\n"
	"Metric variance multiplier\n")
{
	nb_cli_enqueue_change(vty, "./variance", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_variance(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	const char *variance = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " variance %s\n", variance);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/maximum-paths
 */
DEFPY_YANG(
	eigrp_maximum_paths,
	eigrp_maximum_paths_cmd,
	"maximum-paths (1-32)$maximum_paths",
	"Forward packets over multiple paths\n"
	"Number of paths\n")
{
	nb_cli_enqueue_change(vty, "./maximum-paths", NB_OP_MODIFY,
			      maximum_paths_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_maximum_paths,
	no_eigrp_maximum_paths_cmd,
	"no maximum-paths [(1-32)]",
	NO_STR
	"Forward packets over multiple paths\n"
	"Number of paths\n")
{
	nb_cli_enqueue_change(vty, "./maximum-paths", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_maximum_paths(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	const char *maximum_paths = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " maximum-paths %s\n", maximum_paths);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K1
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K2
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K3
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K4
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K5
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K6
 */
DEFPY_YANG(
	eigrp_metric_weights,
	eigrp_metric_weights_cmd,
	"metric weights (0-255)$k1 (0-255)$k2 (0-255)$k3 (0-255)$k4 (0-255)$k5 [(0-255)$k6]",
	"Modify metrics and parameters for advertisement\n"
	"Modify metric coefficients\n"
	"K1\n"
	"K2\n"
	"K3\n"
	"K4\n"
	"K5\n"
	"K6\n")
{
	nb_cli_enqueue_change(vty, "./metric-weights/K1", NB_OP_MODIFY, k1_str);
	nb_cli_enqueue_change(vty, "./metric-weights/K2", NB_OP_MODIFY, k2_str);
	nb_cli_enqueue_change(vty, "./metric-weights/K3", NB_OP_MODIFY, k3_str);
	nb_cli_enqueue_change(vty, "./metric-weights/K4", NB_OP_MODIFY, k4_str);
	nb_cli_enqueue_change(vty, "./metric-weights/K5", NB_OP_MODIFY, k5_str);
	if (k6)
		nb_cli_enqueue_change(vty, "./metric-weights/K6",
				      NB_OP_MODIFY, k6_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_metric_weights,
	no_eigrp_metric_weights_cmd,
	"no metric weights [(0-255) (0-255) (0-255) (0-255) (0-255) (0-255)]",
	NO_STR
	"Modify metrics and parameters for advertisement\n"
	"Modify metric coefficients\n"
	"K1\n"
	"K2\n"
	"K3\n"
	"K4\n"
	"K5\n"
	"K6\n")
{
	nb_cli_enqueue_change(vty, "./metric-weights/K1", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./metric-weights/K2", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./metric-weights/K3", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./metric-weights/K4", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./metric-weights/K5", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./metric-weights/K6", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_metrics(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults)
{
	const char *k1, *k2, *k3, *k4, *k5, *k6;

	k1 = yang_dnode_exists(dnode, "K1") ?
		yang_dnode_get_string(dnode, "K1") : "0";
	k2 = yang_dnode_exists(dnode, "K2") ?
		yang_dnode_get_string(dnode, "K2") : "0";
	k3 = yang_dnode_exists(dnode, "K3") ?
		yang_dnode_get_string(dnode, "K3") : "0";
	k4 = yang_dnode_exists(dnode, "K4") ?
		yang_dnode_get_string(dnode, "K4") : "0";
	k5 = yang_dnode_exists(dnode, "K5") ?
		yang_dnode_get_string(dnode, "K5") : "0";
	k6 = yang_dnode_exists(dnode, "K6") ?
		yang_dnode_get_string(dnode, "K6") : "0";

	vty_out(vty, " metric weights %s %s %s %s %s",
		k1, k2, k3, k4, k5);
	if (k6)
		vty_out(vty, " %s", k6);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/network
 */
DEFPY_YANG(
	eigrp_network,
	eigrp_network_cmd,
	"[no] network A.B.C.D/M$prefix",
	NO_STR
	"Enable routing on an IP network\n"
	"EIGRP network prefix\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./network[.='%s']", prefix_str);

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_network(struct vty *vty, const struct lyd_node *dnode,
			    bool show_defaults)
{
	const char *prefix = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " network %s\n", prefix);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/neighbor
 */
DEFPY_YANG(
	eigrp_neighbor,
	eigrp_neighbor_cmd,
	"[no] neighbor A.B.C.D$addr",
	NO_STR
	"Specify a neighbor router\n"
	"Neighbor address\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./neighbor[.='%s']", addr_str);

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_neighbor(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	const char *prefix = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " neighbor %s\n", prefix);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/distribute-list
 */
DEFPY_YANG (eigrp_distribute_list,
       eigrp_distribute_list_cmd,
       "distribute-list ACCESSLIST4_NAME$name <in|out>$dir [WORD$ifname]",
       "Filter networks in routing updates\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/access-list",
		 ifname ? ifname : "", dir);
	/* nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL); */
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (eigrp_distribute_list_prefix,
       eigrp_distribute_list_prefix_cmd,
       "distribute-list prefix PREFIXLIST4_NAME$name <in|out>$dir [WORD$ifname]",
       "Filter networks in routing updates\n"
       "Specify a prefix list\n"
       "Prefix-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/prefix-list",
		 ifname ? ifname : "", dir);
	/* nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL); */
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (eigrp_no_distribute_list,
       eigrp_no_distribute_list_cmd,
       "no distribute-list [ACCESSLIST4_NAME$name] <in|out>$dir [WORD$ifname]",
       NO_STR
       "Filter networks in routing updates\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const struct lyd_node *value_node;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/access-list",
		 ifname ? ifname : "", dir);
	/*
	 * See if the user has specified specific list so check it exists.
	 *
	 * NOTE: Other FRR CLI commands do not do this sort of verification and
	 * there may be an official decision not to.
	 */
	if (name) {
		value_node = yang_dnode_getf(vty->candidate_config->dnode, "%s/%s",
					     VTY_CURR_XPATH, xpath);
		if (!value_node || strcmp(name, lyd_get_value(value_node))) {
			vty_out(vty, "distribute list doesn't exist\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (eigrp_no_distribute_list_prefix,
       eigrp_no_distribute_list_prefix_cmd,
       "no distribute-list prefix [PREFIXLIST4_NAME$name] <in|out>$dir [WORD$ifname]",
       NO_STR
       "Filter networks in routing updates\n"
       "Specify a prefix list\n"
       "Prefix-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const struct lyd_node *value_node;
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "./distribute-list[interface='%s']/%s/prefix-list",
		 ifname ? ifname : "", dir);
	/*
	 * See if the user has specified specific list so check it exists.
	 *
	 * NOTE: Other FRR CLI commands do not do this sort of verification and
	 * there may be an official decision not to.
	 */
	if (name) {
		value_node = yang_dnode_getf(vty->candidate_config->dnode, "%s/%s",
					     VTY_CURR_XPATH, xpath);
		if (!value_node || strcmp(name, lyd_get_value(value_node))) {
			vty_out(vty, "distribute list doesn't exist\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/route-map
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/bandwidth
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/delay
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/reliability
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/load
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/mtu
 */
DEFPY_YANG(
	eigrp_redistribute_source_metric,
	eigrp_redistribute_source_metric_cmd,
	"[no] redistribute " FRR_REDIST_STR_EIGRPD
	"$proto [metric (1-4294967295)$bw (0-4294967295)$delay (0-255)$rlbt (1-255)$load (1-65535)$mtu]",
	NO_STR
	REDIST_STR
	FRR_REDIST_HELP_STR_EIGRPD
	"Metric for redistributed routes\n"
	"Bandwidth metric in Kbits per second\n"
	"EIGRP delay metric, in 10 microsecond units\n"
	"EIGRP reliability metric where 255 is 100% reliable2 ?\n"
	"EIGRP Effective bandwidth metric (Loading) where 255 is 100% loaded\n"
	"EIGRP MTU of the path\n")
{
	char xpath[XPATH_MAXLEN], xpath_metric[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "./redistribute[protocol='%s']", proto);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (bw == 0 || delay == 0 || rlbt == 0 || load == 0 || mtu == 0)
		return nb_cli_apply_changes(vty, NULL);

	snprintf(xpath_metric, sizeof(xpath_metric), "%s/metrics/bandwidth",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_metric, NB_OP_MODIFY, bw_str);
	snprintf(xpath_metric, sizeof(xpath_metric), "%s/metrics/delay", xpath);
	nb_cli_enqueue_change(vty, xpath_metric, NB_OP_MODIFY, delay_str);
	snprintf(xpath_metric, sizeof(xpath_metric), "%s/metrics/reliability",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_metric, NB_OP_MODIFY, rlbt_str);
	snprintf(xpath_metric, sizeof(xpath_metric), "%s/metrics/load", xpath);
	nb_cli_enqueue_change(vty, xpath_metric, NB_OP_MODIFY, load_str);
	snprintf(xpath_metric, sizeof(xpath_metric), "%s/metrics/mtu", xpath);
	nb_cli_enqueue_change(vty, xpath_metric, NB_OP_MODIFY, mtu_str);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_redistribute(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	const char *proto = yang_dnode_get_string(dnode, "protocol");
	const char *bw, *delay, *load, *mtu, *rlbt;

	bw = yang_dnode_exists(dnode, "metrics/bandwidth") ?
		yang_dnode_get_string(dnode, "metrics/bandwidth") : NULL;
	delay = yang_dnode_exists(dnode, "metrics/delay") ?
		yang_dnode_get_string(dnode, "metrics/delay") : NULL;
	rlbt = yang_dnode_exists(dnode, "metrics/reliability") ?
		yang_dnode_get_string(dnode, "metrics/reliability") : NULL;
	load = yang_dnode_exists(dnode, "metrics/load") ?
		yang_dnode_get_string(dnode, "metrics/load") : NULL;
	mtu = yang_dnode_exists(dnode, "metrics/mtu") ?
		yang_dnode_get_string(dnode, "metrics/mtu") : NULL;

	vty_out(vty, " redistribute %s", proto);
	if (bw || rlbt || delay || load || mtu)
		vty_out(vty, " metric %s %s %s %s %s", bw, delay, rlbt, load,
			mtu);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/delay
 */
DEFPY_YANG(
	eigrp_if_delay,
	eigrp_if_delay_cmd,
	"delay (1-16777215)$delay",
	"Specify interface throughput delay\n"
	"Throughput delay (tens of microseconds)\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/delay",
			      NB_OP_MODIFY, delay_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_if_delay,
	no_eigrp_if_delay_cmd,
	"no delay [(1-16777215)]",
	NO_STR
	"Specify interface throughput delay\n"
	"Throughput delay (tens of microseconds)\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/delay",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_delay(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	const char *delay = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " delay %s\n", delay);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/bandwidth
 */
DEFPY_YANG(
	eigrp_if_bandwidth,
	eigrp_if_bandwidth_cmd,
	"eigrp bandwidth (1-10000000)$bw",
	EIGRP_STR
	"Set bandwidth informational parameter\n"
	"Bandwidth in kilobits\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/bandwidth",
			      NB_OP_MODIFY, bw_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_if_bandwidth,
	no_eigrp_if_bandwidth_cmd,
	"no eigrp bandwidth [(1-10000000)]",
	NO_STR
	EIGRP_STR
	"Set bandwidth informational parameter\n"
	"Bandwidth in kilobits\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/bandwidth",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_bandwidth(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *bandwidth = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " eigrp bandwidth %s\n", bandwidth);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/hello-interval
 */
DEFPY_YANG(
	eigrp_if_ip_hellointerval,
	eigrp_if_ip_hellointerval_cmd,
	"ip hello-interval eigrp (1-65535)$hello",
	"Interface Internet Protocol config commands\n"
	"Configures EIGRP hello interval\n"
	EIGRP_STR
	"Seconds between hello transmissions\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/hello-interval",
			      NB_OP_MODIFY, hello_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_if_ip_hellointerval,
	no_eigrp_if_ip_hellointerval_cmd,
	"no ip hello-interval eigrp [(1-65535)]",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Configures EIGRP hello interval\n"
	EIGRP_STR
	"Seconds between hello transmissions\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/hello-interval",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}


void eigrp_cli_show_hello_interval(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *hello = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " ip hello-interval eigrp %s\n", hello);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/hold-time
 */
DEFPY_YANG(
	eigrp_if_ip_holdinterval,
	eigrp_if_ip_holdinterval_cmd,
	"ip hold-time eigrp (1-65535)$hold",
	"Interface Internet Protocol config commands\n"
	"Configures EIGRP IPv4 hold time\n"
	EIGRP_STR
	"Seconds before neighbor is considered down\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/hold-time",
			      NB_OP_MODIFY, hold_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_if_ip_holdinterval,
	no_eigrp_if_ip_holdinterval_cmd,
	"no ip hold-time eigrp [(1-65535)]",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Configures EIGRP IPv4 hold time\n"
	EIGRP_STR
	"Seconds before neighbor is considered down\n")
{
	nb_cli_enqueue_change(vty, "./frr-eigrpd:eigrp/hold-time",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_hold_time(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *holdtime = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " ip hold-time eigrp %s\n", holdtime);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/split-horizon
 */
/* NOT implemented. */

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/summarize-addresses
 */
DEFPY_YANG(
	eigrp_ip_summary_address,
	eigrp_ip_summary_address_cmd,
	"ip summary-address eigrp (1-65535)$as A.B.C.D/M$prefix",
	"Interface Internet Protocol config commands\n"
	"Perform address summarization\n"
	EIGRP_STR
	AS_STR
	"Summary <network>/<length>, e.g. 192.168.0.0/16\n")
{
	char xpath[XPATH_MAXLEN], xpath_auth[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "./frr-eigrpd:eigrp/instance[asn='%s']",
		 as_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_auth, sizeof(xpath_auth),
		 "%s/summarize-addresses[.='%s']", xpath, prefix_str);
	nb_cli_enqueue_change(vty, xpath_auth, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_ip_summary_address,
	no_eigrp_ip_summary_address_cmd,
	"no ip summary-address eigrp (1-65535)$as A.B.C.D/M$prefix",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Perform address summarization\n"
	EIGRP_STR
	AS_STR
	"Summary <network>/<length>, e.g. 192.168.0.0/16\n")
{
	char xpath[XPATH_MAXLEN], xpath_auth[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "./frr-eigrpd:eigrp/instance[asn='%s']",
		 as_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_auth, sizeof(xpath_auth),
		 "%s/summarize-addresses[.='%s']", xpath, prefix_str);
	nb_cli_enqueue_change(vty, xpath_auth, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_summarize_address(struct vty *vty,
				      const struct lyd_node *dnode,
				      bool show_defaults)
{
	const struct lyd_node *instance =
		yang_dnode_get_parent(dnode, "instance");
	uint16_t asn = yang_dnode_get_uint16(instance, "asn");
	const char *summarize_address = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " ip summary-address eigrp %d %s\n", asn,
		summarize_address);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/authentication
 */
DEFPY_YANG(
	eigrp_authentication_mode,
	eigrp_authentication_mode_cmd,
	"ip authentication mode eigrp (1-65535)$as <md5|hmac-sha-256>$crypt",
	"Interface Internet Protocol config commands\n"
	"Authentication subcommands\n"
	"Mode\n"
	EIGRP_STR
	AS_STR
	"Keyed message digest\n"
	"HMAC SHA256 algorithm \n")
{
	char xpath[XPATH_MAXLEN], xpath_auth[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "./frr-eigrpd:eigrp/instance[asn='%s']",
		 as_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_auth, sizeof(xpath_auth), "%s/authentication", xpath);
	nb_cli_enqueue_change(vty, xpath_auth, NB_OP_MODIFY, crypt);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_authentication_mode,
	no_eigrp_authentication_mode_cmd,
	"no ip authentication mode eigrp (1-65535)$as [<md5|hmac-sha-256>]",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Authentication subcommands\n"
	"Mode\n"
	EIGRP_STR
	AS_STR
	"Keyed message digest\n"
	"HMAC SHA256 algorithm \n")
{
	char xpath[XPATH_MAXLEN], xpath_auth[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "./frr-eigrpd:eigrp/instance[asn='%s']",
		 as_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_auth, sizeof(xpath_auth), "%s/authentication", xpath);
	nb_cli_enqueue_change(vty, xpath_auth, NB_OP_MODIFY, "none");

	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_authentication(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	const struct lyd_node *instance =
		yang_dnode_get_parent(dnode, "instance");
	uint16_t asn = yang_dnode_get_uint16(instance, "asn");
	const char *crypt = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " ip authentication mode eigrp %d %s\n", asn, crypt);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/keychain
 */
DEFPY_YANG(
	eigrp_authentication_keychain,
	eigrp_authentication_keychain_cmd,
	"ip authentication key-chain eigrp (1-65535)$as WORD$name",
	"Interface Internet Protocol config commands\n"
	"Authentication subcommands\n"
	"Key-chain\n"
	EIGRP_STR
	AS_STR
	"Name of key-chain\n")
{
	char xpath[XPATH_MAXLEN], xpath_auth[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "./frr-eigrpd:eigrp/instance[asn='%s']",
		 as_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_auth, sizeof(xpath_auth), "%s/keychain", xpath);
	nb_cli_enqueue_change(vty, xpath_auth, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_eigrp_authentication_keychain,
	no_eigrp_authentication_keychain_cmd,
	"no ip authentication key-chain eigrp (1-65535)$as [WORD]",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Authentication subcommands\n"
	"Key-chain\n"
	EIGRP_STR
	AS_STR
	"Name of key-chain\n")
{
	char xpath[XPATH_MAXLEN], xpath_auth[XPATH_MAXLEN + 64];

	snprintf(xpath, sizeof(xpath), "./frr-eigrpd:eigrp/instance[asn='%s']",
		 as_str);
	snprintf(xpath_auth, sizeof(xpath_auth), "%s/keychain", xpath);
	nb_cli_enqueue_change(vty, xpath_auth, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void eigrp_cli_show_keychain(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	const struct lyd_node *instance =
		yang_dnode_get_parent(dnode, "instance");
	uint16_t asn = yang_dnode_get_uint16(instance, "asn");
	const char *keychain = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " ip authentication key-chain eigrp %d %s\n", asn,
		keychain);
}


/*
 * CLI installation procedures.
 */
static int eigrp_config_write(struct vty *vty);
static struct cmd_node eigrp_node = {
	.name = "eigrp",
	.node = EIGRP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = eigrp_config_write,
};

static int eigrp_config_write(struct vty *vty)
{
	const struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode, "/frr-eigrpd:eigrpd");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}

	return written;
}

void
eigrp_cli_init(void)
{
	install_element(CONFIG_NODE, &router_eigrp_cmd);
	install_element(CONFIG_NODE, &no_router_eigrp_cmd);

	install_node(&eigrp_node);
	install_default(EIGRP_NODE);

	install_element(EIGRP_NODE, &eigrp_router_id_cmd);
	install_element(EIGRP_NODE, &no_eigrp_router_id_cmd);
	install_element(EIGRP_NODE, &eigrp_passive_interface_cmd);
	install_element(EIGRP_NODE, &eigrp_timers_active_cmd);
	install_element(EIGRP_NODE, &no_eigrp_timers_active_cmd);
	install_element(EIGRP_NODE, &eigrp_variance_cmd);
	install_element(EIGRP_NODE, &no_eigrp_variance_cmd);
	install_element(EIGRP_NODE, &eigrp_maximum_paths_cmd);
	install_element(EIGRP_NODE, &no_eigrp_maximum_paths_cmd);
	install_element(EIGRP_NODE, &eigrp_metric_weights_cmd);
	install_element(EIGRP_NODE, &no_eigrp_metric_weights_cmd);
	install_element(EIGRP_NODE, &eigrp_network_cmd);
	install_element(EIGRP_NODE, &eigrp_neighbor_cmd);
	install_element(EIGRP_NODE, &eigrp_distribute_list_cmd);
	install_element(EIGRP_NODE, &eigrp_distribute_list_prefix_cmd);
	install_element(EIGRP_NODE, &eigrp_no_distribute_list_cmd);
	install_element(EIGRP_NODE, &eigrp_no_distribute_list_prefix_cmd);
	install_element(EIGRP_NODE, &eigrp_redistribute_source_metric_cmd);

	vrf_cmd_init(NULL);

	if_cmd_init_default();

	install_element(INTERFACE_NODE, &eigrp_if_delay_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_delay_cmd);
	install_element(INTERFACE_NODE, &eigrp_if_bandwidth_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_bandwidth_cmd);
	install_element(INTERFACE_NODE, &eigrp_if_ip_hellointerval_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_ip_hellointerval_cmd);
	install_element(INTERFACE_NODE, &eigrp_if_ip_holdinterval_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_ip_holdinterval_cmd);
	install_element(INTERFACE_NODE, &eigrp_ip_summary_address_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_ip_summary_address_cmd);
	install_element(INTERFACE_NODE, &eigrp_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &eigrp_authentication_keychain_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_authentication_keychain_cmd);
}
