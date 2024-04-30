// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "if.h"
#include "if_rmap.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "northbound_cli.h"
#include "libfrr.h"

#include "ripd/ripd.h"
#include "ripd/rip_nb.h"
#include "ripd/rip_cli_clippy.c"

/*
 * XPath: /frr-ripd:ripd/instance
 */
DEFPY_YANG_NOSH (router_rip,
       router_rip_cmd,
       "router rip [vrf NAME]",
       "Enable a routing process\n"
       "Routing Information Protocol (RIP)\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];
	int ret;

	/* Build RIP instance XPath. */
	if (!vrf)
		vrf = VRF_DEFAULT_NAME;
	snprintf(xpath, sizeof(xpath), "/frr-ripd:ripd/instance[vrf='%s']",
		 vrf);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(RIP_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_router_rip,
       no_router_rip_cmd,
       "no router rip [vrf NAME]",
       NO_STR
       "Enable a routing process\n"
       "Routing Information Protocol (RIP)\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];

	/* Build RIP instance XPath. */
	if (!vrf)
		vrf = VRF_DEFAULT_NAME;
	snprintf(xpath, sizeof(xpath), "/frr-ripd:ripd/instance[vrf='%s']",
		 vrf);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

void cli_show_router_rip(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults)
{
	const char *vrf_name;

	vrf_name = yang_dnode_get_string(dnode, "vrf");

	vty_out(vty, "!\n");
	vty_out(vty, "router rip");
	if (!strmatch(vrf_name, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf_name);
	vty_out(vty, "\n");
}

void cli_show_end_router_rip(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/allow-ecmp
 */
DEFUN_YANG (rip_allow_ecmp,
       rip_allow_ecmp_cmd,
       "allow-ecmp [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]",
       "Allow Equal Cost MultiPath\n"
       "Number of paths\n")
{
	int idx_number = 0;
	char mpaths[3] = {};
	uint32_t paths = MULTIPATH_NUM;

	if (argv_find(argv, argc, CMD_RANGE_STR(1, MULTIPATH_NUM), &idx_number))
		paths = strtol(argv[idx_number]->arg, NULL, 10);
	snprintf(mpaths, sizeof(mpaths), "%u", paths);

	nb_cli_enqueue_change(vty, "./allow-ecmp", NB_OP_MODIFY, mpaths);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_rip_allow_ecmp,
       no_rip_allow_ecmp_cmd,
       "no allow-ecmp [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]",
       NO_STR
       "Allow Equal Cost MultiPath\n"
       "Number of paths\n")
{
	nb_cli_enqueue_change(vty, "./allow-ecmp", NB_OP_MODIFY, 0);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_allow_ecmp(struct vty *vty, const struct lyd_node *dnode,
			     bool show_defaults)
{
	uint8_t paths;

	paths = yang_dnode_get_uint8(dnode, NULL);

	if (!paths)
		vty_out(vty, " no allow-ecmp\n");
	else
		vty_out(vty, " allow-ecmp %d\n", paths);
}

/*
 * XPath: /frr-ripd:ripd/instance/default-information-originate
 */
DEFPY_YANG (rip_default_information_originate,
       rip_default_information_originate_cmd,
       "[no] default-information originate",
       NO_STR
       "Control distribution of default route\n"
       "Distribute a default route\n")
{
	nb_cli_enqueue_change(vty, "./default-information-originate",
			      NB_OP_MODIFY, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_default_information_originate(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " default-information originate\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/default-metric
 */
DEFPY_YANG (rip_default_metric,
       rip_default_metric_cmd,
       "default-metric (1-16)",
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY,
			      default_metric_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rip_default_metric,
       no_rip_default_metric_cmd,
       "no default-metric [(1-16)]",
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	nb_cli_enqueue_change(vty, "./default-metric", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_default_metric(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " default-metric %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/default
 */
DEFPY_YANG (rip_distance,
       rip_distance_cmd,
       "distance (1-255)",
       "Administrative distance\n"
       "Distance value\n")
{
	nb_cli_enqueue_change(vty, "./distance/default", NB_OP_MODIFY,
			      distance_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rip_distance,
       no_rip_distance_cmd,
       "no distance [(1-255)]",
       NO_STR
       "Administrative distance\n"
       "Distance value\n")
{
	nb_cli_enqueue_change(vty, "./distance/default", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_distance(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	if (yang_dnode_is_default(dnode, NULL))
		vty_out(vty, " no distance\n");
	else
		vty_out(vty, " distance %s\n",
			yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source
 */
DEFPY_YANG (rip_distance_source,
       rip_distance_source_cmd,
       "[no] distance (1-255) A.B.C.D/M$prefix [WORD$acl]",
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./distance", NB_OP_MODIFY,
				      distance_str);
		nb_cli_enqueue_change(vty, "./access-list",
				      acl ? NB_OP_MODIFY : NB_OP_DESTROY, acl);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./distance/source[prefix='%s']",
				    prefix_str);
}

void cli_show_rip_distance_source(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, " distance %s %s",
		yang_dnode_get_string(dnode, "distance"),
		yang_dnode_get_string(dnode, "prefix"));
	if (yang_dnode_exists(dnode, "access-list"))
		vty_out(vty, " %s",
			yang_dnode_get_string(dnode, "access-list"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/explicit-neighbor
 */
DEFPY_YANG (rip_neighbor,
       rip_neighbor_cmd,
       "[no] neighbor A.B.C.D",
       NO_STR
       "Specify a neighbor router\n"
       "Neighbor address\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./explicit-neighbor[.='%s']",
		 neighbor_str);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_neighbor(struct vty *vty, const struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " neighbor %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/network
 */
DEFPY_YANG (rip_network_prefix,
       rip_network_prefix_cmd,
       "[no] network A.B.C.D/M",
       NO_STR
       "Enable routing on an IP network\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./network[.='%s']", network_str);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_network_prefix(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/interface
 */
DEFPY_YANG (rip_network_if,
       rip_network_if_cmd,
       "[no] network WORD",
       NO_STR
       "Enable routing on an IP network\n"
       "Interface name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./interface[.='%s']", network);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_network_interface(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, " network %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list
 */
DEFPY_YANG (rip_offset_list,
       rip_offset_list_cmd,
       "[no] offset-list ACCESSLIST4_NAME$acl <in|out>$direction (0-16)$metric [IFNAME]",
       NO_STR
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n"
       "Interface to match\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./access-list", NB_OP_MODIFY, acl);
		nb_cli_enqueue_change(vty, "./metric", NB_OP_MODIFY,
				      metric_str);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(
		vty, "./offset-list[interface='%s'][direction='%s']",
		ifname ? ifname : "*", direction);
}

void cli_show_rip_offset_list(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *interface;

	interface = yang_dnode_get_string(dnode, "interface");

	vty_out(vty, " offset-list %s %s %s",
		yang_dnode_get_string(dnode, "access-list"),
		yang_dnode_get_string(dnode, "direction"),
		yang_dnode_get_string(dnode, "metric"));
	if (!strmatch(interface, "*"))
		vty_out(vty, " %s", interface);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-default
 */
DEFPY_YANG (rip_passive_default,
       rip_passive_default_cmd,
       "[no] passive-interface default",
       NO_STR
       "Suppress routing updates on an interface\n"
       "default for all interfaces\n")
{
	nb_cli_enqueue_change(vty, "./passive-default", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_passive_default(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " passive-interface default\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-interface
 *        /frr-ripd:ripd/instance/non-passive-interface
 */
DEFPY_YANG (rip_passive_interface,
       rip_passive_interface_cmd,
       "[no] passive-interface IFNAME",
       NO_STR
       "Suppress routing updates on an interface\n"
       "Interface name\n")
{
	bool passive_default =
		yang_dnode_get_bool(vty->candidate_config->dnode, "%s%s",
				    VTY_CURR_XPATH, "/passive-default");
	char xpath[XPATH_MAXLEN];
	enum nb_operation op;

	if (passive_default) {
		snprintf(xpath, sizeof(xpath),
			 "./non-passive-interface[.='%s']", ifname);
		op = no ? NB_OP_CREATE : NB_OP_DESTROY;
	} else {
		snprintf(xpath, sizeof(xpath), "./passive-interface[.='%s']",
			 ifname);
		op = no ? NB_OP_DESTROY : NB_OP_CREATE;
	}

	nb_cli_enqueue_change(vty, xpath, op, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_passive_interface(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, " passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void cli_show_rip_non_passive_interface(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	vty_out(vty, " no passive-interface %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute
 */
DEFPY_YANG (rip_redistribute,
       rip_redistribute_cmd,
       "[no] redistribute " FRR_REDIST_STR_RIPD "$protocol [{metric (0-16)|route-map RMAP_NAME$route_map}]",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map",
				      route_map ? NB_OP_MODIFY : NB_OP_DESTROY,
				      route_map);
		nb_cli_enqueue_change(vty, "./metric",
				      metric_str ? NB_OP_MODIFY : NB_OP_DESTROY,
				      metric_str);
	} else
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./redistribute[protocol='%s']",
				    protocol);
}

void cli_show_rip_redistribute(struct vty *vty, const struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, " redistribute %s",
		yang_dnode_get_string(dnode, "protocol"));
	if (yang_dnode_exists(dnode, "metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "metric"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "route-map"));
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-ripd:ripd/instance/static-route
 */
DEFPY_YANG (rip_route,
       rip_route_cmd,
       "[no] route A.B.C.D/M",
       NO_STR
       "RIP static route configuration\n"
       "IP prefix <network>/<length>\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./static-route[.='%s']", route_str);

	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_route(struct vty *vty, const struct lyd_node *dnode,
			bool show_defaults)
{
	vty_out(vty, " route %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-ripd:ripd/instance/timers
 */
DEFPY_YANG (rip_timers,
       rip_timers_cmd,
       "timers basic (5-2147483647)$update (5-2147483647)$timeout (5-2147483647)$garbage",
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	nb_cli_enqueue_change(vty, "./update-interval", NB_OP_MODIFY,
			      update_str);
	nb_cli_enqueue_change(vty, "./holddown-interval", NB_OP_MODIFY,
			      timeout_str);
	nb_cli_enqueue_change(vty, "./flush-interval", NB_OP_MODIFY,
			      garbage_str);

	return nb_cli_apply_changes(vty, "./timers");
}

DEFPY_YANG (no_rip_timers,
       no_rip_timers_cmd,
       "no timers basic [(5-2147483647) (5-2147483647) (5-2147483647)]",
       NO_STR
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	nb_cli_enqueue_change(vty, "./update-interval", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./holddown-interval", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./flush-interval", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, "./timers");
}

void cli_show_rip_timers(struct vty *vty, const struct lyd_node *dnode,
			 bool show_defaults)
{
	vty_out(vty, " timers basic %s %s %s\n",
		yang_dnode_get_string(dnode, "update-interval"),
		yang_dnode_get_string(dnode, "holddown-interval"),
		yang_dnode_get_string(dnode, "flush-interval"));
}

/*
 * XPath: /frr-ripd:ripd/instance/version
 */
DEFPY_YANG (rip_version,
       rip_version_cmd,
       "version (1-2)",
       "Set routing protocol version\n"
       "version\n")
{
	nb_cli_enqueue_change(vty, "./version/receive", NB_OP_MODIFY,
			      version_str);
	nb_cli_enqueue_change(vty, "./version/send", NB_OP_MODIFY, version_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_rip_version,
       no_rip_version_cmd,
       "no version [(1-2)]",
       NO_STR
       "Set routing protocol version\n"
       "version\n")
{
	nb_cli_enqueue_change(vty, "./version/receive", NB_OP_MODIFY, NULL);
	nb_cli_enqueue_change(vty, "./version/send", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rip_version(struct vty *vty, const struct lyd_node *dnode,
			  bool show_defaults)
{
	/*
	 * We have only one "version" command and three possible combinations of
	 * send/receive values.
	 */
	switch (yang_dnode_get_enum(dnode, "receive")) {
	case RI_RIP_VERSION_1:
		vty_out(vty, " version 1\n");
		break;
	case RI_RIP_VERSION_2:
		vty_out(vty, " version 2\n");
		break;
	case RI_RIP_VERSION_1_AND_2:
		vty_out(vty, " no version\n");
		break;
	}
}

/*
 * XPath: /frr-ripd:ripd/instance/default-bfd-profile
 */
DEFPY_YANG(rip_bfd_default_profile, rip_bfd_default_profile_cmd,
	   "bfd default-profile BFDPROF$profile",
	   "Bidirectional Forwarding Detection\n"
	   "BFD default profile\n"
	   "Profile name\n")
{
	nb_cli_enqueue_change(vty, "./default-bfd-profile", NB_OP_MODIFY,
			      profile);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_rip_bfd_default_profile, no_rip_bfd_default_profile_cmd,
	   "no bfd default-profile [BFDPROF]",
	   NO_STR
	   "Bidirectional Forwarding Detection\n"
	   "BFD default profile\n"
	   "Profile name\n")
{
	nb_cli_enqueue_change(vty, "./default-bfd-profile", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ripd_instance_default_bfd_profile(struct vty *vty,
						const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, " bfd default-profile %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/split-horizon
 */
DEFPY_YANG (ip_rip_split_horizon,
       ip_rip_split_horizon_cmd,
       "[no] ip rip split-horizon [poisoned-reverse$poisoned_reverse]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n"
       "With poisoned-reverse\n")
{
	const char *value;

	if (no)
		value = "disabled";
	else if (poisoned_reverse)
		value = "poison-reverse";
	else
		value = "simple";

	nb_cli_enqueue_change(vty, "./split-horizon", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_split_horizon(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	int value;

	value = yang_dnode_get_enum(dnode, NULL);
	switch (value) {
	case RIP_NO_SPLIT_HORIZON:
		vty_out(vty, " no ip rip split-horizon\n");
		break;
	case RIP_SPLIT_HORIZON:
		vty_out(vty, " ip rip split-horizon\n");
		break;
	case RIP_SPLIT_HORIZON_POISONED_REVERSE:
		vty_out(vty, " ip rip split-horizon poisoned-reverse\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/v2-broadcast
 */
DEFPY_YANG (ip_rip_v2_broadcast,
       ip_rip_v2_broadcast_cmd,
       "[no] ip rip v2-broadcast",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Send ip broadcast v2 update\n")
{
	nb_cli_enqueue_change(vty, "./v2-broadcast", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_v2_broadcast(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " ip rip v2-broadcast\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-receive
 */
DEFPY_YANG (ip_rip_receive_version,
       ip_rip_receive_version_cmd,
       "ip rip receive version <{1$v1|2$v2}|none>",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	const char *value;

	if (v1 && v2)
		value = "both";
	else if (v1)
		value = "1";
	else if (v2)
		value = "2";
	else
		value = "none";

	nb_cli_enqueue_change(vty, "./version-receive", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_receive_version,
       no_ip_rip_receive_version_cmd,
       "no ip rip receive version [<{1|2}|none>]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	nb_cli_enqueue_change(vty, "./version-receive", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_receive_version(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults)
{
	switch (yang_dnode_get_enum(dnode, NULL)) {
	case RI_RIP_UNSPEC:
		vty_out(vty, " no ip rip receive version\n");
		break;
	case RI_RIP_VERSION_1:
		vty_out(vty, " ip rip receive version 1\n");
		break;
	case RI_RIP_VERSION_2:
		vty_out(vty, " ip rip receive version 2\n");
		break;
	case RI_RIP_VERSION_1_AND_2:
		vty_out(vty, " ip rip receive version 1 2\n");
		break;
	case RI_RIP_VERSION_NONE:
		vty_out(vty, " ip rip receive version none\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-send
 */
DEFPY_YANG (ip_rip_send_version,
       ip_rip_send_version_cmd,
       "ip rip send version <{1$v1|2$v2}|none>",
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	const char *value;

	if (v1 && v2)
		value = "both";
	else if (v1)
		value = "1";
	else if (v2)
		value = "2";
	else
		value = "none";

	nb_cli_enqueue_change(vty, "./version-send", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_send_version,
       no_ip_rip_send_version_cmd,
       "no ip rip send version [<{1|2}|none>]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n"
       "None\n")
{
	nb_cli_enqueue_change(vty, "./version-send", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_send_version(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults)
{
	switch (yang_dnode_get_enum(dnode, NULL)) {
	case RI_RIP_UNSPEC:
		vty_out(vty, " no ip rip send version\n");
		break;
	case RI_RIP_VERSION_1:
		vty_out(vty, " ip rip send version 1\n");
		break;
	case RI_RIP_VERSION_2:
		vty_out(vty, " ip rip send version 2\n");
		break;
	case RI_RIP_VERSION_1_AND_2:
		vty_out(vty, " ip rip send version 1 2\n");
		break;
	case RI_RIP_VERSION_NONE:
		vty_out(vty, " ip rip send version none\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme
 */
DEFPY_YANG (ip_rip_authentication_mode,
       ip_rip_authentication_mode_cmd,
       "ip rip authentication mode <md5$mode [auth-length <rfc|old-ripd>$auth_length]|text$mode>",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "MD5 authentication data length\n"
       "RFC compatible\n"
       "Old ripd compatible\n"
       "Clear text authentication\n")
{
	const char *value = NULL;

	if (auth_length) {
		if (strmatch(auth_length, "rfc"))
			value = "16";
		else
			value = "20";
	}

	nb_cli_enqueue_change(vty, "./authentication-scheme/mode", NB_OP_MODIFY,
			      strmatch(mode, "md5") ? "md5" : "plain-text");
	if (strmatch(mode, "md5"))
		nb_cli_enqueue_change(vty,
				      "./authentication-scheme/md5-auth-length",
				      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_authentication_mode,
       no_ip_rip_authentication_mode_cmd,
       "no ip rip authentication mode [<md5 [auth-length <rfc|old-ripd>]|text>]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "MD5 authentication data length\n"
       "RFC compatible\n"
       "Old ripd compatible\n"
       "Clear text authentication\n")
{
	nb_cli_enqueue_change(vty, "./authentication-scheme/mode", NB_OP_MODIFY,
			      NULL);
	nb_cli_enqueue_change(vty, "./authentication-scheme/md5-auth-length",
			      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_authentication_scheme(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults)
{
	switch (yang_dnode_get_enum(dnode, "mode")) {
	case RIP_NO_AUTH:
		vty_out(vty, " no ip rip authentication mode\n");
		break;
	case RIP_AUTH_SIMPLE_PASSWORD:
		vty_out(vty, " ip rip authentication mode text\n");
		break;
	case RIP_AUTH_MD5:
		vty_out(vty, " ip rip authentication mode md5");
		if (show_defaults
		    || !yang_dnode_is_default(dnode, "md5-auth-length")) {
			if (yang_dnode_get_enum(dnode, "md5-auth-length")
			    == RIP_AUTH_MD5_SIZE)
				vty_out(vty, " auth-length rfc");
			else
				vty_out(vty, " auth-length old-ripd");
		}
		vty_out(vty, "\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-password
 */
DEFPY_YANG (ip_rip_authentication_string,
       ip_rip_authentication_string_cmd,
       "ip rip authentication string LINE$password",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")
{
	if (strlen(password) > 16) {
		vty_out(vty,
			"%% RIPv2 authentication string must be shorter than 16\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (yang_dnode_existsf(vty->candidate_config->dnode, "%s%s",
			       VTY_CURR_XPATH,
			       "/frr-ripd:rip/authentication-key-chain")) {
		vty_out(vty, "%% key-chain configuration exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./authentication-password", NB_OP_MODIFY,
			      password);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_authentication_string,
       no_ip_rip_authentication_string_cmd,
       "no ip rip authentication string [LINE]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")
{
	nb_cli_enqueue_change(vty, "./authentication-password", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_authentication_string(struct vty *vty,
					   const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " ip rip authentication string %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain
 */
DEFPY_YANG (ip_rip_authentication_key_chain,
       ip_rip_authentication_key_chain_cmd,
       "ip rip authentication key-chain LINE$keychain",
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")
{
	if (yang_dnode_existsf(vty->candidate_config->dnode, "%s%s",
			       VTY_CURR_XPATH,
			       "/frr-ripd:rip/authentication-password")) {
		vty_out(vty, "%% authentication string configuration exists\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./authentication-key-chain", NB_OP_MODIFY,
			      keychain);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG (no_ip_rip_authentication_key_chain,
       no_ip_rip_authentication_key_chain_cmd,
       "no ip rip authentication key-chain [LINE]",
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")
{
	nb_cli_enqueue_change(vty, "./authentication-key-chain", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_authentication_key_chain(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, " ip rip authentication key-chain %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/enable
 */
DEFPY_YANG(ip_rip_bfd, ip_rip_bfd_cmd, "[no] ip rip bfd",
	   NO_STR IP_STR
	   "Routing Information Protocol\n"
	   "Enable BFD support\n")
{
	nb_cli_enqueue_change(vty, "./bfd-monitoring/enable", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_bfd_enable(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " ip rip bfd\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/bfd/profile
 */
DEFPY_YANG(ip_rip_bfd_profile, ip_rip_bfd_profile_cmd,
	   "[no] ip rip bfd profile BFDPROF$profile",
	   NO_STR IP_STR
	   "Routing Information Protocol\n"
	   "Enable BFD support\n"
	   "Use a pre-configured profile\n"
	   "Profile name\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./bfd-monitoring/profile",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./bfd-monitoring/profile",
				      NB_OP_MODIFY, profile);

	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

DEFPY_YANG(no_ip_rip_bfd_profile, no_ip_rip_bfd_profile_cmd,
	   "no ip rip bfd profile",
	   NO_STR IP_STR
	   "Routing Information Protocol\n"
	   "Enable BFD support\n"
	   "Use a pre-configured profile\n")
{
	nb_cli_enqueue_change(vty, "./bfd-monitoring/profile", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, "./frr-ripd:rip");
}

void cli_show_ip_rip_bfd_profile(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults)
{
	vty_out(vty, " ip rip bfd profile %s\n",
		yang_dnode_get_string(dnode, NULL));
}

DEFPY_YANG(
	rip_distribute_list, rip_distribute_list_cmd,
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

DEFPY_YANG(
	rip_distribute_list_prefix, rip_distribute_list_prefix_cmd,
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

DEFPY_YANG(no_rip_distribute_list,
	   no_rip_distribute_list_cmd,
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

DEFPY_YANG(no_rip_distribute_list_prefix,
	   no_rip_distribute_list_prefix_cmd,
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

/* RIP node structure. */
static struct cmd_node rip_node = {
	.name = "rip",
	.node = RIP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	// .config_write = config_write_rip,
};

void rip_cli_init(void)
{
	install_node(&rip_node);

	install_element(CONFIG_NODE, &router_rip_cmd);
	install_element(CONFIG_NODE, &no_router_rip_cmd);

	install_element(RIP_NODE, &rip_distribute_list_cmd);
	install_element(RIP_NODE, &rip_distribute_list_prefix_cmd);
	install_element(RIP_NODE, &no_rip_distribute_list_cmd);
	install_element(RIP_NODE, &no_rip_distribute_list_prefix_cmd);

	install_element(RIP_NODE, &rip_allow_ecmp_cmd);
	install_element(RIP_NODE, &no_rip_allow_ecmp_cmd);
	install_element(RIP_NODE, &rip_default_information_originate_cmd);
	install_element(RIP_NODE, &rip_default_metric_cmd);
	install_element(RIP_NODE, &no_rip_default_metric_cmd);
	install_element(RIP_NODE, &rip_distance_cmd);
	install_element(RIP_NODE, &no_rip_distance_cmd);
	install_element(RIP_NODE, &rip_distance_source_cmd);
	install_element(RIP_NODE, &rip_neighbor_cmd);
	install_element(RIP_NODE, &rip_network_prefix_cmd);
	install_element(RIP_NODE, &rip_network_if_cmd);
	install_element(RIP_NODE, &rip_offset_list_cmd);
	install_element(RIP_NODE, &rip_passive_default_cmd);
	install_element(RIP_NODE, &rip_passive_interface_cmd);
	install_element(RIP_NODE, &rip_redistribute_cmd);
	install_element(RIP_NODE, &rip_route_cmd);
	install_element(RIP_NODE, &rip_timers_cmd);
	install_element(RIP_NODE, &no_rip_timers_cmd);
	install_element(RIP_NODE, &rip_version_cmd);
	install_element(RIP_NODE, &no_rip_version_cmd);
	install_element(RIP_NODE, &rip_bfd_default_profile_cmd);
	install_element(RIP_NODE, &no_rip_bfd_default_profile_cmd);
	install_default(RIP_NODE);

	install_element(INTERFACE_NODE, &ip_rip_split_horizon_cmd);
	install_element(INTERFACE_NODE, &ip_rip_v2_broadcast_cmd);
	install_element(INTERFACE_NODE, &ip_rip_receive_version_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_receive_version_cmd);
	install_element(INTERFACE_NODE, &ip_rip_send_version_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_send_version_cmd);
	install_element(INTERFACE_NODE, &ip_rip_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &ip_rip_authentication_string_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_authentication_string_cmd);
	install_element(INTERFACE_NODE, &ip_rip_authentication_key_chain_cmd);
	install_element(INTERFACE_NODE,
			&no_ip_rip_authentication_key_chain_cmd);
	install_element(INTERFACE_NODE, &ip_rip_bfd_cmd);
	install_element(INTERFACE_NODE, &ip_rip_bfd_profile_cmd);
	install_element(INTERFACE_NODE, &no_ip_rip_bfd_profile_cmd);

	if_rmap_init(RIP_NODE);
}
/* clang-format off */
const struct frr_yang_module_info frr_ripd_cli_info = {
	.name = "frr-ripd",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-ripd:ripd/instance",
			.cbs.cli_show = cli_show_router_rip,
			.cbs.cli_show_end = cli_show_end_router_rip,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/allow-ecmp",
			.cbs.cli_show = cli_show_rip_allow_ecmp,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-information-originate",
			.cbs.cli_show = cli_show_rip_default_information_originate,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-metric",
			.cbs.cli_show = cli_show_rip_default_metric,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/default",
			.cbs.cli_show = cli_show_rip_distance,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source",
			.cbs.cli_show = cli_show_rip_distance_source,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/explicit-neighbor",
			.cbs.cli_show = cli_show_rip_neighbor,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/network",
			.cbs.cli_show = cli_show_rip_network_prefix,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/interface",
			.cbs.cli_show = cli_show_rip_network_interface,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list",
			.cbs.cli_show = cli_show_rip_offset_list,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-default",
			.cbs.cli_show = cli_show_rip_passive_default,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-interface",
			.cbs.cli_show = cli_show_rip_passive_interface,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/non-passive-interface",
			.cbs.cli_show = cli_show_rip_non_passive_interface,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute",
			.cbs.cli_show = cli_show_rip_redistribute,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/if-route-maps/if-route-map",
			.cbs.cli_show = cli_show_if_route_map,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/static-route",
			.cbs.cli_show = cli_show_rip_route,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers",
			.cbs.cli_show = cli_show_rip_timers,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version",
			.cbs.cli_show = cli_show_rip_version,
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-bfd-profile",
			.cbs.cli_show = cli_show_ripd_instance_default_bfd_profile,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/split-horizon",
			.cbs.cli_show = cli_show_ip_rip_split_horizon,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/v2-broadcast",
			.cbs.cli_show = cli_show_ip_rip_v2_broadcast,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-receive",
			.cbs.cli_show = cli_show_ip_rip_receive_version,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-send",
			.cbs.cli_show = cli_show_ip_rip_send_version,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme",
			.cbs.cli_show = cli_show_ip_rip_authentication_scheme,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-password",
			.cbs.cli_show = cli_show_ip_rip_authentication_string,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain",
			.cbs.cli_show = cli_show_ip_rip_authentication_key_chain,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/enable",
			.cbs.cli_show = cli_show_ip_rip_bfd_enable,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/profile",
			.cbs.cli_show = cli_show_ip_rip_bfd_profile,
		},
		{
			.xpath = NULL,
		},
	}
};
