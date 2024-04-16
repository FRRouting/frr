// SPDX-License-Identifier: GPL-2.0-or-later

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "command.h"
#include "defaults.h"
#include "northbound_cli.h"
#include "vrf.h"

#include "zebra_cli.h"
#include "zebra/zebra_cli_clippy.c"

#define EVPN_MH_VTY_STR "Multihoming\n"

FRR_CFG_DEFAULT_BOOL(ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT,
	{ .val_bool = true, .match_profile = "traditional", },
	{ .val_bool = false },
);

#if HAVE_BFDD == 0
DEFPY_YANG (zebra_ptm_enable,
       zebra_ptm_enable_cmd,
       "[no] ptm-enable",
       NO_STR
       "Enable neighbor check with specified topology\n")
{
	nb_cli_enqueue_change(vty, "/frr-zebra:zebra/ptm-enable", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

static void zebra_ptm_enable_cli_write(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (enable)
		vty_out(vty, "ptm-enable\n");
	else if (show_defaults)
		vty_out(vty, "no ptm-enable\n");
}
#endif

DEFPY_YANG (zebra_route_map_timer,
       zebra_route_map_timer_cmd,
       "[no] zebra route-map delay-timer ![(0-600)$delay]",
       NO_STR
       ZEBRA_STR
       "Set route-map parameters\n"
       "Time to wait before route-map updates are processed\n"
       "0 means route-map changes are run immediately instead of delaying\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "/frr-zebra:zebra/route-map-delay",
				      NB_OP_MODIFY, delay_str);
	else
		nb_cli_enqueue_change(vty, "/frr-zebra:zebra/route-map-delay",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void zebra_route_map_delay_cli_write(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults)
{
	uint32_t delay = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, "zebra route-map delay-timer %u\n", delay);
}

DEFPY_YANG (multicast_new,
	multicast_new_cmd,
	"[no] multicast <enable$on|disable$off>",
	NO_STR
	"Control multicast flag on interface\n"
	"Set multicast flag on interface\n"
	"Unset multicast flag on interface\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/multicast",
				      NB_OP_CREATE, on ? "true" : "false");
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/multicast",
				      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_multicast_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults)
{
	bool multicast = yang_dnode_get_bool(dnode, NULL);

	if (multicast)
		vty_out(vty, " multicast enable\n");
	else
		vty_out(vty, " multicast disable\n");
}

/* Deprecated multicast commands */

DEFPY_YANG_HIDDEN (multicast,
	multicast_cmd,
	"[no] multicast",
	NO_STR
	"Set multicast flag to interface\n")
{
	nb_cli_enqueue_change(vty, "./frr-zebra:zebra/multicast",
			      NB_OP_CREATE, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (mpls,
	mpls_cmd,
	"[no] mpls <enable$on|disable$off>",
	NO_STR
	MPLS_STR
	"Set mpls to be on for the interface\n"
	"Set mpls to be off for the interface\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/mpls",
				      NB_OP_CREATE, on ? "true" : "false");
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/mpls",
				      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_mpls_cli_write(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults)
{
	bool mpls = yang_dnode_get_bool(dnode, NULL);

	if (mpls)
		vty_out(vty, " mpls enable\n");
	else
		vty_out(vty, " mpls disable\n");
}

DEFPY_YANG (linkdetect,
	linkdetect_cmd,
	"[no] link-detect",
	NO_STR
	"Enable link detection on interface\n")
{
	nb_cli_enqueue_change(vty, "./frr-zebra:zebra/link-detect",
			      NB_OP_CREATE, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_detect_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool link_detect = yang_dnode_get_bool(dnode, NULL);

	if (!link_detect)
		vty_out(vty, " no link-detect\n");
	else if (show_defaults)
		vty_out(vty, " link-detect\n");
}

DEFPY_YANG (shutdown_if,
	shutdown_if_cmd,
	"[no] shutdown",
	NO_STR
	"Shutdown the selected interface\n")
{
	nb_cli_enqueue_change(vty, "./frr-zebra:zebra/enabled", NB_OP_CREATE,
			      no ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_enabled_cli_write(struct vty *vty,
						  const struct lyd_node *dnode,
						  bool show_defaults)
{
	bool enabled = yang_dnode_get_bool(dnode, NULL);

	if (!enabled)
		vty_out(vty, " shutdown\n");
	else if (show_defaults)
		vty_out(vty, " no shutdown\n");
}

DEFPY_YANG (bandwidth_if,
	bandwidth_if_cmd,
	"[no] bandwidth ![(1-1000000)]$bw",
	NO_STR
	"Set bandwidth informational parameter\n"
	"Bandwidth in megabits\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/bandwidth",
				      NB_OP_CREATE, bw_str);
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/bandwidth",
				      NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_bandwidth_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults)
{
	uint32_t bandwidth = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " bandwidth %u\n", bandwidth);
}

DEFUN_YANG_NOSH (link_params,
	link_params_cmd,
	"link-params",
	LINK_PARAMS_STR)
{
	int ret;

	nb_cli_enqueue_change(vty, "./frr-zebra:zebra/link-params",
			      NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS) {
		char *xpath;

		xpath = asprintfrr(MTYPE_TMP, "%s/frr-zebra:zebra/link-params",
				   VTY_CURR_XPATH);
		VTY_PUSH_XPATH(LINK_PARAMS_NODE, xpath);
		XFREE(MTYPE_TMP, xpath);
	}

	return ret;
}

DEFUN_YANG_NOSH (exit_link_params,
	exit_link_params_cmd,
	"exit-link-params",
	"Exit from Link Params configuration mode\n")
{
	cmd_exit(vty);
	return CMD_SUCCESS;
}

static void lib_interface_zebra_link_params_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " link-params\n");
}

static void
lib_interface_zebra_link_params_cli_write_end(struct vty *vty,
					      const struct lyd_node *dnode)
{
	vty_out(vty, " exit-link-params\n");
}

DEFUN_YANG (no_link_params,
	no_link_params_cmd,
	"no link-params",
	NO_STR
	LINK_PARAMS_STR)
{
	nb_cli_enqueue_change(vty, "./frr-zebra:zebra/link-params", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* [no] enable is deprecated, link-params is enabled when entering the node. */

DEFUN_YANG_HIDDEN (link_params_enable,
	link_params_enable_cmd,
	"enable",
	"Activate link parameters on this interface\n")
{
	vty_out(vty, "This command is deprecated. Link parameters are activated when \"link-params\" node is entered.\n");

	return CMD_SUCCESS;
}

DEFUN_YANG_NOSH (no_link_params_enable,
	no_link_params_enable_cmd,
	"no enable",
	NO_STR
	"Disable link parameters on this interface\n")
{
	int ret;

	vty_out(vty, "This command is deprecated. To disable link parameters use \"no link-params\" in the interface node.\n");

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		cmd_exit(vty);

	return ret;
}

DEFPY_YANG (link_params_metric,
	link_params_metric_cmd,
	"[no] metric ![(0-4294967295)]$metric",
	NO_STR
	"Link metric for MPLS-TE purpose\n"
	"Metric value in decimal\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./metric", NB_OP_MODIFY, metric_str);
	else
		nb_cli_enqueue_change(vty, "./metric", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_metric_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t metric = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, "  metric %u\n", metric);
}

DEFPY_YANG (link_params_maxbw,
	link_params_maxbw_cmd,
	"max-bw BANDWIDTH",
	"Maximum bandwidth that can be used\n"
	"Bytes/second (IEEE floating point format)\n")
{
	char value[YANG_VALUE_MAXLEN];
	float bw;

	if (sscanf(bandwidth, "%g", &bw) != 1) {
		vty_out(vty, "Invalid bandwidth value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(value, sizeof(value), "%a", bw);

	nb_cli_enqueue_change(vty, "./max-bandwidth", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_max_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	float max_bandwidth = yang_dnode_get_bandwidth_ieee_float32(dnode, NULL);

	vty_out(vty, "  max-bw %g\n", max_bandwidth);
}

DEFPY_YANG (link_params_max_rsv_bw,
	link_params_max_rsv_bw_cmd,
	"max-rsv-bw BANDWIDTH",
	"Maximum bandwidth that may be reserved\n"
	"Bytes/second (IEEE floating point format)\n")
{
	char value[YANG_VALUE_MAXLEN];
	float bw;

	if (sscanf(bandwidth, "%g", &bw) != 1) {
		vty_out(vty, "Invalid bandwidth value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(value, sizeof(value), "%a", bw);

	nb_cli_enqueue_change(vty, "./max-reservable-bandwidth", NB_OP_MODIFY,
			      value);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_max_reservable_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	float max_reservable_bandwidth =
		yang_dnode_get_bandwidth_ieee_float32(dnode, NULL);

	vty_out(vty, "  max-rsv-bw %g\n", max_reservable_bandwidth);
}

DEFPY_YANG (link_params_unrsv_bw,
	link_params_unrsv_bw_cmd,
	"unrsv-bw (0-7)$priority BANDWIDTH",
	"Unreserved bandwidth at each priority level\n"
	"Priority\n"
	"Bytes/second (IEEE floating point format)\n")
{
	char xpath[XPATH_MAXLEN];
	char value[YANG_VALUE_MAXLEN];
	float bw;

	if (sscanf(bandwidth, "%g", &bw) != 1) {
		vty_out(vty, "Invalid bandwidth value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath),
		 "./unreserved-bandwidths/unreserved-bandwidth[priority='%s']/unreserved-bandwidth",
		 priority_str);
	snprintf(value, sizeof(value), "%a", bw);

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint8_t priority = yang_dnode_get_uint8(dnode, "priority");
	float unreserved_bandwidth =
		yang_dnode_get_bandwidth_ieee_float32(dnode,
						      "unreserved-bandwidth");

	vty_out(vty, "  unrsv-bw %u %g\n", priority, unreserved_bandwidth);
}

DEFPY_YANG (link_params_admin_grp,
	link_params_admin_grp_cmd,
	"[no] admin-grp ![BITPATTERN]",
	NO_STR
	"Administrative group membership\n"
	"32-bit Hexadecimal value (e.g. 0xa1)\n")
{
	uint32_t value;
	char value_str[YANG_VALUE_MAXLEN];

	if (!no) {
		assert(bitpattern);

		if (bitpattern[0] != '0' || bitpattern[1] != 'x' ||
		    strlen(bitpattern) > 10) {
			vty_out(vty, "Invalid bitpattern value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (sscanf(bitpattern, "%x", &value) != 1) {
			vty_out(vty, "Invalid bitpattern value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		snprintf(value_str, sizeof(value_str), "%u", value);

		nb_cli_enqueue_change(vty, "./legacy-admin-group", NB_OP_MODIFY,
				      value_str);
	} else {
		nb_cli_enqueue_change(vty, "./legacy-admin-group",
				      NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_legacy_admin_group_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  admin-grp %#x\n", yang_dnode_get_uint32(dnode, NULL));
}

/* RFC5392 & RFC5316: INTER-AS */
DEFPY_YANG (link_params_inter_as,
	link_params_inter_as_cmd,
	"[no] neighbor ![A.B.C.D$ip as (1-4294967295)$as]",
	NO_STR
	"Configure remote ASBR information (Neighbor IP address and AS number)\n"
	"Remote IP address in dot decimal A.B.C.D\n"
	"Remote AS number\n"
	"AS number in the range <1-4294967295>\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, "./neighbor", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./neighbor/remote-as", NB_OP_MODIFY,
				      as_str);
		nb_cli_enqueue_change(vty, "./neighbor/ipv4-remote-id",
				      NB_OP_MODIFY, ip_str);
	} else {
		nb_cli_enqueue_change(vty, "./neighbor", NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_neighbor_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t remote_as = yang_dnode_get_uint32(dnode, "remote-as");
	const char *ipv4_remote_id = yang_dnode_get_string(dnode,
							   "ipv4-remote-id");

	vty_out(vty, "  neighbor %s as %u\n", ipv4_remote_id, remote_as);
}

/* RFC7471 & RFC8570 */
DEFPY_YANG (link_params_delay,
	link_params_delay_cmd,
	"[no] delay ![(0-16777215)$delay [min (0-16777215)$min max (0-16777215)$max]]",
	NO_STR
	"Unidirectional Average Link Delay\n"
	"Average delay in micro-second as decimal (0...16777215)\n"
	"Minimum delay\n"
	"Minimum delay in micro-second as decimal (0...16777215)\n"
	"Maximum delay\n"
	"Maximum delay in micro-second as decimal (0...16777215)\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, "./delay", NB_OP_MODIFY, delay_str);
		if (min_str && max_str) {
			nb_cli_enqueue_change(vty, "./min-max-delay",
					      NB_OP_CREATE, NULL);
			nb_cli_enqueue_change(vty, "./min-max-delay/delay-min",
					      NB_OP_MODIFY, min_str);
			nb_cli_enqueue_change(vty, "./min-max-delay/delay-max",
					      NB_OP_MODIFY, max_str);
		} else {
			nb_cli_enqueue_change(vty, "./min-max-delay",
					      NB_OP_DESTROY, NULL);
		}
	} else {
		nb_cli_enqueue_change(vty, "./delay", NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, "./min-max-delay", NB_OP_DESTROY,
				      NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_delay_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t delay = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, "  delay %u", delay);

	if (yang_dnode_exists(dnode, "../min-max-delay")) {
		uint32_t delay_min =
			yang_dnode_get_uint32(dnode,
					      "../min-max-delay/delay-min");
		uint32_t delay_max =
			yang_dnode_get_uint32(dnode,
					      "../min-max-delay/delay-max");

		vty_out(vty, " min %u max %u", delay_min, delay_max);
	}

	vty_out(vty, "\n");
}

DEFPY_YANG (link_params_delay_var,
	link_params_delay_var_cmd,
	"[no] delay-variation ![(0-16777215)$delay_var]",
	NO_STR
	"Unidirectional Link Delay Variation\n"
	"delay variation in micro-second as decimal (0...16777215)\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./delay-variation", NB_OP_MODIFY,
				      delay_var_str);
	else
		nb_cli_enqueue_change(vty, "./delay-variation", NB_OP_DESTROY,
				      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_delay_variation_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t delay_variation = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, "  delay-variation %u\n", delay_variation);
}

DEFPY_YANG(
	link_params_pkt_loss, link_params_pkt_loss_cmd,
	"[no] packet-loss ![PERCENTAGE]",
	NO_STR
	"Unidirectional Link Packet Loss\n"
	"percentage of total traffic by 0.000003% step and less than 50.331642%\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./packet-loss", NB_OP_MODIFY,
				      percentage);
	else
		nb_cli_enqueue_change(vty, "./packet-loss", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_packet_loss_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	double packet_loss = yang_dnode_get_dec64(dnode, NULL);

	vty_out(vty, "  packet-loss %lf\n", packet_loss);
}

DEFPY_YANG (link_params_res_bw,
	link_params_res_bw_cmd,
	"[no] res-bw ![BANDWIDTH]",
	NO_STR
	"Unidirectional Residual Bandwidth\n"
	"Bytes/second (IEEE floating point format)\n")
{
	char value[YANG_VALUE_MAXLEN];
	float bw;

	if (!no) {
		assert(bandwidth);

		if (sscanf(bandwidth, "%g", &bw) != 1) {
			vty_out(vty, "Invalid bandwidth value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		snprintf(value, sizeof(value), "%a", bw);

		nb_cli_enqueue_change(vty, "./residual-bandwidth", NB_OP_MODIFY,
				      value);
	} else {
		nb_cli_enqueue_change(vty, "./residual-bandwidth",
				      NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_residual_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	float residual_bandwidth = yang_dnode_get_bandwidth_ieee_float32(dnode,
									 NULL);

	vty_out(vty, "  res-bw %g\n", residual_bandwidth);
}

DEFPY_YANG (link_params_ava_bw,
	link_params_ava_bw_cmd,
	"[no] ava-bw ![BANDWIDTH]",
	NO_STR
	"Unidirectional Available Bandwidth\n"
	"Bytes/second (IEEE floating point format)\n")
{
	char value[YANG_VALUE_MAXLEN];
	float bw;

	if (!no) {
		assert(bandwidth);

		if (sscanf(bandwidth, "%g", &bw) != 1) {
			vty_out(vty, "Invalid bandwidth value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		snprintf(value, sizeof(value), "%a", bw);

		nb_cli_enqueue_change(vty, "./available-bandwidth",
				      NB_OP_MODIFY, value);
	} else {
		nb_cli_enqueue_change(vty, "./available-bandwidth",
				      NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_available_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	float available_bandwidth = yang_dnode_get_bandwidth_ieee_float32(dnode,
									  NULL);

	vty_out(vty, "  ava-bw %g\n", available_bandwidth);
}

DEFPY_YANG (link_params_use_bw,
	link_params_use_bw_cmd,
	"[no] use-bw ![BANDWIDTH]",
	NO_STR
	"Unidirectional Utilised Bandwidth\n"
	"Bytes/second (IEEE floating point format)\n")
{
	char value[YANG_VALUE_MAXLEN];
	float bw;

	if (!no) {
		assert(bandwidth);

		if (sscanf(bandwidth, "%g", &bw) != 1) {
			vty_out(vty, "Invalid bandwidth value\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		snprintf(value, sizeof(value), "%a", bw);

		nb_cli_enqueue_change(vty, "./utilized-bandwidth", NB_OP_MODIFY,
				      value);
	} else {
		nb_cli_enqueue_change(vty, "./utilized-bandwidth",
				      NB_OP_DESTROY, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_utilized_bandwidth_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	float utilized_bandwidth = yang_dnode_get_bandwidth_ieee_float32(dnode,
									 NULL);

	vty_out(vty, "  use-bw %g\n", utilized_bandwidth);
}

DEFPY_YANG (link_params_affinity,
	link_params_affinity_cmd,
	"[no] affinity NAME...",
	NO_STR
	"Interface affinities\n"
	"Affinity names\n")
{
	char xpath[XPATH_MAXLEN];
	int i;

	for (i = no ? 2 : 1; i < argc; i++) {
		snprintf(xpath, XPATH_MAXLEN, "./affinities/affinity[.='%s']",
			 argv[i]->arg);
		nb_cli_enqueue_change(vty, xpath,
				      no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static int ag_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct vty *vty = arg;

	vty_out(vty, " %s", yang_dnode_get_string(dnode, NULL));
	return YANG_ITER_CONTINUE;
}

static void lib_interface_zebra_link_params_affinities_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  affinity");
	yang_dnode_iterate(ag_iter_cb, vty, dnode, "affinity");
	vty_out(vty, "\n");
}

DEFPY_YANG (link_params_affinity_mode,
	link_params_affinity_mode_cmd,
	"[no] affinity-mode ![<standard|extended|both>$mode]",
	NO_STR
	"Interface affinity mode\n"
	"Standard Admin-Group only RFC3630,5305,5329\n"
	"Extended Admin-Group only RFC7308 (default)\n"
	"Standard and extended Admin-Group format\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./affinity-mode", NB_OP_MODIFY,
				      mode);
	else
		nb_cli_enqueue_change(vty, "./affinity-mode", NB_OP_DESTROY,
				      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_link_params_affinity_mode_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	enum affinity_mode affinity_mode = yang_dnode_get_enum(dnode, NULL);

	if (affinity_mode == AFFINITY_MODE_STANDARD)
		vty_out(vty, "  affinity-mode standard\n");
	else if (affinity_mode == AFFINITY_MODE_BOTH)
		vty_out(vty, "  affinity-mode both\n");
	else if (affinity_mode == AFFINITY_MODE_EXTENDED && show_defaults)
		vty_out(vty, "  affinity-mode extended\n");
}

#ifdef HAVE_NETLINK
DEFPY_YANG (ip_address,
	ip_address_cmd,
	"[no] ip address A.B.C.D/M [label LINE$label]",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Set the IP address of an interface\n"
	"IP address (e.g. 10.0.0.1/8)\n"
	"Label of this address\n"
	"Label\n")
#else
DEFPY_YANG (ip_address,
	ip_address_cmd,
	"[no] ip address A.B.C.D/M",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Set the IP address of an interface\n"
	"IP address (e.g. 10.0.0.1/8)\n")
#endif
{
	char ip[INET_ADDRSTRLEN + 3];
	char *mask;

	if (no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
#ifdef HAVE_NETLINK
		if (label)
			nb_cli_enqueue_change(vty, "./label", NB_OP_MODIFY,
					      label);
		else
			nb_cli_enqueue_change(vty, "./label", NB_OP_DESTROY,
					      NULL);
#endif
	}

	strlcpy(ip, address_str, sizeof(ip));

	mask = strchr(ip, '/');
	assert(mask);
	*mask = 0;
	mask++;

	return nb_cli_apply_changes(vty,
				    "./frr-zebra:zebra/ipv4-addrs[ip='%s'][prefix-length='%s']",
				    ip, mask);
}

static void lib_interface_zebra_ipv4_addrs_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *ip = yang_dnode_get_string(dnode, "ip");
	uint8_t prefix_length = yang_dnode_get_uint8(dnode, "prefix-length");

	vty_out(vty, " ip address %s/%u", ip, prefix_length);

	if (yang_dnode_exists(dnode, "label")) {
		const char *label = yang_dnode_get_string(dnode, "label");

		vty_out(vty, " label %s", label);
	}

	vty_out(vty, "\n");
}

#ifdef HAVE_NETLINK
DEFPY_YANG (ip_address_peer,
	ip_address_peer_cmd,
	"[no] ip address A.B.C.D peer A.B.C.D/M [label LINE$label]",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Set the IP address of an interface\n"
	"Local IP (e.g. 10.0.0.1) for P-t-P address\n"
	"Specify P-t-P address\n"
	"Peer IP address (e.g. 10.0.0.1/8)\n"
	"Label of this address\n"
	"Label\n")
#else
DEFPY_YANG (ip_address_peer,
	ip_address_peer_cmd,
	"[no] ip address A.B.C.D peer A.B.C.D/M",
	NO_STR
	"Interface Internet Protocol config commands\n"
	"Set the IP address of an interface\n"
	"Local IP (e.g. 10.0.0.1) for P-t-P address\n"
	"Specify P-t-P address\n"
	"Peer IP address (e.g. 10.0.0.1/8)\n")
#endif
{
	char peer_ip[INET_ADDRSTRLEN + 3];
	char *peer_mask;

	if (no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
#ifdef HAVE_NETLINK
		if (label)
			nb_cli_enqueue_change(vty, "./label", NB_OP_MODIFY,
					      label);
		else
			nb_cli_enqueue_change(vty, "./label", NB_OP_DESTROY,
					      NULL);
#endif
	}

	strlcpy(peer_ip, peer_str, sizeof(peer_ip));

	peer_mask = strchr(peer_ip, '/');
	assert(peer_mask);
	*peer_mask = 0;
	peer_mask++;

	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/ipv4-p2p-addrs[ip='%s'][peer-ip='%s'][peer-prefix-length='%s']",
		address_str, peer_ip, peer_mask);
}

static void lib_interface_zebra_ipv4_p2p_addrs_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *ip = yang_dnode_get_string(dnode, "ip");
	const char *peer_ip = yang_dnode_get_string(dnode, "peer-ip");
	uint8_t peer_prefix_length = yang_dnode_get_uint8(dnode,
							  "peer-prefix-length");

	vty_out(vty, " ip address %s peer %s/%u", ip, peer_ip,
		peer_prefix_length);

	if (yang_dnode_exists(dnode, "label")) {
		const char *label = yang_dnode_get_string(dnode, "label");

		vty_out(vty, " label %s", label);
	}

	vty_out(vty, "\n");
}

DEFPY_YANG (ipv6_address,
	ipv6_address_cmd,
	"[no] ipv6 address X:X::X:X/M",
	NO_STR
	"Interface IPv6 config commands\n"
	"Set the IP address of an interface\n"
	"IPv6 address (e.g. 3ffe:506::1/48)\n")
{
	char ip[INET6_ADDRSTRLEN + 4];
	char *mask;

	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);

	strlcpy(ip, address_str, sizeof(ip));

	mask = strchr(ip, '/');
	assert(mask);
	*mask = 0;
	mask++;

	return nb_cli_apply_changes(vty,
				    "./frr-zebra:zebra/ipv6-addrs[ip='%s'][prefix-length='%s']",
				    ip, mask);
}

static void lib_interface_zebra_ipv6_addrs_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *ip = yang_dnode_get_string(dnode, "ip");
	uint8_t prefix_length = yang_dnode_get_uint8(dnode, "prefix-length");

	vty_out(vty, " ipv6 address %s/%u\n", ip, prefix_length);
}

/* CLI for setting an ES in bypass mode */
DEFPY_YANG_HIDDEN (zebra_evpn_es_bypass,
	zebra_evpn_es_bypass_cmd,
	"[no] evpn mh bypass",
	NO_STR
	"EVPN\n"
	EVPN_MH_VTY_STR
	"Set bypass mode\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/evpn-mh/bypass",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/evpn-mh/bypass",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_evpn_mh_bypass_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool bypass = yang_dnode_get_bool(dnode, NULL);

	if (bypass)
		vty_out(vty, " evpn mh bypass\n");
	else if (show_defaults)
		vty_out(vty, " no evpn mh bypass\n");
}

/* CLI for configuring DF preference part for an ES */
DEFPY_YANG (zebra_evpn_es_pref,
	zebra_evpn_es_pref_cmd,
	"[no$no] evpn mh es-df-pref ![(1-65535)$df_pref]",
	NO_STR
	"EVPN\n"
	EVPN_MH_VTY_STR
	"Preference value used for DF election\n"
	"Preference\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/evpn-mh/df-preference",
				      NB_OP_MODIFY, df_pref_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/evpn-mh/df-preference",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_evpn_mh_df_preference_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint16_t df_pref = yang_dnode_get_uint16(dnode, NULL);

	vty_out(vty, " evpn mh es-df-pref %u\n", df_pref);
}

/* CLI for setting up sysmac part of ESI on an access port */
DEFPY_YANG (zebra_evpn_es_sys_mac,
	zebra_evpn_es_sys_mac_cmd,
	"[no$no] evpn mh es-sys-mac ![X:X:X:X:X:X$mac]",
	NO_STR
	"EVPN\n"
	EVPN_MH_VTY_STR
	"Ethernet segment system MAC\n"
	MAC_STR)
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/evpn-mh/type-3/system-mac",
				      NB_OP_MODIFY, mac_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/evpn-mh/type-3/system-mac",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_evpn_mh_type_3_system_mac_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	char buf[ETHER_ADDR_STRLEN];
	struct ethaddr mac;

	yang_dnode_get_mac(&mac, dnode, NULL);

	vty_out(vty, " evpn mh es-sys-mac %s\n",
		prefix_mac2str(&mac, buf, sizeof(buf)));
}

/* CLI for setting up local-ID part of ESI on an access port */
DEFPY_YANG (zebra_evpn_es_id,
	zebra_evpn_es_id_cmd,
	"[no$no] evpn mh es-id ![(1-16777215)$es_lid | NAME$esi_str]",
	NO_STR
	"EVPN\n"
	EVPN_MH_VTY_STR
	"Ethernet segment identifier\n"
	"local discriminator\n"
	"10-byte ID - 00:AA:BB:CC:DD:EE:FF:GG:HH:II\n")
{
	if (no) {
		/* We don't know which one is configured, so detroy both types. */
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/evpn-mh/type-0/esi",
				      NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/evpn-mh/type-3/local-discriminator",
				      NB_OP_DESTROY, NULL);
	} else {
		if (esi_str)
			nb_cli_enqueue_change(vty,
					      "./frr-zebra:zebra/evpn-mh/type-0/esi",
					      NB_OP_MODIFY, esi_str);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-zebra:zebra/evpn-mh/type-3/local-discriminator",
					      NB_OP_MODIFY, es_lid_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_evpn_mh_type_0_esi_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *esi_str = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " evpn mh es-id %s\n", esi_str);
}

static void lib_interface_zebra_evpn_mh_type_3_local_discriminator_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t es_lid = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " evpn mh es-id %u\n", es_lid);
}

/* CLI for tagging an interface as an uplink */
DEFPY_YANG (zebra_evpn_mh_uplink,
	zebra_evpn_mh_uplink_cmd,
	"[no] evpn mh uplink",
	NO_STR
	"EVPN\n"
	EVPN_MH_VTY_STR
	"Uplink to the VxLAN core\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/evpn-mh/uplink",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/evpn-mh/uplink",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_evpn_mh_uplink_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool uplink = yang_dnode_get_bool(dnode, NULL);

	if (uplink)
		vty_out(vty, " evpn mh uplink\n");
	else if (show_defaults)
		vty_out(vty, " no evpn mh uplink\n");
}

#if defined(HAVE_RTADV)
DEFPY_YANG (ipv6_nd_ra_fast_retrans,
	ipv6_nd_ra_fast_retrans_cmd,
	"[no] ipv6 nd ra-fast-retrans",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Fast retransmit of RA packets\n")
{
	if (no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/fast-retransmit",
				      NB_OP_MODIFY, "false");
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/fast-retransmit",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_fast_retransmit_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool fast_retransmit = yang_dnode_get_bool(dnode, NULL);

	if (!fast_retransmit)
		vty_out(vty, " no ipv6 nd ra-fast-retrans\n");
	else if (show_defaults)
		vty_out(vty, " ipv6 nd ra-fast-retrans\n");
}

DEFPY_YANG (ipv6_nd_ra_hop_limit,
	ipv6_nd_ra_hop_limit_cmd,
	"[no] ipv6 nd ra-hop-limit ![(0-255)$hopcount]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Advertisement Hop Limit\n"
	"Advertisement Hop Limit in hops (default:64)\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/cur-hop-limit",
				      NB_OP_MODIFY, hopcount_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/cur-hop-limit",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint8_t hop_limit = yang_dnode_get_uint8(dnode, NULL);

	vty_out(vty, " ipv6 nd ra-hop-limit %u\n", hop_limit);
}

DEFPY_YANG (ipv6_nd_ra_retrans_interval,
	ipv6_nd_ra_retrans_interval_cmd,
	"[no] ipv6 nd ra-retrans-interval ![(0-4294967295)$interval]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Advertisement Retransmit Interval\n"
	"Advertisement Retransmit Interval in msec\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/retrans-timer",
				      NB_OP_MODIFY, interval_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/retrans-timer",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_retrans_timer_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t retrans_timer = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " ipv6 nd ra-retrans-interval %u\n", retrans_timer);
}

DEFPY_YANG (ipv6_nd_suppress_ra,
	ipv6_nd_suppress_ra_cmd,
	"[no] ipv6 nd suppress-ra",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Suppress Router Advertisement\n")
{
	if (no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/send-advertisements",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/send-advertisements",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_send_advertisements_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool send_advertisements = yang_dnode_get_bool(dnode, NULL);

	if (send_advertisements)
		vty_out(vty, " no ipv6 nd suppress-ra\n");
	else if (show_defaults)
		vty_out(vty, " ipv6 nd suppress-ra\n");
}

DEFPY_YANG (ipv6_nd_ra_interval,
	ipv6_nd_ra_interval_cmd,
	"[no] ipv6 nd ra-interval ![<(1-1800)$sec|msec (70-1800000)$msec>]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Router Advertisement interval\n"
	"Router Advertisement interval in seconds\n"
	"Router Advertisement interval in milliseconds\n"
	"Router Advertisement interval in milliseconds\n")
{
	char value[YANG_VALUE_MAXLEN];

	if (!no) {
		if (sec)
			snprintf(value, sizeof(value), "%lu", sec * 1000);
		else
			snprintf(value, sizeof(value), "%lu", msec);

		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/max-rtr-adv-interval",
				      NB_OP_MODIFY, value);
	} else {
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/max-rtr-adv-interval",
				      NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_max_rtr_adv_interval_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t max_rtr_adv_interval = yang_dnode_get_uint32(dnode, NULL);

	if (max_rtr_adv_interval % 1000)
		vty_out(vty, " ipv6 nd ra-interval msec %u\n",
			max_rtr_adv_interval);
	else
		vty_out(vty, " ipv6 nd ra-interval %u\n",
			max_rtr_adv_interval / 1000);
}

DEFPY_YANG (ipv6_nd_ra_lifetime,
	ipv6_nd_ra_lifetime_cmd,
	"[no] ipv6 nd ra-lifetime ![(0-9000)$lifetime]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Router lifetime\n"
	"Router lifetime in seconds (0 stands for a non-default gw)\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/default-lifetime",
				      NB_OP_MODIFY, lifetime_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/default-lifetime",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_default_lifetime_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint16_t default_lifetime = yang_dnode_get_uint16(dnode, NULL);

	vty_out(vty, " ipv6 nd ra-lifetime %u\n", default_lifetime);
}

DEFPY_YANG (ipv6_nd_reachable_time,
	ipv6_nd_reachable_time_cmd,
	"[no] ipv6 nd reachable-time ![(1-3600000)$msec]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Reachable time\n"
	"Reachable time in milliseconds\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/reachable-time",
				      NB_OP_MODIFY, msec_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/reachable-time",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_reachable_time_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t reachable_time = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " ipv6 nd reachable-time %u\n", reachable_time);
}

DEFPY_YANG (ipv6_nd_homeagent_preference,
	ipv6_nd_homeagent_preference_cmd,
	"[no] ipv6 nd home-agent-preference ![(0-65535)$pref]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Home Agent preference\n"
	"preference value (default is 0, least preferred)\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/home-agent-preference",
				      NB_OP_MODIFY, pref_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/home-agent-preference",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint16_t home_agent_preference = yang_dnode_get_uint16(dnode, NULL);

	vty_out(vty, " ipv6 nd home-agent-preference %u\n",
		home_agent_preference);
}

DEFPY_YANG (ipv6_nd_homeagent_lifetime,
	ipv6_nd_homeagent_lifetime_cmd,
	"[no] ipv6 nd home-agent-lifetime ![(1-65520)$lifetime]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Home Agent lifetime\n"
	"Home Agent lifetime in seconds\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/home-agent-lifetime",
				      NB_OP_MODIFY, lifetime_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/home-agent-lifetime",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint16_t home_agent_lifetime = yang_dnode_get_uint16(dnode, NULL);

	vty_out(vty, " ipv6 nd home-agent-lifetime %u\n", home_agent_lifetime);
}

DEFPY_YANG (ipv6_nd_managed_config_flag,
	ipv6_nd_managed_config_flag_cmd,
	"[no] ipv6 nd managed-config-flag",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Managed address configuration flag\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/managed-flag",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/managed-flag",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_ipv6_router_advertisements_managed_flag_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool managed_flag = yang_dnode_get_bool(dnode, NULL);

	if (managed_flag)
		vty_out(vty, " ipv6 nd managed-config-flag\n");
	else if (show_defaults)
		vty_out(vty, " no ipv6 nd managed-config-flag\n");
}

DEFPY_YANG (ipv6_nd_homeagent_config_flag,
	ipv6_nd_homeagent_config_flag_cmd,
	"[no] ipv6 nd home-agent-config-flag",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Home Agent configuration flag\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/home-agent-flag",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/home-agent-flag",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_home_agent_flag_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool home_agent_flag = yang_dnode_get_bool(dnode, NULL);

	if (home_agent_flag)
		vty_out(vty, " ipv6 nd home-agent-config-flag\n");
	else if (show_defaults)
		vty_out(vty, " no ipv6 nd home-agent-config-flag\n");
}

DEFPY_YANG (ipv6_nd_adv_interval_config_option,
	ipv6_nd_adv_interval_config_option_cmd,
	"[no] ipv6 nd adv-interval-option",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Advertisement Interval Option\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/advertisement-interval-option",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/advertisement-interval-option",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_advertisement_interval_option_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool advertisement_interval_option = yang_dnode_get_bool(dnode, NULL);

	if (advertisement_interval_option)
		vty_out(vty, " ipv6 nd adv-interval-option\n");
	else if (show_defaults)
		vty_out(vty, " no ipv6 nd adv-interval-option\n");
}

DEFPY_YANG (ipv6_nd_other_config_flag,
	ipv6_nd_other_config_flag_cmd,
	"[no] ipv6 nd other-config-flag",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Other statefull configuration flag\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/other-config-flag",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/other-config-flag",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_other_config_flag_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool other_config_flag = yang_dnode_get_bool(dnode, NULL);

	if (other_config_flag)
		vty_out(vty, " ipv6 nd other-config-flag\n");
	else if (show_defaults)
		vty_out(vty, " no ipv6 nd other-config-flag\n");
}

DEFPY_YANG (ipv6_nd_prefix,
	ipv6_nd_prefix_cmd,
	"[no] ipv6 nd prefix X:X::X:X/M$prefix [<(0-4294967295)|infinite>$valid <(0-4294967295)|infinite>$preferred] [{router-address$routeraddr|off-link$offlink|no-autoconfig$noautoconf}]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Prefix information\n"
	"IPv6 prefix\n"
	"Valid lifetime in seconds\n"
	"Infinite valid lifetime\n"
	"Preferred lifetime in seconds\n"
	"Infinite preferred lifetime\n"
	"Set Router Address flag\n"
	"Do not use prefix for onlink determination\n"
	"Do not use prefix for autoconfiguration\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		if (valid) {
			if (strmatch(valid, "infinite"))
				valid = "4294967295";
			nb_cli_enqueue_change(vty, "./valid-lifetime",
					      NB_OP_MODIFY, valid);
		} else {
			nb_cli_enqueue_change(vty, "./valid-lifetime",
					      NB_OP_DESTROY, NULL);
		}
		if (preferred) {
			if (strmatch(preferred, "infinite"))
				preferred = "4294967295";
			nb_cli_enqueue_change(vty, "./preferred-lifetime",
					      NB_OP_MODIFY, preferred);
		} else {
			nb_cli_enqueue_change(vty, "./preferred-lifetime",
					      NB_OP_DESTROY, NULL);
		}
		if (routeraddr)
			nb_cli_enqueue_change(vty, "./router-address-flag",
					      NB_OP_MODIFY, "true");
		else
			nb_cli_enqueue_change(vty, "./router-address-flag",
					      NB_OP_DESTROY, NULL);
		if (offlink)
			nb_cli_enqueue_change(vty, "./on-link-flag",
					      NB_OP_MODIFY, "false");
		else
			nb_cli_enqueue_change(vty, "./on-link-flag",
					      NB_OP_DESTROY, NULL);
		if (noautoconf)
			nb_cli_enqueue_change(vty, "./autonomous-flag",
					      NB_OP_MODIFY, "false");
		else
			nb_cli_enqueue_change(vty, "./autonomous-flag",
					      NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix[prefix-spec='%s']",
		prefix_str);
}

static void
lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *prefix = yang_dnode_get_string(dnode, "prefix-spec");
	struct lyd_node *valid = yang_dnode_get(dnode, "valid-lifetime");
	struct lyd_node *preferred = yang_dnode_get(dnode, "preferred-lifetime");
	bool router_address_flag = yang_dnode_get_bool(dnode,
						       "router-address-flag");
	bool on_link_flag = yang_dnode_get_bool(dnode, "on-link-flag");
	bool autonomous_flag = yang_dnode_get_bool(dnode, "autonomous-flag");

	vty_out(vty, " ipv6 nd prefix %s", prefix);

	if (!yang_dnode_is_default(valid, NULL) ||
	    !yang_dnode_is_default(preferred, NULL) || show_defaults) {
		uint32_t valid_lifetime = yang_dnode_get_uint32(valid, NULL);
		uint32_t preferred_lifetime = yang_dnode_get_uint32(preferred,
								    NULL);

		if (valid_lifetime == UINT32_MAX)
			vty_out(vty, " infinite");
		else
			vty_out(vty, " %u", valid_lifetime);
		if (preferred_lifetime == UINT32_MAX)
			vty_out(vty, " infinite");
		else
			vty_out(vty, " %u", preferred_lifetime);
	}

	if (!on_link_flag)
		vty_out(vty, " off-link");

	if (!autonomous_flag)
		vty_out(vty, " no-autoconfig");

	if (router_address_flag)
		vty_out(vty, " router-address");

	vty_out(vty, "\n");
}

DEFPY_YANG (ipv6_nd_router_preference,
	ipv6_nd_router_preference_cmd,
	"[no] ipv6 nd router-preference ![<high|medium|low>$pref]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Default router preference\n"
	"High default router preference\n"
	"Medium default router preference (default)\n"
	"Low default router preference\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/default-router-preference",
				      NB_OP_MODIFY, pref);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/default-router-preference",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void
lib_interface_zebra_ipv6_router_advertisements_default_router_preference_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *default_router_preference = yang_dnode_get_string(dnode,
								      NULL);

	vty_out(vty, " ipv6 nd router-preference %s\n",
		default_router_preference);
}

DEFPY_YANG (ipv6_nd_mtu,
	ipv6_nd_mtu_cmd,
	"[no] ipv6 nd mtu ![(1-65535)]",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Advertised MTU\n"
	"MTU in bytes\n")
{
	if (!no)
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/link-mtu",
				      NB_OP_MODIFY, mtu_str);
	else
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/ipv6-router-advertisements/link-mtu",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_ipv6_router_advertisements_link_mtu_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint16_t link_mtu = yang_dnode_get_uint32(dnode, NULL);

	vty_out(vty, " ipv6 nd mtu %u\n", link_mtu);
}

DEFPY_YANG (ipv6_nd_rdnss,
	ipv6_nd_rdnss_cmd,
	"[no] ipv6 nd rdnss X:X::X:X$addr [<(0-4294967295)|infinite>]$lifetime",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"Recursive DNS server information\n"
	"IPv6 address\n"
	"Valid lifetime in seconds\n"
	"Infinite valid lifetime\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		if (lifetime) {
			if (strmatch(lifetime, "infinite"))
				lifetime = "4294967295";
			nb_cli_enqueue_change(vty, "./lifetime", NB_OP_MODIFY,
					      lifetime);
		} else {
			nb_cli_enqueue_change(vty, "./lifetime", NB_OP_DESTROY,
					      NULL);
		}
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/ipv6-router-advertisements/rdnss/rdnss-address[address='%s']",
		addr_str);
}

static void
lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *address = yang_dnode_get_string(dnode, "address");

	vty_out(vty, " ipv6 nd rdnss %s", address);

	if (yang_dnode_exists(dnode, "lifetime")) {
		uint32_t lifetime = yang_dnode_get_uint32(dnode, "lifetime");

		if (lifetime == UINT32_MAX)
			vty_out(vty, " infinite");
		else
			vty_out(vty, " %u", lifetime);
	}

	vty_out(vty, "\n");
}

DEFPY_YANG (ipv6_nd_dnssl,
	ipv6_nd_dnssl_cmd,
	"[no] ipv6 nd dnssl SUFFIX [<(0-4294967295)|infinite>]$lifetime",
	NO_STR
	"Interface IPv6 config commands\n"
	"Neighbor discovery\n"
	"DNS search list information\n"
	"Domain name suffix\n"
	"Valid lifetime in seconds\n"
	"Infinite valid lifetime\n")
{
	char domain[254];
	size_t len;

	len = strlcpy(domain, suffix, sizeof(domain));
	if (len == 0 || len >= sizeof(domain)) {
		vty_out(vty, "Malformed DNS search domain\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (domain[len - 1] == '.') {
		/*
		 * Allow, but don't require, a trailing dot signifying the root
		 * zone. Canonicalize by cutting it off if present.
		 */
		domain[len - 1] = '\0';
		len--;
	}

	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		if (lifetime) {
			if (strmatch(lifetime, "infinite"))
				lifetime = "4294967295";
			nb_cli_enqueue_change(vty, "./lifetime", NB_OP_MODIFY,
					      lifetime);
		} else {
			nb_cli_enqueue_change(vty, "./lifetime", NB_OP_DESTROY,
					      NULL);
		}
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/ipv6-router-advertisements/dnssl/dnssl-domain[domain='%s']",
		domain);
}

static void
lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *domain = yang_dnode_get_string(dnode, "domain");

	vty_out(vty, " ipv6 nd dnssl %s", domain);

	if (yang_dnode_exists(dnode, "lifetime")) {
		uint32_t lifetime = yang_dnode_get_uint32(dnode, "lifetime");

		if (lifetime == UINT32_MAX)
			vty_out(vty, " infinite");
		else
			vty_out(vty, " %u", lifetime);
	}

	vty_out(vty, "\n");
}
#endif /* HAVE_RTADV */

#if HAVE_BFDD == 0
DEFPY_YANG (zebra_ptm_enable_if,
	zebra_ptm_enable_if_cmd,
	"[no] ptm-enable",
	NO_STR
	"Enable neighbor check with specified topology\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/ptm-enable",
				      NB_OP_MODIFY, "false");
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/ptm-enable",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void lib_interface_zebra_ptm_enable_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (!enable)
		vty_out(vty, " no ptm-enable\n");
	else if (show_defaults)
		vty_out(vty, " ptm-enable\n");
}
#endif /* HAVE_BFDD == 0 */

/*
 * VRF commands
 */

static void zebra_vrf_indent_cli_write(struct vty *vty,
				       const struct lyd_node *dnode)
{
	const struct lyd_node *vrf = yang_dnode_get_parent(dnode, "vrf");

	if (vrf && strcmp(yang_dnode_get_string(vrf, "name"), VRF_DEFAULT_NAME))
		vty_out(vty, " ");
}

DEFPY_YANG (ip_router_id,
       ip_router_id_cmd,
       "[no] ip router-id A.B.C.D$id vrf NAME",
       NO_STR
       IP_STR
       "Manually set the router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/router-id", NB_OP_MODIFY,
			      id_str);
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/router-id", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']", vrf);
}

ALIAS_YANG (ip_router_id,
       router_id_cmd,
       "[no] router-id A.B.C.D$id vrf NAME",
       NO_STR
       "Manually set the router-id\n"
       "IP address to use for router-id\n"
       VRF_CMD_HELP_STR);

DEFPY_YANG (ipv6_router_id,
       ipv6_router_id_cmd,
       "[no] ipv6 router-id X:X::X:X$id vrf NAME",
       NO_STR
       IPV6_STR
       "Manually set the router-id\n"
       "IPv6 address to use for router-id\n"
       VRF_CMD_HELP_STR)
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/ipv6-router-id",
			      NB_OP_MODIFY, id_str);
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/ipv6-router-id",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']", vrf);
}

DEFPY_YANG (ip_router_id_in_vrf,
       ip_router_id_in_vrf_cmd,
       "[no] ip router-id ![A.B.C.D$id]",
       NO_STR
       IP_STR
       "Manually set the router-id\n"
       "IP address to use for router-id\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/router-id", NB_OP_MODIFY,
			      id_str);
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/router-id", NB_OP_DESTROY,
			      NULL);

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']",
					    VRF_DEFAULT_NAME);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (ip_router_id_in_vrf,
       router_id_in_vrf_cmd,
       "[no] router-id ![A.B.C.D$id]",
       NO_STR
       "Manually set the router-id\n"
       "IP address to use for router-id\n");

DEFPY_YANG (ipv6_router_id_in_vrf,
       ipv6_router_id_in_vrf_cmd,
       "[no] ipv6 router-id ![X:X::X:X$id]",
       NO_STR
       IP6_STR
       "Manually set the IPv6 router-id\n"
       "IPV6 address to use for router-id\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/ipv6-router-id",
			      NB_OP_MODIFY, id_str);
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/ipv6-router-id",
			NB_OP_DESTROY, NULL);

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']",
					    VRF_DEFAULT_NAME);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_vrf_zebra_router_id_cli_write(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults)
{
	const char *id = yang_dnode_get_string(dnode, NULL);

	zebra_vrf_indent_cli_write(vty, dnode);

	vty_out(vty, "ip router-id %s\n", id);
}

static void lib_vrf_zebra_ipv6_router_id_cli_write(struct vty *vty,
						   const struct lyd_node *dnode,
						   bool show_defaults)
{
	const char *id = yang_dnode_get_string(dnode, NULL);

	zebra_vrf_indent_cli_write(vty, dnode);

	vty_out(vty, "ipv6 router-id %s\n", id);
}

DEFPY_YANG (ip_protocol,
       ip_protocol_cmd,
       "[no] ip protocol " FRR_IP_PROTOCOL_MAP_STR_ZEBRA
       " $proto ![route-map ROUTE-MAP$rmap]",
       NO_STR
       IP_STR
       "Filter routing info exchanged between zebra and protocol\n"
       FRR_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route-map\n"
       "Route map name\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map", NB_OP_MODIFY, rmap);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(
			vty,
			"/frr-vrf:lib/vrf[name='%s']/frr-zebra:zebra/filter-protocol[afi-safi='%s'][protocol='%s']",
			VRF_DEFAULT_NAME,
			yang_afi_safi_value2identity(AFI_IP, SAFI_UNICAST),
			proto);

	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/filter-protocol[afi-safi='%s'][protocol='%s']",
		yang_afi_safi_value2identity(AFI_IP, SAFI_UNICAST), proto);
}

DEFPY_YANG (ipv6_protocol,
       ipv6_protocol_cmd,
       "[no] ipv6 protocol " FRR_IP6_PROTOCOL_MAP_STR_ZEBRA
       " $proto ![route-map ROUTE-MAP$rmap]",
       NO_STR
       IP6_STR
       "Filter IPv6 routing info exchanged between zebra and protocol\n"
       FRR_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route-map\n"
       "Route map name\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map", NB_OP_MODIFY, rmap);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(
			vty,
			"/frr-vrf:lib/vrf[name='%s']/frr-zebra:zebra/filter-protocol[afi-safi='%s'][protocol='%s']",
			VRF_DEFAULT_NAME,
			yang_afi_safi_value2identity(AFI_IP6, SAFI_UNICAST),
			proto);

	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/filter-protocol[afi-safi='%s'][protocol='%s']",
		yang_afi_safi_value2identity(AFI_IP6, SAFI_UNICAST), proto);
}

static void lib_vrf_zebra_filter_protocol_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults)
{
	const char *afi_safi = yang_dnode_get_string(dnode, "afi-safi");
	const char *proto = yang_dnode_get_string(dnode, "protocol");
	const char *rmap = yang_dnode_get_string(dnode, "route-map");
	afi_t afi;
	safi_t safi;

	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (safi != SAFI_UNICAST)
		return;

	zebra_vrf_indent_cli_write(vty, dnode);

	if (afi == AFI_IP)
		vty_out(vty, "ip protocol %s route-map %s\n", proto, rmap);
	else
		vty_out(vty, "ipv6 protocol %s route-map %s\n", proto, rmap);
}

DEFPY_YANG (ip_protocol_nht_rmap,
       ip_protocol_nht_rmap_cmd,
       "[no] ip nht " FRR_IP_PROTOCOL_MAP_STR_ZEBRA
       " $proto ![route-map ROUTE-MAP$rmap]",
       NO_STR
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       FRR_IP_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map", NB_OP_MODIFY, rmap);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(
			vty,
			"/frr-vrf:lib/vrf[name='%s']/frr-zebra:zebra/filter-nht[afi-safi='%s'][protocol='%s']",
			VRF_DEFAULT_NAME,
			yang_afi_safi_value2identity(AFI_IP, SAFI_UNICAST),
			proto);

	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/filter-nht[afi-safi='%s'][protocol='%s']",
		yang_afi_safi_value2identity(AFI_IP, SAFI_UNICAST), proto);
}

DEFPY_YANG (ipv6_protocol_nht_rmap,
       ipv6_protocol_nht_rmap_cmd,
       "[no] ipv6 nht " FRR_IP6_PROTOCOL_MAP_STR_ZEBRA
       " $proto ![route-map ROUTE-MAP$rmap]",
       NO_STR
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       FRR_IP6_PROTOCOL_MAP_HELP_STR_ZEBRA
       "Specify route map\n"
       "Route map name\n")
{
	if (!no) {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map", NB_OP_MODIFY, rmap);
	} else {
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	}

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(
			vty,
			"/frr-vrf:lib/vrf[name='%s']/frr-zebra:zebra/filter-nht[afi-safi='%s'][protocol='%s']",
			VRF_DEFAULT_NAME,
			yang_afi_safi_value2identity(AFI_IP6, SAFI_UNICAST),
			proto);

	return nb_cli_apply_changes(
		vty,
		"./frr-zebra:zebra/filter-nht[afi-safi='%s'][protocol='%s']",
		yang_afi_safi_value2identity(AFI_IP6, SAFI_UNICAST), proto);
}

static void lib_vrf_zebra_filter_nht_cli_write(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults)
{
	const char *afi_safi = yang_dnode_get_string(dnode, "afi-safi");
	const char *proto = yang_dnode_get_string(dnode, "protocol");
	const char *rmap = yang_dnode_get_string(dnode, "route-map");
	afi_t afi;
	safi_t safi;

	yang_afi_safi_identity2value(afi_safi, &afi, &safi);

	if (safi != SAFI_UNICAST)
		return;

	zebra_vrf_indent_cli_write(vty, dnode);

	if (afi == AFI_IP)
		vty_out(vty, "ip nht %s route-map %s\n", proto, rmap);
	else
		vty_out(vty, "ipv6 nht %s route-map %s\n", proto, rmap);
}

DEFPY_YANG (ip_nht_default_route,
       ip_nht_default_route_cmd,
       "[no] ip nht resolve-via-default",
       NO_STR
       IP_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{
	nb_cli_enqueue_change(vty, "./frr-zebra:zebra/resolve-via-default",
			      NB_OP_MODIFY, no ? "false" : "true");

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']",
					    VRF_DEFAULT_NAME);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_vrf_zebra_resolve_via_default_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool resolve_via_default = yang_dnode_get_bool(dnode, NULL);

	if (resolve_via_default != SAVE_ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT ||
	    show_defaults) {
		zebra_vrf_indent_cli_write(vty, dnode);

		vty_out(vty, "%sip nht resolve-via-default\n",
			resolve_via_default ? "" : "no ");
	}
}

DEFPY_YANG (ipv6_nht_default_route,
       ipv6_nht_default_route_cmd,
       "[no] ipv6 nht resolve-via-default",
       NO_STR
       IP6_STR
       "Filter Next Hop tracking route resolution\n"
       "Resolve via default route\n")
{
	nb_cli_enqueue_change(vty, "./frr-zebra:zebra/ipv6-resolve-via-default",
			      NB_OP_MODIFY, no ? "false" : "true");

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']",
					    VRF_DEFAULT_NAME);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_vrf_zebra_ipv6_resolve_via_default_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool resolve_via_default = yang_dnode_get_bool(dnode, NULL);

	if (resolve_via_default != SAVE_ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT ||
	    show_defaults) {
		zebra_vrf_indent_cli_write(vty, dnode);

		vty_out(vty, "%sipv6 nht resolve-via-default\n",
			resolve_via_default ? "" : "no ");
	}
}

DEFPY_YANG (vrf_netns,
       vrf_netns_cmd,
       "[no] netns ![NAME$netns_name]",
       NO_STR
       "Attach VRF to a Namespace\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	vty_out(vty, "%% This command doesn't do anything.\n");
	vty_out(vty,
		"%% VRF is linked to a netns automatically based on its name.\n");
	return CMD_WARNING;
}

DEFPY_YANG (ip_table_range, ip_table_range_cmd,
      "[no] ip table range ![(1-4294967295)$start (1-4294967295)$end]",
      NO_STR IP_STR
      "table configuration\n"
      "Configure table range\n"
      "Start Routing Table\n"
      "End Routing Table\n")
{
	if (!no) {
		const struct lyd_node *start_node;
		const struct lyd_node *end_node;

		if (vty->node == CONFIG_NODE) {
			start_node =
				yang_dnode_getf(vty->candidate_config->dnode,
						"/frr-vrf:lib/vrf[name='%s']/frr-zebra:zebra/netns/table-range/start",
						VRF_DEFAULT_NAME);
			end_node =
				yang_dnode_getf(vty->candidate_config->dnode,
						"/frr-vrf:lib/vrf[name='%s']/frr-zebra:zebra/netns/table-range/end",
						VRF_DEFAULT_NAME);
		} else {
			start_node =
				yang_dnode_getf(vty->candidate_config->dnode,
						"%s/frr-zebra:zebra/netns/table-range/start",
						VTY_CURR_XPATH);
			end_node =
				yang_dnode_getf(vty->candidate_config->dnode,
						"%s/frr-zebra:zebra/netns/table-range/end",
						VTY_CURR_XPATH);
		}

		if (start_node && end_node) {
			if (yang_dnode_get_uint32(start_node, NULL) !=
				    (uint32_t)start ||
			    yang_dnode_get_uint32(end_node, NULL) !=
				    (uint32_t)end) {
				vty_out(vty,
					"%% New range will be taken into account at restart.\n");
				vty_out(vty,
					"%% Don't forget to save your configuration.\n");
			}
		}

		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/netns/table-range",
				      NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/netns/table-range/start",
				      NB_OP_MODIFY, start_str);
		nb_cli_enqueue_change(vty,
				      "./frr-zebra:zebra/netns/table-range/end",
				      NB_OP_MODIFY, end_str);
	} else {
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/netns/table-range",
				      NB_OP_DESTROY, NULL);
	}

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']",
					    VRF_DEFAULT_NAME);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_vrf_zebra_netns_table_range_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t start = yang_dnode_get_uint32(dnode, "start");
	uint32_t end = yang_dnode_get_uint32(dnode, "end");

	zebra_vrf_indent_cli_write(vty, dnode);

	vty_out(vty, "ip table range %u %u\n", start, end);
}

DEFPY_YANG (vni_mapping,
       vni_mapping_cmd,
       "[no] vni ![" CMD_VNI_RANGE "[prefix-routes-only$filter]]",
       NO_STR
       "VNI corresponding to tenant VRF\n"
       "VNI-ID\n"
       "prefix-routes-only\n")
{
	if (!no)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/l3vni-id", NB_OP_MODIFY,
			      vni_str);
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/l3vni-id", NB_OP_DESTROY,
			      NULL);

	if (filter)
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/prefix-only",
				      NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, "./frr-zebra:zebra/prefix-only",
				      NB_OP_DESTROY, NULL);

	if (vty->node == CONFIG_NODE)
		return nb_cli_apply_changes(vty, "/frr-vrf:lib/vrf[name='%s']",
					    VRF_DEFAULT_NAME);

	return nb_cli_apply_changes(vty, NULL);
}

static void lib_vrf_zebra_l3vni_id_cli_write(struct vty *vty,
					     const struct lyd_node *dnode,
					     bool show_defaults)
{
	vni_t vni = yang_dnode_get_uint32(dnode, NULL);
	bool prefix_only = yang_dnode_get_bool(dnode, "../prefix-only");

	zebra_vrf_indent_cli_write(vty, dnode);

	vty_out(vty, "vni %u", vni);

	if (prefix_only)
		vty_out(vty, " prefix-routes-only");

	vty_out(vty, "\n");
}

DEFPY_YANG(
	match_ip_address_prefix_len, match_ip_address_prefix_len_cmd,
	"match ip address prefix-len (0-32)$length",
	MATCH_STR
	IP_STR
	"Match prefix length of IP address\n"
	"Match prefix length of IP address\n"
	"Prefix length\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:ipv4-prefix-length']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, length_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ip_address_prefix_len, no_match_ip_address_prefix_len_cmd,
	"no match ip address prefix-len [(0-32)]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match prefix length of IP address\n"
	"Match prefix length of IP address\n"
	"Prefix length\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:ipv4-prefix-length']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ipv6_address_prefix_len, match_ipv6_address_prefix_len_cmd,
	"match ipv6 address prefix-len (0-128)$length",
	MATCH_STR
	IPV6_STR
	"Match prefix length of IPv6 address\n"
	"Match prefix length of IPv6 address\n"
	"Prefix length\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:ipv6-prefix-length']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-zebra-route-map:ipv6-prefix-length",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, length_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ipv6_address_prefix_len, no_match_ipv6_address_prefix_len_cmd,
	"no match ipv6 address prefix-len [(0-128)]",
	NO_STR
	MATCH_STR
	IPV6_STR
	"Match prefix length of IPv6 address\n"
	"Match prefix length of IPv6 address\n"
	"Prefix length\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:ipv6-prefix-length']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_ip_nexthop_prefix_len, match_ip_nexthop_prefix_len_cmd,
	"match ip next-hop prefix-len (0-32)$length",
	MATCH_STR
	IP_STR
	"Match prefixlen of nexthop IP address\n"
	"Match prefixlen of given nexthop\n"
	"Prefix length\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:ipv4-next-hop-prefix-length']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-zebra-route-map:ipv4-prefix-length",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, length_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_ip_nexthop_prefix_len, no_match_ip_nexthop_prefix_len_cmd,
	"no match ip next-hop prefix-len [(0-32)]",
	NO_STR
	MATCH_STR
	IP_STR
	"Match prefixlen of nexthop IP address\n"
	"Match prefix length of nexthop\n"
	"Prefix length\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:ipv4-next-hop-prefix-length']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_source_protocol, match_source_protocol_cmd,
	"match source-protocol " FRR_REDIST_STR_ZEBRA "$proto",
	MATCH_STR
	"Match protocol via which the route was learnt\n"
	FRR_REDIST_HELP_STR_ZEBRA)
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:source-protocol']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-zebra-route-map:source-protocol",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, proto);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_source_protocol, no_match_source_protocol_cmd,
	"no match source-protocol [" FRR_REDIST_STR_ZEBRA "]",
	NO_STR
	MATCH_STR
	"Match protocol via which the route was learnt\n"
	FRR_REDIST_HELP_STR_ZEBRA)
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:source-protocol']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_source_instance, match_source_instance_cmd,
	"match source-instance (0-255)$instance",
	MATCH_STR
	"Match the protocol's instance number\n"
	"The instance number\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:source-instance']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-zebra-route-map:source-instance",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, instance_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_match_source_instance, no_match_source_instance_cmd,
	"no match source-instance [(0-255)]",
	NO_STR MATCH_STR
	"Match the protocol's instance number\n"
	"The instance number\n")
{
	const char *xpath =
		"./match-condition[condition='frr-zebra-route-map:source-instance']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* set functions */

DEFPY_YANG(
	set_src, set_src_cmd,
	"set src <A.B.C.D$addrv4|X:X::X:X$addrv6>",
	SET_STR
	"src address for route\n"
	"IPv4 src address\n"
	"IPv6 src address\n")
{
	const char *xpath =
		"./set-action[action='frr-zebra-route-map:src-address']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (addrv4_str) {
		snprintf(
			xpath_value, sizeof(xpath_value),
			"%s/rmap-set-action/frr-zebra-route-map:ipv4-src-address",
			xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      addrv4_str);
	} else {
		snprintf(
			xpath_value, sizeof(xpath_value),
			"%s/rmap-set-action/frr-zebra-route-map:ipv6-src-address",
			xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      addrv6_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	no_set_src, no_set_src_cmd,
	"no set src [<A.B.C.D|X:X::X:X>]",
	NO_STR
	SET_STR
	"Source address for route\n"
	"IPv4 address\n"
	"IPv6 address\n")
{
	const char *xpath =
		"./set-action[action='frr-zebra-route-map:src-address']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

const char *features[] = {
#if HAVE_BFDD == 0
	"ptm-bfd",
#endif
#if defined(HAVE_RTADV)
	"ipv6-router-advertisements",
#endif
	NULL
};

/* clang-format off */
const struct frr_yang_module_info frr_zebra_cli_info = {
	.name = "frr-zebra",
	.ignore_cfg_cbs = true,
	.features = features,
	.nodes = {
#if HAVE_BFDD == 0
		{
			.xpath = "/frr-zebra:zebra/ptm-enable",
			.cbs.cli_show = zebra_ptm_enable_cli_write,
		},
#endif
		{
			.xpath = "/frr-zebra:zebra/route-map-delay",
			.cbs.cli_show = zebra_route_map_delay_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv4-addrs",
			.cbs.cli_show = lib_interface_zebra_ipv4_addrs_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv4-p2p-addrs",
			.cbs.cli_show = lib_interface_zebra_ipv4_p2p_addrs_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-addrs",
			.cbs.cli_show = lib_interface_zebra_ipv6_addrs_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/multicast",
			.cbs.cli_show = lib_interface_zebra_multicast_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-detect",
			.cbs.cli_show = lib_interface_zebra_link_detect_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/enabled",
			.cbs.cli_show = lib_interface_zebra_enabled_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/bandwidth",
			.cbs.cli_show = lib_interface_zebra_bandwidth_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/mpls",
			.cbs.cli_show = lib_interface_zebra_mpls_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params",
			.cbs.cli_show = lib_interface_zebra_link_params_cli_write,
			.cbs.cli_show_end = lib_interface_zebra_link_params_cli_write_end,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/metric",
			.cbs.cli_show = lib_interface_zebra_link_params_metric_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/max-bandwidth",
			.cbs.cli_show = lib_interface_zebra_link_params_max_bandwidth_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/max-reservable-bandwidth",
			.cbs.cli_show = lib_interface_zebra_link_params_max_reservable_bandwidth_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/unreserved-bandwidths/unreserved-bandwidth",
			.cbs.cli_show = lib_interface_zebra_link_params_unreserved_bandwidths_unreserved_bandwidth_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/residual-bandwidth",
			.cbs.cli_show = lib_interface_zebra_link_params_residual_bandwidth_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/available-bandwidth",
			.cbs.cli_show = lib_interface_zebra_link_params_available_bandwidth_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/utilized-bandwidth",
			.cbs.cli_show = lib_interface_zebra_link_params_utilized_bandwidth_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/legacy-admin-group",
			.cbs.cli_show = lib_interface_zebra_link_params_legacy_admin_group_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/affinities",
			.cbs.cli_show = lib_interface_zebra_link_params_affinities_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/affinity-mode",
			.cbs.cli_show = lib_interface_zebra_link_params_affinity_mode_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/neighbor",
			.cbs.cli_show = lib_interface_zebra_link_params_neighbor_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/delay",
			.cbs.cli_show = lib_interface_zebra_link_params_delay_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/delay-variation",
			.cbs.cli_show = lib_interface_zebra_link_params_delay_variation_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/link-params/packet-loss",
			.cbs.cli_show = lib_interface_zebra_link_params_packet_loss_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-0/esi",
			.cbs.cli_show = lib_interface_zebra_evpn_mh_type_0_esi_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3/system-mac",
			.cbs.cli_show = lib_interface_zebra_evpn_mh_type_3_system_mac_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/type-3/local-discriminator",
			.cbs.cli_show = lib_interface_zebra_evpn_mh_type_3_local_discriminator_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/df-preference",
			.cbs.cli_show = lib_interface_zebra_evpn_mh_df_preference_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/bypass",
			.cbs.cli_show = lib_interface_zebra_evpn_mh_bypass_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/evpn-mh/uplink",
			.cbs.cli_show = lib_interface_zebra_evpn_mh_uplink_cli_write,
		},
#if defined(HAVE_RTADV)
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/send-advertisements",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_send_advertisements_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/max-rtr-adv-interval",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_max_rtr_adv_interval_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/managed-flag",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_managed_flag_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/other-config-flag",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_other_config_flag_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-flag",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_home_agent_flag_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/link-mtu",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_link_mtu_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/reachable-time",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_reachable_time_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/retrans-timer",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_retrans_timer_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/cur-hop-limit",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_cur_hop_limit_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/default-lifetime",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_default_lifetime_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/fast-retransmit",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_fast_retransmit_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/advertisement-interval-option",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_advertisement_interval_option_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-preference",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_home_agent_preference_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/home-agent-lifetime",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_home_agent_lifetime_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/default-router-preference",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_default_router_preference_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/prefix-list/prefix",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_prefix_list_prefix_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/dnssl/dnssl-domain",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_dnssl_dnssl_domain_cli_write,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ipv6-router-advertisements/rdnss/rdnss-address",
			.cbs.cli_show = lib_interface_zebra_ipv6_router_advertisements_rdnss_rdnss_address_cli_write,
		},
#endif /* defined(HAVE_RTADV) */
#if HAVE_BFDD == 0
		{
			.xpath = "/frr-interface:lib/interface/frr-zebra:zebra/ptm-enable",
			.cbs.cli_show = lib_interface_zebra_ptm_enable_cli_write,
		},
#endif
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/router-id",
			.cbs.cli_show = lib_vrf_zebra_router_id_cli_write,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ipv6-router-id",
			.cbs.cli_show = lib_vrf_zebra_ipv6_router_id_cli_write,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/filter-protocol",
			.cbs.cli_show = lib_vrf_zebra_filter_protocol_cli_write,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/filter-nht",
			.cbs.cli_show = lib_vrf_zebra_filter_nht_cli_write,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/resolve-via-default",
			.cbs.cli_show = lib_vrf_zebra_resolve_via_default_cli_write,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/ipv6-resolve-via-default",
			.cbs.cli_show = lib_vrf_zebra_ipv6_resolve_via_default_cli_write,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/netns/table-range",
			.cbs.cli_show = lib_vrf_zebra_netns_table_range_cli_write,
		},
		{
			.xpath = "/frr-vrf:lib/vrf/frr-zebra:zebra/l3vni-id",
			.cbs.cli_show = lib_vrf_zebra_l3vni_id_cli_write,
		},
		{
			.xpath = NULL,
		},
	}
};

struct cmd_node link_params_node = {
	.name = "link-params",
	.node = LINK_PARAMS_NODE,
	.parent_node = INTERFACE_NODE,
	.prompt = "%s(config-link-params)# ",
};

void zebra_cli_init(void)
{
	install_node(&link_params_node);

	install_element(INTERFACE_NODE, &multicast_new_cmd);
	install_element(INTERFACE_NODE, &multicast_cmd);
	install_element(INTERFACE_NODE, &mpls_cmd);
	install_element(INTERFACE_NODE, &linkdetect_cmd);
	install_element(INTERFACE_NODE, &shutdown_if_cmd);
	install_element(INTERFACE_NODE, &bandwidth_if_cmd);
	install_element(INTERFACE_NODE, &ip_address_cmd);
	install_element(INTERFACE_NODE, &ip_address_peer_cmd);
	install_element(INTERFACE_NODE, &ipv6_address_cmd);
	install_element(INTERFACE_NODE, &link_params_cmd);
	install_element(INTERFACE_NODE, &no_link_params_cmd);
	install_default(LINK_PARAMS_NODE);
	install_element(LINK_PARAMS_NODE, &link_params_enable_cmd);
	install_element(LINK_PARAMS_NODE, &no_link_params_enable_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_metric_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_maxbw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_max_rsv_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_unrsv_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_admin_grp_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_inter_as_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_delay_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_delay_var_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_pkt_loss_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_ava_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_res_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_use_bw_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_affinity_cmd);
	install_element(LINK_PARAMS_NODE, &link_params_affinity_mode_cmd);
	install_element(LINK_PARAMS_NODE, &exit_link_params_cmd);

	install_element(INTERFACE_NODE, &zebra_evpn_es_id_cmd);
	install_element(INTERFACE_NODE, &zebra_evpn_es_sys_mac_cmd);
	install_element(INTERFACE_NODE, &zebra_evpn_es_pref_cmd);
	install_element(INTERFACE_NODE, &zebra_evpn_es_bypass_cmd);
	install_element(INTERFACE_NODE, &zebra_evpn_mh_uplink_cmd);

#if defined(HAVE_RTADV)
	install_element(INTERFACE_NODE, &ipv6_nd_ra_fast_retrans_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_ra_retrans_interval_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_ra_hop_limit_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_suppress_ra_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_ra_interval_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_ra_lifetime_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_reachable_time_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_managed_config_flag_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_other_config_flag_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_homeagent_config_flag_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_homeagent_preference_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_homeagent_lifetime_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_adv_interval_config_option_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_prefix_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_router_preference_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_mtu_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_rdnss_cmd);
	install_element(INTERFACE_NODE, &ipv6_nd_dnssl_cmd);
#endif
#if HAVE_BFDD == 0
	install_element(INTERFACE_NODE, &zebra_ptm_enable_if_cmd);
#endif

	install_element(CONFIG_NODE, &ip_router_id_cmd);
	install_element(CONFIG_NODE, &router_id_cmd);
	install_element(CONFIG_NODE, &ipv6_router_id_cmd);
	install_element(CONFIG_NODE, &ip_router_id_in_vrf_cmd);
	install_element(CONFIG_NODE, &router_id_in_vrf_cmd);
	install_element(CONFIG_NODE, &ipv6_router_id_in_vrf_cmd);
	install_element(VRF_NODE, &ip_router_id_in_vrf_cmd);
	install_element(VRF_NODE, &router_id_in_vrf_cmd);
	install_element(VRF_NODE, &ipv6_router_id_in_vrf_cmd);

	install_element(CONFIG_NODE, &ip_protocol_cmd);
	install_element(VRF_NODE, &ip_protocol_cmd);
	install_element(CONFIG_NODE, &ipv6_protocol_cmd);
	install_element(VRF_NODE, &ipv6_protocol_cmd);
	install_element(CONFIG_NODE, &ip_protocol_nht_rmap_cmd);
	install_element(VRF_NODE, &ip_protocol_nht_rmap_cmd);
	install_element(CONFIG_NODE, &ipv6_protocol_nht_rmap_cmd);
	install_element(VRF_NODE, &ipv6_protocol_nht_rmap_cmd);
	install_element(CONFIG_NODE, &zebra_route_map_timer_cmd);

	install_element(CONFIG_NODE, &ip_nht_default_route_cmd);
	install_element(CONFIG_NODE, &ipv6_nht_default_route_cmd);
	install_element(VRF_NODE, &ip_nht_default_route_cmd);
	install_element(VRF_NODE, &ipv6_nht_default_route_cmd);

	install_element(CONFIG_NODE, &vni_mapping_cmd);
	install_element(VRF_NODE, &vni_mapping_cmd);

	if (vrf_is_backend_netns())
		install_element(VRF_NODE, &vrf_netns_cmd);

	install_element(CONFIG_NODE, &ip_table_range_cmd);
	install_element(VRF_NODE, &ip_table_range_cmd);
#if HAVE_BFDD == 0
	install_element(CONFIG_NODE, &zebra_ptm_enable_cmd);
#endif
	install_element(RMAP_NODE, &match_ip_nexthop_prefix_len_cmd);
	install_element(RMAP_NODE, &no_match_ip_nexthop_prefix_len_cmd);
	install_element(RMAP_NODE, &match_ip_address_prefix_len_cmd);
	install_element(RMAP_NODE, &match_ipv6_address_prefix_len_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_address_prefix_len_cmd);
	install_element(RMAP_NODE, &no_match_ip_address_prefix_len_cmd);
	install_element(RMAP_NODE, &match_source_protocol_cmd);
	install_element(RMAP_NODE, &no_match_source_protocol_cmd);
	install_element(RMAP_NODE, &match_source_instance_cmd);
	install_element(RMAP_NODE, &no_match_source_instance_cmd);

	install_element(RMAP_NODE, &set_src_cmd);
	install_element(RMAP_NODE, &no_set_src_cmd);
}
