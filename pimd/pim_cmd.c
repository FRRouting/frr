// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "lib/json.h"
#include "command.h"
#include "if.h"
#include "prefix.h"
#include "zclient.h"
#include "plist.h"
#include "hash.h"
#include "nexthop.h"
#include "vrf.h"
#include "ferr.h"

#include "pimd.h"
#include "pim_mroute.h"
#include "pim_cmd.h"
#include "pim_iface.h"
#include "pim_vty.h"
#include "pim_mroute.h"
#include "pim_str.h"
#include "pim_igmp.h"
#include "pim_igmpv3.h"
#include "pim_sock.h"
#include "pim_time.h"
#include "pim_util.h"
#include "pim_oil.h"
#include "pim_neighbor.h"
#include "pim_pim.h"
#include "pim_ifchannel.h"
#include "pim_hello.h"
#include "pim_msg.h"
#include "pim_upstream.h"
#include "pim_rpf.h"
#include "pim_macro.h"
#include "pim_ssmpingd.h"
#include "pim_zebra.h"
#include "pim_static.h"
#include "pim_rp.h"
#include "pim_zlookup.h"
#include "pim_msdp.h"
#include "pim_ssm.h"
#include "pim_nht.h"
#include "pim_bfd.h"
#include "pim_vxlan.h"
#include "pim_mlag.h"
#include "bfd.h"
#include "pim_bsm.h"
#include "lib/northbound_cli.h"
#include "pim_errors.h"
#include "pim_nb.h"
#include "pim_addr.h"
#include "pim_cmd_common.h"

#include "pimd/pim_cmd_clippy.c"

static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = pim_debug_config_write,
};

static struct vrf *pim_cmd_lookup_vrf(struct vty *vty, struct cmd_token *argv[],
				      const int argc, int *idx, bool uj)
{
	struct vrf *vrf;

	if (argv_find(argv, argc, "NAME", idx))
		vrf = vrf_lookup_by_name(argv[*idx]->arg);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf) {
		if (uj)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "Specified VRF: %s does not exist\n",
				argv[*idx]->arg);
	}

	return vrf;
}

static void pim_show_assert_helper(struct vty *vty,
				   struct pim_interface *pim_ifp,
				   struct pim_ifchannel *ch, time_t now)
{
	char winner_str[INET_ADDRSTRLEN];
	struct in_addr ifaddr;
	char uptime[10];
	char timer[10];
	char buf[PREFIX_STRLEN];

	ifaddr = pim_ifp->primary_address;

	pim_inet4_dump("<assrt_win?>", ch->ifassert_winner, winner_str,
		       sizeof(winner_str));

	pim_time_uptime(uptime, sizeof(uptime), now - ch->ifassert_creation);
	pim_time_timer_to_mmss(timer, sizeof(timer), ch->t_ifassert_timer);

	vty_out(vty, "%-16s %-15s %-15pPAs %-15pPAs %-6s %-15s %-8s %-5s\n",
		ch->interface->name,
		inet_ntop(AF_INET, &ifaddr, buf, sizeof(buf)), &ch->sg.src,
		&ch->sg.grp, pim_ifchannel_ifassert_name(ch->ifassert_state),
		winner_str, uptime, timer);
}

static void pim_show_assert(struct pim_instance *pim, struct vty *vty)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct interface *ifp;
	time_t now;

	now = pim_time_monotonic_sec();

	vty_out(vty,
		"Interface        Address         Source          Group           State  Winner          Uptime   Timer\n");

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
			if (ch->ifassert_state == PIM_IFASSERT_NOINFO)
				continue;

			pim_show_assert_helper(vty, pim_ifp, ch, now);
		} /* scan interface channels */
	}
}

static void pim_show_assert_internal_helper(struct vty *vty,
					    struct pim_interface *pim_ifp,
					    struct pim_ifchannel *ch)
{
	struct in_addr ifaddr;
	char buf[PREFIX_STRLEN];

	ifaddr = pim_ifp->primary_address;

	vty_out(vty, "%-16s %-15s %-15pPAs %-15pPAs %-3s %-3s %-3s %-4s\n",
		ch->interface->name,
		inet_ntop(AF_INET, &ifaddr, buf, sizeof(buf)), &ch->sg.src,
		&ch->sg.grp,
		PIM_IF_FLAG_TEST_COULD_ASSERT(ch->flags) ? "yes" : "no",
		pim_macro_ch_could_assert_eval(ch) ? "yes" : "no",
		PIM_IF_FLAG_TEST_ASSERT_TRACKING_DESIRED(ch->flags) ? "yes"
		: "no",
		pim_macro_assert_tracking_desired_eval(ch) ? "yes" : "no");
}

static void pim_show_assert_internal(struct pim_instance *pim, struct vty *vty)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct interface *ifp;

	vty_out(vty,
		"CA:   CouldAssert\n"
		"ECA:  Evaluate CouldAssert\n"
		"ATD:  AssertTrackingDesired\n"
		"eATD: Evaluate AssertTrackingDesired\n\n");

	vty_out(vty,
		"Interface        Address         Source          Group           CA  eCA ATD eATD\n");
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
			pim_show_assert_internal_helper(vty, pim_ifp, ch);
		} /* scan interface channels */
	}
}

static void pim_show_assert_metric_helper(struct vty *vty,
					  struct pim_interface *pim_ifp,
					  struct pim_ifchannel *ch)
{
	char addr_str[INET_ADDRSTRLEN];
	struct pim_assert_metric am;
	struct in_addr ifaddr;
	char buf[PREFIX_STRLEN];

	ifaddr = pim_ifp->primary_address;

	am = pim_macro_spt_assert_metric(&ch->upstream->rpf,
					 pim_ifp->primary_address);

	pim_inet4_dump("<addr?>", am.ip_address, addr_str, sizeof(addr_str));

	vty_out(vty, "%-16s %-15s %-15pPAs %-15pPAs %-3s %4u %6u %-15s\n",
		ch->interface->name,
		inet_ntop(AF_INET, &ifaddr, buf, sizeof(buf)), &ch->sg.src,
		&ch->sg.grp, am.rpt_bit_flag ? "yes" : "no",
		am.metric_preference, am.route_metric, addr_str);
}

static void pim_show_assert_metric(struct pim_instance *pim, struct vty *vty)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct interface *ifp;

	vty_out(vty,
		"Interface        Address         Source          Group           RPT Pref Metric Address        \n");

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
			pim_show_assert_metric_helper(vty, pim_ifp, ch);
		} /* scan interface channels */
	}
}

static void pim_show_assert_winner_metric_helper(struct vty *vty,
						 struct pim_interface *pim_ifp,
						 struct pim_ifchannel *ch)
{
	char addr_str[INET_ADDRSTRLEN];
	struct pim_assert_metric *am;
	struct in_addr ifaddr;
	char pref_str[16];
	char metr_str[16];
	char buf[PREFIX_STRLEN];

	ifaddr = pim_ifp->primary_address;

	am = &ch->ifassert_winner_metric;

	pim_inet4_dump("<addr?>", am->ip_address, addr_str, sizeof(addr_str));

	if (am->metric_preference == PIM_ASSERT_METRIC_PREFERENCE_MAX)
		snprintf(pref_str, sizeof(pref_str), "INFI");
	else
		snprintf(pref_str, sizeof(pref_str), "%4u",
			 am->metric_preference);

	if (am->route_metric == PIM_ASSERT_ROUTE_METRIC_MAX)
		snprintf(metr_str, sizeof(metr_str), "INFI");
	else
		snprintf(metr_str, sizeof(metr_str), "%6u", am->route_metric);

	vty_out(vty, "%-16s %-15s %-15pPAs %-15pPAs %-3s %-4s %-6s %-15s\n",
		ch->interface->name,
		inet_ntop(AF_INET, &ifaddr, buf, sizeof(buf)), &ch->sg.src,
		&ch->sg.grp, am->rpt_bit_flag ? "yes" : "no", pref_str,
		metr_str, addr_str);
}

static void pim_show_assert_winner_metric(struct pim_instance *pim,
					  struct vty *vty)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct interface *ifp;

	vty_out(vty,
		"Interface        Address         Source          Group           RPT Pref Metric Address        \n");

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
			pim_show_assert_winner_metric_helper(vty, pim_ifp, ch);
		} /* scan interface channels */
	}
}

static void igmp_show_interfaces(struct pim_instance *pim, struct vty *vty,
				 bool uj)
{
	struct interface *ifp;
	time_t now;
	char buf[PREFIX_STRLEN];
	json_object *json = NULL;
	json_object *json_row = NULL;

	now = pim_time_monotonic_sec();

	if (uj)
		json = json_object_new_object();
	else
		vty_out(vty,
			"Interface         State          Address  V  Querier          QuerierIp  Query Timer    Uptime\n");

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp;
		struct listnode *sock_node;
		struct gm_sock *igmp;

		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_socket_list, sock_node,
					  igmp)) {
			char uptime[10];
			char query_hhmmss[10];

			pim_time_uptime(uptime, sizeof(uptime),
					now - igmp->sock_creation);
			pim_time_timer_to_hhmmss(query_hhmmss,
						 sizeof(query_hhmmss),
						 igmp->t_igmp_query_timer);

			if (uj) {
				json_row = json_object_new_object();
				json_object_pim_ifp_add(json_row, ifp);
				json_object_string_add(json_row, "upTime",
						       uptime);
				json_object_int_add(json_row, "version",
						    pim_ifp->igmp_version);

				if (igmp->t_igmp_query_timer) {
					json_object_boolean_true_add(json_row,
								     "querier");
					json_object_string_add(json_row,
							       "queryTimer",
							       query_hhmmss);
				}
				json_object_string_addf(json_row, "querierIp",
							"%pI4",
							&igmp->querier_addr);

				json_object_object_add(json, ifp->name,
						       json_row);

				if (igmp->mtrace_only) {
					json_object_boolean_true_add(
						json_row, "mtraceOnly");
				}
			} else {
				vty_out(vty,
					"%-16s  %5s  %15s  %d  %7s  %17pI4  %11s  %8s\n",
					ifp->name,
					if_is_up(ifp)
						? (igmp->mtrace_only ? "mtrc"
								     : "up")
						: "down",
					inet_ntop(AF_INET, &igmp->ifaddr, buf,
						  sizeof(buf)),
					pim_ifp->igmp_version,
					igmp->t_igmp_query_timer ? "local"
								 : "other",
					&igmp->querier_addr, query_hhmmss,
					uptime);
			}
		}
	}

	if (uj)
		vty_json(vty, json);
}

static void igmp_show_interfaces_single(struct pim_instance *pim,
					struct vty *vty, const char *ifname,
					bool uj)
{
	struct gm_sock *igmp;
	struct interface *ifp;
	struct listnode *sock_node;
	struct pim_interface *pim_ifp;
	char uptime[10];
	char query_hhmmss[10];
	char other_hhmmss[10];
	int found_ifname = 0;
	int sqi;
	long gmi_msec; /* Group Membership Interval */
	long lmqt_msec;
	long ohpi_msec;
	long oqpi_msec; /* Other Querier Present Interval */
	long qri_msec;
	time_t now;
	int lmqc;

	json_object *json = NULL;
	json_object *json_row = NULL;

	if (uj)
		json = json_object_new_object();

	now = pim_time_monotonic_sec();

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (strcmp(ifname, "detail") && strcmp(ifname, ifp->name))
			continue;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_socket_list, sock_node,
					  igmp)) {
			found_ifname = 1;
			pim_time_uptime(uptime, sizeof(uptime),
					now - igmp->sock_creation);
			pim_time_timer_to_hhmmss(query_hhmmss,
						 sizeof(query_hhmmss),
						 igmp->t_igmp_query_timer);
			pim_time_timer_to_hhmmss(other_hhmmss,
						 sizeof(other_hhmmss),
						 igmp->t_other_querier_timer);

			gmi_msec = PIM_IGMP_GMI_MSEC(
				igmp->querier_robustness_variable,
				igmp->querier_query_interval,
				pim_ifp->gm_query_max_response_time_dsec);

			sqi = PIM_IGMP_SQI(pim_ifp->gm_default_query_interval);

			oqpi_msec = PIM_IGMP_OQPI_MSEC(
				igmp->querier_robustness_variable,
				igmp->querier_query_interval,
				pim_ifp->gm_query_max_response_time_dsec);

			lmqt_msec = PIM_IGMP_LMQT_MSEC(
				pim_ifp->gm_specific_query_max_response_time_dsec,
				pim_ifp->gm_last_member_query_count);

			ohpi_msec =
				PIM_IGMP_OHPI_DSEC(
					igmp->querier_robustness_variable,
					igmp->querier_query_interval,
					pim_ifp->gm_query_max_response_time_dsec) *
				100;

			qri_msec =
				pim_ifp->gm_query_max_response_time_dsec * 100;
			lmqc = pim_ifp->gm_last_member_query_count;

			if (uj) {
				json_row = json_object_new_object();
				json_object_pim_ifp_add(json_row, ifp);
				json_object_string_add(json_row, "upTime",
						       uptime);
				json_object_string_add(json_row, "querier",
						       igmp->t_igmp_query_timer
						       ? "local"
						       : "other");
				json_object_string_addf(json_row, "querierIp",
							"%pI4",
							&igmp->querier_addr);
				json_object_int_add(json_row, "queryStartCount",
						    igmp->startup_query_count);
				json_object_string_add(json_row,
						       "queryQueryTimer",
						       query_hhmmss);
				json_object_string_add(json_row,
						       "queryOtherTimer",
						       other_hhmmss);
				json_object_int_add(json_row, "version",
						    pim_ifp->igmp_version);
				json_object_int_add(
					json_row,
					"timerGroupMembershipIntervalMsec",
					gmi_msec);
				json_object_int_add(json_row,
						    "lastMemberQueryCount",
						    lmqc);
				json_object_int_add(json_row,
						    "timerLastMemberQueryMsec",
						    lmqt_msec);
				json_object_int_add(
					json_row,
					"timerOlderHostPresentIntervalMsec",
					ohpi_msec);
				json_object_int_add(
					json_row,
					"timerOtherQuerierPresentIntervalMsec",
					oqpi_msec);
				json_object_int_add(
					json_row, "timerQueryInterval",
					igmp->querier_query_interval);
				json_object_int_add(
					json_row,
					"timerQueryResponseIntervalMsec",
					qri_msec);
				json_object_int_add(
					json_row, "timerRobustnessVariable",
					igmp->querier_robustness_variable);
				json_object_int_add(json_row,
						    "timerStartupQueryInterval",
						    sqi);

				json_object_object_add(json, ifp->name,
						       json_row);

				if (igmp->mtrace_only) {
					json_object_boolean_true_add(
						json_row, "mtraceOnly");
				}
			} else {
				vty_out(vty, "Interface : %s\n", ifp->name);
				vty_out(vty, "State     : %s\n",
					if_is_up(ifp) ? (igmp->mtrace_only ?
							 "mtrace"
							 : "up")
					: "down");
				vty_out(vty, "Address   : %pI4\n",
					&pim_ifp->primary_address);
				vty_out(vty, "Uptime    : %s\n", uptime);
				vty_out(vty, "Version   : %d\n",
					pim_ifp->igmp_version);
				vty_out(vty, "\n");
				vty_out(vty, "\n");

				vty_out(vty, "Querier\n");
				vty_out(vty, "-------\n");
				vty_out(vty, "Querier     : %s\n",
					igmp->t_igmp_query_timer ? "local"
					: "other");
				vty_out(vty, "QuerierIp   : %pI4",
					&igmp->querier_addr);
				if (pim_ifp->primary_address.s_addr
				    == igmp->querier_addr.s_addr)
					vty_out(vty, " (this router)\n");
				else
					vty_out(vty, "\n");

				vty_out(vty, "Start Count : %d\n",
					igmp->startup_query_count);
				vty_out(vty, "Query Timer : %s\n",
					query_hhmmss);
				vty_out(vty, "Other Timer : %s\n",
					other_hhmmss);
				vty_out(vty, "\n");
				vty_out(vty, "\n");

				vty_out(vty, "Timers\n");
				vty_out(vty, "------\n");
				vty_out(vty,
					"Group Membership Interval      : %lis\n",
					gmi_msec / 1000);
				vty_out(vty,
					"Last Member Query Count        : %d\n",
					lmqc);
				vty_out(vty,
					"Last Member Query Time         : %lis\n",
					lmqt_msec / 1000);
				vty_out(vty,
					"Older Host Present Interval    : %lis\n",
					ohpi_msec / 1000);
				vty_out(vty,
					"Other Querier Present Interval : %lis\n",
					oqpi_msec / 1000);
				vty_out(vty,
					"Query Interval                 : %ds\n",
					igmp->querier_query_interval);
				vty_out(vty,
					"Query Response Interval        : %lis\n",
					qri_msec / 1000);
				vty_out(vty,
					"Robustness Variable            : %d\n",
					igmp->querier_robustness_variable);
				vty_out(vty,
					"Startup Query Interval         : %ds\n",
					sqi);
				vty_out(vty, "\n");
				vty_out(vty, "\n");

				pim_print_ifp_flags(vty, ifp);
			}
		}
	}

	if (uj)
		vty_json(vty, json);
	else if (!found_ifname)
		vty_out(vty, "%% No such interface\n");
}

static void igmp_show_interface_join(struct pim_instance *pim, struct vty *vty,
				     bool uj)
{
	struct interface *ifp;
	time_t now;
	json_object *json = NULL;
	json_object *json_iface = NULL;
	json_object *json_grp = NULL;
	json_object *json_grp_arr = NULL;

	now = pim_time_monotonic_sec();

	if (uj) {
		json = json_object_new_object();
		json_object_string_add(json, "vrf",
				       vrf_id_to_name(pim->vrf->vrf_id));
	} else {
		vty_out(vty,
			"Interface        Address         Source          Group           Socket Uptime  \n");
	}

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp;
		struct listnode *join_node;
		struct gm_join *ij;
		struct in_addr pri_addr;
		char pri_addr_str[INET_ADDRSTRLEN];

		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (!pim_ifp->gm_join_list)
			continue;

		pri_addr = pim_find_primary_addr(ifp);
		pim_inet4_dump("<pri?>", pri_addr, pri_addr_str,
			       sizeof(pri_addr_str));

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_join_list, join_node,
					  ij)) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			char uptime[10];

			pim_time_uptime(uptime, sizeof(uptime),
					now - ij->sock_creation);
			pim_inet4_dump("<grp?>", ij->group_addr, group_str,
				       sizeof(group_str));
			pim_inet4_dump("<src?>", ij->source_addr, source_str,
				       sizeof(source_str));

			if (uj) {
				json_object_object_get_ex(json, ifp->name,
							  &json_iface);

				if (!json_iface) {
					json_iface = json_object_new_object();
					json_object_string_add(
						json_iface, "name", ifp->name);
					json_object_object_add(json, ifp->name,
							       json_iface);
					json_grp_arr = json_object_new_array();
					json_object_object_add(json_iface,
							       "groups",
							       json_grp_arr);
				}

				json_grp = json_object_new_object();
				json_object_string_add(json_grp, "source",
						       source_str);
				json_object_string_add(json_grp, "group",
						       group_str);
				json_object_string_add(json_grp, "primaryAddr",
						       pri_addr_str);
				json_object_int_add(json_grp, "sockFd",
						    ij->sock_fd);
				json_object_string_add(json_grp, "upTime",
						       uptime);
				json_object_array_add(json_grp_arr, json_grp);
			} else {
				vty_out(vty,
					"%-16s %-15s %-15s %-15s %6d %8s\n",
					ifp->name, pri_addr_str, source_str,
					group_str, ij->sock_fd, uptime);
			}
		} /* for (pim_ifp->gm_join_list) */

	} /* for (iflist) */

	if (uj)
		vty_json(vty, json);
}

static void igmp_show_statistics(struct pim_instance *pim, struct vty *vty,
				 const char *ifname, bool uj)
{
	struct interface *ifp;
	struct igmp_stats igmp_stats;
	bool found_ifname = false;
	json_object *json = NULL;

	igmp_stats_init(&igmp_stats);

	if (uj)
		json = json_object_new_object();

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp;
		struct listnode *sock_node, *source_node, *group_node;
		struct gm_sock *igmp;
		struct gm_group *group;
		struct gm_source *src;

		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (ifname && strcmp(ifname, ifp->name))
			continue;

		found_ifname = true;

		igmp_stats.joins_failed += pim_ifp->igmp_ifstat_joins_failed;
		igmp_stats.joins_sent += pim_ifp->igmp_ifstat_joins_sent;
		igmp_stats.total_groups +=
			pim_ifp->gm_group_list
				? listcount(pim_ifp->gm_group_list)
				: 0;
		igmp_stats.peak_groups += pim_ifp->igmp_peak_group_count;


		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, group_node,
					  group)) {
			for (ALL_LIST_ELEMENTS_RO(group->group_source_list,
						  source_node, src)) {
				if (pim_addr_is_any(src->source_addr))
					continue;

				igmp_stats.total_source_groups++;
			}
		}

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_socket_list, sock_node,
					  igmp)) {
			igmp_stats_add(&igmp_stats, &igmp->igmp_stats);
		}
	}

	if (!found_ifname) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty, "%% No such interface\n");
		return;
	}

	if (uj) {
		json_object *json_row = json_object_new_object();

		json_object_string_add(json_row, "name",
				       ifname ? ifname : "global");
		json_object_int_add(json_row, "queryV1", igmp_stats.query_v1);
		json_object_int_add(json_row, "queryV2", igmp_stats.query_v2);
		json_object_int_add(json_row, "queryV3", igmp_stats.query_v3);
		json_object_int_add(json_row, "leaveV2", igmp_stats.leave_v2);
		json_object_int_add(json_row, "reportV1", igmp_stats.report_v1);
		json_object_int_add(json_row, "reportV2", igmp_stats.report_v2);
		json_object_int_add(json_row, "reportV3", igmp_stats.report_v3);
		json_object_int_add(json_row, "mtraceResponse",
				    igmp_stats.mtrace_rsp);
		json_object_int_add(json_row, "mtraceRequest",
				    igmp_stats.mtrace_req);
		json_object_int_add(json_row, "unsupported",
				    igmp_stats.unsupported);
		json_object_int_add(json_row, "totalReceivedMessages",
				    igmp_stats.total_recv_messages);
		json_object_int_add(json_row, "peakGroups",
				    igmp_stats.peak_groups);
		json_object_int_add(json_row, "totalGroups",
				    igmp_stats.total_groups);
		json_object_int_add(json_row, "totalSourceGroups",
				    igmp_stats.total_source_groups);
		json_object_int_add(json_row, "joinsFailed",
				    igmp_stats.joins_failed);
		json_object_int_add(json_row, "joinsSent",
				    igmp_stats.joins_sent);
		json_object_int_add(json_row, "generalQueriesSent",
				    igmp_stats.general_queries_sent);
		json_object_int_add(json_row, "groupQueriesSent",
				    igmp_stats.group_queries_sent);
		json_object_object_add(json, ifname ? ifname : "global",
				       json_row);
		vty_json(vty, json);
	} else {
		vty_out(vty, "IGMP statistics\n");
		vty_out(vty, "Interface               : %s\n",
			ifname ? ifname : "global");
		vty_out(vty, "V1 query                : %u\n",
			igmp_stats.query_v1);
		vty_out(vty, "V2 query                : %u\n",
			igmp_stats.query_v2);
		vty_out(vty, "V3 query                : %u\n",
			igmp_stats.query_v3);
		vty_out(vty, "V2 leave                : %u\n",
			igmp_stats.leave_v2);
		vty_out(vty, "V1 report               : %u\n",
			igmp_stats.report_v1);
		vty_out(vty, "V2 report               : %u\n",
			igmp_stats.report_v2);
		vty_out(vty, "V3 report               : %u\n",
			igmp_stats.report_v3);
		vty_out(vty, "mtrace response         : %u\n",
			igmp_stats.mtrace_rsp);
		vty_out(vty, "mtrace request          : %u\n",
			igmp_stats.mtrace_req);
		vty_out(vty, "unsupported             : %u\n",
			igmp_stats.unsupported);
		vty_out(vty, "total received messages : %u\n",
			igmp_stats.total_recv_messages);
		vty_out(vty, "joins failed            : %u\n",
			igmp_stats.joins_failed);
		vty_out(vty, "joins sent              : %u\n",
			igmp_stats.joins_sent);
		vty_out(vty, "general queries sent    : %u\n",
			igmp_stats.general_queries_sent);
		vty_out(vty, "group queries sent      : %u\n",
			igmp_stats.group_queries_sent);
		vty_out(vty, "peak groups             : %u\n",
			igmp_stats.peak_groups);
		vty_out(vty, "total groups            : %u\n",
			igmp_stats.total_groups);
		vty_out(vty, "total source groups     : %u\n",
			igmp_stats.total_source_groups);
	}
}

static void igmp_source_json_helper(struct gm_source *src,
				    json_object *json_sources, char *source_str,
				    char *mmss, char *uptime)
{
	json_object *json_source = NULL;

	json_source = json_object_new_object();
	if (!json_source)
		return;

	json_object_string_add(json_source, "source", source_str);
	json_object_string_add(json_source, "timer", mmss);
	json_object_boolean_add(json_source, "forwarded",
				IGMP_SOURCE_TEST_FORWARDING(src->source_flags));
	json_object_string_add(json_source, "uptime", uptime);
	json_object_array_add(json_sources, json_source);
}

static void igmp_group_print(struct interface *ifp, struct vty *vty, bool uj,
			     json_object *json, struct gm_group *grp,
			     time_t now, bool detail)
{
	json_object *json_iface = NULL;
	json_object *json_group = NULL;
	json_object *json_groups = NULL;
	char group_str[INET_ADDRSTRLEN];
	char hhmmss[PIM_TIME_STRLEN];
	char uptime[PIM_TIME_STRLEN];

	pim_inet4_dump("<group?>", grp->group_addr, group_str,
		       sizeof(group_str));
	pim_time_timer_to_hhmmss(hhmmss, sizeof(hhmmss), grp->t_group_timer);
	pim_time_uptime(uptime, sizeof(uptime), now - grp->group_creation);

	if (uj) {
		json_object_object_get_ex(json, ifp->name, &json_iface);
		if (!json_iface) {
			json_iface = json_object_new_object();
			if (!json_iface)
				return;
			json_object_pim_ifp_add(json_iface, ifp);
			json_object_object_add(json, ifp->name, json_iface);
			json_groups = json_object_new_array();
			if (!json_groups)
				return;
			json_object_object_add(json_iface, "groups",
					       json_groups);
		}

		json_object_object_get_ex(json_iface, "groups", &json_groups);
		if (json_groups) {
			json_group = json_object_new_object();
			if (!json_group)
				return;

			json_object_string_add(json_group, "group", group_str);
			if (grp->igmp_version == IGMP_DEFAULT_VERSION)
				json_object_string_add(
					json_group, "mode",
					grp->group_filtermode_isexcl
						? "EXCLUDE"
						: "INCLUDE");

			json_object_string_add(json_group, "timer", hhmmss);
			json_object_int_add(
				json_group, "sourcesCount",
				grp->group_source_list
					? listcount(grp->group_source_list)
					: 0);
			json_object_int_add(json_group, "version",
					    grp->igmp_version);
			json_object_string_add(json_group, "uptime", uptime);
			json_object_array_add(json_groups, json_group);

			if (detail) {
				struct listnode *srcnode;
				struct gm_source *src;
				json_object *json_sources = NULL;

				json_sources = json_object_new_array();
				if (!json_sources)
					return;

				json_object_object_add(json_group, "sources",
						       json_sources);

				for (ALL_LIST_ELEMENTS_RO(
					     grp->group_source_list, srcnode,
					     src)) {
					char source_str[INET_ADDRSTRLEN];
					char mmss[PIM_TIME_STRLEN];
					char src_uptime[PIM_TIME_STRLEN];

					pim_inet4_dump(
						"<source?>", src->source_addr,
						source_str, sizeof(source_str));
					pim_time_timer_to_mmss(
						mmss, sizeof(mmss),
						src->t_source_timer);
					pim_time_uptime(
						src_uptime, sizeof(src_uptime),
						now - src->source_creation);

					igmp_source_json_helper(
						src, json_sources, source_str,
						mmss, src_uptime);
				}
			}
		}
	} else {
		if (detail) {
			struct listnode *srcnode;
			struct gm_source *src;

			for (ALL_LIST_ELEMENTS_RO(grp->group_source_list,
						  srcnode, src)) {
				char source_str[INET_ADDRSTRLEN];

				pim_inet4_dump("<source?>", src->source_addr,
					       source_str, sizeof(source_str));

				vty_out(vty,
					"%-16s %-15s %4s %8s %-15s %d %8s\n",
					ifp->name, group_str,
					grp->igmp_version == 3
						? (grp->group_filtermode_isexcl
							   ? "EXCL"
							   : "INCL")
						: "----",
					hhmmss, source_str, grp->igmp_version,
					uptime);
			}
			return;
		}

		vty_out(vty, "%-16s %-15s %4s %8s %4d %d %8s\n", ifp->name,
			group_str,
			grp->igmp_version == 3
				? (grp->group_filtermode_isexcl ? "EXCL"
								: "INCL")
				: "----",
			hhmmss,
			grp->group_source_list
				? listcount(grp->group_source_list)
				: 0,
			grp->igmp_version, uptime);
	}
}

static void igmp_show_groups_interface_single(struct pim_instance *pim,
					      struct vty *vty, bool uj,
					      const char *ifname,
					      const char *grp_str, bool detail)
{
	struct interface *ifp;
	time_t now;
	json_object *json = NULL;
	struct pim_interface *pim_ifp = NULL;
	struct gm_group *grp;

	now = pim_time_monotonic_sec();

	if (uj) {
		json = json_object_new_object();
		if (!json)
			return;
		json_object_int_add(json, "totalGroups", pim->gm_group_count);
		json_object_int_add(json, "watermarkLimit",
				    pim->gm_watermark_limit);
	} else {
		vty_out(vty, "Total IGMP groups: %u\n", pim->gm_group_count);
		vty_out(vty, "Watermark warn limit(%s): %u\n",
			pim->gm_watermark_limit ? "Set" : "Not Set",
			pim->gm_watermark_limit);

		if (!detail)
			vty_out(vty,
				"Interface        Group           Mode Timer    Srcs V Uptime\n");
		else
			vty_out(vty,
				"Interface        Group           Mode Timer    Source          V Uptime\n");
	}

	ifp = if_lookup_by_name(ifname, pim->vrf->vrf_id);
	if (!ifp) {
		if (uj)
			vty_json(vty, json);
		return;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		if (uj)
			vty_json(vty, json);
		return;
	}

	if (grp_str) {
		struct in_addr group_addr;
		struct gm_sock *igmp;

		if (inet_pton(AF_INET, grp_str, &group_addr) == 1) {
			igmp = pim_igmp_sock_lookup_ifaddr(
				pim_ifp->gm_socket_list,
				pim_ifp->primary_address);
			if (igmp) {
				grp = find_group_by_addr(igmp, group_addr);
				if (grp)
					igmp_group_print(ifp, vty, uj, json,
							 grp, now, detail);
			}
		}
	} else {
		struct listnode *grpnode;

		/* scan igmp groups */
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, grpnode, grp))
			igmp_group_print(ifp, vty, uj, json, grp, now, detail);
	}

	if (uj) {
		if (detail)
			vty_json_no_pretty(vty, json);
		else
			vty_json(vty, json);
	}
}

static void igmp_show_groups(struct pim_instance *pim, struct vty *vty, bool uj,
			     const char *grp_str, bool detail)
{
	struct interface *ifp;
	time_t now;
	json_object *json = NULL;

	now = pim_time_monotonic_sec();

	if (uj) {
		json = json_object_new_object();
		if (!json)
			return;
		json_object_int_add(json, "totalGroups", pim->gm_group_count);
		json_object_int_add(json, "watermarkLimit",
				    pim->gm_watermark_limit);
	} else {
		vty_out(vty, "Total IGMP groups: %u\n", pim->gm_group_count);
		vty_out(vty, "Watermark warn limit(%s): %u\n",
			pim->gm_watermark_limit ? "Set" : "Not Set",
			pim->gm_watermark_limit);
		if (!detail)
			vty_out(vty,
				"Interface        Group           Mode Timer    Srcs V Uptime\n");
		else
			vty_out(vty,
				"Interface        Group           Mode Timer    Source          V Uptime\n");
	}

	/* scan interfaces */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct listnode *grpnode;
		struct gm_group *grp;

		if (!pim_ifp)
			continue;

		if (grp_str) {
			struct in_addr group_addr;
			struct gm_sock *igmp;

			if (inet_pton(AF_INET, grp_str, &group_addr) == 1) {
				igmp = pim_igmp_sock_lookup_ifaddr(
					pim_ifp->gm_socket_list,
					pim_ifp->primary_address);
				if (igmp) {
					grp = find_group_by_addr(igmp,
								 group_addr);
					if (grp)
						igmp_group_print(ifp, vty, uj,
								 json, grp, now,
								 detail);
				}
			}
		} else {
			/* scan igmp groups */
			for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list,
						  grpnode, grp))
				igmp_group_print(ifp, vty, uj, json, grp, now,
						 detail);
		}
	} /* scan interfaces */

	if (uj) {
		if (detail)
			vty_json_no_pretty(vty, json);
		else
			vty_json(vty, json);
	}
}

static void igmp_show_group_retransmission(struct pim_instance *pim,
					   struct vty *vty)
{
	struct interface *ifp;

	vty_out(vty,
		"Interface        Group           RetTimer Counter RetSrcs\n");

	/* scan interfaces */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct listnode *grpnode;
		struct gm_group *grp;

		if (!pim_ifp)
			continue;

		/* scan igmp groups */
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, grpnode,
					  grp)) {
			char group_str[INET_ADDRSTRLEN];
			char grp_retr_mmss[10];
			struct listnode *src_node;
			struct gm_source *src;
			int grp_retr_sources = 0;

			pim_inet4_dump("<group?>", grp->group_addr, group_str,
				       sizeof(group_str));
			pim_time_timer_to_mmss(
				grp_retr_mmss, sizeof(grp_retr_mmss),
				grp->t_group_query_retransmit_timer);


			/* count group sources with retransmission state
			 */
			for (ALL_LIST_ELEMENTS_RO(grp->group_source_list,
						  src_node, src)) {
				if (src->source_query_retransmit_count > 0) {
					++grp_retr_sources;
				}
			}

			vty_out(vty, "%-16s %-15s %-8s %7d %7d\n", ifp->name,
				group_str, grp_retr_mmss,
				grp->group_specific_query_retransmit_count,
				grp_retr_sources);

		} /* scan igmp groups */
	}	  /* scan interfaces */
}

static void igmp_sources_print(struct interface *ifp, char *group_str,
			       struct gm_source *src, time_t now,
			       json_object *json, struct vty *vty, bool uj)
{
	json_object *json_iface = NULL;
	json_object *json_group = NULL;
	json_object *json_sources = NULL;
	char source_str[INET_ADDRSTRLEN];
	char mmss[PIM_TIME_STRLEN];
	char uptime[PIM_TIME_STRLEN];

	pim_inet4_dump("<source?>", src->source_addr, source_str,
		       sizeof(source_str));
	pim_time_timer_to_mmss(mmss, sizeof(mmss), src->t_source_timer);
	pim_time_uptime(uptime, sizeof(uptime), now - src->source_creation);

	if (uj) {
		json_object_object_get_ex(json, ifp->name, &json_iface);
		if (!json_iface) {
			json_iface = json_object_new_object();
			if (!json_iface)
				return;
			json_object_string_add(json_iface, "name", ifp->name);
			json_object_object_add(json, ifp->name, json_iface);
		}

		json_object_object_get_ex(json_iface, group_str, &json_group);
		if (!json_group) {
			json_group = json_object_new_object();
			if (!json_group)
				return;
			json_object_string_add(json_group, "group", group_str);
			json_object_object_add(json_iface, group_str,
					       json_group);
			json_sources = json_object_new_array();
			if (!json_sources)
				return;
			json_object_object_add(json_group, "sources",
					       json_sources);
		}

		json_object_object_get_ex(json_group, "sources", &json_sources);
		if (json_sources)
			igmp_source_json_helper(src, json_sources, source_str,
						mmss, uptime);
	} else {
		vty_out(vty, "%-16s %-15s %-15s %5s %3s %8s\n", ifp->name,
			group_str, source_str, mmss,
			IGMP_SOURCE_TEST_FORWARDING(src->source_flags) ? "Y"
								       : "N",
			uptime);
	}
}

static void igmp_show_sources_interface_single(struct pim_instance *pim,
					       struct vty *vty, bool uj,
					       const char *ifname,
					       const char *grp_str)
{
	struct interface *ifp;
	time_t now;
	json_object *json = NULL;
	struct pim_interface *pim_ifp;
	struct gm_group *grp;

	now = pim_time_monotonic_sec();

	if (uj) {
		json = json_object_new_object();
		if (!json)
			return;
	} else {
		vty_out(vty,
			"Interface        Group           Source          Timer Fwd Uptime  \n");
	}

	ifp = if_lookup_by_name(ifname, pim->vrf->vrf_id);
	if (!ifp) {
		if (uj)
			vty_json(vty, json);
		return;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		if (uj)
			vty_json(vty, json);
		return;
	}

	if (grp_str) {
		struct in_addr group_addr;
		struct gm_sock *igmp;
		struct listnode *srcnode;
		struct gm_source *src;
		char group_str[INET_ADDRSTRLEN];
		int res;

		res = inet_pton(AF_INET, grp_str, &group_addr);
		if (res <= 0) {
			if (uj)
				vty_json(vty, json);
			return;
		}

		igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->gm_socket_list,
						   pim_ifp->primary_address);
		if (!igmp) {
			if (uj)
				vty_json(vty, json);
			return;
		}

		grp = find_group_by_addr(igmp, group_addr);
		if (!grp) {
			if (uj)
				vty_json(vty, json);
			return;
		}
		pim_inet4_dump("<group?>", grp->group_addr, group_str,
			       sizeof(group_str));

		/* scan group sources */
		for (ALL_LIST_ELEMENTS_RO(grp->group_source_list, srcnode, src))
			igmp_sources_print(ifp, group_str, src, now, json, vty,
					   uj);
	} else {
		struct listnode *grpnode;

		/* scan igmp groups */
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, grpnode,
					  grp)) {
			char group_str[INET_ADDRSTRLEN];
			struct listnode *srcnode;
			struct gm_source *src;

			pim_inet4_dump("<group?>", grp->group_addr, group_str,
				       sizeof(group_str));

			/* scan group sources */
			for (ALL_LIST_ELEMENTS_RO(grp->group_source_list,
						  srcnode, src))
				igmp_sources_print(ifp, group_str, src, now,
						   json, vty, uj);

		} /* scan igmp groups */
	}

	if (uj)
		vty_json(vty, json);
}

static void igmp_show_sources(struct pim_instance *pim, struct vty *vty,
			      bool uj)
{
	struct interface *ifp;
	time_t now;
	json_object *json = NULL;

	now = pim_time_monotonic_sec();

	if (uj) {
		json = json_object_new_object();
		if (!json)
			return;
	} else {
		vty_out(vty,
			"Interface        Group           Source          Timer Fwd Uptime\n");
	}

	/* scan interfaces */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct listnode *grpnode;
		struct gm_group *grp;

		if (!pim_ifp)
			continue;

		/* scan igmp groups */
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, grpnode,
					  grp)) {
			char group_str[INET_ADDRSTRLEN];
			struct listnode *srcnode;
			struct gm_source *src;

			pim_inet4_dump("<group?>", grp->group_addr, group_str,
				       sizeof(group_str));

			/* scan group sources */
			for (ALL_LIST_ELEMENTS_RO(grp->group_source_list,
						  srcnode, src))
				igmp_sources_print(ifp, group_str, src, now,
						   json, vty, uj);
		}	 /* scan igmp groups */
	}		  /* scan interfaces */

	if (uj)
		vty_json(vty, json);
}

static void igmp_show_source_retransmission(struct pim_instance *pim,
					    struct vty *vty)
{
	struct interface *ifp;

	vty_out(vty,
		"Interface        Group           Source          Counter\n");

	/* scan interfaces */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct listnode *grpnode;
		struct gm_group *grp;

		if (!pim_ifp)
			continue;

		/* scan igmp groups */
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_group_list, grpnode,
					  grp)) {
			char group_str[INET_ADDRSTRLEN];
			struct listnode *srcnode;
			struct gm_source *src;

			pim_inet4_dump("<group?>", grp->group_addr, group_str,
				       sizeof(group_str));

			/* scan group sources */
			for (ALL_LIST_ELEMENTS_RO(grp->group_source_list,
						  srcnode, src)) {
				char source_str[INET_ADDRSTRLEN];

				pim_inet4_dump("<source?>", src->source_addr,
					       source_str, sizeof(source_str));

				vty_out(vty, "%-16s %-15s %-15s %7d\n",
					ifp->name, group_str, source_str,
					src->source_query_retransmit_count);

			} /* scan group sources */
		}	 /* scan igmp groups */
	}		  /* scan interfaces */
}

static void clear_igmp_interfaces(struct pim_instance *pim)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (pim->vrf, ifp)
		pim_if_addr_del_all_igmp(ifp);

	FOR_ALL_INTERFACES (pim->vrf, ifp)
		pim_if_addr_add_all(ifp);
}

static void clear_interfaces(struct pim_instance *pim)
{
	clear_igmp_interfaces(pim);
	clear_pim_interfaces(pim);
}

#define PIM_GET_PIM_INTERFACE(pim_ifp, ifp)				\
	pim_ifp = ifp->info;						\
	if (!pim_ifp) {							\
		vty_out(vty,						\
			"%% Enable PIM and/or IGMP on this interface first\n"); \
		return CMD_WARNING_CONFIG_FAILED;			\
	}

/**
 * Compatibility function to keep the legacy mesh group CLI behavior:
 * Delete group when there are no more configurations in it.
 *
 * NOTE:
 * Don't forget to call `nb_cli_apply_changes` after this.
 */
static void pim_cli_legacy_mesh_group_behavior(struct vty *vty,
					       const char *gname)
{
	const char *vrfname;
	char xpath_value[XPATH_MAXLEN];
	char xpath_member_value[XPATH_MAXLEN];
	const struct lyd_node *member_dnode;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return;

	/* Get mesh group base XPath. */
	snprintf(xpath_value, sizeof(xpath_value),
		 FRR_PIM_VRF_XPATH "/msdp-mesh-groups[name='%s']",
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4", gname);
	/* Group must exists, otherwise just quit. */
	if (!yang_dnode_exists(vty->candidate_config->dnode, xpath_value))
		return;

	/* Group members check: */
	strlcpy(xpath_member_value, xpath_value, sizeof(xpath_member_value));
	strlcat(xpath_member_value, "/members", sizeof(xpath_member_value));
	if (yang_dnode_exists(vty->candidate_config->dnode,
			      xpath_member_value)) {
		member_dnode = yang_dnode_get(vty->candidate_config->dnode,
					      xpath_member_value);
		if (!member_dnode || !yang_is_last_list_dnode(member_dnode))
			return;
	}

	/* Source address check: */
	strlcpy(xpath_member_value, xpath_value, sizeof(xpath_member_value));
	strlcat(xpath_member_value, "/source", sizeof(xpath_member_value));
	if (yang_dnode_exists(vty->candidate_config->dnode, xpath_member_value))
		return;

	/* No configurations found: delete it. */
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, NULL);
}

DEFUN (clear_ip_interfaces,
       clear_ip_interfaces_cmd,
       "clear ip interfaces [vrf NAME]",
       CLEAR_STR
       IP_STR
       "Reset interfaces\n"
       VRF_CMD_HELP_STR)
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	clear_interfaces(vrf->info);

	return CMD_SUCCESS;
}

DEFUN (clear_ip_igmp_interfaces,
       clear_ip_igmp_interfaces_cmd,
       "clear ip igmp [vrf NAME] interfaces",
       CLEAR_STR
       IP_STR
       CLEAR_IP_IGMP_STR
       VRF_CMD_HELP_STR
       "Reset IGMP interfaces\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	clear_igmp_interfaces(vrf->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ip_pim_statistics,
       clear_ip_pim_statistics_cmd,
       "clear ip pim statistics [vrf NAME]$name",
       CLEAR_STR
       IP_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset PIM statistics\n")
{
	struct vrf *v = pim_cmd_lookup(vty, name);

	if (!v)
		return CMD_WARNING;

	clear_pim_statistics(v->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ip_mroute,
       clear_ip_mroute_cmd,
       "clear ip mroute [vrf NAME]$name",
       CLEAR_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR)
{
	struct vrf *v = pim_cmd_lookup(vty, name);

	if (!v)
		return CMD_WARNING;

	clear_mroute(v->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ip_pim_interfaces,
       clear_ip_pim_interfaces_cmd,
       "clear ip pim [vrf NAME] interfaces",
       CLEAR_STR
       IP_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset PIM interfaces\n")
{
	struct vrf *v = pim_cmd_lookup(vty, vrf);

	if (!v)
		return CMD_WARNING;

	clear_pim_interfaces(v->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ip_pim_interface_traffic,
       clear_ip_pim_interface_traffic_cmd,
       "clear ip pim [vrf NAME] interface traffic",
       CLEAR_STR
       IP_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset PIM interfaces\n"
       "Reset Protocol Packet counters\n")
{
	return clear_pim_interface_traffic(vrf, vty);
}

DEFPY (clear_ip_pim_oil,
       clear_ip_pim_oil_cmd,
       "clear ip pim [vrf NAME]$name oil",
       CLEAR_STR
       IP_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Rescan PIM OIL (output interface list)\n")
{
	struct vrf *v = pim_cmd_lookup(vty, name);

	if (!v)
		return CMD_WARNING;

	pim_scan_oil(v->info);

	return CMD_SUCCESS;
}

DEFUN (clear_ip_pim_bsr_db,
       clear_ip_pim_bsr_db_cmd,
       "clear ip pim [vrf NAME] bsr-data",
       CLEAR_STR
       IP_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset pim bsr data\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	pim_bsm_clear(vrf->info);

	return CMD_SUCCESS;
}

DEFUN (show_ip_igmp_interface,
       show_ip_igmp_interface_cmd,
       "show ip igmp [vrf NAME] interface [detail|WORD] [json]",
       SHOW_STR
       IP_STR
       IGMP_STR
       VRF_CMD_HELP_STR
       "IGMP interface information\n"
       "Detailed output\n"
       "interface name\n"
       JSON_STR)
{
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	if (argv_find(argv, argc, "detail", &idx)
	    || argv_find(argv, argc, "WORD", &idx))
		igmp_show_interfaces_single(vrf->info, vty, argv[idx]->arg, uj);
	else
		igmp_show_interfaces(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

DEFUN (show_ip_igmp_interface_vrf_all,
       show_ip_igmp_interface_vrf_all_cmd,
       "show ip igmp vrf all interface [detail|WORD] [json]",
       SHOW_STR
       IP_STR
       IGMP_STR
       VRF_CMD_HELP_STR
       "IGMP interface information\n"
       "Detailed output\n"
       "interface name\n"
       JSON_STR)
{
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	bool first = true;

	if (uj)
		vty_out(vty, "{ ");
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (uj) {
			if (!first)
				vty_out(vty, ", ");
			vty_out(vty, " \"%s\": ", vrf->name);
			first = false;
		} else
			vty_out(vty, "VRF: %s\n", vrf->name);
		if (argv_find(argv, argc, "detail", &idx)
		    || argv_find(argv, argc, "WORD", &idx))
			igmp_show_interfaces_single(vrf->info, vty,
						    argv[idx]->arg, uj);
		else
			igmp_show_interfaces(vrf->info, vty, uj);
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_igmp_join,
       show_ip_igmp_join_cmd,
       "show ip igmp [vrf NAME] join [json]",
       SHOW_STR
       IP_STR
       IGMP_STR
       VRF_CMD_HELP_STR
       "IGMP static join information\n"
       JSON_STR)
{
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	igmp_show_interface_join(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

DEFUN (show_ip_igmp_join_vrf_all,
       show_ip_igmp_join_vrf_all_cmd,
       "show ip igmp vrf all join [json]",
       SHOW_STR
       IP_STR
       IGMP_STR
       VRF_CMD_HELP_STR
       "IGMP static join information\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	bool first = true;

	if (uj)
		vty_out(vty, "{ ");
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (uj) {
			if (!first)
				vty_out(vty, ", ");
			vty_out(vty, " \"%s\": ", vrf->name);
			first = false;
		} else
			vty_out(vty, "VRF: %s\n", vrf->name);
		igmp_show_interface_join(vrf->info, vty, uj);
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

DEFPY(show_ip_igmp_groups,
      show_ip_igmp_groups_cmd,
      "show ip igmp [vrf NAME$vrf_name] groups [INTERFACE$ifname [GROUP$grp_str]] [detail$detail] [json$json]",
      SHOW_STR
      IP_STR
      IGMP_STR
      VRF_CMD_HELP_STR
      IGMP_GROUP_STR
      "Interface name\n"
      "Group address\n"
      "Detailed Information\n"
      JSON_STR)
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, !!json);

	if (!vrf)
		return CMD_WARNING;

	if (ifname)
		igmp_show_groups_interface_single(vrf->info, vty, !!json,
						  ifname, grp_str, !!detail);
	else
		igmp_show_groups(vrf->info, vty, !!json, NULL, !!detail);

	return CMD_SUCCESS;
}

DEFPY(show_ip_igmp_groups_vrf_all,
      show_ip_igmp_groups_vrf_all_cmd,
      "show ip igmp vrf all groups [GROUP$grp_str] [detail$detail] [json$json]",
      SHOW_STR
      IP_STR
      IGMP_STR
      VRF_CMD_HELP_STR
      IGMP_GROUP_STR
      "Group address\n"
      "Detailed Information\n"
      JSON_STR)
{
	bool uj = !!json;
	struct vrf *vrf;
	bool first = true;

	if (uj)
		vty_out(vty, "{ ");
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (uj) {
			if (!first)
				vty_out(vty, ", ");
			vty_out(vty, " \"%s\": ", vrf->name);
			first = false;
		} else
			vty_out(vty, "VRF: %s\n", vrf->name);
		igmp_show_groups(vrf->info, vty, uj, grp_str, !!detail);
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_igmp_groups_retransmissions,
       show_ip_igmp_groups_retransmissions_cmd,
       "show ip igmp [vrf NAME] groups retransmissions",
       SHOW_STR
       IP_STR
       IGMP_STR
       VRF_CMD_HELP_STR
       IGMP_GROUP_STR
       "IGMP group retransmissions\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	igmp_show_group_retransmission(vrf->info, vty);

	return CMD_SUCCESS;
}

DEFPY(show_ip_igmp_sources,
      show_ip_igmp_sources_cmd,
      "show ip igmp [vrf NAME$vrf_name] sources [INTERFACE$ifname [GROUP$grp_str]] [json$json]",
      SHOW_STR
      IP_STR
      IGMP_STR
      VRF_CMD_HELP_STR
      IGMP_SOURCE_STR
      "Interface name\n"
      "Group address\n"
      JSON_STR)
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, !!json);

	if (!vrf)
		return CMD_WARNING;

	if (ifname)
		igmp_show_sources_interface_single(vrf->info, vty, !!json,
						   ifname, grp_str);
	else
		igmp_show_sources(vrf->info, vty, !!json);

	return CMD_SUCCESS;
}

DEFUN (show_ip_igmp_sources_retransmissions,
       show_ip_igmp_sources_retransmissions_cmd,
       "show ip igmp [vrf NAME] sources retransmissions",
       SHOW_STR
       IP_STR
       IGMP_STR
       VRF_CMD_HELP_STR
       IGMP_SOURCE_STR
       "IGMP source retransmissions\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	igmp_show_source_retransmission(vrf->info, vty);

	return CMD_SUCCESS;
}

DEFUN (show_ip_igmp_statistics,
       show_ip_igmp_statistics_cmd,
       "show ip igmp [vrf NAME] statistics [interface WORD] [json]",
       SHOW_STR
       IP_STR
       IGMP_STR
       VRF_CMD_HELP_STR
       "IGMP statistics\n"
       "interface\n"
       "IGMP interface\n"
       JSON_STR)
{
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	if (argv_find(argv, argc, "WORD", &idx))
		igmp_show_statistics(vrf->info, vty, argv[idx]->arg, uj);
	else
		igmp_show_statistics(vrf->info, vty, NULL, uj);

	return CMD_SUCCESS;
}

DEFUN (show_ip_pim_mlag_summary,
       show_ip_pim_mlag_summary_cmd,
       "show ip pim mlag summary [json]",
       SHOW_STR
       IP_STR
       PIM_STR
       "MLAG\n"
       "status and stats\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	char role_buf[MLAG_ROLE_STRSIZE];
	char addr_buf[INET_ADDRSTRLEN];

	if (uj) {
		json_object *json = NULL;
		json_object *json_stat = NULL;

		json = json_object_new_object();
		if (router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP)
			json_object_boolean_true_add(json, "mlagConnUp");
		if (router->mlag_flags & PIM_MLAGF_PEER_CONN_UP)
			json_object_boolean_true_add(json, "mlagPeerConnUp");
		if (router->mlag_flags & PIM_MLAGF_PEER_ZEBRA_UP)
			json_object_boolean_true_add(json, "mlagPeerZebraUp");
		json_object_string_add(json, "mlagRole",
				       mlag_role2str(router->mlag_role,
						     role_buf, sizeof(role_buf)));
		inet_ntop(AF_INET, &router->local_vtep_ip,
			  addr_buf, INET_ADDRSTRLEN);
		json_object_string_add(json, "localVtepIp", addr_buf);
		inet_ntop(AF_INET, &router->anycast_vtep_ip,
			  addr_buf, INET_ADDRSTRLEN);
		json_object_string_add(json, "anycastVtepIp", addr_buf);
		json_object_string_add(json, "peerlinkRif",
				       router->peerlink_rif);

		json_stat = json_object_new_object();
		json_object_int_add(json_stat, "mlagConnFlaps",
				    router->mlag_stats.mlagd_session_downs);
		json_object_int_add(json_stat, "mlagPeerConnFlaps",
				    router->mlag_stats.peer_session_downs);
		json_object_int_add(json_stat, "mlagPeerZebraFlaps",
				    router->mlag_stats.peer_zebra_downs);
		json_object_int_add(json_stat, "mrouteAddRx",
				    router->mlag_stats.msg.mroute_add_rx);
		json_object_int_add(json_stat, "mrouteAddTx",
				    router->mlag_stats.msg.mroute_add_tx);
		json_object_int_add(json_stat, "mrouteDelRx",
				    router->mlag_stats.msg.mroute_del_rx);
		json_object_int_add(json_stat, "mrouteDelTx",
				    router->mlag_stats.msg.mroute_del_tx);
		json_object_int_add(json_stat, "mlagStatusUpdates",
				    router->mlag_stats.msg.mlag_status_updates);
		json_object_int_add(json_stat, "peerZebraStatusUpdates",
				    router->mlag_stats.msg.peer_zebra_status_updates);
		json_object_int_add(json_stat, "pimStatusUpdates",
				    router->mlag_stats.msg.pim_status_updates);
		json_object_int_add(json_stat, "vxlanUpdates",
				    router->mlag_stats.msg.vxlan_updates);
		json_object_object_add(json, "connStats", json_stat);

		vty_json(vty, json);
		return CMD_SUCCESS;
	}

	vty_out(vty, "MLAG daemon connection: %s\n",
		(router->mlag_flags & PIM_MLAGF_LOCAL_CONN_UP)
		? "up" : "down");
	vty_out(vty, "MLAG peer state: %s\n",
		(router->mlag_flags & PIM_MLAGF_PEER_CONN_UP)
		? "up" : "down");
	vty_out(vty, "Zebra peer state: %s\n",
		(router->mlag_flags & PIM_MLAGF_PEER_ZEBRA_UP)
		? "up" : "down");
	vty_out(vty, "MLAG role: %s\n",
		mlag_role2str(router->mlag_role, role_buf, sizeof(role_buf)));
	inet_ntop(AF_INET, &router->local_vtep_ip,
		  addr_buf, INET_ADDRSTRLEN);
	vty_out(vty, "Local VTEP IP: %s\n", addr_buf);
	inet_ntop(AF_INET, &router->anycast_vtep_ip,
		  addr_buf, INET_ADDRSTRLEN);
	vty_out(vty, "Anycast VTEP IP: %s\n", addr_buf);
	vty_out(vty, "Peerlink: %s\n", router->peerlink_rif);
	vty_out(vty, "Session flaps: mlagd: %d mlag-peer: %d zebra-peer: %d\n",
		router->mlag_stats.mlagd_session_downs,
		router->mlag_stats.peer_session_downs,
		router->mlag_stats.peer_zebra_downs);
	vty_out(vty, "Message Statistics:\n");
	vty_out(vty, "  mroute adds: rx: %d, tx: %d\n",
		router->mlag_stats.msg.mroute_add_rx,
		router->mlag_stats.msg.mroute_add_tx);
	vty_out(vty, "  mroute dels: rx: %d, tx: %d\n",
		router->mlag_stats.msg.mroute_del_rx,
		router->mlag_stats.msg.mroute_del_tx);
	vty_out(vty, "  peer zebra status updates: %d\n",
		router->mlag_stats.msg.peer_zebra_status_updates);
	vty_out(vty, "  PIM status updates: %d\n",
		router->mlag_stats.msg.pim_status_updates);
	vty_out(vty, "  VxLAN updates: %d\n",
		router->mlag_stats.msg.vxlan_updates);

	return CMD_SUCCESS;
}

DEFUN (show_ip_pim_assert,
       show_ip_pim_assert_cmd,
       "show ip pim [vrf NAME] assert",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface assert\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	pim_show_assert(vrf->info, vty);

	return CMD_SUCCESS;
}

DEFUN (show_ip_pim_assert_internal,
       show_ip_pim_assert_internal_cmd,
       "show ip pim [vrf NAME] assert-internal",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface internal assert state\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	pim_show_assert_internal(vrf->info, vty);

	return CMD_SUCCESS;
}

DEFUN (show_ip_pim_assert_metric,
       show_ip_pim_assert_metric_cmd,
       "show ip pim [vrf NAME] assert-metric",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface assert metric\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	pim_show_assert_metric(vrf->info, vty);

	return CMD_SUCCESS;
}

DEFUN (show_ip_pim_assert_winner_metric,
       show_ip_pim_assert_winner_metric_cmd,
       "show ip pim [vrf NAME] assert-winner-metric",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface assert winner metric\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	pim_show_assert_winner_metric(vrf->info, vty);

	return CMD_SUCCESS;
}

DEFPY (show_ip_pim_interface,
       show_ip_pim_interface_cmd,
       "show ip pim [mlag$mlag] [vrf NAME] interface [detail|WORD]$interface [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       "MLAG\n"
       VRF_CMD_HELP_STR
       "PIM interface information\n"
       "Detailed output\n"
       "interface name\n"
       JSON_STR)
{
	return pim_show_interface_cmd_helper(vrf, vty, !!json, !!mlag,
					     interface);
}

DEFPY (show_ip_pim_interface_vrf_all,
       show_ip_pim_interface_vrf_all_cmd,
       "show ip pim [mlag$mlag] vrf all interface [detail|WORD]$interface [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       "MLAG\n"
       VRF_CMD_HELP_STR
       "PIM interface information\n"
       "Detailed output\n"
       "interface name\n"
       JSON_STR)
{
	return pim_show_interface_vrf_all_cmd_helper(vty, !!json, !!mlag,
						     interface);
}

DEFPY (show_ip_pim_join,
       show_ip_pim_join_cmd,
       "show ip pim [vrf NAME] join [A.B.C.D$s_or_g [A.B.C.D$g]] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface join information\n"
       "The Source or Group\n"
       "The Group\n"
       JSON_STR)
{
	return pim_show_join_cmd_helper(vrf, vty, s_or_g, g, json);
}

DEFPY (show_ip_pim_join_vrf_all,
       show_ip_pim_join_vrf_all_cmd,
       "show ip pim vrf all join [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface join information\n"
       JSON_STR)
{
	return pim_show_join_vrf_all_cmd_helper(vty, json);
}

DEFPY (show_ip_pim_jp_agg,
       show_ip_pim_jp_agg_cmd,
       "show ip pim [vrf NAME] jp-agg",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "join prune aggregation list\n")
{
	return pim_show_jp_agg_list_cmd_helper(vrf, vty);
}

DEFPY (show_ip_pim_local_membership,
       show_ip_pim_local_membership_cmd,
       "show ip pim [vrf NAME] local-membership [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface local-membership\n"
       JSON_STR)
{
	return pim_show_membership_cmd_helper(vrf, vty, !!json);
}

static void pim_show_mlag_up_entry_detail(struct vrf *vrf,
					  struct vty *vty,
					  struct pim_upstream *up,
					  char *src_str, char *grp_str,
					  json_object *json)
{
	if (json) {
		json_object *json_row = NULL;
		json_object *own_list = NULL;
		json_object *json_group = NULL;


		json_object_object_get_ex(json, grp_str, &json_group);
		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, grp_str,
					       json_group);
		}

		json_row = json_object_new_object();
		json_object_string_add(json_row, "source", src_str);
		json_object_string_add(json_row, "group", grp_str);

		own_list = json_object_new_array();
		if (pim_up_mlag_is_local(up))
			json_object_array_add(own_list,
					      json_object_new_string("local"));
		if (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_PEER))
			json_object_array_add(own_list,
					      json_object_new_string("peer"));
		if (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE))
			json_object_array_add(
				own_list, json_object_new_string("Interface"));
		json_object_object_add(json_row, "owners", own_list);

		json_object_int_add(json_row, "localCost",
				    pim_up_mlag_local_cost(up));
		json_object_int_add(json_row, "peerCost",
				    pim_up_mlag_peer_cost(up));
		if (PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags))
			json_object_boolean_false_add(json_row, "df");
		else
			json_object_boolean_true_add(json_row, "df");
		json_object_object_add(json_group, src_str, json_row);
	} else {
		char own_str[6];

		own_str[0] = '\0';
		if (pim_up_mlag_is_local(up))
			strlcat(own_str, "L", sizeof(own_str));
		if (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_PEER))
			strlcat(own_str, "P", sizeof(own_str));
		if (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE))
			strlcat(own_str, "I", sizeof(own_str));
		/* XXX - fixup, print paragraph output */
		vty_out(vty,
			"%-15s %-15s %-6s %-11u %-10d %2s\n",
			src_str, grp_str, own_str,
			pim_up_mlag_local_cost(up),
			pim_up_mlag_peer_cost(up),
			PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags)
			? "n" : "y");
	}
}

static void pim_show_mlag_up_detail(struct vrf *vrf,
				    struct vty *vty, const char *src_or_group,
				    const char *group, bool uj)
{
	char src_str[PIM_ADDRSTRLEN];
	char grp_str[PIM_ADDRSTRLEN];
	struct pim_upstream *up;
	struct pim_instance *pim = vrf->info;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();
	else
		vty_out(vty,
			"Source          Group           Owner  Local-cost  Peer-cost  DF\n");

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!(up->flags & PIM_UPSTREAM_FLAG_MASK_MLAG_PEER)
		    && !(up->flags & PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE)
		    && !pim_up_mlag_is_local(up))
			continue;

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs", &up->sg.grp);
		snprintfrr(src_str, sizeof(src_str), "%pPAs", &up->sg.src);

		/* XXX: strcmps are clearly inefficient. we should do uint comps
		 * here instead.
		 */
		if (group) {
			if (strcmp(src_str, src_or_group) ||
			    strcmp(grp_str, group))
				continue;
		} else {
			if (strcmp(src_str, src_or_group) &&
			    strcmp(grp_str, src_or_group))
				continue;
		}
		pim_show_mlag_up_entry_detail(vrf, vty, up,
					      src_str, grp_str, json);
	}

	if (uj)
		vty_json(vty, json);
}

static void pim_show_mlag_up_vrf(struct vrf *vrf, struct vty *vty, bool uj)
{
	json_object *json = NULL;
	json_object *json_row;
	struct pim_upstream *up;
	struct pim_instance *pim = vrf->info;
	json_object *json_group = NULL;

	if (uj) {
		json = json_object_new_object();
	} else {
		vty_out(vty,
			"Source          Group           Owner  Local-cost  Peer-cost  DF\n");
	}

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!(up->flags & PIM_UPSTREAM_FLAG_MASK_MLAG_PEER)
		    && !(up->flags & PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE)
		    && !pim_up_mlag_is_local(up))
			continue;
		if (uj) {
			char src_str[PIM_ADDRSTRLEN];
			char grp_str[PIM_ADDRSTRLEN];
			json_object *own_list = NULL;

			snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
				   &up->sg.grp);
			snprintfrr(src_str, sizeof(src_str), "%pPAs",
				   &up->sg.src);

			json_object_object_get_ex(json, grp_str, &json_group);
			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			json_row = json_object_new_object();
			json_object_string_add(json_row, "vrf", vrf->name);
			json_object_string_add(json_row, "source", src_str);
			json_object_string_add(json_row, "group", grp_str);

			own_list = json_object_new_array();
			if (pim_up_mlag_is_local(up)) {

				json_object_array_add(own_list,
						      json_object_new_string(
							      "local"));
			}
			if (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_PEER)) {
				json_object_array_add(own_list,
						      json_object_new_string(
							      "peer"));
			}
			json_object_object_add(json_row, "owners", own_list);

			json_object_int_add(json_row, "localCost",
					    pim_up_mlag_local_cost(up));
			json_object_int_add(json_row, "peerCost",
					    pim_up_mlag_peer_cost(up));
			if (PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags))
				json_object_boolean_false_add(json_row, "df");
			else
				json_object_boolean_true_add(json_row, "df");
			json_object_object_add(json_group, src_str, json_row);
		} else {
			char own_str[6];

			own_str[0] = '\0';
			if (pim_up_mlag_is_local(up))
				strlcat(own_str, "L", sizeof(own_str));
			if (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_PEER))
				strlcat(own_str, "P", sizeof(own_str));
			if (up->flags & (PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE))
				strlcat(own_str, "I", sizeof(own_str));
			vty_out(vty,
				"%-15pPAs %-15pPAs %-6s %-11u %-10u %2s\n",
				&up->sg.src, &up->sg.grp, own_str,
				pim_up_mlag_local_cost(up),
				pim_up_mlag_peer_cost(up),
				PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags)
				? "n" : "y");
		}
	}
	if (uj)
		vty_json(vty, json);
}

static void pim_show_mlag_help_string(struct vty *vty, bool uj)
{
	if (!uj) {
		vty_out(vty, "Owner codes:\n");
		vty_out(vty,
			"L: EVPN-MLAG Entry, I:PIM-MLAG Entry, P: Peer Entry\n");
	}
}


DEFUN(show_ip_pim_mlag_up, show_ip_pim_mlag_up_cmd,
      "show ip pim [vrf NAME] mlag upstream [A.B.C.D [A.B.C.D]] [json]",
      SHOW_STR
      IP_STR
      PIM_STR
      VRF_CMD_HELP_STR
      "MLAG\n"
      "upstream\n"
      "Unicast or Multicast address\n"
      "Multicast address\n" JSON_STR)
{
	const char *src_or_group = NULL;
	const char *group = NULL;
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf || !vrf->info) {
		vty_out(vty, "%s: VRF or Info missing\n", __func__);
		return CMD_WARNING;
	}

	if (uj)
		argc--;

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		src_or_group = argv[idx]->arg;
		if (idx + 1 < argc)
			group = argv[idx + 1]->arg;
	}

	pim_show_mlag_help_string(vty, uj);

	if (src_or_group)
		pim_show_mlag_up_detail(vrf, vty, src_or_group, group, uj);
	else
		pim_show_mlag_up_vrf(vrf, vty, uj);

	return CMD_SUCCESS;
}


DEFUN(show_ip_pim_mlag_up_vrf_all, show_ip_pim_mlag_up_vrf_all_cmd,
      "show ip pim vrf all mlag upstream [json]",
      SHOW_STR IP_STR PIM_STR VRF_CMD_HELP_STR
      "MLAG\n"
      "upstream\n" JSON_STR)
{
	struct vrf *vrf;
	bool uj = use_json(argc, argv);

	pim_show_mlag_help_string(vty, uj);
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		pim_show_mlag_up_vrf(vrf, vty, uj);
	}

	return CMD_SUCCESS;
}

DEFPY (show_ip_pim_neighbor,
       show_ip_pim_neighbor_cmd,
       "show ip pim [vrf NAME] neighbor [detail|WORD]$interface [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM neighbor information\n"
       "Detailed output\n"
       "Name of interface or neighbor\n"
       JSON_STR)
{
	return pim_show_neighbors_cmd_helper(vrf, vty, json, interface);
}

DEFPY (show_ip_pim_neighbor_vrf_all,
       show_ip_pim_neighbor_vrf_all_cmd,
       "show ip pim vrf all neighbor [detail|WORD]$interface [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM neighbor information\n"
       "Detailed output\n"
       "Name of interface or neighbor\n"
       JSON_STR)
{
	return pim_show_neighbors_vrf_all_cmd_helper(vty, json, interface);
}

DEFPY (show_ip_pim_secondary,
       show_ip_pim_secondary_cmd,
       "show ip pim [vrf NAME] secondary",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM neighbor addresses\n")
{
	return pim_show_secondary_helper(vrf, vty);
}

DEFPY (show_ip_pim_state,
       show_ip_pim_state_cmd,
       "show ip pim [vrf NAME] state [A.B.C.D$s_or_g [A.B.C.D$g]] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM state information\n"
       "Unicast or Multicast address\n"
       "Multicast address\n"
       JSON_STR)
{
	return pim_show_state_helper(vrf, vty, s_or_g_str, g_str, !!json);
}

DEFPY (show_ip_pim_state_vrf_all,
       show_ip_pim_state_vrf_all_cmd,
       "show ip pim vrf all state [A.B.C.D$s_or_g [A.B.C.D$g]] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM state information\n"
       "Unicast or Multicast address\n"
       "Multicast address\n"
       JSON_STR)
{
	return pim_show_state_vrf_all_helper(vty, s_or_g_str, g_str, !!json);
}

DEFPY (show_ip_pim_upstream,
       show_ip_pim_upstream_cmd,
       "show ip pim [vrf NAME] upstream [A.B.C.D$s_or_g [A.B.C.D$g]] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream information\n"
       "The Source or Group\n"
       "The Group\n"
       JSON_STR)
{
	return pim_show_upstream_helper(vrf, vty, s_or_g, g, !!json);
}

DEFPY (show_ip_pim_upstream_vrf_all,
       show_ip_pim_upstream_vrf_all_cmd,
       "show ip pim vrf all upstream [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream information\n"
       JSON_STR)
{
	return pim_show_upstream_vrf_all_helper(vty, !!json);
}

DEFPY (show_ip_pim_channel,
       show_ip_pim_channel_cmd,
       "show ip pim [vrf NAME] channel [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM downstream channel info\n"
       JSON_STR)
{
	return pim_show_channel_cmd_helper(vrf, vty, !!json);
}

DEFPY (show_ip_pim_upstream_join_desired,
       show_ip_pim_upstream_join_desired_cmd,
       "show ip pim [vrf NAME] upstream-join-desired [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream join-desired\n"
       JSON_STR)
{
	return pim_show_upstream_join_desired_helper(vrf, vty, !!json);
}

DEFPY (show_ip_pim_upstream_rpf,
       show_ip_pim_upstream_rpf_cmd,
       "show ip pim [vrf NAME] upstream-rpf [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream source rpf\n"
       JSON_STR)
{
	return pim_show_upstream_rpf_helper(vrf, vty, !!json);
}

DEFPY (show_ip_pim_rp,
       show_ip_pim_rp_cmd,
       "show ip pim [vrf NAME] rp-info [A.B.C.D/M$group] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM RP information\n"
       "Multicast Group range\n"
       JSON_STR)
{
	return pim_show_rp_helper(vrf, vty, group_str, (struct prefix *)group,
				  !!json);
}

DEFPY (show_ip_pim_rp_vrf_all,
       show_ip_pim_rp_vrf_all_cmd,
       "show ip pim vrf all rp-info [A.B.C.D/M$group] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM RP information\n"
       "Multicast Group range\n"
       JSON_STR)
{
	return pim_show_rp_vrf_all_helper(vty, group_str,
					  (struct prefix *)group, !!json);
}

DEFPY (show_ip_pim_rpf,
       show_ip_pim_rpf_cmd,
       "show ip pim [vrf NAME] rpf [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached source rpf information\n"
       JSON_STR)
{
	return pim_show_rpf_helper(vrf, vty, !!json);
}

DEFPY (show_ip_pim_rpf_vrf_all,
       show_ip_pim_rpf_vrf_all_cmd,
       "show ip pim vrf all rpf [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached source rpf information\n"
       JSON_STR)
{
	return pim_show_rpf_vrf_all_helper(vty, !!json);
}

DEFPY (show_ip_pim_nexthop,
       show_ip_pim_nexthop_cmd,
       "show ip pim [vrf NAME] nexthop [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached nexthop rpf information\n"
       JSON_STR)
{
	return pim_show_nexthop_cmd_helper(vrf, vty, !!json);
}

DEFPY (show_ip_pim_nexthop_lookup,
       show_ip_pim_nexthop_lookup_cmd,
       "show ip pim [vrf NAME] nexthop-lookup A.B.C.D$source A.B.C.D$group",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached nexthop rpf lookup\n"
       "Source/RP address\n"
       "Multicast Group address\n")
{
	return pim_show_nexthop_lookup_cmd_helper(vrf, vty, source, group);
}

DEFPY (show_ip_pim_interface_traffic,
       show_ip_pim_interface_traffic_cmd,
       "show ip pim [vrf NAME] interface traffic [WORD$if_name] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface information\n"
       "Protocol Packet counters\n"
       "Interface name\n"
       JSON_STR)
{
	return pim_show_interface_traffic_helper(vrf, if_name, vty, !!json);
}

DEFPY (show_ip_pim_bsm_db,
       show_ip_pim_bsm_db_cmd,
       "show ip pim bsm-database [vrf NAME] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       "PIM cached bsm packets information\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_bsm_db_helper(vrf, vty, !!json);
}

DEFPY (show_ip_pim_bsrp,
       show_ip_pim_bsrp_cmd,
       "show ip pim bsrp-info [vrf NAME] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       "PIM cached group-rp mappings information\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_group_rp_mappings_info_helper(vrf, vty, !!json);
}

DEFPY (show_ip_pim_statistics,
       show_ip_pim_statistics_cmd,
       "show ip pim [vrf NAME] statistics [interface WORD$word] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM statistics\n"
       INTERFACE_STR
       "PIM interface\n"
       JSON_STR)
{
	return pim_show_statistics_helper(vrf, vty, word, !!json);
}

DEFPY (show_ip_multicast,
       show_ip_multicast_cmd,
       "show ip multicast [vrf NAME]",
       SHOW_STR
       IP_STR
       "Multicast global information\n"
       VRF_CMD_HELP_STR)
{
	return pim_show_multicast_helper(vrf, vty);
}

DEFPY (show_ip_multicast_vrf_all,
       show_ip_multicast_vrf_all_cmd,
       "show ip multicast vrf all",
       SHOW_STR
       IP_STR
       "Multicast global information\n"
       VRF_CMD_HELP_STR)
{
	return pim_show_multicast_vrf_all_helper(vty);
}

DEFPY (show_ip_multicast_count,
       show_ip_multicast_count_cmd,
       "show ip multicast count [vrf NAME] [json$json]",
       SHOW_STR
       IP_STR
       "Multicast global information\n"
       "Data packet count\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_multicast_count_helper(vrf, vty, !!json);
}

DEFPY (show_ip_multicast_count_vrf_all,
       show_ip_multicast_count_vrf_all_cmd,
       "show ip multicast count vrf all [json$json]",
       SHOW_STR
       IP_STR
       "Multicast global information\n"
       "Data packet count\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_multicast_count_vrf_all_helper(vty, !!json);
}

DEFPY (show_ip_mroute,
       show_ip_mroute_cmd,
       "show ip mroute [vrf NAME] [A.B.C.D$s_or_g [A.B.C.D$g]] [fill$fill] [json$json]",
       SHOW_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "The Source or Group\n"
       "The Group\n"
       "Fill in Assumed data\n"
       JSON_STR)
{
	return pim_show_mroute_helper(vrf, vty, s_or_g, g, !!fill, !!json);
}

DEFPY (show_ip_mroute_vrf_all,
       show_ip_mroute_vrf_all_cmd,
       "show ip mroute vrf all [fill$fill] [json$json]",
       SHOW_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Fill in Assumed data\n"
       JSON_STR)
{
	return pim_show_mroute_vrf_all_helper(vty, !!fill, !!json);
}

DEFPY (clear_ip_mroute_count,
       clear_ip_mroute_count_cmd,
       "clear ip mroute [vrf NAME]$name count",
       CLEAR_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Route and packet count data\n")
{
	return clear_ip_mroute_count_command(vty, name);
}

DEFPY (show_ip_mroute_count,
       show_ip_mroute_count_cmd,
       "show ip mroute [vrf NAME] count [json$json]",
       SHOW_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Route and packet count data\n"
       JSON_STR)
{
	return pim_show_mroute_count_helper(vrf, vty, !!json);
}

DEFPY (show_ip_mroute_count_vrf_all,
       show_ip_mroute_count_vrf_all_cmd,
       "show ip mroute vrf all count [json$json]",
       SHOW_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Route and packet count data\n"
       JSON_STR)
{
	return pim_show_mroute_count_vrf_all_helper(vty, !!json);
}

DEFPY (show_ip_mroute_summary,
       show_ip_mroute_summary_cmd,
       "show ip mroute [vrf NAME] summary [json$json]",
       SHOW_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Summary of all mroutes\n"
       JSON_STR)
{
	return pim_show_mroute_summary_helper(vrf, vty, !!json);
}

DEFPY (show_ip_mroute_summary_vrf_all,
       show_ip_mroute_summary_vrf_all_cmd,
       "show ip mroute vrf all summary [json$json]",
       SHOW_STR
       IP_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Summary of all mroutes\n"
       JSON_STR)
{
	return pim_show_mroute_summary_vrf_all_helper(vty, !!json);
}

DEFUN (show_ip_rib,
       show_ip_rib_cmd,
       "show ip rib [vrf NAME] A.B.C.D",
       SHOW_STR
       IP_STR
       RIB_STR
       VRF_CMD_HELP_STR
       "Unicast address\n")
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);
	struct in_addr addr;
	const char *addr_str;
	struct pim_nexthop nexthop;
	int result;

	if (!vrf)
		return CMD_WARNING;

	memset(&nexthop, 0, sizeof(nexthop));
	argv_find(argv, argc, "A.B.C.D", &idx);
	addr_str = argv[idx]->arg;
	result = inet_pton(AF_INET, addr_str, &addr);
	if (result <= 0) {
		vty_out(vty, "Bad unicast address %s: errno=%d: %s\n", addr_str,
			errno, safe_strerror(errno));
		return CMD_WARNING;
	}

	if (!pim_nexthop_lookup(vrf->info, &nexthop, addr, 0)) {
		vty_out(vty,
			"Failure querying RIB nexthop for unicast address %s\n",
			addr_str);
		return CMD_WARNING;
	}

	vty_out(vty,
		"Address         NextHop         Interface Metric Preference\n");

	vty_out(vty, "%-15s %-15pPAs %-9s %6d %10d\n", addr_str,
		&nexthop.mrib_nexthop_addr,
		nexthop.interface ? nexthop.interface->name : "<ifname?>",
		nexthop.mrib_route_metric, nexthop.mrib_metric_preference);

	return CMD_SUCCESS;
}

static void show_ssmpingd(struct pim_instance *pim, struct vty *vty)
{
	struct listnode *node;
	struct ssmpingd_sock *ss;
	time_t now;

	vty_out(vty,
		"Source          Socket Address          Port Uptime   Requests\n");

	if (!pim->ssmpingd_list)
		return;

	now = pim_time_monotonic_sec();

	for (ALL_LIST_ELEMENTS_RO(pim->ssmpingd_list, node, ss)) {
		char source_str[INET_ADDRSTRLEN];
		char ss_uptime[10];
		struct sockaddr_in bind_addr;
		socklen_t len = sizeof(bind_addr);
		char bind_addr_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<src?>", ss->source_addr, source_str,
			       sizeof(source_str));

		if (pim_socket_getsockname(
			    ss->sock_fd, (struct sockaddr *)&bind_addr, &len)) {
			vty_out(vty,
				"%% Failure reading socket name for ssmpingd source %s on fd=%d\n",
				source_str, ss->sock_fd);
		}

		pim_inet4_dump("<addr?>", bind_addr.sin_addr, bind_addr_str,
			       sizeof(bind_addr_str));
		pim_time_uptime(ss_uptime, sizeof(ss_uptime),
				now - ss->creation);

		vty_out(vty, "%-15s %6d %-15s %5d %8s %8lld\n", source_str,
			ss->sock_fd, bind_addr_str, ntohs(bind_addr.sin_port),
			ss_uptime, (long long)ss->requests);
	}
}

DEFUN (show_ip_ssmpingd,
       show_ip_ssmpingd_cmd,
       "show ip ssmpingd [vrf NAME]",
       SHOW_STR
       IP_STR
       SHOW_SSMPINGD_STR
       VRF_CMD_HELP_STR)
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, false);

	if (!vrf)
		return CMD_WARNING;

	show_ssmpingd(vrf->info, vty);
	return CMD_SUCCESS;
}

DEFUN (ip_pim_spt_switchover_infinity,
       ip_pim_spt_switchover_infinity_cmd,
       "ip pim spt-switchover infinity-and-beyond",
       IP_STR
       PIM_STR
       "SPT-Switchover\n"
       "Never switch to SPT Tree\n")
{
	return pim_process_spt_switchover_infinity_cmd(vty);
}

DEFPY (ip_pim_spt_switchover_infinity_plist,
       ip_pim_spt_switchover_infinity_plist_cmd,
       "ip pim spt-switchover infinity-and-beyond prefix-list PREFIXLIST4_NAME$plist",
       IP_STR
       PIM_STR
       "SPT-Switchover\n"
       "Never switch to SPT Tree\n"
       "Prefix-List to control which groups to switch\n"
       "Prefix-List name\n")
{
	return pim_process_spt_switchover_prefixlist_cmd(vty, plist);
}

DEFUN (no_ip_pim_spt_switchover_infinity,
       no_ip_pim_spt_switchover_infinity_cmd,
       "no ip pim spt-switchover infinity-and-beyond",
       NO_STR
       IP_STR
       PIM_STR
       "SPT_Switchover\n"
       "Never switch to SPT Tree\n")
{
	return pim_process_no_spt_switchover_cmd(vty);
}

DEFUN (no_ip_pim_spt_switchover_infinity_plist,
       no_ip_pim_spt_switchover_infinity_plist_cmd,
       "no ip pim spt-switchover infinity-and-beyond prefix-list PREFIXLIST4_NAME",
       NO_STR
       IP_STR
       PIM_STR
       "SPT_Switchover\n"
       "Never switch to SPT Tree\n"
       "Prefix-List to control which groups to switch\n"
       "Prefix-List name\n")
{
	return pim_process_no_spt_switchover_cmd(vty);
}

DEFPY (pim_register_accept_list,
       pim_register_accept_list_cmd,
       "[no] ip pim register-accept-list PREFIXLIST4_NAME$word",
       NO_STR
       IP_STR
       PIM_STR
       "Only accept registers from a specific source prefix list\n"
       "Prefix-List name\n")
{
	const char *vrfname;
	char reg_alist_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(reg_alist_xpath, sizeof(reg_alist_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 "frr-routing:ipv4");
	strlcat(reg_alist_xpath, "/register-accept-list",
		sizeof(reg_alist_xpath));

	if (no)
		nb_cli_enqueue_change(vty, reg_alist_xpath,
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, reg_alist_xpath,
				      NB_OP_MODIFY, word);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY (ip_pim_joinprune_time,
       ip_pim_joinprune_time_cmd,
       "ip pim join-prune-interval (1-65535)$jpi",
       IP_STR
       "pim multicast routing\n"
       "Join Prune Send Interval\n"
       "Seconds\n")
{
	return pim_process_join_prune_cmd(vty, jpi_str);
}

DEFUN (no_ip_pim_joinprune_time,
       no_ip_pim_joinprune_time_cmd,
       "no ip pim join-prune-interval [(1-65535)]",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Join Prune Send Interval\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_join_prune_cmd(vty);
}

DEFPY (ip_pim_register_suppress,
       ip_pim_register_suppress_cmd,
       "ip pim register-suppress-time (1-65535)$rst",
       IP_STR
       "pim multicast routing\n"
       "Register Suppress Timer\n"
       "Seconds\n")
{
	return pim_process_register_suppress_cmd(vty, rst_str);
}

DEFUN (no_ip_pim_register_suppress,
       no_ip_pim_register_suppress_cmd,
       "no ip pim register-suppress-time [(1-65535)]",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Register Suppress Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_register_suppress_cmd(vty);
}

DEFPY (ip_pim_rp_keep_alive,
       ip_pim_rp_keep_alive_cmd,
       "ip pim rp keep-alive-timer (1-65535)$kat",
       IP_STR
       "pim multicast routing\n"
       "Rendezvous Point\n"
       "Keep alive Timer\n"
       "Seconds\n")
{
	return pim_process_rp_kat_cmd(vty, kat_str);
}

DEFUN (no_ip_pim_rp_keep_alive,
       no_ip_pim_rp_keep_alive_cmd,
       "no ip pim rp keep-alive-timer [(1-65535)]",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Rendezvous Point\n"
       "Keep alive Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_rp_kat_cmd(vty);
}

DEFPY (ip_pim_keep_alive,
       ip_pim_keep_alive_cmd,
       "ip pim keep-alive-timer (1-65535)$kat",
       IP_STR
       "pim multicast routing\n"
       "Keep alive Timer\n"
       "Seconds\n")
{
	return pim_process_keepalivetimer_cmd(vty, kat_str);
}

DEFUN (no_ip_pim_keep_alive,
       no_ip_pim_keep_alive_cmd,
       "no ip pim keep-alive-timer [(1-65535)]",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Keep alive Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_keepalivetimer_cmd(vty);
}

DEFPY (ip_pim_packets,
       ip_pim_packets_cmd,
       "ip pim packets (1-255)",
       IP_STR
       "pim multicast routing\n"
       "packets to process at one time per fd\n"
       "Number of packets\n")
{
	return pim_process_pim_packet_cmd(vty, packets_str);
}

DEFUN (no_ip_pim_packets,
       no_ip_pim_packets_cmd,
       "no ip pim packets [(1-255)]",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "packets to process at one time per fd\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_pim_packet_cmd(vty);
}

DEFPY (ip_igmp_group_watermark,
       ip_igmp_group_watermark_cmd,
       "ip igmp watermark-warn (1-65535)$limit",
       IP_STR
       IGMP_STR
       "Configure group limit for watermark warning\n"
       "Group count to generate watermark warning\n")
{
	PIM_DECLVAR_CONTEXT_VRF(vrf, pim);
	pim->gm_watermark_limit = limit;

	return CMD_SUCCESS;
}

DEFPY (no_ip_igmp_group_watermark,
       no_ip_igmp_group_watermark_cmd,
       "no ip igmp watermark-warn [(1-65535)$limit]",
       NO_STR
       IP_STR
       IGMP_STR
       "Unconfigure group limit for watermark warning\n"
       IGNORED_IN_NO_STR)
{
	PIM_DECLVAR_CONTEXT_VRF(vrf, pim);
	pim->gm_watermark_limit = 0;

	return CMD_SUCCESS;
}

DEFUN (ip_pim_v6_secondary,
       ip_pim_v6_secondary_cmd,
       "ip pim send-v6-secondary",
       IP_STR
       "pim multicast routing\n"
       "Send v6 secondary addresses\n")
{
	const char *vrfname;
	char send_v6_secondary_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(send_v6_secondary_xpath, sizeof(send_v6_secondary_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(send_v6_secondary_xpath, "/send-v6-secondary",
		sizeof(send_v6_secondary_xpath));

	nb_cli_enqueue_change(vty, send_v6_secondary_xpath, NB_OP_MODIFY,
			      "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (no_ip_pim_v6_secondary,
       no_ip_pim_v6_secondary_cmd,
       "no ip pim send-v6-secondary",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Send v6 secondary addresses\n")
{
	const char *vrfname;
	char send_v6_secondary_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(send_v6_secondary_xpath, sizeof(send_v6_secondary_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(send_v6_secondary_xpath, "/send-v6-secondary",
		sizeof(send_v6_secondary_xpath));

	nb_cli_enqueue_change(vty, send_v6_secondary_xpath, NB_OP_MODIFY,
			      "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY (ip_pim_rp,
       ip_pim_rp_cmd,
       "ip pim rp A.B.C.D$rp [A.B.C.D/M]$gp",
       IP_STR
       "pim multicast routing\n"
       "Rendezvous Point\n"
       "ip address of RP\n"
       "Group Address range to cover\n")
{
	const char *group_str = (gp_str) ? gp_str : "224.0.0.0/4";

	return pim_process_rp_cmd(vty, rp_str, group_str);
}

DEFPY (ip_pim_rp_prefix_list,
       ip_pim_rp_prefix_list_cmd,
       "ip pim rp A.B.C.D$rp prefix-list PREFIXLIST4_NAME$plist",
       IP_STR
       "pim multicast routing\n"
       "Rendezvous Point\n"
       "ip address of RP\n"
       "group prefix-list filter\n"
       "Name of a prefix-list\n")
{
	return pim_process_rp_plist_cmd(vty, rp_str, plist);
}

DEFPY (no_ip_pim_rp,
       no_ip_pim_rp_cmd,
       "no ip pim rp A.B.C.D$rp [A.B.C.D/M]$gp",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Rendezvous Point\n"
       "ip address of RP\n"
       "Group Address range to cover\n")
{
	const char *group_str = (gp_str) ? gp_str : "224.0.0.0/4";

	return pim_process_no_rp_cmd(vty, rp_str, group_str);
}

DEFPY (no_ip_pim_rp_prefix_list,
       no_ip_pim_rp_prefix_list_cmd,
       "no ip pim rp A.B.C.D$rp prefix-list PREFIXLIST4_NAME$plist",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Rendezvous Point\n"
       "ip address of RP\n"
       "group prefix-list filter\n"
       "Name of a prefix-list\n")
{
	return pim_process_no_rp_plist_cmd(vty, rp_str, plist);
}

DEFUN (ip_pim_ssm_prefix_list,
       ip_pim_ssm_prefix_list_cmd,
       "ip pim ssm prefix-list PREFIXLIST4_NAME",
       IP_STR
       "pim multicast routing\n"
       "Source Specific Multicast\n"
       "group range prefix-list filter\n"
       "Name of a prefix-list\n")
{
	const char *vrfname;
	char ssm_plist_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ssm_plist_xpath, sizeof(ssm_plist_xpath), FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ssm_plist_xpath, "/ssm-prefix-list", sizeof(ssm_plist_xpath));

	nb_cli_enqueue_change(vty, ssm_plist_xpath, NB_OP_MODIFY, argv[4]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (no_ip_pim_ssm_prefix_list,
       no_ip_pim_ssm_prefix_list_cmd,
       "no ip pim ssm prefix-list",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Source Specific Multicast\n"
       "group range prefix-list filter\n")
{
	const char *vrfname;
	char ssm_plist_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ssm_plist_xpath, sizeof(ssm_plist_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ssm_plist_xpath, "/ssm-prefix-list", sizeof(ssm_plist_xpath));

	nb_cli_enqueue_change(vty, ssm_plist_xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (no_ip_pim_ssm_prefix_list_name,
       no_ip_pim_ssm_prefix_list_name_cmd,
       "no ip pim ssm prefix-list PREFIXLIST4_NAME",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Source Specific Multicast\n"
       "group range prefix-list filter\n"
       "Name of a prefix-list\n")
{
	const char *vrfname;
	const struct lyd_node *ssm_plist_dnode;
	char ssm_plist_xpath[XPATH_MAXLEN];
	const char *ssm_plist_name;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ssm_plist_xpath, sizeof(ssm_plist_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ssm_plist_xpath, "/ssm-prefix-list", sizeof(ssm_plist_xpath));
	ssm_plist_dnode = yang_dnode_get(vty->candidate_config->dnode,
					 ssm_plist_xpath);

	if (!ssm_plist_dnode) {
		vty_out(vty,
			"%% pim ssm prefix-list %s doesn't exist\n",
			argv[5]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ssm_plist_name = yang_dnode_get_string(ssm_plist_dnode, ".");

	if (ssm_plist_name && !strcmp(ssm_plist_name, argv[5]->arg)) {
		nb_cli_enqueue_change(vty, ssm_plist_xpath, NB_OP_DESTROY,
				      NULL);

		return nb_cli_apply_changes(vty, NULL);
	}

	vty_out(vty, "%% pim ssm prefix-list %s doesn't exist\n", argv[5]->arg);

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (show_ip_pim_ssm_range,
       show_ip_pim_ssm_range_cmd,
       "show ip pim [vrf NAME] group-type [json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM group type\n"
       JSON_STR)
{
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	ip_pim_ssm_show_group_range(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

static void ip_pim_ssm_show_group_type(struct pim_instance *pim,
				       struct vty *vty, bool uj,
				       const char *group)
{
	struct in_addr group_addr;
	const char *type_str;
	int result;

	result = inet_pton(AF_INET, group, &group_addr);
	if (result <= 0)
		type_str = "invalid";
	else {
		if (pim_is_group_224_4(group_addr))
			type_str =
				pim_is_grp_ssm(pim, group_addr) ? "SSM" : "ASM";
		else
			type_str = "not-multicast";
	}

	if (uj) {
		json_object *json;
		json = json_object_new_object();
		json_object_string_add(json, "groupType", type_str);
		vty_json(vty, json);
	} else
		vty_out(vty, "Group type : %s\n", type_str);
}

DEFUN (show_ip_pim_group_type,
       show_ip_pim_group_type_cmd,
       "show ip pim [vrf NAME] group-type A.B.C.D [json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "multicast group type\n"
       "group address\n"
       JSON_STR)
{
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	argv_find(argv, argc, "A.B.C.D", &idx);
	ip_pim_ssm_show_group_type(vrf->info, vty, uj, argv[idx]->arg);

	return CMD_SUCCESS;
}

DEFPY (show_ip_pim_bsr,
       show_ip_pim_bsr_cmd,
       "show ip pim bsr [vrf NAME] [json$json]",
       SHOW_STR
       IP_STR
       PIM_STR
       "boot-strap router information\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_bsr_helper(vrf, vty, !!json);
}

DEFUN (ip_ssmpingd,
       ip_ssmpingd_cmd,
       "ip ssmpingd [A.B.C.D]",
       IP_STR
       CONF_SSMPINGD_STR
       "Source address\n")
{
	int idx_ipv4 = 2;
	const char *src_str = (argc == 3) ? argv[idx_ipv4]->arg : "0.0.0.0";

	return pim_process_ssmpingd_cmd(vty, NB_OP_CREATE, src_str);
}

DEFUN (no_ip_ssmpingd,
       no_ip_ssmpingd_cmd,
       "no ip ssmpingd [A.B.C.D]",
       NO_STR
       IP_STR
       CONF_SSMPINGD_STR
       "Source address\n")
{
	int idx_ipv4 = 3;
	const char *src_str = (argc == 4) ? argv[idx_ipv4]->arg : "0.0.0.0";

	return pim_process_ssmpingd_cmd(vty, NB_OP_DESTROY, src_str);
}

DEFUN (ip_pim_ecmp,
       ip_pim_ecmp_cmd,
       "ip pim ecmp",
       IP_STR
       "pim multicast routing\n"
       "Enable PIM ECMP \n")
{
	const char *vrfname;
	char ecmp_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ecmp_xpath, sizeof(ecmp_xpath), FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ecmp_xpath, "/ecmp", sizeof(ecmp_xpath));

	nb_cli_enqueue_change(vty, ecmp_xpath, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (no_ip_pim_ecmp,
       no_ip_pim_ecmp_cmd,
       "no ip pim ecmp",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Disable PIM ECMP \n")
{
	const char *vrfname;
	char ecmp_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ecmp_xpath, sizeof(ecmp_xpath), FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ecmp_xpath, "/ecmp", sizeof(ecmp_xpath));

	nb_cli_enqueue_change(vty, ecmp_xpath, NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (ip_pim_ecmp_rebalance,
       ip_pim_ecmp_rebalance_cmd,
       "ip pim ecmp rebalance",
       IP_STR
       "pim multicast routing\n"
       "Enable PIM ECMP \n"
       "Enable PIM ECMP Rebalance\n")
{
	const char *vrfname;
	char ecmp_xpath[XPATH_MAXLEN];
	char ecmp_rebalance_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ecmp_xpath, sizeof(ecmp_xpath), FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ecmp_xpath, "/ecmp", sizeof(ecmp_xpath));
	snprintf(ecmp_rebalance_xpath, sizeof(ecmp_rebalance_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ecmp_rebalance_xpath, "/ecmp-rebalance",
		sizeof(ecmp_rebalance_xpath));

	nb_cli_enqueue_change(vty, ecmp_xpath, NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, ecmp_rebalance_xpath, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (no_ip_pim_ecmp_rebalance,
       no_ip_pim_ecmp_rebalance_cmd,
       "no ip pim ecmp rebalance",
       NO_STR
       IP_STR
       "pim multicast routing\n"
       "Disable PIM ECMP \n"
       "Disable PIM ECMP Rebalance\n")
{
	const char *vrfname;
	char ecmp_rebalance_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ecmp_rebalance_xpath, sizeof(ecmp_rebalance_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	strlcat(ecmp_rebalance_xpath, "/ecmp-rebalance",
		sizeof(ecmp_rebalance_xpath));

	nb_cli_enqueue_change(vty, ecmp_rebalance_xpath, NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (interface_ip_igmp,
       interface_ip_igmp_cmd,
       "ip igmp",
       IP_STR
       IFACE_IGMP_STR)
{
	nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFUN (interface_no_ip_igmp,
       interface_no_ip_igmp_cmd,
       "no ip igmp",
       NO_STR
       IP_STR
       IFACE_IGMP_STR)
{
	const struct lyd_node *pim_enable_dnode;
	char pim_if_xpath[XPATH_MAXLEN];

	int printed =
		snprintf(pim_if_xpath, sizeof(pim_if_xpath),
			 "%s/frr-pim:pim/address-family[address-family='%s']",
			 VTY_CURR_XPATH, "frr-routing:ipv4");

	if (printed >= (int)(sizeof(pim_if_xpath))) {
		vty_out(vty, "Xpath too long (%d > %u)", printed + 1,
			XPATH_MAXLEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	pim_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
					   "frr-routing:ipv4");
	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, pim_if_xpath, NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, ".")) {
			nb_cli_enqueue_change(vty, pim_if_xpath, NB_OP_DESTROY,
					      NULL);
			nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
		} else
			nb_cli_enqueue_change(vty, "./enable",
					      NB_OP_MODIFY, "false");
	}

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFUN (interface_ip_igmp_join,
       interface_ip_igmp_join_cmd,
       "ip igmp join A.B.C.D [A.B.C.D]",
       IP_STR
       IFACE_IGMP_STR
       "IGMP join multicast group\n"
       "Multicast group address\n"
       "Source address\n")
{
	int idx_group = 3;
	int idx_source = 4;
	const char *source_str;
	char xpath[XPATH_MAXLEN];

	if (argc == 5) {
		source_str = argv[idx_source]->arg;

		if (strcmp(source_str, "0.0.0.0") == 0) {
			vty_out(vty, "Bad source address %s\n",
				argv[idx_source]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else
		source_str = "0.0.0.0";

	snprintf(xpath, sizeof(xpath), FRR_GMP_JOIN_XPATH,
		 "frr-routing:ipv4", argv[idx_group]->arg, source_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (interface_no_ip_igmp_join,
       interface_no_ip_igmp_join_cmd,
       "no ip igmp join A.B.C.D [A.B.C.D]",
       NO_STR
       IP_STR
       IFACE_IGMP_STR
       "IGMP join multicast group\n"
       "Multicast group address\n"
       "Source address\n")
{
	int idx_group = 4;
	int idx_source = 5;
	const char *source_str;
	char xpath[XPATH_MAXLEN];

	if (argc == 6) {
		source_str = argv[idx_source]->arg;

		if (strcmp(source_str, "0.0.0.0") == 0) {
			vty_out(vty, "Bad source address %s\n",
				argv[idx_source]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else
		source_str = "0.0.0.0";

	snprintf(xpath, sizeof(xpath), FRR_GMP_JOIN_XPATH,
		 "frr-routing:ipv4", argv[idx_group]->arg, source_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN (interface_ip_igmp_query_interval,
       interface_ip_igmp_query_interval_cmd,
       "ip igmp query-interval (1-65535)",
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_QUERY_INTERVAL_STR
       "Query interval in seconds\n")
{
	const struct lyd_node *pim_enable_dnode;

	pim_enable_dnode =
		yang_dnode_getf(vty->candidate_config->dnode,
				FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
				"frr-routing:ipv4");
	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
				      "true");
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./enable",
					      NB_OP_MODIFY, "true");
	}

	nb_cli_enqueue_change(vty, "./query-interval", NB_OP_MODIFY,
			      argv[3]->arg);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFUN (interface_no_ip_igmp_query_interval,
       interface_no_ip_igmp_query_interval_cmd,
       "no ip igmp query-interval [(1-65535)]",
       NO_STR
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_QUERY_INTERVAL_STR
       IGNORED_IN_NO_STR)
{
	nb_cli_enqueue_change(vty, "./query-interval", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFUN (interface_ip_igmp_version,
       interface_ip_igmp_version_cmd,
       "ip igmp version (2-3)",
       IP_STR
       IFACE_IGMP_STR
       "IGMP version\n"
       "IGMP version number\n")
{
	nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
			      "true");
	nb_cli_enqueue_change(vty, "./igmp-version", NB_OP_MODIFY,
			      argv[3]->arg);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFUN (interface_no_ip_igmp_version,
       interface_no_ip_igmp_version_cmd,
       "no ip igmp version (2-3)",
       NO_STR
       IP_STR
       IFACE_IGMP_STR
       "IGMP version\n"
       "IGMP version number\n")
{
	nb_cli_enqueue_change(vty, "./igmp-version", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFPY (interface_ip_igmp_query_max_response_time,
       interface_ip_igmp_query_max_response_time_cmd,
       "ip igmp query-max-response-time (1-65535)$qmrt",
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_QUERY_MAX_RESPONSE_TIME_STR
       "Query response value in deci-seconds\n")
{
	return gm_process_query_max_response_time_cmd(vty, qmrt_str);
}

DEFUN (interface_no_ip_igmp_query_max_response_time,
       interface_no_ip_igmp_query_max_response_time_cmd,
       "no ip igmp query-max-response-time [(1-65535)]",
       NO_STR
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_QUERY_MAX_RESPONSE_TIME_STR
       IGNORED_IN_NO_STR)
{
	return gm_process_no_query_max_response_time_cmd(vty);
}

DEFUN_HIDDEN (interface_ip_igmp_query_max_response_time_dsec,
	      interface_ip_igmp_query_max_response_time_dsec_cmd,
	      "ip igmp query-max-response-time-dsec (1-65535)",
	      IP_STR
	      IFACE_IGMP_STR
	      IFACE_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC_STR
	      "Query response value in deciseconds\n")
{
	const struct lyd_node *pim_enable_dnode;

	pim_enable_dnode =
		yang_dnode_getf(vty->candidate_config->dnode,
				FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
				"frr-routing:ipv4");
	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
				      "true");
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./enable",
					      NB_OP_MODIFY, "true");
	}

	nb_cli_enqueue_change(vty, "./query-max-response-time", NB_OP_MODIFY,
			      argv[3]->arg);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFUN_HIDDEN (interface_no_ip_igmp_query_max_response_time_dsec,
	      interface_no_ip_igmp_query_max_response_time_dsec_cmd,
	      "no ip igmp query-max-response-time-dsec [(1-65535)]",
	      NO_STR
	      IP_STR
	      IFACE_IGMP_STR
	      IFACE_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC_STR
	      IGNORED_IN_NO_STR)
{
	nb_cli_enqueue_change(vty, "./query-max-response-time", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFPY (interface_ip_igmp_last_member_query_count,
       interface_ip_igmp_last_member_query_count_cmd,
       "ip igmp last-member-query-count (1-255)$lmqc",
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_LAST_MEMBER_QUERY_COUNT_STR
       "Last member query count\n")
{
	return gm_process_last_member_query_count_cmd(vty, lmqc_str);
}

DEFUN (interface_no_ip_igmp_last_member_query_count,
       interface_no_ip_igmp_last_member_query_count_cmd,
       "no ip igmp last-member-query-count [(1-255)]",
       NO_STR
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_LAST_MEMBER_QUERY_COUNT_STR
       IGNORED_IN_NO_STR)
{
	return gm_process_no_last_member_query_count_cmd(vty);
}

DEFPY (interface_ip_igmp_last_member_query_interval,
       interface_ip_igmp_last_member_query_interval_cmd,
       "ip igmp last-member-query-interval (1-65535)$lmqi",
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_LAST_MEMBER_QUERY_INTERVAL_STR
       "Last member query interval in deciseconds\n")
{
	return gm_process_last_member_query_interval_cmd(vty, lmqi_str);
}

DEFUN (interface_no_ip_igmp_last_member_query_interval,
       interface_no_ip_igmp_last_member_query_interval_cmd,
       "no ip igmp last-member-query-interval [(1-65535)]",
       NO_STR
       IP_STR
       IFACE_IGMP_STR
       IFACE_IGMP_LAST_MEMBER_QUERY_INTERVAL_STR
       IGNORED_IN_NO_STR)
{
	return gm_process_no_last_member_query_interval_cmd(vty);
}

DEFUN (interface_ip_pim_drprio,
       interface_ip_pim_drprio_cmd,
       "ip pim drpriority (0-4294967295)",
       IP_STR
       PIM_STR
       "Set the Designated Router Election Priority\n"
       "Value of the new DR Priority\n")
{
	int idx_number = 3;

	return pim_process_ip_pim_drprio_cmd(vty, argv[idx_number]->arg);
}

DEFUN (interface_no_ip_pim_drprio,
       interface_no_ip_pim_drprio_cmd,
       "no ip pim drpriority [(0-4294967295)]",
       NO_STR
       IP_STR
       PIM_STR
       "Revert the Designated Router Priority to default\n"
       "Old Value of the Priority\n")
{
	return pim_process_no_ip_pim_drprio_cmd(vty);
}

DEFPY_HIDDEN (interface_ip_igmp_query_generate,
	      interface_ip_igmp_query_generate_cmd,
	      "ip igmp generate-query-once [version (2-3)]",
	      IP_STR
	      IFACE_IGMP_STR
	      "Generate igmp general query once\n"
	      "IGMP version\n"
	      "IGMP version number\n")
{
#if PIM_IPV == 4
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int igmp_version;
	struct pim_interface *pim_ifp = ifp->info;

	if (!ifp->info) {
		vty_out(vty, "IGMP/PIM is not enabled on the interface %s\n",
			ifp->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* It takes the igmp version configured on the interface as default */
	igmp_version = pim_ifp->igmp_version;

	if (argc > 3)
		igmp_version = atoi(argv[4]->arg);

	igmp_send_query_on_intf(ifp, igmp_version);
#endif
	return CMD_SUCCESS;
}

DEFPY_HIDDEN (pim_test_sg_keepalive,
	      pim_test_sg_keepalive_cmd,
	      "test pim [vrf NAME$name] keepalive-reset A.B.C.D$source A.B.C.D$group",
	      "Test code\n"
	      PIM_STR
	      VRF_CMD_HELP_STR
	      "Reset the Keepalive Timer\n"
	      "The Source we are resetting\n"
	      "The Group we are resetting\n")
{
	struct pim_upstream *up;
	struct vrf *vrf;
	struct pim_instance *pim;
	pim_sgaddr sg;

	sg.src = source;
	sg.grp = group;

	vrf = vrf_lookup_by_name(name ? name : VRF_DEFAULT_NAME);
	if (!vrf) {
		vty_out(vty, "%% Vrf specified: %s does not exist\n", name);
		return CMD_WARNING;
	}

	pim = vrf->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	up = pim_upstream_find(pim, &sg);
	if (!up) {
		vty_out(vty, "%% Unable to find %pSG specified\n", &sg);
		return CMD_WARNING;
	}

	vty_out(vty, "Setting %pSG to current keep alive time: %d\n", &sg,
		pim->keep_alive_time);
	pim_upstream_keep_alive_timer_start(up, pim->keep_alive_time);

	return CMD_SUCCESS;
}

DEFPY (interface_ip_pim_activeactive,
       interface_ip_pim_activeactive_cmd,
       "[no$no] ip pim active-active",
       NO_STR
       IP_STR
       PIM_STR
       "Mark interface as Active-Active for MLAG operations, Hidden because not finished yet\n")
{
	return pim_process_ip_pim_activeactive_cmd(vty, no);
}

DEFUN_HIDDEN (interface_ip_pim_ssm,
	      interface_ip_pim_ssm_cmd,
	      "ip pim ssm",
	      IP_STR
	      PIM_STR
	      IFACE_PIM_STR)
{
	int ret;

	ret = pim_process_ip_pim_cmd(vty);

	if (ret != NB_OK)
		return ret;

	vty_out(vty,
		"WARN: Enabled PIM SM on interface; configure PIM SSM range if needed\n");

	return NB_OK;
}

DEFUN_HIDDEN (interface_ip_pim_sm,
	      interface_ip_pim_sm_cmd,
	      "ip pim sm",
	      IP_STR
	      PIM_STR
	      IFACE_PIM_SM_STR)
{
	return pim_process_ip_pim_cmd(vty);
}

DEFPY (interface_ip_pim,
       interface_ip_pim_cmd,
       "ip pim [passive$passive]",
       IP_STR
       PIM_STR
       "Disable exchange of protocol packets\n")
{
	int ret;

	ret = pim_process_ip_pim_cmd(vty);

	if (ret != NB_OK)
		return ret;

	if (passive)
		return pim_process_ip_pim_passive_cmd(vty, true);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (interface_no_ip_pim_ssm,
	      interface_no_ip_pim_ssm_cmd,
	      "no ip pim ssm",
	      NO_STR
	      IP_STR
	      PIM_STR
	      IFACE_PIM_STR)
{
	return pim_process_no_ip_pim_cmd(vty);
}

DEFUN_HIDDEN (interface_no_ip_pim_sm,
	      interface_no_ip_pim_sm_cmd,
	      "no ip pim sm",
	      NO_STR
	      IP_STR
	      PIM_STR
	      IFACE_PIM_SM_STR)
{
	return pim_process_no_ip_pim_cmd(vty);
}

DEFPY (interface_no_ip_pim,
       interface_no_ip_pim_cmd,
       "no ip pim [passive$passive]",
       NO_STR
       IP_STR
       PIM_STR
       "Disable exchange of protocol packets\n")
{
	if (passive)
		return pim_process_ip_pim_passive_cmd(vty, false);

	return pim_process_no_ip_pim_cmd(vty);
}

/* boundaries */
DEFUN(interface_ip_pim_boundary_oil,
      interface_ip_pim_boundary_oil_cmd,
      "ip multicast boundary oil WORD",
      IP_STR
      "Generic multicast configuration options\n"
      "Define multicast boundary\n"
      "Filter OIL by group using prefix list\n"
      "Prefix list to filter OIL with\n")
{
	return pim_process_ip_pim_boundary_oil_cmd(vty, argv[4]->arg);
}

DEFUN(interface_no_ip_pim_boundary_oil,
      interface_no_ip_pim_boundary_oil_cmd,
      "no ip multicast boundary oil [WORD]",
      NO_STR
      IP_STR
      "Generic multicast configuration options\n"
      "Define multicast boundary\n"
      "Filter OIL by group using prefix list\n"
      "Prefix list to filter OIL with\n")
{
	return pim_process_no_ip_pim_boundary_oil_cmd(vty);
}

DEFUN (interface_ip_mroute,
       interface_ip_mroute_cmd,
       "ip mroute INTERFACE A.B.C.D [A.B.C.D]",
       IP_STR
       "Add multicast route\n"
       "Outgoing interface name\n"
       "Group address\n"
       "Source address\n")
{
	int idx_interface = 2;
	int idx_ipv4 = 3;
	const char *source_str;

	if (argc == (idx_ipv4 + 1))
		source_str = "0.0.0.0";
	else
		source_str = argv[idx_ipv4 + 1]->arg;

	return pim_process_ip_mroute_cmd(vty, argv[idx_interface]->arg,
					 argv[idx_ipv4]->arg, source_str);
}

DEFUN (interface_no_ip_mroute,
       interface_no_ip_mroute_cmd,
       "no ip mroute INTERFACE A.B.C.D [A.B.C.D]",
       NO_STR
       IP_STR
       "Add multicast route\n"
       "Outgoing interface name\n"
       "Group Address\n"
       "Source Address\n")
{
	int idx_interface = 3;
	int idx_ipv4 = 4;
	const char *source_str;

	if (argc == (idx_ipv4 + 1))
		source_str = "0.0.0.0";
	else
		source_str = argv[idx_ipv4 + 1]->arg;

	return pim_process_no_ip_mroute_cmd(vty, argv[idx_interface]->arg,
					    argv[idx_ipv4]->arg, source_str);
}

DEFUN (interface_ip_pim_hello,
       interface_ip_pim_hello_cmd,
       "ip pim hello (1-65535) [(1-65535)]",
       IP_STR
       PIM_STR
       IFACE_PIM_HELLO_STR
       IFACE_PIM_HELLO_TIME_STR
       IFACE_PIM_HELLO_HOLD_STR)
{
	int idx_time = 3;
	int idx_hold = 4;

	if (argc == idx_hold + 1)
		return pim_process_ip_pim_hello_cmd(vty, argv[idx_time]->arg,
						    argv[idx_hold]->arg);

	else
		return pim_process_ip_pim_hello_cmd(vty, argv[idx_time]->arg,
						    NULL);
}

DEFUN (interface_no_ip_pim_hello,
       interface_no_ip_pim_hello_cmd,
       "no ip pim hello [(1-65535) [(1-65535)]]",
       NO_STR
       IP_STR
       PIM_STR
       IFACE_PIM_HELLO_STR
       IGNORED_IN_NO_STR
       IGNORED_IN_NO_STR)
{
	return pim_process_no_ip_pim_hello_cmd(vty);
}

DEFUN (debug_igmp,
       debug_igmp_cmd,
       "debug igmp",
       DEBUG_STR
       DEBUG_IGMP_STR)
{
	PIM_DO_DEBUG_GM_EVENTS;
	PIM_DO_DEBUG_GM_PACKETS;
	PIM_DO_DEBUG_GM_TRACE;
	return CMD_SUCCESS;
}

DEFUN (no_debug_igmp,
       no_debug_igmp_cmd,
       "no debug igmp",
       NO_STR
       DEBUG_STR
       DEBUG_IGMP_STR)
{
	PIM_DONT_DEBUG_GM_EVENTS;
	PIM_DONT_DEBUG_GM_PACKETS;
	PIM_DONT_DEBUG_GM_TRACE;
	return CMD_SUCCESS;
}


DEFUN (debug_igmp_events,
       debug_igmp_events_cmd,
       "debug igmp events",
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_EVENTS_STR)
{
	PIM_DO_DEBUG_GM_EVENTS;
	return CMD_SUCCESS;
}

DEFUN (no_debug_igmp_events,
       no_debug_igmp_events_cmd,
       "no debug igmp events",
       NO_STR
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_EVENTS_STR)
{
	PIM_DONT_DEBUG_GM_EVENTS;
	return CMD_SUCCESS;
}


DEFUN (debug_igmp_packets,
       debug_igmp_packets_cmd,
       "debug igmp packets",
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_PACKETS_STR)
{
	PIM_DO_DEBUG_GM_PACKETS;
	return CMD_SUCCESS;
}

DEFUN (no_debug_igmp_packets,
       no_debug_igmp_packets_cmd,
       "no debug igmp packets",
       NO_STR
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_PACKETS_STR)
{
	PIM_DONT_DEBUG_GM_PACKETS;
	return CMD_SUCCESS;
}


DEFUN (debug_igmp_trace,
       debug_igmp_trace_cmd,
       "debug igmp trace",
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_TRACE_STR)
{
	PIM_DO_DEBUG_GM_TRACE;
	return CMD_SUCCESS;
}

DEFUN (no_debug_igmp_trace,
       no_debug_igmp_trace_cmd,
       "no debug igmp trace",
       NO_STR
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_TRACE_STR)
{
	PIM_DONT_DEBUG_GM_TRACE;
	return CMD_SUCCESS;
}


DEFUN (debug_igmp_trace_detail,
       debug_igmp_trace_detail_cmd,
       "debug igmp trace detail",
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_TRACE_STR
       "detailed\n")
{
	PIM_DO_DEBUG_GM_TRACE_DETAIL;
	return CMD_SUCCESS;
}

DEFUN (no_debug_igmp_trace_detail,
       no_debug_igmp_trace_detail_cmd,
       "no debug igmp trace detail",
       NO_STR
       DEBUG_STR
       DEBUG_IGMP_STR
       DEBUG_IGMP_TRACE_STR
       "detailed\n")
{
	PIM_DONT_DEBUG_GM_TRACE_DETAIL;
	return CMD_SUCCESS;
}


DEFUN (debug_mroute,
       debug_mroute_cmd,
       "debug mroute",
       DEBUG_STR
       DEBUG_MROUTE_STR)
{
	PIM_DO_DEBUG_MROUTE;
	return CMD_SUCCESS;
}

DEFUN (debug_mroute_detail,
       debug_mroute_detail_cmd,
       "debug mroute detail",
       DEBUG_STR
       DEBUG_MROUTE_STR
       "detailed\n")
{
	PIM_DO_DEBUG_MROUTE_DETAIL;
	return CMD_SUCCESS;
}

DEFUN (no_debug_mroute,
       no_debug_mroute_cmd,
       "no debug mroute",
       NO_STR
       DEBUG_STR
       DEBUG_MROUTE_STR)
{
	PIM_DONT_DEBUG_MROUTE;
	return CMD_SUCCESS;
}

DEFUN (no_debug_mroute_detail,
       no_debug_mroute_detail_cmd,
       "no debug mroute detail",
       NO_STR
       DEBUG_STR
       DEBUG_MROUTE_STR
       "detailed\n")
{
	PIM_DONT_DEBUG_MROUTE_DETAIL;
	return CMD_SUCCESS;
}

DEFUN (debug_pim_static,
       debug_pim_static_cmd,
       "debug pim static",
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_STATIC_STR)
{
	PIM_DO_DEBUG_STATIC;
	return CMD_SUCCESS;
}

DEFUN (no_debug_pim_static,
       no_debug_pim_static_cmd,
       "no debug pim static",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_STATIC_STR)
{
	PIM_DONT_DEBUG_STATIC;
	return CMD_SUCCESS;
}


DEFPY (debug_pim,
       debug_pim_cmd,
       "[no] debug pim",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR)
{
	if (!no)
		return pim_debug_pim_cmd();
	else
		return pim_no_debug_pim_cmd();
}

DEFPY (debug_pim_nht,
       debug_pim_nht_cmd,
       "[no] debug pim nht",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       "Nexthop Tracking\n")
{
	if (!no)
		PIM_DO_DEBUG_PIM_NHT;
	else
		PIM_DONT_DEBUG_PIM_NHT;
	return CMD_SUCCESS;
}

DEFPY (debug_pim_nht_det,
       debug_pim_nht_det_cmd,
       "[no] debug pim nht detail",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       "Nexthop Tracking\n"
       "Detailed Information\n")
{
	if (!no)
		PIM_DO_DEBUG_PIM_NHT_DETAIL;
	else
		PIM_DONT_DEBUG_PIM_NHT_DETAIL;
	return CMD_SUCCESS;
}

DEFUN (debug_pim_nht_rp,
       debug_pim_nht_rp_cmd,
       "debug pim nht rp",
       DEBUG_STR
       DEBUG_PIM_STR
       "Nexthop Tracking\n"
       "RP Nexthop Tracking\n")
{
	PIM_DO_DEBUG_PIM_NHT_RP;
	return CMD_SUCCESS;
}

DEFUN (no_debug_pim_nht_rp,
       no_debug_pim_nht_rp_cmd,
       "no debug pim nht rp",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       "Nexthop Tracking\n"
       "RP Nexthop Tracking\n")
{
	PIM_DONT_DEBUG_PIM_NHT_RP;
	return CMD_SUCCESS;
}

DEFPY (debug_pim_events,
       debug_pim_events_cmd,
       "[no] debug pim events",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_EVENTS_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_EVENTS;
	else
		PIM_DONT_DEBUG_PIM_EVENTS;
	return CMD_SUCCESS;
}

DEFPY (debug_pim_packets,
       debug_pim_packets_cmd,
       "[no] debug pim packets [<hello$hello|joins$joins|register$registers>]",
       NO_STR DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_PACKETS_STR
       DEBUG_PIM_HELLO_PACKETS_STR
       DEBUG_PIM_J_P_PACKETS_STR
       DEBUG_PIM_PIM_REG_PACKETS_STR)
{
	if (!no)
		return pim_debug_pim_packets_cmd(hello, joins, registers, vty);
	else
		return pim_no_debug_pim_packets_cmd(hello, joins, registers,
						    vty);
}

DEFPY (debug_pim_packetdump_send,
       debug_pim_packetdump_send_cmd,
       "[no] debug pim packet-dump send",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_PACKETDUMP_STR
       DEBUG_PIM_PACKETDUMP_SEND_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_PACKETDUMP_SEND;
	else
		PIM_DONT_DEBUG_PIM_PACKETDUMP_SEND;
	return CMD_SUCCESS;
}

DEFPY (debug_pim_packetdump_recv,
       debug_pim_packetdump_recv_cmd,
       "[no] debug pim packet-dump receive",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_PACKETDUMP_STR
       DEBUG_PIM_PACKETDUMP_RECV_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_PACKETDUMP_RECV;
	else
		PIM_DONT_DEBUG_PIM_PACKETDUMP_RECV;
	return CMD_SUCCESS;
}

DEFPY (debug_pim_trace,
       debug_pim_trace_cmd,
       "[no] debug pim trace",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_TRACE_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_TRACE;
	else
		PIM_DONT_DEBUG_PIM_TRACE;
	return CMD_SUCCESS;
}

DEFPY (debug_pim_trace_detail,
       debug_pim_trace_detail_cmd,
       "[no] debug pim trace detail",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_TRACE_STR
       "Detailed Information\n")
{
	if (!no)
		PIM_DO_DEBUG_PIM_TRACE_DETAIL;
	else
		PIM_DONT_DEBUG_PIM_TRACE_DETAIL;
	return CMD_SUCCESS;
}

DEFUN (debug_ssmpingd,
       debug_ssmpingd_cmd,
       "debug ssmpingd",
       DEBUG_STR
       DEBUG_SSMPINGD_STR)
{
	PIM_DO_DEBUG_SSMPINGD;
	return CMD_SUCCESS;
}

DEFUN (no_debug_ssmpingd,
       no_debug_ssmpingd_cmd,
       "no debug ssmpingd",
       NO_STR
       DEBUG_STR
       DEBUG_SSMPINGD_STR)
{
	PIM_DONT_DEBUG_SSMPINGD;
	return CMD_SUCCESS;
}

DEFPY (debug_pim_zebra,
       debug_pim_zebra_cmd,
       "[no] debug pim zebra",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_ZEBRA_STR)
{
	if (!no)
		PIM_DO_DEBUG_ZEBRA;
	else
		PIM_DONT_DEBUG_ZEBRA;
	return CMD_SUCCESS;
}

DEFUN(debug_pim_mlag, debug_pim_mlag_cmd, "debug pim mlag",
      DEBUG_STR DEBUG_PIM_STR DEBUG_PIM_MLAG_STR)
{
	PIM_DO_DEBUG_MLAG;
	return CMD_SUCCESS;
}

DEFUN(no_debug_pim_mlag, no_debug_pim_mlag_cmd, "no debug pim mlag",
      NO_STR DEBUG_STR DEBUG_PIM_STR DEBUG_PIM_MLAG_STR)
{
	PIM_DONT_DEBUG_MLAG;
	return CMD_SUCCESS;
}

DEFUN (debug_pim_vxlan,
       debug_pim_vxlan_cmd,
       "debug pim vxlan",
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_VXLAN_STR)
{
	PIM_DO_DEBUG_VXLAN;
	return CMD_SUCCESS;
}

DEFUN (no_debug_pim_vxlan,
       no_debug_pim_vxlan_cmd,
       "no debug pim vxlan",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_VXLAN_STR)
{
	PIM_DONT_DEBUG_VXLAN;
	return CMD_SUCCESS;
}

DEFUN (debug_msdp,
       debug_msdp_cmd,
       "debug msdp",
       DEBUG_STR
       DEBUG_MSDP_STR)
{
	PIM_DO_DEBUG_MSDP_EVENTS;
	PIM_DO_DEBUG_MSDP_PACKETS;
	return CMD_SUCCESS;
}

DEFUN (no_debug_msdp,
       no_debug_msdp_cmd,
       "no debug msdp",
       NO_STR
       DEBUG_STR
       DEBUG_MSDP_STR)
{
	PIM_DONT_DEBUG_MSDP_EVENTS;
	PIM_DONT_DEBUG_MSDP_PACKETS;
	return CMD_SUCCESS;
}

DEFUN (debug_msdp_events,
       debug_msdp_events_cmd,
       "debug msdp events",
       DEBUG_STR
       DEBUG_MSDP_STR
       DEBUG_MSDP_EVENTS_STR)
{
	PIM_DO_DEBUG_MSDP_EVENTS;
	return CMD_SUCCESS;
}

DEFUN (no_debug_msdp_events,
       no_debug_msdp_events_cmd,
       "no debug msdp events",
       NO_STR
       DEBUG_STR
       DEBUG_MSDP_STR
       DEBUG_MSDP_EVENTS_STR)
{
	PIM_DONT_DEBUG_MSDP_EVENTS;
	return CMD_SUCCESS;
}

DEFUN (debug_msdp_packets,
       debug_msdp_packets_cmd,
       "debug msdp packets",
       DEBUG_STR
       DEBUG_MSDP_STR
       DEBUG_MSDP_PACKETS_STR)
{
	PIM_DO_DEBUG_MSDP_PACKETS;
	return CMD_SUCCESS;
}

DEFUN (no_debug_msdp_packets,
       no_debug_msdp_packets_cmd,
       "no debug msdp packets",
       NO_STR
       DEBUG_STR
       DEBUG_MSDP_STR
       DEBUG_MSDP_PACKETS_STR)
{
	PIM_DONT_DEBUG_MSDP_PACKETS;
	return CMD_SUCCESS;
}

DEFUN (debug_mtrace,
       debug_mtrace_cmd,
       "debug mtrace",
       DEBUG_STR
       DEBUG_MTRACE_STR)
{
	PIM_DO_DEBUG_MTRACE;
	return CMD_SUCCESS;
}

DEFUN (no_debug_mtrace,
       no_debug_mtrace_cmd,
       "no debug mtrace",
       NO_STR
       DEBUG_STR
       DEBUG_MTRACE_STR)
{
	PIM_DONT_DEBUG_MTRACE;
	return CMD_SUCCESS;
}

DEFUN (debug_bsm,
       debug_bsm_cmd,
       "debug pim bsm",
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_BSM_STR)
{
	PIM_DO_DEBUG_BSM;
	return CMD_SUCCESS;
}

DEFUN (no_debug_bsm,
       no_debug_bsm_cmd,
       "no debug pim bsm",
       NO_STR
       DEBUG_STR
       DEBUG_PIM_STR
       DEBUG_PIM_BSM_STR)
{
	PIM_DONT_DEBUG_BSM;
	return CMD_SUCCESS;
}


DEFUN_NOSH (show_debugging_pim,
	    show_debugging_pim_cmd,
	    "show debugging [pim]",
	    SHOW_STR
	    DEBUG_STR
	    PIM_STR)
{
	vty_out(vty, "PIM debugging status\n");

	pim_debug_config_write(vty);

	cmd_show_lib_debugs(vty);
	return CMD_SUCCESS;
}

DEFUN (interface_pim_use_source,
       interface_pim_use_source_cmd,
       "ip pim use-source A.B.C.D",
       IP_STR
       PIM_STR
       "Configure primary IP address\n"
       "source ip address\n")
{
	nb_cli_enqueue_change(vty, "./use-source", NB_OP_MODIFY, argv[3]->arg);

	return nb_cli_apply_changes(vty,
				    FRR_PIM_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFUN (interface_no_pim_use_source,
       interface_no_pim_use_source_cmd,
       "no ip pim use-source [A.B.C.D]",
       NO_STR
       IP_STR
       PIM_STR
       "Delete source IP address\n"
       "source ip address\n")
{
	nb_cli_enqueue_change(vty, "./use-source", NB_OP_MODIFY, "0.0.0.0");

	return nb_cli_apply_changes(vty,
				    FRR_PIM_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFPY (ip_pim_bfd,
       ip_pim_bfd_cmd,
       "ip pim bfd [profile BFDPROF$prof]",
       IP_STR
       PIM_STR
       "Enables BFD support\n"
       "Use BFD profile\n"
       "Use BFD profile name\n")
{
	const struct lyd_node *igmp_enable_dnode;

	igmp_enable_dnode =
		yang_dnode_getf(vty->candidate_config->dnode,
				FRR_GMP_ENABLE_XPATH, VTY_CURR_XPATH,
				"frr-routing:ipv4");
	if (!igmp_enable_dnode)
		nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
				      "true");
	else {
		if (!yang_dnode_get_bool(igmp_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./bfd", NB_OP_CREATE, NULL);
	if (prof)
		nb_cli_enqueue_change(vty, "./bfd/profile", NB_OP_MODIFY, prof);

	return nb_cli_apply_changes(vty,
				    FRR_PIM_INTERFACE_XPATH,
				    "frr-routing:ipv4");
}

DEFPY(no_ip_pim_bfd_profile, no_ip_pim_bfd_profile_cmd,
      "no ip pim bfd profile [BFDPROF]",
      NO_STR
      IP_STR
      PIM_STR
      "Enables BFD support\n"
      "Disable BFD profile\n"
      "BFD Profile name\n")
{
	nb_cli_enqueue_change(vty, "./bfd/profile", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty,
			FRR_PIM_INTERFACE_XPATH,
			"frr-routing:ipv4");
}

DEFUN (no_ip_pim_bfd,
       no_ip_pim_bfd_cmd,
       "no ip pim bfd",
       NO_STR
       IP_STR
       PIM_STR
       "Disables BFD support\n")
{
	nb_cli_enqueue_change(vty, "./bfd", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty,
			FRR_PIM_INTERFACE_XPATH,
			"frr-routing:ipv4");
}

DEFUN (ip_pim_bsm,
       ip_pim_bsm_cmd,
       "ip pim bsm",
       IP_STR
       PIM_STR
       "Enable BSM support on the interface\n")
{
	return pim_process_bsm_cmd(vty);
}
DEFUN (no_ip_pim_bsm,
       no_ip_pim_bsm_cmd,
       "no ip pim bsm",
       NO_STR
       IP_STR
       PIM_STR
       "Enable BSM support on the interface\n")
{
	return pim_process_no_bsm_cmd(vty);
}

DEFUN (ip_pim_ucast_bsm,
       ip_pim_ucast_bsm_cmd,
       "ip pim unicast-bsm",
       IP_STR
       PIM_STR
       "Accept/Send unicast BSM on the interface\n")
{
	return pim_process_unicast_bsm_cmd(vty);
}

DEFUN (no_ip_pim_ucast_bsm,
       no_ip_pim_ucast_bsm_cmd,
       "no ip pim unicast-bsm",
       NO_STR
       IP_STR
       PIM_STR
       "Accept/Send unicast BSM on the interface\n")
{
	return pim_process_no_unicast_bsm_cmd(vty);
}

#if HAVE_BFDD > 0
DEFUN_HIDDEN (
	ip_pim_bfd_param,
	ip_pim_bfd_param_cmd,
	"ip pim bfd (2-255) (1-65535) (1-65535)",
	IP_STR
	PIM_STR
	"Enables BFD support\n"
	"Detect Multiplier\n"
	"Required min receive interval\n"
	"Desired min transmit interval\n")
#else
	DEFUN(
		ip_pim_bfd_param,
		ip_pim_bfd_param_cmd,
		"ip pim bfd (2-255) (1-65535) (1-65535)",
		IP_STR
		PIM_STR
		"Enables BFD support\n"
		"Detect Multiplier\n"
		"Required min receive interval\n"
		"Desired min transmit interval\n")
#endif /* HAVE_BFDD */
{
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	const struct lyd_node *igmp_enable_dnode;

	igmp_enable_dnode =
		yang_dnode_getf(vty->candidate_config->dnode,
				FRR_GMP_ENABLE_XPATH, VTY_CURR_XPATH,
				"frr-routing:ipv4");
	if (!igmp_enable_dnode)
		nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
				      "true");
	else {
		if (!yang_dnode_get_bool(igmp_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./bfd", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./bfd/min-rx-interval", NB_OP_MODIFY,
			      argv[idx_number_2]->arg);
	nb_cli_enqueue_change(vty, "./bfd/min-tx-interval", NB_OP_MODIFY,
			      argv[idx_number_3]->arg);
	nb_cli_enqueue_change(vty, "./bfd/detect_mult", NB_OP_MODIFY,
			      argv[idx_number]->arg);

	return nb_cli_apply_changes(vty,
			FRR_PIM_INTERFACE_XPATH, "frr-routing:ipv4");
}

#if HAVE_BFDD == 0
ALIAS(no_ip_pim_bfd, no_ip_pim_bfd_param_cmd,
      "no ip pim bfd (2-255) (1-65535) (1-65535)",
      NO_STR
      IP_STR
      PIM_STR
      "Enables BFD support\n"
      "Detect Multiplier\n"
      "Required min receive interval\n"
      "Desired min transmit interval\n")
#endif /* !HAVE_BFDD */

DEFPY(ip_msdp_peer, ip_msdp_peer_cmd,
      "ip msdp peer A.B.C.D$peer source A.B.C.D$source",
      IP_STR
      CFG_MSDP_STR
      "Configure MSDP peer\n"
      "Peer IP address\n"
      "Source address for TCP connection\n"
      "Local IP address\n")
{
	const char *vrfname;
	char temp_xpath[XPATH_MAXLEN];
	char msdp_peer_source_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(msdp_peer_source_xpath, sizeof(msdp_peer_source_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 "frr-routing:ipv4");
	snprintf(temp_xpath, sizeof(temp_xpath),
		 "/msdp-peer[peer-ip='%s']/source-ip", peer_str);
	strlcat(msdp_peer_source_xpath, temp_xpath,
		sizeof(msdp_peer_source_xpath));

	nb_cli_enqueue_change(vty, msdp_peer_source_xpath, NB_OP_MODIFY,
			      source_str);

	return nb_cli_apply_changes(vty,
			FRR_PIM_INTERFACE_XPATH, "frr-routing:ipv4");
}

DEFPY(ip_msdp_timers, ip_msdp_timers_cmd,
      "ip msdp timers (1-65535)$keepalive (1-65535)$holdtime [(1-65535)$connretry]",
      IP_STR
      CFG_MSDP_STR
      "MSDP timers configuration\n"
      "Keep alive period (in seconds)\n"
      "Hold time period (in seconds)\n"
      "Connection retry period (in seconds)\n")
{
	const char *vrfname;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, "./hold-time", NB_OP_MODIFY, holdtime_str);
	nb_cli_enqueue_change(vty, "./keep-alive", NB_OP_MODIFY, keepalive_str);
	if (connretry_str)
		nb_cli_enqueue_change(vty, "./connection-retry", NB_OP_MODIFY,
				      connretry_str);
	else
		nb_cli_enqueue_change(vty, "./connection-retry", NB_OP_DESTROY,
				      NULL);

	nb_cli_apply_changes(vty, FRR_PIM_MSDP_XPATH, "frr-pim:pimd", "pim",
			     vrfname, "frr-routing:ipv4");
	return CMD_SUCCESS;
}

DEFPY(no_ip_msdp_timers, no_ip_msdp_timers_cmd,
      "no ip msdp timers [(1-65535) (1-65535) [(1-65535)]]",
      NO_STR
      IP_STR
      CFG_MSDP_STR
      "MSDP timers configuration\n"
      IGNORED_IN_NO_STR
      IGNORED_IN_NO_STR
      IGNORED_IN_NO_STR)
{
	const char *vrfname;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, "./hold-time", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./keep-alive", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./connection-retry", NB_OP_DESTROY, NULL);

	nb_cli_apply_changes(vty, FRR_PIM_MSDP_XPATH, "frr-pim:pimd", "pim",
			     vrfname, "frr-routing:ipv4");

	return CMD_SUCCESS;
}

DEFUN (no_ip_msdp_peer,
       no_ip_msdp_peer_cmd,
       "no ip msdp peer A.B.C.D",
       NO_STR
       IP_STR
       CFG_MSDP_STR
       "Delete MSDP peer\n"
       "peer ip address\n")
{
	const char *vrfname;
	char msdp_peer_xpath[XPATH_MAXLEN];
	char temp_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(msdp_peer_xpath, sizeof(msdp_peer_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4");
	snprintf(temp_xpath, sizeof(temp_xpath),
		 "/msdp-peer[peer-ip='%s']",
		 argv[4]->arg);

	strlcat(msdp_peer_xpath, temp_xpath, sizeof(msdp_peer_xpath));

	nb_cli_enqueue_change(vty, msdp_peer_xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(ip_msdp_mesh_group_member,
      ip_msdp_mesh_group_member_cmd,
      "ip msdp mesh-group WORD$gname member A.B.C.D$maddr",
      IP_STR
      CFG_MSDP_STR
      "Configure MSDP mesh-group\n"
      "Mesh group name\n"
      "Mesh group member\n"
      "Peer IP address\n")
{
	const char *vrfname;
	char xpath_value[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	/* Create mesh group. */
	snprintf(xpath_value, sizeof(xpath_value),
		 FRR_PIM_VRF_XPATH "/msdp-mesh-groups[name='%s']",
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4", gname);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);

	/* Create mesh group member. */
	strlcat(xpath_value, "/members[address='", sizeof(xpath_value));
	strlcat(xpath_value, maddr_str, sizeof(xpath_value));
	strlcat(xpath_value, "']", sizeof(xpath_value));
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_ip_msdp_mesh_group_member,
      no_ip_msdp_mesh_group_member_cmd,
      "no ip msdp mesh-group WORD$gname member A.B.C.D$maddr",
      NO_STR
      IP_STR
      CFG_MSDP_STR
      "Delete MSDP mesh-group member\n"
      "Mesh group name\n"
      "Mesh group member\n"
      "Peer IP address\n")
{
	const char *vrfname;
	char xpath_value[XPATH_MAXLEN];
	char xpath_member_value[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	/* Get mesh group base XPath. */
	snprintf(xpath_value, sizeof(xpath_value),
		 FRR_PIM_VRF_XPATH "/msdp-mesh-groups[name='%s']",
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4", gname);

	if (!yang_dnode_exists(vty->candidate_config->dnode, xpath_value)) {
		vty_out(vty, "%% mesh-group does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Remove mesh group member. */
	strlcpy(xpath_member_value, xpath_value, sizeof(xpath_member_value));
	strlcat(xpath_member_value, "/members[address='",
		sizeof(xpath_member_value));
	strlcat(xpath_member_value, maddr_str, sizeof(xpath_member_value));
	strlcat(xpath_member_value, "']", sizeof(xpath_member_value));
	if (!yang_dnode_exists(vty->candidate_config->dnode,
			       xpath_member_value)) {
		vty_out(vty, "%% mesh-group member does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath_member_value, NB_OP_DESTROY, NULL);

	/*
	 * If this is the last member, then we must remove the group altogether
	 * to not break legacy CLI behaviour.
	 */
	pim_cli_legacy_mesh_group_behavior(vty, gname);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(ip_msdp_mesh_group_source,
      ip_msdp_mesh_group_source_cmd,
      "ip msdp mesh-group WORD$gname source A.B.C.D$saddr",
      IP_STR
      CFG_MSDP_STR
      "Configure MSDP mesh-group\n"
      "Mesh group name\n"
      "Mesh group local address\n"
      "Source IP address for the TCP connection\n")
{
	const char *vrfname;
	char xpath_value[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	/* Create mesh group. */
	snprintf(xpath_value, sizeof(xpath_value),
		 FRR_PIM_VRF_XPATH "/msdp-mesh-groups[name='%s']",
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4", gname);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);

	/* Create mesh group source. */
	strlcat(xpath_value, "/source", sizeof(xpath_value));
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, saddr_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_ip_msdp_mesh_group_source,
      no_ip_msdp_mesh_group_source_cmd,
      "no ip msdp mesh-group WORD$gname source [A.B.C.D]",
      NO_STR
      IP_STR
      CFG_MSDP_STR
      "Delete MSDP mesh-group source\n"
      "Mesh group name\n"
      "Mesh group source\n"
      "Mesh group local address\n")
{
	const char *vrfname;
	char xpath_value[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	/* Get mesh group base XPath. */
	snprintf(xpath_value, sizeof(xpath_value),
		 FRR_PIM_VRF_XPATH "/msdp-mesh-groups[name='%s']",
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4", gname);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);

	/* Create mesh group source. */
	strlcat(xpath_value, "/source", sizeof(xpath_value));
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, NULL);

	/*
	 * If this is the last member, then we must remove the group altogether
	 * to not break legacy CLI behaviour.
	 */
	pim_cli_legacy_mesh_group_behavior(vty, gname);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_ip_msdp_mesh_group,
      no_ip_msdp_mesh_group_cmd,
      "no ip msdp mesh-group WORD$gname",
      NO_STR
      IP_STR
      CFG_MSDP_STR
      "Delete MSDP mesh-group\n"
      "Mesh group name\n")
{
	const char *vrfname;
	char xpath_value[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	/* Get mesh group base XPath. */
	snprintf(xpath_value, sizeof(xpath_value),
		 FRR_PIM_VRF_XPATH "/msdp-mesh-groups[name='%s']",
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv4", gname);
	if (!yang_dnode_exists(vty->candidate_config->dnode, xpath_value))
		return CMD_SUCCESS;

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static void ip_msdp_show_mesh_group(struct vty *vty, struct pim_msdp_mg *mg,
				    struct json_object *json)
{
	struct listnode *mbrnode;
	struct pim_msdp_mg_mbr *mbr;
	char mbr_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char state_str[PIM_MSDP_STATE_STRLEN];
	enum pim_msdp_peer_state state;
	json_object *json_mg_row = NULL;
	json_object *json_members = NULL;
	json_object *json_row = NULL;

	pim_inet4_dump("<source?>", mg->src_ip, src_str, sizeof(src_str));
	if (json) {
		/* currently there is only one mesh group but we should still
		 * make
		 * it a dict with mg-name as key */
		json_mg_row = json_object_new_object();
		json_object_string_add(json_mg_row, "name",
				       mg->mesh_group_name);
		json_object_string_add(json_mg_row, "source", src_str);
	} else {
		vty_out(vty, "Mesh group : %s\n", mg->mesh_group_name);
		vty_out(vty, "  Source : %s\n", src_str);
		vty_out(vty, "  Member                 State\n");
	}

	for (ALL_LIST_ELEMENTS_RO(mg->mbr_list, mbrnode, mbr)) {
		pim_inet4_dump("<mbr?>", mbr->mbr_ip, mbr_str, sizeof(mbr_str));
		if (mbr->mp) {
			state = mbr->mp->state;
		} else {
			state = PIM_MSDP_DISABLED;
		}
		pim_msdp_state_dump(state, state_str, sizeof(state_str));
		if (json) {
			json_row = json_object_new_object();
			json_object_string_add(json_row, "member", mbr_str);
			json_object_string_add(json_row, "state", state_str);
			if (!json_members) {
				json_members = json_object_new_object();
				json_object_object_add(json_mg_row, "members",
						       json_members);
			}
			json_object_object_add(json_members, mbr_str, json_row);
		} else {
			vty_out(vty, "  %-15s  %11s\n", mbr_str, state_str);
		}
	}

	if (json)
		json_object_object_add(json, mg->mesh_group_name, json_mg_row);
}

DEFUN (show_ip_msdp_mesh_group,
       show_ip_msdp_mesh_group_cmd,
       "show ip msdp [vrf NAME] mesh-group [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP mesh-group information\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	int idx = 2;
	struct pim_msdp_mg *mg;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);
	struct pim_instance *pim;
	struct json_object *json = NULL;

	if (!vrf)
		return CMD_WARNING;

	pim = vrf->info;
	/* Quick case: list is empty. */
	if (SLIST_EMPTY(&pim->msdp.mglist)) {
		if (uj)
			vty_out(vty, "{}\n");

		return CMD_SUCCESS;
	}

	if (uj)
		json = json_object_new_object();

	SLIST_FOREACH (mg, &pim->msdp.mglist, mg_entry)
		ip_msdp_show_mesh_group(vty, mg, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN (show_ip_msdp_mesh_group_vrf_all,
       show_ip_msdp_mesh_group_vrf_all_cmd,
       "show ip msdp vrf all mesh-group [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP mesh-group information\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct json_object *json = NULL, *vrf_json = NULL;
	struct pim_instance *pim;
	struct pim_msdp_mg *mg;
	struct vrf *vrf;

	if (uj)
		json = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (uj) {
			vrf_json = json_object_new_object();
			json_object_object_add(json, vrf->name, vrf_json);
		} else
			vty_out(vty, "VRF: %s\n", vrf->name);

		pim = vrf->info;
		SLIST_FOREACH (mg, &pim->msdp.mglist, mg_entry)
			ip_msdp_show_mesh_group(vty, mg, vrf_json);
	}

	if (uj)
		vty_json(vty, json);


	return CMD_SUCCESS;
}

static void ip_msdp_show_peers(struct pim_instance *pim, struct vty *vty,
			       bool uj)
{
	struct listnode *mpnode;
	struct pim_msdp_peer *mp;
	char peer_str[INET_ADDRSTRLEN];
	char local_str[INET_ADDRSTRLEN];
	char state_str[PIM_MSDP_STATE_STRLEN];
	char timebuf[PIM_MSDP_UPTIME_STRLEN];
	int64_t now;
	json_object *json = NULL;
	json_object *json_row = NULL;


	if (uj) {
		json = json_object_new_object();
	} else {
		vty_out(vty,
			"Peer                       Local        State    Uptime   SaCnt\n");
	}

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.peer_list, mpnode, mp)) {
		if (mp->state == PIM_MSDP_ESTABLISHED) {
			now = pim_time_monotonic_sec();
			pim_time_uptime(timebuf, sizeof(timebuf),
					now - mp->uptime);
		} else {
			strlcpy(timebuf, "-", sizeof(timebuf));
		}
		pim_inet4_dump("<peer?>", mp->peer, peer_str, sizeof(peer_str));
		pim_inet4_dump("<local?>", mp->local, local_str,
			       sizeof(local_str));
		pim_msdp_state_dump(mp->state, state_str, sizeof(state_str));
		if (uj) {
			json_row = json_object_new_object();
			json_object_string_add(json_row, "peer", peer_str);
			json_object_string_add(json_row, "local", local_str);
			json_object_string_add(json_row, "state", state_str);
			json_object_string_add(json_row, "upTime", timebuf);
			json_object_int_add(json_row, "saCount", mp->sa_cnt);
			json_object_object_add(json, peer_str, json_row);
		} else {
			vty_out(vty, "%-15s  %15s  %11s  %8s  %6d\n", peer_str,
				local_str, state_str, timebuf, mp->sa_cnt);
		}
	}

	if (uj)
		vty_json(vty, json);
}

static void ip_msdp_show_peers_detail(struct pim_instance *pim, struct vty *vty,
				      const char *peer, bool uj)
{
	struct listnode *mpnode;
	struct pim_msdp_peer *mp;
	char peer_str[INET_ADDRSTRLEN];
	char local_str[INET_ADDRSTRLEN];
	char state_str[PIM_MSDP_STATE_STRLEN];
	char timebuf[PIM_MSDP_UPTIME_STRLEN];
	char katimer[PIM_MSDP_TIMER_STRLEN];
	char crtimer[PIM_MSDP_TIMER_STRLEN];
	char holdtimer[PIM_MSDP_TIMER_STRLEN];
	int64_t now;
	json_object *json = NULL;
	json_object *json_row = NULL;

	if (uj) {
		json = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.peer_list, mpnode, mp)) {
		pim_inet4_dump("<peer?>", mp->peer, peer_str, sizeof(peer_str));
		if (strcmp(peer, "detail") && strcmp(peer, peer_str))
			continue;

		if (mp->state == PIM_MSDP_ESTABLISHED) {
			now = pim_time_monotonic_sec();
			pim_time_uptime(timebuf, sizeof(timebuf),
					now - mp->uptime);
		} else {
			strlcpy(timebuf, "-", sizeof(timebuf));
		}
		pim_inet4_dump("<local?>", mp->local, local_str,
			       sizeof(local_str));
		pim_msdp_state_dump(mp->state, state_str, sizeof(state_str));
		pim_time_timer_to_hhmmss(katimer, sizeof(katimer),
					 mp->ka_timer);
		pim_time_timer_to_hhmmss(crtimer, sizeof(crtimer),
					 mp->cr_timer);
		pim_time_timer_to_hhmmss(holdtimer, sizeof(holdtimer),
					 mp->hold_timer);

		if (uj) {
			json_row = json_object_new_object();
			json_object_string_add(json_row, "peer", peer_str);
			json_object_string_add(json_row, "local", local_str);
			if (mp->flags & PIM_MSDP_PEERF_IN_GROUP)
				json_object_string_add(json_row,
						       "meshGroupName",
						       mp->mesh_group_name);
			json_object_string_add(json_row, "state", state_str);
			json_object_string_add(json_row, "upTime", timebuf);
			json_object_string_add(json_row, "keepAliveTimer",
					       katimer);
			json_object_string_add(json_row, "connRetryTimer",
					       crtimer);
			json_object_string_add(json_row, "holdTimer",
					       holdtimer);
			json_object_string_add(json_row, "lastReset",
					       mp->last_reset);
			json_object_int_add(json_row, "connAttempts",
					    mp->conn_attempts);
			json_object_int_add(json_row, "establishedChanges",
					    mp->est_flaps);
			json_object_int_add(json_row, "saCount", mp->sa_cnt);
			json_object_int_add(json_row, "kaSent", mp->ka_tx_cnt);
			json_object_int_add(json_row, "kaRcvd", mp->ka_rx_cnt);
			json_object_int_add(json_row, "saSent", mp->sa_tx_cnt);
			json_object_int_add(json_row, "saRcvd", mp->sa_rx_cnt);
			json_object_object_add(json, peer_str, json_row);
		} else {
			vty_out(vty, "Peer : %s\n", peer_str);
			vty_out(vty, "  Local               : %s\n", local_str);
			if (mp->flags & PIM_MSDP_PEERF_IN_GROUP)
				vty_out(vty, "  Mesh Group          : %s\n",
					mp->mesh_group_name);
			vty_out(vty, "  State               : %s\n", state_str);
			vty_out(vty, "  Uptime              : %s\n", timebuf);

			vty_out(vty, "  Keepalive Timer     : %s\n", katimer);
			vty_out(vty, "  Conn Retry Timer    : %s\n", crtimer);
			vty_out(vty, "  Hold Timer          : %s\n", holdtimer);
			vty_out(vty, "  Last Reset          : %s\n",
				mp->last_reset);
			vty_out(vty, "  Conn Attempts       : %d\n",
				mp->conn_attempts);
			vty_out(vty, "  Established Changes : %d\n",
				mp->est_flaps);
			vty_out(vty, "  SA Count            : %d\n",
				mp->sa_cnt);
			vty_out(vty, "  Statistics          :\n");
			vty_out(vty,
				"                       Sent       Rcvd\n");
			vty_out(vty, "    Keepalives : %10d %10d\n",
				mp->ka_tx_cnt, mp->ka_rx_cnt);
			vty_out(vty, "    SAs        : %10d %10d\n",
				mp->sa_tx_cnt, mp->sa_rx_cnt);
			vty_out(vty, "\n");
		}
	}

	if (uj)
		vty_json(vty, json);
}

DEFUN (show_ip_msdp_peer_detail,
       show_ip_msdp_peer_detail_cmd,
       "show ip msdp [vrf NAME] peer [detail|A.B.C.D] [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP peer information\n"
       "Detailed output\n"
       "peer ip address\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	char *arg = NULL;

	if (argv_find(argv, argc, "detail", &idx))
		arg = argv[idx]->text;
	else if (argv_find(argv, argc, "A.B.C.D", &idx))
		arg = argv[idx]->arg;

	if (arg)
		ip_msdp_show_peers_detail(vrf->info, vty, argv[idx]->arg, uj);
	else
		ip_msdp_show_peers(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

DEFUN (show_ip_msdp_peer_detail_vrf_all,
       show_ip_msdp_peer_detail_vrf_all_cmd,
       "show ip msdp vrf all peer [detail|A.B.C.D] [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP peer information\n"
       "Detailed output\n"
       "peer ip address\n"
       JSON_STR)
{
	int idx = 2;
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	bool first = true;

	if (uj)
		vty_out(vty, "{ ");
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (uj) {
			if (!first)
				vty_out(vty, ", ");
			vty_out(vty, " \"%s\": ", vrf->name);
			first = false;
		} else
			vty_out(vty, "VRF: %s\n", vrf->name);
		if (argv_find(argv, argc, "detail", &idx)
		    || argv_find(argv, argc, "A.B.C.D", &idx))
			ip_msdp_show_peers_detail(vrf->info, vty,
						  argv[idx]->arg, uj);
		else
			ip_msdp_show_peers(vrf->info, vty, uj);
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

static void ip_msdp_show_sa(struct pim_instance *pim, struct vty *vty, bool uj)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;
	char rp_str[INET_ADDRSTRLEN];
	char timebuf[PIM_MSDP_UPTIME_STRLEN];
	char spt_str[8];
	char local_str[8];
	int64_t now;
	json_object *json = NULL;
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	if (uj) {
		json = json_object_new_object();
	} else {
		vty_out(vty,
			"Source                     Group               RP  Local  SPT    Uptime\n");
	}

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		now = pim_time_monotonic_sec();
		pim_time_uptime(timebuf, sizeof(timebuf), now - sa->uptime);
		if (sa->flags & PIM_MSDP_SAF_PEER) {
			pim_inet4_dump("<rp?>", sa->rp, rp_str, sizeof(rp_str));
			if (sa->up) {
				strlcpy(spt_str, "yes", sizeof(spt_str));
			} else {
				strlcpy(spt_str, "no", sizeof(spt_str));
			}
		} else {
			strlcpy(rp_str, "-", sizeof(rp_str));
			strlcpy(spt_str, "-", sizeof(spt_str));
		}
		if (sa->flags & PIM_MSDP_SAF_LOCAL) {
			strlcpy(local_str, "yes", sizeof(local_str));
		} else {
			strlcpy(local_str, "no", sizeof(local_str));
		}
		if (uj) {
			char src_str[PIM_ADDRSTRLEN];
			char grp_str[PIM_ADDRSTRLEN];

			snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
				   &sa->sg.grp);
			snprintfrr(src_str, sizeof(src_str), "%pPAs",
				   &sa->sg.src);

			json_object_object_get_ex(json, grp_str, &json_group);

			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			json_row = json_object_new_object();
			json_object_string_add(json_row, "source", src_str);
			json_object_string_add(json_row, "group", grp_str);
			json_object_string_add(json_row, "rp", rp_str);
			json_object_string_add(json_row, "local", local_str);
			json_object_string_add(json_row, "sptSetup", spt_str);
			json_object_string_add(json_row, "upTime", timebuf);
			json_object_object_add(json_group, src_str, json_row);
		} else {
			vty_out(vty, "%-15pPAs  %15pPAs  %15s  %5c  %3c  %8s\n",
				&sa->sg.src, &sa->sg.grp, rp_str, local_str[0],
				spt_str[0], timebuf);
		}
	}

	if (uj)
		vty_json(vty, json);
}

static void ip_msdp_show_sa_entry_detail(struct pim_msdp_sa *sa,
					 const char *src_str,
					 const char *grp_str, struct vty *vty,
					 bool uj, json_object *json)
{
	char rp_str[INET_ADDRSTRLEN];
	char peer_str[INET_ADDRSTRLEN];
	char timebuf[PIM_MSDP_UPTIME_STRLEN];
	char spt_str[8];
	char local_str[8];
	char statetimer[PIM_MSDP_TIMER_STRLEN];
	int64_t now;
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	now = pim_time_monotonic_sec();
	pim_time_uptime(timebuf, sizeof(timebuf), now - sa->uptime);
	if (sa->flags & PIM_MSDP_SAF_PEER) {
		pim_inet4_dump("<rp?>", sa->rp, rp_str, sizeof(rp_str));
		pim_inet4_dump("<peer?>", sa->peer, peer_str, sizeof(peer_str));
		if (sa->up) {
			strlcpy(spt_str, "yes", sizeof(spt_str));
		} else {
			strlcpy(spt_str, "no", sizeof(spt_str));
		}
	} else {
		strlcpy(rp_str, "-", sizeof(rp_str));
		strlcpy(peer_str, "-", sizeof(peer_str));
		strlcpy(spt_str, "-", sizeof(spt_str));
	}
	if (sa->flags & PIM_MSDP_SAF_LOCAL) {
		strlcpy(local_str, "yes", sizeof(local_str));
	} else {
		strlcpy(local_str, "no", sizeof(local_str));
	}
	pim_time_timer_to_hhmmss(statetimer, sizeof(statetimer),
				 sa->sa_state_timer);
	if (uj) {
		json_object_object_get_ex(json, grp_str, &json_group);

		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, grp_str, json_group);
		}

		json_row = json_object_new_object();
		json_object_string_add(json_row, "source", src_str);
		json_object_string_add(json_row, "group", grp_str);
		json_object_string_add(json_row, "rp", rp_str);
		json_object_string_add(json_row, "local", local_str);
		json_object_string_add(json_row, "sptSetup", spt_str);
		json_object_string_add(json_row, "upTime", timebuf);
		json_object_string_add(json_row, "stateTimer", statetimer);
		json_object_object_add(json_group, src_str, json_row);
	} else {
		vty_out(vty, "SA : %s\n", sa->sg_str);
		vty_out(vty, "  RP          : %s\n", rp_str);
		vty_out(vty, "  Peer        : %s\n", peer_str);
		vty_out(vty, "  Local       : %s\n", local_str);
		vty_out(vty, "  SPT Setup   : %s\n", spt_str);
		vty_out(vty, "  Uptime      : %s\n", timebuf);
		vty_out(vty, "  State Timer : %s\n", statetimer);
		vty_out(vty, "\n");
	}
}

static void ip_msdp_show_sa_detail(struct pim_instance *pim, struct vty *vty,
				   bool uj)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;
	json_object *json = NULL;

	if (uj) {
		json = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		char src_str[PIM_ADDRSTRLEN];
		char grp_str[PIM_ADDRSTRLEN];

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs", &sa->sg.grp);
		snprintfrr(src_str, sizeof(src_str), "%pPAs", &sa->sg.src);

		ip_msdp_show_sa_entry_detail(sa, src_str, grp_str, vty, uj,
					     json);
	}

	if (uj)
		vty_json(vty, json);
}

DEFUN (show_ip_msdp_sa_detail,
       show_ip_msdp_sa_detail_cmd,
       "show ip msdp [vrf NAME] sa detail [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP active-source information\n"
       "Detailed output\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	ip_msdp_show_sa_detail(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

DEFUN (show_ip_msdp_sa_detail_vrf_all,
       show_ip_msdp_sa_detail_vrf_all_cmd,
       "show ip msdp vrf all sa detail [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP active-source information\n"
       "Detailed output\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	bool first = true;

	if (uj)
		vty_out(vty, "{ ");
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (uj) {
			if (!first)
				vty_out(vty, ", ");
			vty_out(vty, " \"%s\": ", vrf->name);
			first = false;
		} else
			vty_out(vty, "VRF: %s\n", vrf->name);
		ip_msdp_show_sa_detail(vrf->info, vty, uj);
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

static void ip_msdp_show_sa_addr(struct pim_instance *pim, struct vty *vty,
				 const char *addr, bool uj)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;
	json_object *json = NULL;

	if (uj) {
		json = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		char src_str[PIM_ADDRSTRLEN];
		char grp_str[PIM_ADDRSTRLEN];

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs", &sa->sg.grp);
		snprintfrr(src_str, sizeof(src_str), "%pPAs", &sa->sg.src);

		if (!strcmp(addr, src_str) || !strcmp(addr, grp_str)) {
			ip_msdp_show_sa_entry_detail(sa, src_str, grp_str, vty,
						     uj, json);
		}
	}

	if (uj)
		vty_json(vty, json);
}

static void ip_msdp_show_sa_sg(struct pim_instance *pim, struct vty *vty,
			       const char *src, const char *grp, bool uj)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;
	json_object *json = NULL;

	if (uj) {
		json = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		char src_str[PIM_ADDRSTRLEN];
		char grp_str[PIM_ADDRSTRLEN];

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs", &sa->sg.grp);
		snprintfrr(src_str, sizeof(src_str), "%pPAs", &sa->sg.src);

		if (!strcmp(src, src_str) && !strcmp(grp, grp_str)) {
			ip_msdp_show_sa_entry_detail(sa, src_str, grp_str, vty,
						     uj, json);
		}
	}

	if (uj)
		vty_json(vty, json);
}

DEFUN (show_ip_msdp_sa_sg,
       show_ip_msdp_sa_sg_cmd,
       "show ip msdp [vrf NAME] sa [A.B.C.D [A.B.C.D]] [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP active-source information\n"
       "source or group ip\n"
       "group ip\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	int idx = 2;

	vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	char *src_ip = argv_find(argv, argc, "A.B.C.D", &idx) ? argv[idx++]->arg
		: NULL;
	char *grp_ip = idx < argc && argv_find(argv, argc, "A.B.C.D", &idx)
		? argv[idx]->arg
		: NULL;

	if (src_ip && grp_ip)
		ip_msdp_show_sa_sg(vrf->info, vty, src_ip, grp_ip, uj);
	else if (src_ip)
		ip_msdp_show_sa_addr(vrf->info, vty, src_ip, uj);
	else
		ip_msdp_show_sa(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

DEFUN (show_ip_msdp_sa_sg_vrf_all,
       show_ip_msdp_sa_sg_vrf_all_cmd,
       "show ip msdp vrf all sa [A.B.C.D [A.B.C.D]] [json]",
       SHOW_STR
       IP_STR
       MSDP_STR
       VRF_CMD_HELP_STR
       "MSDP active-source information\n"
       "source or group ip\n"
       "group ip\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	bool first = true;
	int idx = 2;

	char *src_ip = argv_find(argv, argc, "A.B.C.D", &idx) ? argv[idx++]->arg
		: NULL;
	char *grp_ip = idx < argc && argv_find(argv, argc, "A.B.C.D", &idx)
		? argv[idx]->arg
		: NULL;

	if (uj)
		vty_out(vty, "{ ");
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (uj) {
			if (!first)
				vty_out(vty, ", ");
			vty_out(vty, " \"%s\": ", vrf->name);
			first = false;
		} else
			vty_out(vty, "VRF: %s\n", vrf->name);

		if (src_ip && grp_ip)
			ip_msdp_show_sa_sg(vrf->info, vty, src_ip, grp_ip, uj);
		else if (src_ip)
			ip_msdp_show_sa_addr(vrf->info, vty, src_ip, uj);
		else
			ip_msdp_show_sa(vrf->info, vty, uj);
	}
	if (uj)
		vty_out(vty, "}\n");

	return CMD_SUCCESS;
}

struct pim_sg_cache_walk_data {
	struct vty *vty;
	json_object *json;
	json_object *json_group;
	struct in_addr addr;
	bool addr_match;
};

static void pim_show_vxlan_sg_entry(struct pim_vxlan_sg *vxlan_sg,
				    struct pim_sg_cache_walk_data *cwd)
{
	struct vty *vty = cwd->vty;
	json_object *json = cwd->json;
	json_object *json_row;
	bool installed = (vxlan_sg->up) ? true : false;
	const char *iif_name = vxlan_sg->iif?vxlan_sg->iif->name:"-";
	const char *oif_name;

	if (pim_vxlan_is_orig_mroute(vxlan_sg))
		oif_name = vxlan_sg->orig_oif?vxlan_sg->orig_oif->name:"";
	else
		oif_name = vxlan_sg->term_oif?vxlan_sg->term_oif->name:"";

	if (cwd->addr_match && pim_addr_cmp(vxlan_sg->sg.src, cwd->addr) &&
	    pim_addr_cmp(vxlan_sg->sg.grp, cwd->addr)) {
		return;
	}
	if (json) {
		char src_str[PIM_ADDRSTRLEN];
		char grp_str[PIM_ADDRSTRLEN];

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
			   &vxlan_sg->sg.grp);
		snprintfrr(src_str, sizeof(src_str), "%pPAs",
			   &vxlan_sg->sg.src);

		json_object_object_get_ex(json, grp_str, &cwd->json_group);

		if (!cwd->json_group) {
			cwd->json_group = json_object_new_object();
			json_object_object_add(json, grp_str,
					       cwd->json_group);
		}

		json_row = json_object_new_object();
		json_object_string_add(json_row, "source", src_str);
		json_object_string_add(json_row, "group", grp_str);
		json_object_string_add(json_row, "input", iif_name);
		json_object_string_add(json_row, "output", oif_name);
		if (installed)
			json_object_boolean_true_add(json_row, "installed");
		else
			json_object_boolean_false_add(json_row, "installed");
		json_object_object_add(cwd->json_group, src_str, json_row);
	} else {
		vty_out(vty, "%-15pPAs %-15pPAs %-15s %-15s %-5s\n",
			&vxlan_sg->sg.src, &vxlan_sg->sg.grp, iif_name,
			oif_name, installed ? "I" : "");
	}
}

static void pim_show_vxlan_sg_hash_entry(struct hash_bucket *bucket, void *arg)
{
	pim_show_vxlan_sg_entry((struct pim_vxlan_sg *)bucket->data,
				(struct pim_sg_cache_walk_data *)arg);
}

static void pim_show_vxlan_sg(struct pim_instance *pim,
			      struct vty *vty, bool uj)
{
	json_object *json = NULL;
	struct pim_sg_cache_walk_data cwd;

	if (uj) {
		json = json_object_new_object();
	} else {
		vty_out(vty, "Codes: I -> installed\n");
		vty_out(vty,
			"Source          Group           Input           Output          Flags\n");
	}

	memset(&cwd, 0, sizeof(cwd));
	cwd.vty = vty;
	cwd.json = json;
	hash_iterate(pim->vxlan.sg_hash, pim_show_vxlan_sg_hash_entry, &cwd);

	if (uj)
		vty_json(vty, json);
}

static void pim_show_vxlan_sg_match_addr(struct pim_instance *pim,
					 struct vty *vty, char *addr_str,
					 bool uj)
{
	json_object *json = NULL;
	struct pim_sg_cache_walk_data cwd;
	int result = 0;

	memset(&cwd, 0, sizeof(cwd));
	result = inet_pton(AF_INET, addr_str, &cwd.addr);
	if (result <= 0) {
		vty_out(vty, "Bad address %s: errno=%d: %s\n", addr_str,
			errno, safe_strerror(errno));
		return;
	}

	if (uj) {
		json = json_object_new_object();
	} else {
		vty_out(vty, "Codes: I -> installed\n");
		vty_out(vty,
			"Source          Group           Input           Output          Flags\n");
	}

	cwd.vty = vty;
	cwd.json = json;
	cwd.addr_match = true;
	hash_iterate(pim->vxlan.sg_hash, pim_show_vxlan_sg_hash_entry, &cwd);

	if (uj)
		vty_json(vty, json);
}

static void pim_show_vxlan_sg_one(struct pim_instance *pim,
				  struct vty *vty, char *src_str, char *grp_str,
				  bool uj)
{
	json_object *json = NULL;
	pim_sgaddr sg;
	int result = 0;
	struct pim_vxlan_sg *vxlan_sg;
	const char *iif_name;
	bool installed;
	const char *oif_name;

	result = inet_pton(AF_INET, src_str, &sg.src);
	if (result <= 0) {
		vty_out(vty, "Bad src address %s: errno=%d: %s\n", src_str,
			errno, safe_strerror(errno));
		return;
	}
	result = inet_pton(AF_INET, grp_str, &sg.grp);
	if (result <= 0) {
		vty_out(vty, "Bad grp address %s: errno=%d: %s\n", grp_str,
			errno, safe_strerror(errno));
		return;
	}

	if (uj)
		json = json_object_new_object();

	vxlan_sg = pim_vxlan_sg_find(pim, &sg);
	if (vxlan_sg) {
		installed = (vxlan_sg->up) ? true : false;
		iif_name = vxlan_sg->iif?vxlan_sg->iif->name:"-";

		if (pim_vxlan_is_orig_mroute(vxlan_sg))
			oif_name =
				vxlan_sg->orig_oif?vxlan_sg->orig_oif->name:"";
		else
			oif_name =
				vxlan_sg->term_oif?vxlan_sg->term_oif->name:"";

		if (uj) {
			json_object_string_add(json, "source", src_str);
			json_object_string_add(json, "group", grp_str);
			json_object_string_add(json, "input", iif_name);
			json_object_string_add(json, "output", oif_name);
			if (installed)
				json_object_boolean_true_add(json, "installed");
			else
				json_object_boolean_false_add(json,
							      "installed");
		} else {
			vty_out(vty, "SG : %s\n", vxlan_sg->sg_str);
			vty_out(vty, "  Input     : %s\n", iif_name);
			vty_out(vty, "  Output    : %s\n", oif_name);
			vty_out(vty, "  installed : %s\n",
				installed?"yes":"no");
		}
	}

	if (uj)
		vty_json(vty, json);
}

DEFUN (show_ip_pim_vxlan_sg,
       show_ip_pim_vxlan_sg_cmd,
       "show ip pim [vrf NAME] vxlan-groups [A.B.C.D [A.B.C.D]] [json]",
       SHOW_STR
       IP_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "VxLAN BUM groups\n"
       "source or group ip\n"
       "group ip\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	int idx = 2;

	vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	char *src_ip = argv_find(argv, argc, "A.B.C.D", &idx) ?
		argv[idx++]->arg:NULL;
	char *grp_ip = idx < argc && argv_find(argv, argc, "A.B.C.D", &idx) ?
		argv[idx]->arg:NULL;

	if (src_ip && grp_ip)
		pim_show_vxlan_sg_one(vrf->info, vty, src_ip, grp_ip, uj);
	else if (src_ip)
		pim_show_vxlan_sg_match_addr(vrf->info, vty, src_ip, uj);
	else
		pim_show_vxlan_sg(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

static void pim_show_vxlan_sg_work(struct pim_instance *pim,
				   struct vty *vty, bool uj)
{
	json_object *json = NULL;
	struct pim_sg_cache_walk_data cwd;
	struct listnode *node;
	struct pim_vxlan_sg *vxlan_sg;

	if (uj) {
		json = json_object_new_object();
	} else {
		vty_out(vty, "Codes: I -> installed\n");
		vty_out(vty,
			"Source          Group           Input           Flags\n");
	}

	memset(&cwd, 0, sizeof(cwd));
	cwd.vty = vty;
	cwd.json = json;
	for (ALL_LIST_ELEMENTS_RO(pim_vxlan_p->work_list, node, vxlan_sg))
		pim_show_vxlan_sg_entry(vxlan_sg, &cwd);

	if (uj)
		vty_json(vty, json);
}

DEFUN_HIDDEN (show_ip_pim_vxlan_sg_work,
              show_ip_pim_vxlan_sg_work_cmd,
              "show ip pim [vrf NAME] vxlan-work [json]",
              SHOW_STR
              IP_STR
              PIM_STR
              VRF_CMD_HELP_STR
              "VxLAN work list\n"
              JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct vrf *vrf;
	int idx = 2;

	vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, uj);

	if (!vrf)
		return CMD_WARNING;

	pim_show_vxlan_sg_work(vrf->info, vty, uj);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ip_pim_mlag,
	      no_ip_pim_mlag_cmd,
	      "no ip pim mlag",
	      NO_STR
	      IP_STR
	      PIM_STR
	      "MLAG\n")
{
	char mlag_xpath[XPATH_MAXLEN];

	snprintf(mlag_xpath, sizeof(mlag_xpath), FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", "default", "frr-routing:ipv4");
	strlcat(mlag_xpath, "/mlag", sizeof(mlag_xpath));

	nb_cli_enqueue_change(vty, mlag_xpath, NB_OP_DESTROY, NULL);


	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_HIDDEN (ip_pim_mlag,
	      ip_pim_mlag_cmd,
	      "ip pim mlag INTERFACE role [primary|secondary] state [up|down] addr A.B.C.D",
	      IP_STR
	      PIM_STR
	      "MLAG\n"
	      "peerlink sub interface\n"
	      "MLAG role\n"
	      "MLAG role primary\n"
	      "MLAG role secondary\n"
	      "peer session state\n"
	      "peer session state up\n"
	      "peer session state down\n"
	      "configure PIP\n"
	      "unique ip address\n")
{
	int idx;
	char mlag_peerlink_rif_xpath[XPATH_MAXLEN];
	char mlag_my_role_xpath[XPATH_MAXLEN];
	char mlag_peer_state_xpath[XPATH_MAXLEN];
	char mlag_reg_address_xpath[XPATH_MAXLEN];

	snprintf(mlag_peerlink_rif_xpath, sizeof(mlag_peerlink_rif_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", "default", "frr-routing:ipv4");
	strlcat(mlag_peerlink_rif_xpath, "/mlag/peerlink-rif",
		sizeof(mlag_peerlink_rif_xpath));

	idx = 3;
	nb_cli_enqueue_change(vty, mlag_peerlink_rif_xpath, NB_OP_MODIFY,
			      argv[idx]->arg);

	snprintf(mlag_my_role_xpath, sizeof(mlag_my_role_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", "default", "frr-routing:ipv4");
	strlcat(mlag_my_role_xpath, "/mlag/my-role",
		sizeof(mlag_my_role_xpath));

	idx += 2;
	if (!strcmp(argv[idx]->arg, "primary")) {
		nb_cli_enqueue_change(vty, mlag_my_role_xpath, NB_OP_MODIFY,
				      "MLAG_ROLE_PRIMARY");

	} else if (!strcmp(argv[idx]->arg, "secondary")) {
		nb_cli_enqueue_change(vty, mlag_my_role_xpath, NB_OP_MODIFY,
				      "MLAG_ROLE_SECONDARY");

	} else {
		vty_out(vty, "unknown MLAG role %s\n", argv[idx]->arg);
		return CMD_WARNING;
	}

	snprintf(mlag_peer_state_xpath, sizeof(mlag_peer_state_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", "default", "frr-routing:ipv4");
	strlcat(mlag_peer_state_xpath, "/mlag/peer-state",
		sizeof(mlag_peer_state_xpath));

	idx += 2;
	if (!strcmp(argv[idx]->arg, "up")) {
		nb_cli_enqueue_change(vty, mlag_peer_state_xpath, NB_OP_MODIFY,
				      "true");

	} else if (strcmp(argv[idx]->arg, "down")) {
		nb_cli_enqueue_change(vty, mlag_peer_state_xpath, NB_OP_MODIFY,
				      "false");

	} else {
		vty_out(vty, "unknown MLAG state %s\n", argv[idx]->arg);
		return CMD_WARNING;
	}

	snprintf(mlag_reg_address_xpath, sizeof(mlag_reg_address_xpath),
		 FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", "default", "frr-routing:ipv4");
	strlcat(mlag_reg_address_xpath, "/mlag/reg-address",
		sizeof(mlag_reg_address_xpath));

	idx += 2;
	nb_cli_enqueue_change(vty, mlag_reg_address_xpath, NB_OP_MODIFY,
			      argv[idx]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

void pim_cmd_init(void)
{
	if_cmd_init(pim_interface_config_write);

	install_node(&debug_node);

	install_element(ENABLE_NODE, &pim_test_sg_keepalive_cmd);

	install_element(CONFIG_NODE, &ip_pim_rp_cmd);
	install_element(VRF_NODE, &ip_pim_rp_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_rp_cmd);
	install_element(VRF_NODE, &no_ip_pim_rp_cmd);
	install_element(CONFIG_NODE, &ip_pim_rp_prefix_list_cmd);
	install_element(VRF_NODE, &ip_pim_rp_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_rp_prefix_list_cmd);
	install_element(VRF_NODE, &no_ip_pim_rp_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_ssm_prefix_list_cmd);
	install_element(VRF_NODE, &no_ip_pim_ssm_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_ssm_prefix_list_name_cmd);
	install_element(VRF_NODE, &no_ip_pim_ssm_prefix_list_name_cmd);
	install_element(CONFIG_NODE, &ip_pim_ssm_prefix_list_cmd);
	install_element(VRF_NODE, &ip_pim_ssm_prefix_list_cmd);
	install_element(CONFIG_NODE, &ip_pim_register_suppress_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_register_suppress_cmd);
	install_element(CONFIG_NODE, &ip_pim_spt_switchover_infinity_cmd);
	install_element(VRF_NODE, &ip_pim_spt_switchover_infinity_cmd);
	install_element(CONFIG_NODE, &ip_pim_spt_switchover_infinity_plist_cmd);
	install_element(VRF_NODE, &ip_pim_spt_switchover_infinity_plist_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_spt_switchover_infinity_cmd);
	install_element(VRF_NODE, &no_ip_pim_spt_switchover_infinity_cmd);
	install_element(CONFIG_NODE,
			&no_ip_pim_spt_switchover_infinity_plist_cmd);
	install_element(VRF_NODE, &no_ip_pim_spt_switchover_infinity_plist_cmd);
	install_element(CONFIG_NODE, &pim_register_accept_list_cmd);
	install_element(VRF_NODE, &pim_register_accept_list_cmd);
	install_element(CONFIG_NODE, &ip_pim_joinprune_time_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_joinprune_time_cmd);
	install_element(CONFIG_NODE, &ip_pim_keep_alive_cmd);
	install_element(VRF_NODE, &ip_pim_keep_alive_cmd);
	install_element(CONFIG_NODE, &ip_pim_rp_keep_alive_cmd);
	install_element(VRF_NODE, &ip_pim_rp_keep_alive_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_keep_alive_cmd);
	install_element(VRF_NODE, &no_ip_pim_keep_alive_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_rp_keep_alive_cmd);
	install_element(VRF_NODE, &no_ip_pim_rp_keep_alive_cmd);
	install_element(CONFIG_NODE, &ip_pim_packets_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_packets_cmd);
	install_element(CONFIG_NODE, &ip_pim_v6_secondary_cmd);
	install_element(VRF_NODE, &ip_pim_v6_secondary_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_v6_secondary_cmd);
	install_element(VRF_NODE, &no_ip_pim_v6_secondary_cmd);
	install_element(CONFIG_NODE, &ip_ssmpingd_cmd);
	install_element(VRF_NODE, &ip_ssmpingd_cmd);
	install_element(CONFIG_NODE, &no_ip_ssmpingd_cmd);
	install_element(VRF_NODE, &no_ip_ssmpingd_cmd);
	install_element(CONFIG_NODE, &ip_msdp_peer_cmd);
	install_element(VRF_NODE, &ip_msdp_peer_cmd);
	install_element(CONFIG_NODE, &no_ip_msdp_peer_cmd);
	install_element(VRF_NODE, &no_ip_msdp_peer_cmd);
	install_element(CONFIG_NODE, &ip_pim_ecmp_cmd);
	install_element(VRF_NODE, &ip_pim_ecmp_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_ecmp_cmd);
	install_element(VRF_NODE, &no_ip_pim_ecmp_cmd);
	install_element(CONFIG_NODE, &ip_pim_ecmp_rebalance_cmd);
	install_element(VRF_NODE, &ip_pim_ecmp_rebalance_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_ecmp_rebalance_cmd);
	install_element(VRF_NODE, &no_ip_pim_ecmp_rebalance_cmd);
	install_element(CONFIG_NODE, &ip_pim_mlag_cmd);
	install_element(CONFIG_NODE, &no_ip_pim_mlag_cmd);
	install_element(CONFIG_NODE, &ip_igmp_group_watermark_cmd);
	install_element(VRF_NODE, &ip_igmp_group_watermark_cmd);
	install_element(CONFIG_NODE, &no_ip_igmp_group_watermark_cmd);
	install_element(VRF_NODE, &no_ip_igmp_group_watermark_cmd);

	install_element(INTERFACE_NODE, &interface_ip_igmp_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_igmp_cmd);
	install_element(INTERFACE_NODE, &interface_ip_igmp_join_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_igmp_join_cmd);
	install_element(INTERFACE_NODE, &interface_ip_igmp_version_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_igmp_version_cmd);
	install_element(INTERFACE_NODE, &interface_ip_igmp_query_interval_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ip_igmp_query_interval_cmd);
	install_element(INTERFACE_NODE,
			&interface_ip_igmp_query_max_response_time_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ip_igmp_query_max_response_time_cmd);
	install_element(INTERFACE_NODE,
			&interface_ip_igmp_query_max_response_time_dsec_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ip_igmp_query_max_response_time_dsec_cmd);
	install_element(INTERFACE_NODE,
			&interface_ip_igmp_last_member_query_count_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ip_igmp_last_member_query_count_cmd);
	install_element(INTERFACE_NODE,
			&interface_ip_igmp_last_member_query_interval_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ip_igmp_last_member_query_interval_cmd);
	install_element(INTERFACE_NODE, &interface_ip_pim_activeactive_cmd);
	install_element(INTERFACE_NODE, &interface_ip_pim_ssm_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_pim_ssm_cmd);
	install_element(INTERFACE_NODE, &interface_ip_pim_sm_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_pim_sm_cmd);
	install_element(INTERFACE_NODE, &interface_ip_pim_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_pim_cmd);
	install_element(INTERFACE_NODE, &interface_ip_pim_drprio_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_pim_drprio_cmd);
	install_element(INTERFACE_NODE, &interface_ip_pim_hello_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_pim_hello_cmd);
	install_element(INTERFACE_NODE, &interface_ip_pim_boundary_oil_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_pim_boundary_oil_cmd);
	install_element(INTERFACE_NODE, &interface_ip_igmp_query_generate_cmd);

	// Static mroutes NEB
	install_element(INTERFACE_NODE, &interface_ip_mroute_cmd);
	install_element(INTERFACE_NODE, &interface_no_ip_mroute_cmd);

	install_element(VIEW_NODE, &show_ip_igmp_interface_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_interface_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_join_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_join_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_groups_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_groups_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_groups_retransmissions_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_sources_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_sources_retransmissions_cmd);
	install_element(VIEW_NODE, &show_ip_igmp_statistics_cmd);
	install_element(VIEW_NODE, &show_ip_pim_assert_cmd);
	install_element(VIEW_NODE, &show_ip_pim_assert_internal_cmd);
	install_element(VIEW_NODE, &show_ip_pim_assert_metric_cmd);
	install_element(VIEW_NODE, &show_ip_pim_assert_winner_metric_cmd);
	install_element(VIEW_NODE, &show_ip_pim_interface_traffic_cmd);
	install_element(VIEW_NODE, &show_ip_pim_interface_cmd);
	install_element(VIEW_NODE, &show_ip_pim_interface_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_join_cmd);
	install_element(VIEW_NODE, &show_ip_pim_join_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_jp_agg_cmd);
	install_element(VIEW_NODE, &show_ip_pim_local_membership_cmd);
	install_element(VIEW_NODE, &show_ip_pim_mlag_summary_cmd);
	install_element(VIEW_NODE, &show_ip_pim_mlag_up_cmd);
	install_element(VIEW_NODE, &show_ip_pim_mlag_up_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_neighbor_cmd);
	install_element(VIEW_NODE, &show_ip_pim_neighbor_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_rpf_cmd);
	install_element(VIEW_NODE, &show_ip_pim_rpf_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_secondary_cmd);
	install_element(VIEW_NODE, &show_ip_pim_state_cmd);
	install_element(VIEW_NODE, &show_ip_pim_state_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_upstream_cmd);
	install_element(VIEW_NODE, &show_ip_pim_upstream_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_channel_cmd);
	install_element(VIEW_NODE, &show_ip_pim_upstream_join_desired_cmd);
	install_element(VIEW_NODE, &show_ip_pim_upstream_rpf_cmd);
	install_element(VIEW_NODE, &show_ip_pim_rp_cmd);
	install_element(VIEW_NODE, &show_ip_pim_rp_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_bsr_cmd);
	install_element(VIEW_NODE, &show_ip_multicast_cmd);
	install_element(VIEW_NODE, &show_ip_multicast_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_multicast_count_cmd);
	install_element(VIEW_NODE, &show_ip_multicast_count_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_mroute_cmd);
	install_element(VIEW_NODE, &show_ip_mroute_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_mroute_count_cmd);
	install_element(VIEW_NODE, &show_ip_mroute_count_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_mroute_summary_cmd);
	install_element(VIEW_NODE, &show_ip_mroute_summary_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_rib_cmd);
	install_element(VIEW_NODE, &show_ip_ssmpingd_cmd);
	install_element(VIEW_NODE, &show_ip_pim_nexthop_cmd);
	install_element(VIEW_NODE, &show_ip_pim_nexthop_lookup_cmd);
	install_element(VIEW_NODE, &show_ip_pim_bsrp_cmd);
	install_element(VIEW_NODE, &show_ip_pim_bsm_db_cmd);
	install_element(VIEW_NODE, &show_ip_pim_statistics_cmd);

	install_element(ENABLE_NODE, &clear_ip_mroute_count_cmd);
	install_element(ENABLE_NODE, &clear_ip_interfaces_cmd);
	install_element(ENABLE_NODE, &clear_ip_igmp_interfaces_cmd);
	install_element(ENABLE_NODE, &clear_ip_mroute_cmd);
	install_element(ENABLE_NODE, &clear_ip_pim_interfaces_cmd);
	install_element(ENABLE_NODE, &clear_ip_pim_interface_traffic_cmd);
	install_element(ENABLE_NODE, &clear_ip_pim_oil_cmd);
	install_element(ENABLE_NODE, &clear_ip_pim_statistics_cmd);
	install_element(ENABLE_NODE, &clear_ip_pim_bsr_db_cmd);

	install_element(ENABLE_NODE, &show_debugging_pim_cmd);

	install_element(ENABLE_NODE, &debug_igmp_cmd);
	install_element(ENABLE_NODE, &no_debug_igmp_cmd);
	install_element(ENABLE_NODE, &debug_igmp_events_cmd);
	install_element(ENABLE_NODE, &no_debug_igmp_events_cmd);
	install_element(ENABLE_NODE, &debug_igmp_packets_cmd);
	install_element(ENABLE_NODE, &no_debug_igmp_packets_cmd);
	install_element(ENABLE_NODE, &debug_igmp_trace_cmd);
	install_element(ENABLE_NODE, &no_debug_igmp_trace_cmd);
	install_element(ENABLE_NODE, &debug_igmp_trace_detail_cmd);
	install_element(ENABLE_NODE, &no_debug_igmp_trace_detail_cmd);
	install_element(ENABLE_NODE, &debug_mroute_cmd);
	install_element(ENABLE_NODE, &debug_mroute_detail_cmd);
	install_element(ENABLE_NODE, &no_debug_mroute_cmd);
	install_element(ENABLE_NODE, &no_debug_mroute_detail_cmd);
	install_element(ENABLE_NODE, &debug_pim_static_cmd);
	install_element(ENABLE_NODE, &no_debug_pim_static_cmd);
	install_element(ENABLE_NODE, &debug_pim_cmd);
	install_element(ENABLE_NODE, &debug_pim_nht_cmd);
	install_element(ENABLE_NODE, &debug_pim_nht_det_cmd);
	install_element(ENABLE_NODE, &debug_pim_nht_rp_cmd);
	install_element(ENABLE_NODE, &no_debug_pim_nht_rp_cmd);
	install_element(ENABLE_NODE, &debug_pim_events_cmd);
	install_element(ENABLE_NODE, &debug_pim_packets_cmd);
	install_element(ENABLE_NODE, &debug_pim_packetdump_send_cmd);
	install_element(ENABLE_NODE, &debug_pim_packetdump_recv_cmd);
	install_element(ENABLE_NODE, &debug_pim_trace_cmd);
	install_element(ENABLE_NODE, &debug_pim_trace_detail_cmd);
	install_element(ENABLE_NODE, &debug_ssmpingd_cmd);
	install_element(ENABLE_NODE, &no_debug_ssmpingd_cmd);
	install_element(ENABLE_NODE, &debug_pim_zebra_cmd);
	install_element(ENABLE_NODE, &debug_pim_mlag_cmd);
	install_element(ENABLE_NODE, &no_debug_pim_mlag_cmd);
	install_element(ENABLE_NODE, &debug_pim_vxlan_cmd);
	install_element(ENABLE_NODE, &no_debug_pim_vxlan_cmd);
	install_element(ENABLE_NODE, &debug_msdp_cmd);
	install_element(ENABLE_NODE, &no_debug_msdp_cmd);
	install_element(ENABLE_NODE, &debug_msdp_events_cmd);
	install_element(ENABLE_NODE, &no_debug_msdp_events_cmd);
	install_element(ENABLE_NODE, &debug_msdp_packets_cmd);
	install_element(ENABLE_NODE, &no_debug_msdp_packets_cmd);
	install_element(ENABLE_NODE, &debug_mtrace_cmd);
	install_element(ENABLE_NODE, &no_debug_mtrace_cmd);
	install_element(ENABLE_NODE, &debug_bsm_cmd);
	install_element(ENABLE_NODE, &no_debug_bsm_cmd);

	install_element(CONFIG_NODE, &debug_igmp_cmd);
	install_element(CONFIG_NODE, &no_debug_igmp_cmd);
	install_element(CONFIG_NODE, &debug_igmp_events_cmd);
	install_element(CONFIG_NODE, &no_debug_igmp_events_cmd);
	install_element(CONFIG_NODE, &debug_igmp_packets_cmd);
	install_element(CONFIG_NODE, &no_debug_igmp_packets_cmd);
	install_element(CONFIG_NODE, &debug_igmp_trace_cmd);
	install_element(CONFIG_NODE, &no_debug_igmp_trace_cmd);
	install_element(CONFIG_NODE, &debug_igmp_trace_detail_cmd);
	install_element(CONFIG_NODE, &no_debug_igmp_trace_detail_cmd);
	install_element(CONFIG_NODE, &debug_mroute_cmd);
	install_element(CONFIG_NODE, &debug_mroute_detail_cmd);
	install_element(CONFIG_NODE, &no_debug_mroute_cmd);
	install_element(CONFIG_NODE, &no_debug_mroute_detail_cmd);
	install_element(CONFIG_NODE, &debug_pim_static_cmd);
	install_element(CONFIG_NODE, &no_debug_pim_static_cmd);
	install_element(CONFIG_NODE, &debug_pim_cmd);
	install_element(CONFIG_NODE, &debug_pim_nht_cmd);
	install_element(CONFIG_NODE, &debug_pim_nht_det_cmd);
	install_element(CONFIG_NODE, &debug_pim_nht_rp_cmd);
	install_element(CONFIG_NODE, &no_debug_pim_nht_rp_cmd);
	install_element(CONFIG_NODE, &debug_pim_events_cmd);
	install_element(CONFIG_NODE, &debug_pim_packets_cmd);
	install_element(CONFIG_NODE, &debug_pim_packetdump_send_cmd);
	install_element(CONFIG_NODE, &debug_pim_packetdump_recv_cmd);
	install_element(CONFIG_NODE, &debug_pim_trace_cmd);
	install_element(CONFIG_NODE, &debug_pim_trace_detail_cmd);
	install_element(CONFIG_NODE, &debug_ssmpingd_cmd);
	install_element(CONFIG_NODE, &no_debug_ssmpingd_cmd);
	install_element(CONFIG_NODE, &debug_pim_zebra_cmd);
	install_element(CONFIG_NODE, &debug_pim_mlag_cmd);
	install_element(CONFIG_NODE, &no_debug_pim_mlag_cmd);
	install_element(CONFIG_NODE, &debug_pim_vxlan_cmd);
	install_element(CONFIG_NODE, &no_debug_pim_vxlan_cmd);
	install_element(CONFIG_NODE, &debug_msdp_cmd);
	install_element(CONFIG_NODE, &no_debug_msdp_cmd);
	install_element(CONFIG_NODE, &debug_msdp_events_cmd);
	install_element(CONFIG_NODE, &no_debug_msdp_events_cmd);
	install_element(CONFIG_NODE, &debug_msdp_packets_cmd);
	install_element(CONFIG_NODE, &no_debug_msdp_packets_cmd);
	install_element(CONFIG_NODE, &debug_mtrace_cmd);
	install_element(CONFIG_NODE, &no_debug_mtrace_cmd);
	install_element(CONFIG_NODE, &debug_bsm_cmd);
	install_element(CONFIG_NODE, &no_debug_bsm_cmd);

	install_element(CONFIG_NODE, &ip_msdp_timers_cmd);
	install_element(VRF_NODE, &ip_msdp_timers_cmd);
	install_element(CONFIG_NODE, &no_ip_msdp_timers_cmd);
	install_element(VRF_NODE, &no_ip_msdp_timers_cmd);
	install_element(CONFIG_NODE, &ip_msdp_mesh_group_member_cmd);
	install_element(VRF_NODE, &ip_msdp_mesh_group_member_cmd);
	install_element(CONFIG_NODE, &no_ip_msdp_mesh_group_member_cmd);
	install_element(VRF_NODE, &no_ip_msdp_mesh_group_member_cmd);
	install_element(CONFIG_NODE, &ip_msdp_mesh_group_source_cmd);
	install_element(VRF_NODE, &ip_msdp_mesh_group_source_cmd);
	install_element(CONFIG_NODE, &no_ip_msdp_mesh_group_source_cmd);
	install_element(VRF_NODE, &no_ip_msdp_mesh_group_source_cmd);
	install_element(CONFIG_NODE, &no_ip_msdp_mesh_group_cmd);
	install_element(VRF_NODE, &no_ip_msdp_mesh_group_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_peer_detail_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_peer_detail_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_sa_detail_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_sa_detail_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_sa_sg_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_sa_sg_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_mesh_group_cmd);
	install_element(VIEW_NODE, &show_ip_msdp_mesh_group_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ip_pim_ssm_range_cmd);
	install_element(VIEW_NODE, &show_ip_pim_group_type_cmd);
	install_element(VIEW_NODE, &show_ip_pim_vxlan_sg_cmd);
	install_element(VIEW_NODE, &show_ip_pim_vxlan_sg_work_cmd);
	install_element(INTERFACE_NODE, &interface_pim_use_source_cmd);
	install_element(INTERFACE_NODE, &interface_no_pim_use_source_cmd);
	/* Install BSM command */
	install_element(INTERFACE_NODE, &ip_pim_bsm_cmd);
	install_element(INTERFACE_NODE, &no_ip_pim_bsm_cmd);
	install_element(INTERFACE_NODE, &ip_pim_ucast_bsm_cmd);
	install_element(INTERFACE_NODE, &no_ip_pim_ucast_bsm_cmd);
	/* Install BFD command */
	install_element(INTERFACE_NODE, &ip_pim_bfd_cmd);
	install_element(INTERFACE_NODE, &ip_pim_bfd_param_cmd);
	install_element(INTERFACE_NODE, &no_ip_pim_bfd_profile_cmd);
	install_element(INTERFACE_NODE, &no_ip_pim_bfd_cmd);
#if HAVE_BFDD == 0
	install_element(INTERFACE_NODE, &no_ip_pim_bfd_param_cmd);
#endif /* !HAVE_BFDD */
}
