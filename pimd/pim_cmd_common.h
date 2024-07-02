// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for IPv6 FRR
 * Copyright (C) 2022  Vmware, Inc.
 *		       Mobashshera Rasool <mrasool@vmware.com>
 */
#ifndef PIM_CMD_COMMON_H
#define PIM_CMD_COMMON_H

struct pim_upstream;
struct pim_instance;

const char *pim_cli_get_vrf_name(struct vty *vty);
int pim_process_join_prune_cmd(struct vty *vty, const char *jpi_str);
int pim_process_no_join_prune_cmd(struct vty *vty);
int pim_process_spt_switchover_infinity_cmd(struct vty *vty);
int pim_process_spt_switchover_prefixlist_cmd(struct vty *vty,
					      const char *plist);
int pim_process_no_spt_switchover_cmd(struct vty *vty);
int pim_process_pim_packet_cmd(struct vty *vty, const char *packet);
int pim_process_no_pim_packet_cmd(struct vty *vty);
int pim_process_keepalivetimer_cmd(struct vty *vty, const char *kat);
int pim_process_no_keepalivetimer_cmd(struct vty *vty);
int pim_process_rp_kat_cmd(struct vty *vty, const char *rpkat);
int pim_process_no_rp_kat_cmd(struct vty *vty);
int pim_process_register_suppress_cmd(struct vty *vty, const char *rst);
int pim_process_no_register_suppress_cmd(struct vty *vty);
int pim_process_rp_cmd(struct vty *vty, const char *rp_str,
		       const char *group_str);
int pim_process_no_rp_cmd(struct vty *vty, const char *rp_str,
			  const char *group_str);
int pim_process_rp_plist_cmd(struct vty *vty, const char *rp_str,
			     const char *prefix_list);
int pim_process_no_rp_plist_cmd(struct vty *vty, const char *rp_str,
				const char *prefix_list);

int pim_process_ip_pim_cmd(struct vty *vty);
int pim_process_no_ip_pim_cmd(struct vty *vty);
int pim_process_ip_pim_passive_cmd(struct vty *vty, bool enable);
int pim_process_ip_pim_drprio_cmd(struct vty *vty, const char *drpriority_str);
int pim_process_no_ip_pim_drprio_cmd(struct vty *vty);
int pim_process_ip_pim_hello_cmd(struct vty *vty, const char *hello_str,
				 const char *hold_str);
int pim_process_no_ip_pim_hello_cmd(struct vty *vty);
int pim_process_ip_pim_activeactive_cmd(struct vty *vty, const char *no);
int pim_process_ip_pim_boundary_oil_cmd(struct vty *vty, const char *oil);
int pim_process_no_ip_pim_boundary_oil_cmd(struct vty *vty);
int pim_process_ip_mroute_cmd(struct vty *vty, const char *interface,
			      const char *group_str, const char *source_str);
int pim_process_no_ip_mroute_cmd(struct vty *vty, const char *interface,
				 const char *group_str, const char *src_str);
int pim_process_bsm_cmd(struct vty *vty);
int pim_process_no_bsm_cmd(struct vty *vty);
int pim_process_unicast_bsm_cmd(struct vty *vty);
int pim_process_no_unicast_bsm_cmd(struct vty *vty);
void json_object_pim_upstream_add(json_object *json, struct pim_upstream *up);
void pim_show_rpf(struct pim_instance *pim, struct vty *vty, json_object *json);
void pim_show_neighbors_secondary(struct pim_instance *pim, struct vty *vty);
void pim_show_state(struct pim_instance *pim, struct vty *vty,
		    const char *src_or_group, const char *group,
		    json_object *json);
void pim_show_statistics(struct pim_instance *pim, struct vty *vty,
			 const char *ifname, bool uj);
void pim_show_upstream(struct pim_instance *pim, struct vty *vty,
		       pim_sgaddr *sg, json_object *json);
void pim_show_join_desired(struct pim_instance *pim, struct vty *vty, bool uj);
void pim_show_upstream_rpf(struct pim_instance *pim, struct vty *vty, bool uj);
void pim_show_rpf_refresh_stats(struct vty *vty, struct pim_instance *pim,
				time_t now, json_object *json);
bool pim_sgaddr_match(pim_sgaddr item, pim_sgaddr match);
void json_object_pim_ifp_add(struct json_object *json, struct interface *ifp);
void pim_print_ifp_flags(struct vty *vty, struct interface *ifp);
void json_object_pim_upstream_add(json_object *json, struct pim_upstream *up);
int pim_show_join_cmd_helper(const char *vrf, struct vty *vty, pim_addr s_or_g,
			     pim_addr g, const char *json);
int pim_show_join_vrf_all_cmd_helper(struct vty *vty, const char *json);
void pim_show_join(struct pim_instance *pim, struct vty *vty, pim_sgaddr *sg,
		   json_object *json);
int pim_show_jp_agg_list_cmd_helper(const char *vrf, struct vty *vty);
void pim_show_jp_agg_list(struct pim_instance *pim, struct vty *vty);
int pim_show_membership_cmd_helper(const char *vrf, struct vty *vty, bool uj);
void pim_show_membership(struct pim_instance *pim, struct vty *vty, bool uj);
void pim_show_channel(struct pim_instance *pim, struct vty *vty, bool uj);
int pim_show_channel_cmd_helper(const char *vrf, struct vty *vty, bool uj);
int pim_show_interface_cmd_helper(const char *vrf, struct vty *vty, bool uj,
				  bool mlag, const char *interface);
int pim_show_interface_vrf_all_cmd_helper(struct vty *vty, bool uj, bool mlag,
					  const char *interface);
void pim_show_interfaces(struct pim_instance *pim, struct vty *vty, bool mlag,
			 json_object *json);
void pim_show_interfaces_single(struct pim_instance *pim, struct vty *vty,
				const char *ifname, bool mlag,
				json_object *json);
void ip_pim_ssm_show_group_range(struct pim_instance *pim, struct vty *vty,
				 bool uj);
int pim_show_nexthop_lookup_cmd_helper(const char *vrf, struct vty *vty,
				       pim_addr source, pim_addr group);
int pim_show_nexthop_cmd_helper(const char *vrf, struct vty *vty, bool uj);
void pim_show_nexthop(struct pim_instance *pim, struct vty *vty, bool uj);
int pim_show_neighbors_cmd_helper(const char *vrf, struct vty *vty,
				  const char *json, const char *interface);
int pim_show_neighbors_vrf_all_cmd_helper(struct vty *vty, const char *json,
					  const char *interface);
void pim_show_neighbors_single(struct pim_instance *pim, struct vty *vty,
			       const char *neighbor, json_object *json);
void pim_show_neighbors(struct pim_instance *pim, struct vty *vty,
			json_object *json);
int pim_show_group_rp_mappings_info_helper(const char *vrf, struct vty *vty,
					   bool uj);
int pim_show_bsm_db_helper(const char *vrf, struct vty *vty, bool uj);
int gm_process_query_max_response_time_cmd(struct vty *vty,
					   const char *qmrt_str);
int gm_process_no_query_max_response_time_cmd(struct vty *vty);
int gm_process_last_member_query_count_cmd(struct vty *vty,
					   const char *lmqc_str);
int gm_process_no_last_member_query_count_cmd(struct vty *vty);
int gm_process_last_member_query_interval_cmd(struct vty *vty,
					      const char *lmqi_str);
int gm_process_no_last_member_query_interval_cmd(struct vty *vty);
int pim_process_ssmpingd_cmd(struct vty *vty, enum nb_operation operation,
			     const char *src_str);
void pim_cmd_show_ip_multicast_helper(struct pim_instance *pim,
				      struct vty *vty);
void show_multicast_interfaces(struct pim_instance *pim, struct vty *vty,
			       json_object *json);
void show_mroute(struct pim_instance *pim, struct vty *vty, pim_sgaddr *sg,
		 bool fill, json_object *json);
void show_mroute_count(struct pim_instance *pim, struct vty *vty,
		       json_object *json);
void show_mroute_summary(struct pim_instance *pim, struct vty *vty,
			 json_object *json);
int clear_ip_mroute_count_command(struct vty *vty, const char *name);
struct vrf *pim_cmd_lookup(struct vty *vty, const char *name);
void clear_mroute(struct pim_instance *pim);
void clear_pim_statistics(struct pim_instance *pim);
int clear_pim_interface_traffic(const char *vrf, struct vty *vty);
int pim_debug_pim_cmd(void);
int pim_no_debug_pim_cmd(void);
int pim_debug_pim_packets_cmd(const char *hello, const char *joins,
			      const char *registers, struct vty *vty);
int pim_no_debug_pim_packets_cmd(const char *hello, const char *joins,
				 const char *registers, struct vty *vty);
int pim_show_rpf_helper(const char *vrf, struct vty *vty, bool json);
int pim_show_rpf_vrf_all_helper(struct vty *vty, bool json);
int pim_show_rp_helper(const char *vrf, struct vty *vty, const char *group_str,
		       const struct prefix *group, bool json);
int pim_show_rp_vrf_all_helper(struct vty *vty, const char *group_str,
			       const struct prefix *group, bool json);
int pim_show_secondary_helper(const char *vrf, struct vty *vty);
int pim_show_statistics_helper(const char *vrf, struct vty *vty,
			       const char *word, bool uj);
int pim_show_upstream_helper(const char *vrf, struct vty *vty, pim_addr s_or_g,
			     pim_addr g, bool json);
int pim_show_upstream_vrf_all_helper(struct vty *vty, bool json);
int pim_show_upstream_join_desired_helper(const char *vrf, struct vty *vty,
					  bool uj);
int pim_show_upstream_rpf_helper(const char *vrf, struct vty *vty, bool uj);
int pim_show_state_helper(const char *vrf, struct vty *vty,
			  const char *s_or_g_str, const char *g_str, bool json);
int pim_show_state_vrf_all_helper(struct vty *vty, const char *s_or_g_str,
				  const char *g_str, bool json);
int pim_show_multicast_helper(const char *vrf, struct vty *vty);
int pim_show_multicast_vrf_all_helper(struct vty *vty);
int pim_show_multicast_count_helper(const char *vrf, struct vty *vty,
				    bool json);
int pim_show_multicast_count_vrf_all_helper(struct vty *vty, bool json);
int pim_show_mroute_helper(const char *vrf, struct vty *vty, pim_addr s_or_g,
			   pim_addr g, bool fill, bool json);
int pim_show_mroute_vrf_all_helper(struct vty *vty, bool fill, bool json);
int pim_show_mroute_count_helper(const char *vrf, struct vty *vty, bool json);
int pim_show_mroute_count_vrf_all_helper(struct vty *vty, bool json);
int pim_show_mroute_summary_helper(const char *vrf, struct vty *vty, bool json);
int pim_show_mroute_summary_vrf_all_helper(struct vty *vty, bool json);

void pim_show_interface_traffic_single(struct pim_instance *pim,
				       struct vty *vty, const char *ifname,
				       bool uj);
void pim_show_interface_traffic(struct pim_instance *pim, struct vty *vty,
				bool uj);
int pim_show_interface_traffic_helper(const char *vrf, const char *if_name,
				      struct vty *vty, bool uj);
void clear_pim_interfaces(struct pim_instance *pim);
void pim_show_bsr(struct pim_instance *pim, struct vty *vty, bool uj);
int pim_show_bsr_helper(const char *vrf, struct vty *vty, bool uj);
int pim_router_config_write(struct vty *vty);

/*
 * Special Macro to allow us to get the correct pim_instance;
 */
#define PIM_DECLVAR_CONTEXT_VRF(vrfptr, pimptr)                                \
	VTY_DECLVAR_CONTEXT_VRF(vrfptr);                                       \
	struct pim_instance *pimptr = vrfptr->info;                            \
	MACRO_REQUIRE_SEMICOLON() /* end */

/*
 * Macros used to fix up the xpath so that global style PIM CLI handlers
 * can continue to use the common functions which now expect "router pim"
 * style configuration.
 * Global PIM configuration was at the top-level config node, or
 * within the vrf config node. Now configuration is moved to the
 * router pim[6] [vrf NAME] node.
 * So these macros will move vty to the router pim context and push
 * the correct base xpath, then all the common config handling assumes
 * that VTY_CURR_XPATH is correct and/or uses relative paths, and at
 * the end vty is moved back to the original node and xpath popped
 */
#define START_PIM_DEPRECATED(clinode)                           \
	const char *__vrfname;                                       \
	char __xpath[XPATH_MAXLEN];                                  \
	int __orig_node = -1;                                        \
	if (vty->node != clinode) {                                  \
		__vrfname = pim_cli_get_vrf_name(vty);                    \
		if (__vrfname) {                                          \
			snprintf(__xpath, sizeof(__xpath), FRR_PIM_VRF_XPATH,  \
				 "frr-pim:pimd", "pim", __vrfname,                  \
				 FRR_PIM_AF_XPATH_VAL);                             \
			nb_cli_enqueue_change(vty, __xpath, NB_OP_CREATE,      \
					      NULL);                                     \
			if (nb_cli_apply_changes_clear_pending(vty, NULL) ==   \
			    CMD_SUCCESS) {                                     \
				__orig_node = vty->node;                            \
				VTY_PUSH_XPATH(clinode, __xpath);                   \
			} else {                                               \
				return CMD_WARNING_CONFIG_FAILED;                   \
			}                                                      \
		} else {                                                  \
			vty_out(vty, "%% Failed to determine vrf name\n");     \
			return CMD_WARNING_CONFIG_FAILED;                      \
		}                                                         \
	}

#define END_PIM_DEPRECATED         \
	do {                            \
		if (__orig_node != -1) {     \
			vty->node = __orig_node;  \
			vty->xpath_index--;       \
		}                            \
	} while (0)

#endif /* PIM_CMD_COMMON_H */
