// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * Definitions of PCEP Counters.
 */

#ifndef PCEP_UTILS_INCLUDE_PCEP_UTILS_COUNTERS_H_
#define PCEP_UTILS_INCLUDE_PCEP_UTILS_COUNTERS_H_

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Example Counter group with sub-groups and counters
 *
 *  pcep_counters {
 *      counters_group_rx {
 *          message_open;
 *          message_keepalive;
 *          message_pcreq;
 *      }
 *      counters_group_tx {
 *          message_open;
 *          message_keepalive;
 *          message_pcreq;
 *      }
 *      counters_group_events {
 *          pcc_connect;
 *          pce_connect;
 *          pcc_disconnect;
 *          pce_disconnect;
 *      }
 *  }
 *
 * To create the above structure of groups, sub-groups, and counters, do the
 * following:
 *
 * struct counters_subgroup *rx_subgroup = create_counters_subgroup("rx
 * counters", 3); struct counters_subgroup *tx_subgroup =
 * create_counters_subgroup("tx counters", 3); struct counters_subgroup
 * *events_subgroup = create_counters_subgroup("events counters", 4);
 *
 * Use message_id: PCEP_TYPE_OPEN=1
 * create_subgroup_counter(rx_subgroup, 1, "Message Open", "messageOpen");
 * create_subgroup_counter(rx_subgroup, 2, "Message KeepAlive", "messageKeepAlive");
 * create_subgroup_counter(rx_subgroup, 3, "Message PcReq", "messagePcReq");
 *
 * create_subgroup_counter(tx_subgroup, 1, "Message Open", "messageOpen");
 * create_subgroup_counter(tx_subgroup, 2, "Message KeepAlive", "messageKeepAlive");
 * create_subgroup_counter(tx_subgroup, 3, "Message PcReq", "messagePcReq");
 *
 * create_subgroup_counter(events_subgroup, 1, "PCC Connect", "PCConnect");
 * create_subgroup_counter(events_subgroup, 2, "PCE Connect", "PCEConnect");
 * create_subgroup_counter(events_subgroup, 3, "PCC Disconnect", "PCCDisconnect");
 * create_subgroup_counter(events_subgroup, 4, "PCE Disconnect", "PCEDisconnect");
 *
 * struct counters_group *cntrs_group = create_counters_group("PCEP Counters",
 * 3); add_counters_subgroup(cntrs_group, rx_subgroup);
 * add_counters_subgroup(cntrs_group, tx_subgroup);
 * add_counters_subgroup(cntrs_group, events_subgroup);
 */

#define MAX_COUNTER_STR_LENGTH 128
#define MAX_COUNTER_GROUPS 500
#define MAX_COUNTERS 500

struct counter {
	uint16_t counter_id;
	char counter_name[MAX_COUNTER_STR_LENGTH];
	char counter_name_json[MAX_COUNTER_STR_LENGTH];
	uint32_t counter_value;
};

struct counters_subgroup {
	char counters_subgroup_name[MAX_COUNTER_STR_LENGTH];
	uint16_t subgroup_id;
	uint16_t num_counters;
	uint16_t max_counters;
	/* Array of (struct counter *) allocated when the subgroup is created.
	 * The array is indexed by the struct counter->counter_id */
	struct counter **counters;
};

struct counters_group {
	char counters_group_name[MAX_COUNTER_STR_LENGTH];
	uint16_t num_subgroups;
	uint16_t max_subgroups;
	time_t start_time;
	/* Array  of (struct counters_subgroup *) allocated when the group is
	 * created. The subgroup is indexed by the (struct counters_subgroup
	 * *)->subgroup_id */
	struct counters_subgroup **subgroups;
};

/*
 * Create a counters group with the given group_name and number of subgroups.
 * Subgroup_ids are 0-based, so take that into account when setting
 * max_subgroups. Return true on success or false if group_name is NULL or
 * max_subgroups >= MAX_COUNTER_GROUPS.
 */
struct counters_group *create_counters_group(const char *group_name,
					     uint16_t max_subgroups);

/*
 * Create a counters subgroup with the given subgroup_name, subgroup_id and
 * number of counters. The subgroup_id is 0-based. counter_ids are 0-based, so
 * take that into account when setting max_counters. Return true on success or
 * false if subgroup_name is NULL, subgroup_id >= MAX_COUNTER_GROUPS, or
 * max_counters >= MAX_COUNTERS.
 */
struct counters_subgroup *create_counters_subgroup(const char *subgroup_name,
						   uint16_t subgroup_id,
						   uint16_t max_counters);

/*
 * Add a counter_subgroup to a counter_group.
 * Return true on success or false if group is NULL or if subgroup is NULL.
 */
bool add_counters_subgroup(struct counters_group *group,
			   struct counters_subgroup *subgroup);

/*
 * Clone a subgroup and set a new name and subgroup_id for the new subgroup.
 * This is useful for RX and TX counters: just create the RX counters and clone
 * it for the TX counters.
 */
struct counters_subgroup *
clone_counters_subgroup(struct counters_subgroup *subgroup,
			const char *subgroup_name, uint16_t subgroup_id);

/*
 * Create a counter in a subgroup with the given counter_id and counter_name
 * and counter_name_json.
 * The counter_id is 0-based.
 * Return true on success or false if subgroup is NULL, counter_id >=
 * MAX_COUNTERS, or if counter_name is NULL.
 */
bool create_subgroup_counter(struct counters_subgroup *subgroup,
			     uint32_t counter_id, const char *counter_name,
			     const char *couter_name_json);

/*
 * Delete the counters_group and recursively delete all subgroups and their
 * counters. Return true on success or false if group is NULL.
 */
bool delete_counters_group(struct counters_group *group);

/*
 * Delete the counters_subgroup and all its counters counters.
 * Return true on success or false if subgroup is NULL.
 */
bool delete_counters_subgroup(struct counters_subgroup *subgroup);

/*
 * Reset all the counters in all sub-groups contained in this group.
 * Return true on success or false if group is NULL.
 */
bool reset_group_counters(struct counters_group *group);

/*
 * Reset all the counters in this subgroup.
 * Return true on success or false if subgroup is NULL.
 */
bool reset_subgroup_counters(struct counters_subgroup *subgroup);

/*
 * Increment a counter given a counter_group, subgroup_id, and counter_id.
 * Return true on success or false if group is NULL, subgroup_id >=
 * MAX_COUNTER_GROUPS, or counter_id >= MAX_COUNTERS.
 */
bool increment_counter(struct counters_group *group, uint16_t subgroup_id,
		       uint16_t counter_id);

/*
 * Increment a counter given the counter_subgroup and counter_id.
 * Return true on success or false if subgroup is NULL or counter_id >=
 * MAX_COUNTERS.
 */
bool increment_subgroup_counter(struct counters_subgroup *subgroup,
				uint16_t counter_id);

/*
 * Dump the counter_group info and all its counter_subgroups.
 * Return true on success or false if group is NULL.
 */
bool dump_counters_group_to_log(struct counters_group *group);

/*
 * Dump all the counters in a counter_subgroup.
 * Return true on success or false if subgroup is NULL.
 */
bool dump_counters_subgroup_to_log(struct counters_subgroup *subgroup);

/*
 * Search for a counters_subgroup by subgroup_id in a counters_group
 * and return it, if found, else return NULL.
 */
struct counters_subgroup *find_subgroup(const struct counters_group *group,
					uint16_t subgroup_id);

/*
 * Given a counters_subgroup, return the sum of all the counters.
 */
uint32_t subgroup_counters_total(struct counters_subgroup *subgroup);

#ifdef __cplusplus
}
#endif

#endif /* PCEP_UTILS_INCLUDE_PCEP_UTILS_COUNTERS_H_ */
