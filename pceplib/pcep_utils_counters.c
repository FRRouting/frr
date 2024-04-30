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
 * Implementation of PCEP Counters.
 */

#include <zebra.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pcep_utils_counters.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

struct counters_group *create_counters_group(const char *group_name,
					     uint16_t max_subgroups)
{
	if (group_name == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create counters group: group_name is NULL.",
			__func__);
		return NULL;
	}

	if (max_subgroups > MAX_COUNTER_GROUPS) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create counters group: max_subgroups [%d] is larger than max the [%d].",
			__func__, max_subgroups, MAX_COUNTER_GROUPS);
		return NULL;
	}

	struct counters_group *group =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(struct counters_group));
	memset(group, 0, sizeof(struct counters_group));
	group->subgroups =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(struct counters_subgroup *)
						      * (max_subgroups + 1));
	memset(group->subgroups, 0,
	       sizeof(struct counters_subgroup *) * (max_subgroups + 1));

	strlcpy(group->counters_group_name, group_name,
		sizeof(group->counters_group_name));
	group->max_subgroups = max_subgroups;
	group->start_time = time(NULL);

	return group;
}

struct counters_subgroup *create_counters_subgroup(const char *subgroup_name,
						   uint16_t subgroup_id,
						   uint16_t max_counters)
{
	if (subgroup_name == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create counters subgroup: subgroup_name is NULL.",
			__func__);
		return NULL;
	}

	if (max_counters > MAX_COUNTERS) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create counters subgroup: max_counters [%d] is larger than the max [%d].",
			__func__, max_counters, MAX_COUNTERS);
		return NULL;
	}

	if (subgroup_id > MAX_COUNTER_GROUPS) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create counters subgroup: subgroup_id [%d] is larger than max the [%d].",
			__func__, subgroup_id, MAX_COUNTER_GROUPS);
		return NULL;
	}

	struct counters_subgroup *subgroup =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(struct counters_subgroup));
	memset(subgroup, 0, sizeof(struct counters_subgroup));
	subgroup->counters = pceplib_malloc(
		PCEPLIB_INFRA, sizeof(struct counter *) * (max_counters + 1));
	memset(subgroup->counters, 0,
	       sizeof(struct counter *) * (max_counters + 1));

	strlcpy(subgroup->counters_subgroup_name, subgroup_name,
		sizeof(subgroup->counters_subgroup_name));
	subgroup->subgroup_id = subgroup_id;
	subgroup->max_counters = max_counters;

	return subgroup;
}

struct counters_subgroup *
clone_counters_subgroup(struct counters_subgroup *subgroup,
			const char *subgroup_name, uint16_t subgroup_id)
{
	if (subgroup == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot clone counters subgroup: input counters_subgroup is NULL.",
			__func__);
		return NULL;
	}

	if (subgroup_name == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot clone counters subgroup: subgroup_name is NULL.",
			__func__);
		return NULL;
	}

	if (subgroup_id > MAX_COUNTER_GROUPS) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot clone counters subgroup: subgroup_id [%d] is larger than max the [%d].",
			__func__, subgroup_id, MAX_COUNTER_GROUPS);
		return NULL;
	}

	struct counters_subgroup *cloned_subgroup = create_counters_subgroup(
		subgroup_name, subgroup_id, subgroup->max_counters);
	int i = 0;
	for (; i <= subgroup->max_counters; i++) {
		struct counter *counter = subgroup->counters[i];
		if (counter != NULL) {
			create_subgroup_counter(cloned_subgroup,
						counter->counter_id,
						counter->counter_name,
						counter->counter_name_json);
		}
	}

	return cloned_subgroup;
}

bool add_counters_subgroup(struct counters_group *group,
			   struct counters_subgroup *subgroup)
{
	if (group == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot add counters subgroup: counters_group is NULL.",
			__func__);
		return false;
	}

	if (subgroup == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot add counters subgroup: counters_subgroup is NULL.",
			__func__);
		return false;
	}

	if (subgroup->subgroup_id >= group->max_subgroups) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot add counters subgroup: counters_subgroup id [%d] is larger than the group max_subgroups [%d].",
			__func__, subgroup->subgroup_id, group->max_subgroups);
		return false;
	}

	group->num_subgroups++;
	group->subgroups[subgroup->subgroup_id] = subgroup;

	return true;
}

bool create_subgroup_counter(struct counters_subgroup *subgroup,
			     uint32_t counter_id, const char *counter_name,
			     const char *counter_name_json)
{
	if (subgroup == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create subgroup counter: counters_subgroup is NULL.",
			__func__);
		return false;
	}

	if (counter_id >= subgroup->max_counters) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create subgroup counter: counter_id [%d] is larger than the subgroup max_counters [%d].",
			__func__, counter_id, subgroup->max_counters);
		return false;
	}

	if (counter_name == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot create subgroup counter: counter_name is NULL.",
			__func__);
		return NULL;
	}

	struct counter *counter =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(struct counter));
	memset(counter, 0, sizeof(struct counter));
	counter->counter_id = counter_id;
	strlcpy(counter->counter_name, counter_name,
		sizeof(counter->counter_name));
	if (counter_name_json)
		strlcpy(counter->counter_name_json, counter_name_json,
			sizeof(counter->counter_name_json));
	subgroup->num_counters++;
	subgroup->counters[counter->counter_id] = counter;

	return true;
}

bool delete_counters_group(struct counters_group *group)
{
	if (group == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot delete group counters: counters_group is NULL.",
			__func__);
		return false;
	}

	int i = 0;
	for (; i <= group->max_subgroups; i++) {
		struct counters_subgroup *subgroup = group->subgroups[i];
		if (subgroup != NULL) {
			delete_counters_subgroup(subgroup);
		}
	}

	pceplib_free(PCEPLIB_INFRA, group->subgroups);
	pceplib_free(PCEPLIB_INFRA, group);

	return true;
}

bool delete_counters_subgroup(struct counters_subgroup *subgroup)
{
	if (subgroup == NULL || subgroup->counters == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot delete subgroup counters: counters_subgroup is NULL.",
			__func__);
		return false;
	}

	int i = 0;
	for (; i <= subgroup->max_counters; i++) {
		struct counter *counter = subgroup->counters[i];
		if (counter != NULL) {
			pceplib_free(PCEPLIB_INFRA, counter);
		}
	}

	pceplib_free(PCEPLIB_INFRA, subgroup->counters);
	pceplib_free(PCEPLIB_INFRA, subgroup);

	return true;
}

bool reset_group_counters(struct counters_group *group)
{
	if (group == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot reset group counters: counters_group is NULL.",
			__func__);
		return false;
	}

	int i = 0;
	for (; i <= group->max_subgroups; i++) {
		struct counters_subgroup *subgroup = group->subgroups[i];
		if (subgroup != NULL) {
			reset_subgroup_counters(subgroup);
		}
	}

	group->start_time = time(NULL);

	return true;
}

bool reset_subgroup_counters(struct counters_subgroup *subgroup)
{
	if (subgroup == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot reset subgroup counters: counters_subgroup is NULL.",
			__func__);
		return false;
	}

	int i = 0;
	for (; i <= subgroup->max_counters; i++) {
		struct counter *counter = subgroup->counters[i];
		if (counter != NULL) {
			counter->counter_value = 0;
		}
	}

	return true;
}

bool increment_counter(struct counters_group *group, uint16_t subgroup_id,
		       uint16_t counter_id)
{
	if (group == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot increment counter: counters_group is NULL.",
			__func__);
		return false;
	}

	if (subgroup_id >= group->max_subgroups) {
		pcep_log(
			LOG_DEBUG,
			"%s: Cannot increment counter: subgroup_id [%d] is larger than the group max_subgroups [%d].",
			__func__, subgroup_id, group->max_subgroups);
		return false;
	}

	struct counters_subgroup *subgroup = group->subgroups[subgroup_id];
	if (subgroup == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot increment counter: counters_subgroup in counters_group is NULL.",
			__func__);
		return false;
	}

	return increment_subgroup_counter(subgroup, counter_id);
}

bool increment_subgroup_counter(struct counters_subgroup *subgroup,
				uint16_t counter_id)
{
	if (subgroup == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot increment counter: counters_subgroup is NULL.",
			__func__);
		return false;
	}

	if (counter_id >= subgroup->max_counters) {
		pcep_log(
			LOG_DEBUG,
			"%s: Cannot increment counter: counter_id [%d] is larger than the subgroup max_counters [%d].",
			__func__, counter_id, subgroup->max_counters);
		return false;
	}

	if (subgroup->counters[counter_id] == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot increment counter: No counter exists for counter_id [%d].",
			__func__, counter_id);
		return false;
	}

	subgroup->counters[counter_id]->counter_value++;

	return true;
}

bool dump_counters_group_to_log(struct counters_group *group)
{
	if (group == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot dump group counters to log: counters_group is NULL.",
			__func__);
		return false;
	}

	time_t now = time(NULL);
	pcep_log(
		LOG_INFO,
		"%s: PCEP Counters group:\n  %s \n  Sub-Groups [%d] \n  Active for [%d seconds]",
		__func__, group->counters_group_name, group->num_subgroups,
		(now - group->start_time));

	int i = 0;
	for (; i <= group->max_subgroups; i++) {
		struct counters_subgroup *subgroup = group->subgroups[i];
		if (subgroup != NULL) {
			dump_counters_subgroup_to_log(subgroup);
		}
	}

	return true;
}

bool dump_counters_subgroup_to_log(struct counters_subgroup *subgroup)
{
	if (subgroup == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Cannot dump subgroup counters to log: counters_subgroup is NULL.",
			__func__);
		return false;
	}

	pcep_log(LOG_INFO,
		 "%s: \tPCEP Counters sub-group [%s] with [%d] counters",
		 __func__, subgroup->counters_subgroup_name,
		 subgroup->num_counters);

	int i = 0;
	for (; i <= subgroup->max_counters; i++) {
		struct counter *counter = subgroup->counters[i];
		if (counter != NULL) {
			pcep_log(LOG_INFO, "%s: \t\t%s %d", __func__,
				 counter->counter_name, counter->counter_value);
		}
	}

	return true;
}

struct counters_subgroup *find_subgroup(const struct counters_group *group,
					uint16_t subgroup_id)
{
	int i = 0;
	for (; i <= group->max_subgroups; i++) {
		struct counters_subgroup *subgroup = group->subgroups[i];
		if (subgroup != NULL) {
			if (subgroup->subgroup_id == subgroup_id) {
				return subgroup;
			}
		}
	}

	return NULL;
}

uint32_t subgroup_counters_total(struct counters_subgroup *subgroup)
{
	if (subgroup == NULL) {
		return 0;
	}
	uint32_t counter_total = 0;
	int i = 0;
	for (; i <= subgroup->max_counters; i++) {
		struct counter *counter = subgroup->counters[i];
		if (counter != NULL) {
			counter_total += counter->counter_value;
		}
	}

	return counter_total;
}
