// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep_utils_counters.h"
#include "pcep_utils_counters_test.h"


void test_create_counters_group(void)
{
	const char group_name[] = "group";
	uint16_t num_subgroups = 10;

	struct counters_group *group =
		create_counters_group(NULL, num_subgroups);
	CU_ASSERT_PTR_NULL(group);

	group = create_counters_group(group_name, MAX_COUNTER_GROUPS + 1);
	CU_ASSERT_PTR_NULL(group);

	group = create_counters_group(group_name, num_subgroups);
	CU_ASSERT_PTR_NOT_NULL(group);
	assert(group != NULL);

	CU_ASSERT_EQUAL(group->num_subgroups, 0);
	CU_ASSERT_EQUAL(group->max_subgroups, num_subgroups);
	CU_ASSERT_EQUAL(strcmp(group->counters_group_name, group_name), 0);

	delete_counters_group(group);
}

void test_create_counters_subgroup(void)
{
	const char subgroup_name[] = "subgroup";
	uint16_t subgroup_id = 10;
	uint16_t num_counters = 20;

	struct counters_subgroup *subgroup =
		create_counters_subgroup(NULL, subgroup_id, num_counters);
	CU_ASSERT_PTR_NULL(subgroup);

	subgroup = create_counters_subgroup(
		subgroup_name, MAX_COUNTER_GROUPS + 1, num_counters);
	CU_ASSERT_PTR_NULL(subgroup);

	subgroup = create_counters_subgroup(subgroup_name, subgroup_id,
					    MAX_COUNTERS + 1);
	CU_ASSERT_PTR_NULL(subgroup);

	subgroup = create_counters_subgroup(subgroup_name, subgroup_id,
					    num_counters);
	CU_ASSERT_PTR_NOT_NULL(subgroup);
	assert(subgroup != NULL);

	CU_ASSERT_EQUAL(subgroup->subgroup_id, subgroup_id);
	CU_ASSERT_EQUAL(subgroup->num_counters, 0);
	CU_ASSERT_EQUAL(subgroup->max_counters, num_counters);
	CU_ASSERT_EQUAL(strcmp(subgroup->counters_subgroup_name, subgroup_name),
			0);

	delete_counters_subgroup(subgroup);
}

void test_add_counters_subgroup(void)
{
	struct counters_group *group = create_counters_group("group", 1);
	struct counters_subgroup *subgroup1 =
		create_counters_subgroup("subgroup", 0, 5);
	struct counters_subgroup *subgroup2 =
		create_counters_subgroup("subgroup", 1, 5);

	CU_ASSERT_FALSE(add_counters_subgroup(NULL, NULL));
	CU_ASSERT_FALSE(add_counters_subgroup(NULL, subgroup1));
	CU_ASSERT_FALSE(add_counters_subgroup(group, NULL));

	CU_ASSERT_EQUAL(group->num_subgroups, 0);
	CU_ASSERT_TRUE(add_counters_subgroup(group, subgroup1));
	CU_ASSERT_EQUAL(group->num_subgroups, 1);
	/* Cant add more than num_subgroups to the group */
	CU_ASSERT_FALSE(add_counters_subgroup(group, subgroup2));

	CU_ASSERT_PTR_NOT_NULL(find_subgroup(group, 0));
	CU_ASSERT_PTR_NULL(find_subgroup(group, 1));

	delete_counters_group(group);
	delete_counters_subgroup(subgroup2);
}

void test_create_subgroup_counter(void)
{
	uint16_t counter_id = 1;
	char counter_name[] = "my counter";
	char counter_name_json[] = "myCounter";
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", 1, 2);

	CU_ASSERT_FALSE(create_subgroup_counter(NULL, counter_id, counter_name,
						counter_name_json));
	CU_ASSERT_FALSE(create_subgroup_counter(subgroup, counter_id + 1,
						counter_name, counter_name_json));
	CU_ASSERT_FALSE(
		create_subgroup_counter(subgroup, counter_id, NULL, NULL));
	CU_ASSERT_EQUAL(subgroup->num_counters, 0);
	CU_ASSERT_TRUE(create_subgroup_counter(subgroup, counter_id,
					       counter_name, counter_name_json));
	CU_ASSERT_EQUAL(subgroup->num_counters, 1);

	delete_counters_subgroup(subgroup);
}

void test_delete_counters_group(void)
{
	struct counters_group *group = create_counters_group("group", 1);

	CU_ASSERT_FALSE(delete_counters_group(NULL));
	CU_ASSERT_TRUE(delete_counters_group(group));
}

void test_delete_counters_subgroup(void)
{
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", 1, 1);

	CU_ASSERT_FALSE(delete_counters_subgroup(NULL));
	CU_ASSERT_TRUE(delete_counters_subgroup(subgroup));
}

void test_reset_group_counters(void)
{
	uint16_t subgroup_id = 1;
	uint16_t counter_id = 1;
	struct counters_group *group = create_counters_group("group", 10);
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", subgroup_id, 10);
	create_subgroup_counter(subgroup, counter_id, "counter", "counter");
	add_counters_subgroup(group, subgroup);

	struct counter *counter = subgroup->counters[counter_id];
	counter->counter_value = 100;

	CU_ASSERT_FALSE(reset_group_counters(NULL));
	CU_ASSERT_TRUE(reset_group_counters(group));
	CU_ASSERT_EQUAL(counter->counter_value, 0);

	delete_counters_group(group);
}

void test_reset_subgroup_counters(void)
{
	uint16_t counter_id = 1;
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", 1, 10);
	create_subgroup_counter(subgroup, counter_id, "counter", "counter");

	struct counter *counter = subgroup->counters[counter_id];
	counter->counter_value = 100;

	CU_ASSERT_FALSE(reset_subgroup_counters(NULL));
	CU_ASSERT_TRUE(reset_subgroup_counters(subgroup));
	CU_ASSERT_EQUAL(counter->counter_value, 0);

	delete_counters_subgroup(subgroup);
}

void test_increment_counter(void)
{
	uint16_t subgroup_id = 1;
	uint16_t counter_id = 1;
	struct counters_group *group = create_counters_group("group", 10);
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", subgroup_id, 10);
	create_subgroup_counter(subgroup, counter_id, "counter", "counter");
	add_counters_subgroup(group, subgroup);

	struct counter *counter = subgroup->counters[counter_id];
	counter->counter_value = 100;

	CU_ASSERT_FALSE(increment_counter(NULL, subgroup_id, counter_id));
	CU_ASSERT_FALSE(increment_counter(group, 100, counter_id));
	CU_ASSERT_FALSE(increment_counter(group, subgroup_id, 123));
	CU_ASSERT_TRUE(increment_counter(group, subgroup_id, counter_id));
	CU_ASSERT_EQUAL(counter->counter_value, 101);
	CU_ASSERT_EQUAL(subgroup_counters_total(subgroup), 101);

	delete_counters_group(group);
}

void test_increment_subgroup_counter(void)
{
	int counter_id = 1;
	uint32_t counter_value = 100;
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", 1, 10);
	create_subgroup_counter(subgroup, counter_id, "counter", "counter");

	struct counter *counter = subgroup->counters[counter_id];
	counter->counter_value = counter_value;

	CU_ASSERT_FALSE(increment_subgroup_counter(NULL, counter_id));
	CU_ASSERT_FALSE(increment_subgroup_counter(subgroup, counter_id + 1));
	CU_ASSERT_TRUE(increment_subgroup_counter(subgroup, counter_id));
	CU_ASSERT_EQUAL(counter->counter_value, counter_value + 1);

	delete_counters_subgroup(subgroup);
}

void test_dump_counters_group_to_log(void)
{
	uint16_t subgroup_id = 1;
	uint16_t counter_id = 1;
	struct counters_group *group = create_counters_group("group", 10);
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", subgroup_id, 10);
	create_subgroup_counter(subgroup, counter_id, "counter", "counter");
	add_counters_subgroup(group, subgroup);

	CU_ASSERT_FALSE(dump_counters_group_to_log(NULL));
	CU_ASSERT_TRUE(dump_counters_group_to_log(group));

	delete_counters_group(group);
}

void test_dump_counters_subgroup_to_log(void)
{
	uint16_t subgroup_id = 1;
	uint16_t counter_id = 1;
	struct counters_subgroup *subgroup =
		create_counters_subgroup("subgroup", subgroup_id, 10);
	create_subgroup_counter(subgroup, counter_id, "counter", "counter");

	CU_ASSERT_FALSE(dump_counters_subgroup_to_log(NULL));
	CU_ASSERT_TRUE(dump_counters_subgroup_to_log(subgroup));

	delete_counters_subgroup(subgroup);
}
