// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF ASBR summary-address member lifetime regression tests.
 *
 * Regression coverage for issue #23637: an external route that belongs to an
 * ASBR summary-address ("aggregate") keeps a non-owning reference inside the
 * aggregate's member hash.  The object itself is owned by the external route
 * table, so every code path that frees an external_info must first drop that
 * reference.  Replacement of an aggregated route (tag, nexthop, metric or
 * ifindex change) and implicit deletion of it (route source or instance
 * change) used to free the object with the reference still in place, leaving
 * the aggregate pointing at freed memory.  Later walks of the member hash -
 * deferred summary deletion, "show ip ospf summary-address detail" - then
 * dereferenced the stale member.
 *
 * The tests below drive the real external_info add/delete entry points and
 * check that the aggregate no longer counts a member that was freed.  They do
 * not depend on the allocator, so they fail deterministically without any
 * memory sanitizer.
 */

#include <zebra.h>

#include "frrevent.h"
#include "lib/command.h"
#include "lib/hash.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/privs.h"
#include "lib/routemap.h"
#include "lib/table.h"
#include "lib/vrf.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_zebra.h"

struct event_loop *master;

/* Referenced by ospfd objects that are linked in but not exercised here. */
struct zebra_privs_t ospfd_privs;

static int failures;

static void check(bool ok, const char *what)
{
	printf("%-70s %s\n", what, ok ? "OK" : "failed");
	if (!ok)
		failures++;
}

static struct ospf *test_ospf_new(void)
{
	struct ospf *ospf;
	struct in_addr router_id;

	ospf = ospf_new_alloc(0, VRF_DEFAULT_NAME);

	/* A router ID is required before external LSAs are originated. */
	inet_aton("10.255.0.4", &router_id);
	ospf->router_id = router_id;
	ospf->router_id_static = router_id;

	return ospf;
}

/*
 * Create the aggregate the same way the CLI does.  The aggregation delay
 * timer is cancelled again: these tests link and unlink members directly
 * through the production helpers instead of waiting for the timer, so that
 * both member and aggregate state stay under test control.
 */
static struct ospf_external_aggr_rt *test_aggr_add(struct ospf *ospf, const char *summary)
{
	struct prefix_ipv4 p;

	str2prefix_ipv4(summary, &p);
	ospf_asbr_external_aggregator_set(ospf, &p, 0);
	event_cancel(&ospf->t_external_aggr);

	return ospf_external_aggregator_lookup(ospf, &p);
}

/*
 * Add an external route and link it to the aggregate.  Linking goes through
 * ospf_originate_summary_lsa(), the same path zebra route ADD uses, so the
 * member hash and ei->aggr_route are set up by production code.
 */
static struct external_info *test_member_add(struct ospf *ospf, struct ospf_external_aggr_rt *aggr,
					     const char *prefix, uint8_t type,
					     unsigned short instance, route_tag_t tag)
{
	struct in_addr nexthop = { .s_addr = INADDR_ANY };
	struct external_info *ei;
	struct prefix_ipv4 p;

	str2prefix_ipv4(prefix, &p);
	ei = ospf_external_info_add(ospf, type, instance, p, 0, nexthop, tag, 20);
	if (ei && aggr)
		ospf_originate_summary_lsa(ospf, aggr, ei);

	return ei;
}

static void test_member_replacement(struct ospf *ospf, struct ospf_external_aggr_rt *aggr)
{
	struct in_addr nexthop = { .s_addr = INADDR_ANY };
	struct external_info *ei, *ei_new;
	struct prefix_ipv4 p;

	str2prefix_ipv4("10.150.0.0/24", &p);

	ei = test_member_add(ospf, aggr, "10.150.0.0/24", ZEBRA_ROUTE_STATIC, 0, 0);
	check(ei != NULL && OSPF_EXTERNAL_RT_COUNT(aggr) == 1,
	      "aggregated member is linked before the update");

	/* Same prefix, changed tag: this replaces the external_info object. */
	ei_new = ospf_external_info_add(ospf, ZEBRA_ROUTE_STATIC, 0, p, 0, nexthop, 20, 20);
	check(ei_new != NULL, "changing the tag replaces the external info");
	check(OSPF_EXTERNAL_RT_COUNT(aggr) == 0, "replaced member is dropped from the aggregate");

	/* The route ADD path links the replacement object again. */
	ospf_originate_summary_lsa(ospf, aggr, ei_new);
	check(OSPF_EXTERNAL_RT_COUNT(aggr) == 1,
	      "replacement member is linked again by the ADD path");

	ospf_external_info_delete(ospf, ZEBRA_ROUTE_STATIC, 0, p);
	check(OSPF_EXTERNAL_RT_COUNT(aggr) == 0, "deleted member is dropped from the aggregate");
}

static void test_member_multi_instance_delete(struct ospf *ospf, struct ospf_external_aggr_rt *aggr)
{
	struct external_info *ei;
	struct prefix_ipv4 p;

	str2prefix_ipv4("10.150.1.0/24", &p);

	ei = test_member_add(ospf, aggr, "10.150.1.0/24", ZEBRA_ROUTE_STATIC, 1, 0);
	check(ei != NULL && OSPF_EXTERNAL_RT_COUNT(aggr) == 1,
	      "member of a second instance is linked");

	/*
	 * A route ADD for the same prefix with another instance implicitly
	 * deletes the previous instance.  See ospf_zebra_read_route().
	 */
	ospf_external_info_delete_multi_instance(ospf, ZEBRA_ROUTE_STATIC, p, 0);
	check(OSPF_EXTERNAL_RT_COUNT(aggr) == 0,
	      "implicitly deleted member is dropped from the aggregate");
}

/*
 * Every field that takes part in the "same prefix, different data" check
 * replaces the external_info object: ifindex, nexthop, tag and metric.  The
 * tag case is covered above; the other three must drop the aggregate
 * reference just the same.
 */
static void test_member_field_changes(struct ospf *ospf, struct ospf_external_aggr_rt *aggr)
{
	struct in_addr nexthop = { .s_addr = INADDR_ANY };
	struct external_info *ei, *ei_new;
	struct prefix_ipv4 p;

	str2prefix_ipv4("10.150.2.0/24", &p);

	ei = test_member_add(ospf, aggr, "10.150.2.0/24", ZEBRA_ROUTE_STATIC, 0, 0);
	check(ei != NULL && OSPF_EXTERNAL_RT_COUNT(aggr) == 1,
	      "member used for the field changes is linked");

	/* metric change */
	ei_new = ospf_external_info_add(ospf, ZEBRA_ROUTE_STATIC, 0, p, 0, nexthop, 0, 100);
	check(ei_new != NULL && OSPF_EXTERNAL_RT_COUNT(aggr) == 0,
	      "metric change drops the old member from the aggregate");
	ospf_originate_summary_lsa(ospf, aggr, ei_new);

	/* nexthop change */
	inet_aton("10.150.0.1", &nexthop);
	ei = ospf_external_info_add(ospf, ZEBRA_ROUTE_STATIC, 0, p, 0, nexthop, 0, 100);
	check(ei != NULL && OSPF_EXTERNAL_RT_COUNT(aggr) == 0,
	      "nexthop change drops the old member from the aggregate");
	ospf_originate_summary_lsa(ospf, aggr, ei);

	/* ifindex change */
	ei_new = ospf_external_info_add(ospf, ZEBRA_ROUTE_STATIC, 0, p, 7, nexthop, 0, 100);
	check(ei_new != NULL && OSPF_EXTERNAL_RT_COUNT(aggr) == 0,
	      "ifindex change drops the old member from the aggregate");
	ospf_originate_summary_lsa(ospf, aggr, ei_new);

	check(OSPF_EXTERNAL_RT_COUNT(aggr) == 1, "member is linked again after the field changes");

	ospf_external_info_delete(ospf, ZEBRA_ROUTE_STATIC, 0, p);
	check(OSPF_EXTERNAL_RT_COUNT(aggr) == 0,
	      "member deleted after the field changes is dropped");
}

/*
 * Overlapping summary-addresses: a member belongs to the aggregate it was
 * linked to, which is not necessarily the aggregate that currently is the
 * longest match for its prefix.  Moving the member has to remove it from the
 * aggregate that actually holds it.
 */
static void test_member_moves_to_nested_aggregate(struct ospf *ospf)
{
	struct ospf_external_aggr_rt *wide, *narrow;
	struct external_info *ei;
	struct prefix_ipv4 p;

	wide = test_aggr_add(ospf, "10.151.0.0/15");
	narrow = test_aggr_add(ospf, "10.151.0.0/16");
	check(wide != NULL && narrow != NULL,
	      "nested aggregates 10.151.0.0/15 and /16 are configured");
	if (!wide || !narrow)
		return;

	str2prefix_ipv4("10.151.1.0/24", &p);
	ei = test_member_add(ospf, wide, "10.151.1.0/24", ZEBRA_ROUTE_STATIC, 0, 0);
	check(ei != NULL && OSPF_EXTERNAL_RT_COUNT(wide) == 1 &&
		      OSPF_EXTERNAL_RT_COUNT(narrow) == 0,
	      "member starts in the less specific aggregate");

	/* The aggregation path now hands the member to the specific one. */
	ospf_originate_summary_lsa(ospf, narrow, ei);
	check(OSPF_EXTERNAL_RT_COUNT(wide) == 0 && OSPF_EXTERNAL_RT_COUNT(narrow) == 1,
	      "member moved out of the less specific aggregate");

	ospf_external_info_delete(ospf, ZEBRA_ROUTE_STATIC, 0, p);
	check(OSPF_EXTERNAL_RT_COUNT(wide) == 0 && OSPF_EXTERNAL_RT_COUNT(narrow) == 0,
	      "member deleted from the more specific aggregate");
}

/*
 * Releasing an aggregate clears the backpointer of every member (see
 * ospf_aggr_unlink_external_info()), so a member that is freed afterwards must
 * not touch the released aggregate.  The free helper dereferences
 * ei->aggr_route, so this order has to stay safe.
 *
 * Note this is deliberately the reverse of ospf_finish_final(), which frees
 * the remaining external routes first and the aggregators afterwards.
 */
static void test_aggregate_release_before_member_delete(void)
{
	struct ospf_external_aggr_rt *aggr;
	struct ospf *ospf;
	struct external_info *ei;
	struct prefix_ipv4 p;

	ospf = test_ospf_new();
	str2prefix_ipv4("10.152.0.0/24", &p);

	aggr = test_aggr_add(ospf, "10.152.0.0/15");
	ei = test_member_add(ospf, aggr, "10.152.0.0/24", ZEBRA_ROUTE_STATIC, 0, 0);
	check(aggr != NULL && ei != NULL && OSPF_EXTERNAL_RT_COUNT(aggr) == 1,
	      "teardown member is linked to its aggregate");

	ospf_external_aggregator_free(aggr);
	check(ei != NULL && ei->aggr_route == NULL,
	      "releasing the aggregate clears the member backpointer");

	ospf_external_info_delete(ospf, ZEBRA_ROUTE_STATIC, 0, p);
	check(true, "member can still be deleted after the aggregate was freed");
}

/*
 * A member can be owned by one aggregate while a different aggregate is the
 * longest match for its prefix: a more specific summary was configured and the
 * aggregation timer has not moved the member over yet.  Filter rejection
 * (ospf_external_lsa_refresh_type()) and deletion have to drop the member from
 * the aggregate that really holds it, not from the best match.
 */
static void test_unlink_uses_recorded_owner(void)
{
	struct ospf_external_aggr_rt *wide, *narrow;
	struct ospf_redist *red;
	struct route_map *deny;
	struct external_info *ei;
	struct ospf *ospf;
	struct prefix_ipv4 p;

	ospf = test_ospf_new();

	wide = test_aggr_add(ospf, "10.153.0.0/15");
	narrow = test_aggr_add(ospf, "10.153.0.0/16");
	check(wide != NULL && narrow != NULL,
	      "wrong-owner aggregates 10.153.0.0/15 and /16 are configured");
	if (!wide || !narrow)
		return;

	/*
	 * Make redistribution deny this route: a route map with a name but an
	 * empty (or missing) rule set makes route_map_apply() return
	 * RMAP_DENYMATCH, which is what the CLI reaches when the last
	 * "route-map <name> permit" entry is removed.
	 */
	deny = route_map_get("DENY_SUMMARY_TEST");
	check(deny != NULL, "denying route map is available");
	red = ospf_redist_add(ospf, ZEBRA_ROUTE_STATIC, 0);
	ROUTEMAP_NAME(red) = XSTRDUP(MTYPE_TMP, "DENY_SUMMARY_TEST");
	ROUTEMAP(red) = deny;

	str2prefix_ipv4("10.153.1.0/24", &p);

	/* the member belongs to "wide" while "narrow" is the best match */
	ei = test_member_add(ospf, wide, "10.153.1.0/24", ZEBRA_ROUTE_STATIC, 0, 0);
	check(ei != NULL && OSPF_EXTERNAL_RT_COUNT(wide) == 1 &&
		      OSPF_EXTERNAL_RT_COUNT(narrow) == 0,
	      "member is owned by the less specific aggregate");

	ospf_external_lsa_refresh_type(ospf, ZEBRA_ROUTE_STATIC, 0, LSA_REFRESH_FORCE);
	check(OSPF_EXTERNAL_RT_COUNT(wide) == 0 && OSPF_EXTERNAL_RT_COUNT(narrow) == 0,
	      "filter rejection unlinks from the owning aggregate");

	/*
	 * Implicit deletion while a different aggregate is the best match.
	 * Filter rejection only unlinks, so re-link the existing object the way
	 * the zebra ADD path does before deleting it.
	 */
	ei = ospf_external_info_lookup(ospf, ZEBRA_ROUTE_STATIC, 0, &p);
	check(ei != NULL, "member survives the filter rejection");
	ospf_originate_summary_lsa(ospf, wide, ei);
	check(OSPF_EXTERNAL_RT_COUNT(wide) == 1, "member is linked again for the delete case");

	ospf_external_info_delete(ospf, ZEBRA_ROUTE_STATIC, 0, p);
	check(OSPF_EXTERNAL_RT_COUNT(wide) == 0 && OSPF_EXTERNAL_RT_COUNT(narrow) == 0,
	      "deleting the member unlinks it from the owning aggregate");
}

int main(int argc, char **argv)
{
	struct ospf_external_aggr_rt *aggr;
	struct ospf *ospf;

	master = event_master_create(NULL);
	cmd_init(1);
	zlog_aux_init("NONE: ", ZLOG_DISABLED);
	route_map_init();

	printf("OSPF ASBR summary member lifetime tests\n\n");

	ospf = test_ospf_new();
	aggr = test_aggr_add(ospf, "10.150.0.0/15");
	check(aggr != NULL, "aggregate 10.150.0.0/15 is configured");
	if (aggr == NULL) {
		printf("\nresult: failed\n");
		return 1;
	}

	test_member_replacement(ospf, aggr);
	test_member_multi_instance_delete(ospf, aggr);
	test_member_field_changes(ospf, aggr);
	test_member_moves_to_nested_aggregate(ospf);
	test_aggregate_release_before_member_delete();
	test_unlink_uses_recorded_owner();

	/* The aggregate itself is a reference holder, not an owner. */
	check(OSPF_EXTERNAL_RT_COUNT(aggr) == 0, "aggregate holds no member reference at the end");

	printf("\nresult: %s\n", failures ? "failed" : "OK");

	return failures ? 1 : 0;
}
