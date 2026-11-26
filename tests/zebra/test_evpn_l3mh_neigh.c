// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN L3MH neighbor lifecycle tests.
 * Copyright (C) 2026 Cisco Systems, Inc.
 */

#include <zebra.h>

#include "zebra/zebra_evpn_neigh.h"

struct transition {
	enum zebra_l3mh_neigh_lifecycle current;
	enum zebra_l3mh_neigh_lifecycle next;
};

static void verify_transitions(const struct transition *transitions, size_t count, bool expected)
{
	size_t i;

	for (i = 0; i < count; i++) {
		bool valid = zebra_evpn_l3mh_neigh_transition_valid(transitions[i].current,
								    transitions[i].next);

		if (valid != expected) {
			fprintf(stderr, "transition %u -> %u unexpectedly %s\n",
				transitions[i].current, transitions[i].next,
				valid ? "allowed" : "rejected");
			exit(EXIT_FAILURE);
		}
	}
}

static void test_transitions(void)
{
	static const struct transition allowed[] = {
		{ ZEBRA_L3MH_NEIGH_NOT_MANAGED, ZEBRA_L3MH_NEIGH_NOT_MANAGED },
		{ ZEBRA_L3MH_NEIGH_NOT_MANAGED, ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC },
		{ ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC, ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC },
		{ ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC, ZEBRA_L3MH_NEIGH_NOT_MANAGED },
		{ ZEBRA_L3MH_NEIGH_NOT_MANAGED, ZEBRA_L3MH_NEIGH_PEER_SYNC_PROTECTED },
		{ ZEBRA_L3MH_NEIGH_PEER_SYNC_PROTECTED, ZEBRA_L3MH_NEIGH_PEER_SYNC_PROTECTED },
		{ ZEBRA_L3MH_NEIGH_PEER_SYNC_PROTECTED, ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC },
		{ ZEBRA_L3MH_NEIGH_PEER_SYNC_PROTECTED, ZEBRA_L3MH_NEIGH_NOT_MANAGED },
		{ ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC, ZEBRA_L3MH_NEIGH_PEER_SYNC_PROTECTED },
	};
	static const struct transition rejected[] = {
		{ ZEBRA_L3MH_NEIGH_PEER_SYNC_PROTECTED, ZEBRA_L3MH_NEIGH_HANDOFF_WAIT },
		{ ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC, ZEBRA_L3MH_NEIGH_HANDOFF_WAIT },
		{ (enum zebra_l3mh_neigh_lifecycle)99, ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC },
		{ ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC, (enum zebra_l3mh_neigh_lifecycle)99 },
	};

	verify_transitions(allowed, array_size(allowed), true);
	verify_transitions(rejected, array_size(rejected), false);
	printf("L3MH neighbor lifecycle transitions passed.\n");
}

static void test_local_binding(void)
{
	struct zebra_neigh neigh = {
		.emac = { { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } },
		.eth_tag = 100,
	};
	esi_t esi = { { 0x00, 0x01 } };
	const struct ethaddr empty_mac = {};
	const esi_t empty_esi = {};

	zebra_evpn_l3mh_neigh_record_local(&neigh, 0, NULL);
	assert(neigh.l3mh_state == ZEBRA_L3MH_NEIGH_NOT_MANAGED);
	assert(neigh.l3mh_generation == 0);

	zebra_evpn_l3mh_neigh_record_local(&neigh, 10, &esi);
	assert(neigh.l3mh_state == ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC);
	assert(neigh.l3mh_generation == 1);
	assert(neigh.l3mh_expected_ifindex == 10);
	assert(neigh.l3mh_expected_eth_tag == 100);
	assert(!memcmp(&neigh.l3mh_expected_esi, &esi, sizeof(esi)));
	assert(!memcmp(&neigh.l3mh_expected_mac, &neigh.emac, sizeof(neigh.emac)));

	zebra_evpn_l3mh_neigh_record_local(&neigh, 10, &esi);
	assert(neigh.l3mh_generation == 1);

	neigh.emac.octet[5]++;
	zebra_evpn_l3mh_neigh_record_local(&neigh, 10, &esi);
	assert(neigh.l3mh_generation == 2);
	assert(!memcmp(&neigh.l3mh_expected_mac, &neigh.emac, sizeof(neigh.emac)));

	neigh.eth_tag = 200;
	zebra_evpn_l3mh_neigh_record_local(&neigh, 10, &esi);
	assert(neigh.l3mh_generation == 3);
	assert(neigh.l3mh_expected_eth_tag == 200);

	zebra_evpn_l3mh_neigh_record_local(&neigh, 11, &esi);
	assert(neigh.l3mh_generation == 4);
	assert(neigh.l3mh_expected_ifindex == 11);

	esi.val[1]++;
	zebra_evpn_l3mh_neigh_record_local(&neigh, 11, &esi);
	assert(neigh.l3mh_generation == 5);
	assert(!memcmp(&neigh.l3mh_expected_esi, &esi, sizeof(esi)));

	zebra_evpn_l3mh_neigh_record_local(&neigh, 0, NULL);
	assert(neigh.l3mh_state == ZEBRA_L3MH_NEIGH_NOT_MANAGED);
	assert(neigh.l3mh_generation == 6);
	assert(neigh.l3mh_expected_ifindex == 0);
	assert(neigh.l3mh_expected_eth_tag == 0);
	assert(!memcmp(&neigh.l3mh_expected_mac, &empty_mac, sizeof(empty_mac)));
	assert(!memcmp(&neigh.l3mh_expected_esi, &empty_esi, sizeof(empty_esi)));

	zebra_evpn_l3mh_neigh_record_local(&neigh, 0, NULL);
	assert(neigh.l3mh_generation == 6);

	zebra_evpn_l3mh_neigh_record_local(&neigh, 11, &esi);
	assert(neigh.l3mh_state == ZEBRA_L3MH_NEIGH_LOCAL_DYNAMIC);
	assert(neigh.l3mh_generation == 7);

	printf("L3MH local binding generation checks passed.\n");
}

static void test_nud_events(void)
{
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_REACHABLE, false) ==
	       ZEBRA_L3MH_NUD_LEARN);
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_STALE, false) ==
	       ZEBRA_L3MH_NUD_LEARN);
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_INCOMPLETE, false) ==
	       ZEBRA_L3MH_NUD_TRANSIENT);
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_DELAY, false) ==
	       ZEBRA_L3MH_NUD_TRANSIENT);
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_PROBE, false) ==
	       ZEBRA_L3MH_NUD_TRANSIENT);
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_FAILED, false) ==
	       ZEBRA_L3MH_NUD_FAILED);
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_FAILED, true) ==
	       ZEBRA_L3MH_NUD_DELETE);
	assert(zebra_evpn_l3mh_nud_classify(ZEBRA_NEIGH_STATE_NONE, false) ==
	       ZEBRA_L3MH_NUD_IGNORE);
	puts("L3MH NUD event classification passed.");
}

static void test_probe_results(void)
{
	struct zebra_neigh n = { .l3mh_generation = 1 };

	assert(zebra_evpn_l3mh_probe_begin(&n, 1));
	assert(!zebra_evpn_l3mh_probe_begin(&n, 2));
	assert(!zebra_evpn_l3mh_probe_complete(&n, 2, true));
	assert(!zebra_evpn_l3mh_probe_complete(&n, 1, false));
	assert(!zebra_evpn_l3mh_probe_current(&n));
	assert(!zebra_evpn_l3mh_probe_complete(&n, 1, true));

	assert(zebra_evpn_l3mh_probe_begin(&n, 2));
	zebra_evpn_l3mh_probe_cancel(&n);
	assert(!zebra_evpn_l3mh_probe_begin(&n, 3));
	assert(!zebra_evpn_l3mh_probe_complete(&n, 2, true));

	assert(zebra_evpn_l3mh_probe_begin(&n, 3));
	n.l3mh_generation++;
	assert(!zebra_evpn_l3mh_probe_complete(&n, 3, true));

	assert(zebra_evpn_l3mh_probe_begin(&n, 4));
	assert(zebra_evpn_l3mh_probe_complete(&n, 4, true));
	assert(zebra_evpn_l3mh_probe_current(&n));
	assert(zebra_evpn_l3mh_probe_begin(&n, 5));
	assert(!zebra_evpn_l3mh_probe_complete(&n, 4, true));
	assert(zebra_evpn_l3mh_probe_complete(&n, 5, true));
	zebra_evpn_l3mh_probe_cancel(&n);
	assert(!zebra_evpn_l3mh_probe_current(&n));
	puts("L3MH probe result ordering passed.");
}

int main(void)
{
	test_transitions();
	test_local_binding();
	test_nud_events();
	test_probe_results();
	return EXIT_SUCCESS;
}
