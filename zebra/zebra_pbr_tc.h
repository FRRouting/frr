// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra PBR traffic class (QoS 2.21): PBR rule -> tc classifier
 * Copyright (C) 2026 Aviz Networks
 */
#ifndef _ZEBRA_PBR_TC_H
#define _ZEBRA_PBR_TC_H

#include <zebra.h>

#include "pbr.h"
#include "tc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A PBR rule with PBR_ACTION_TRAFFIC_CLASS becomes one flower filter per
 * frame shape it can match on the ingress interface.  The kernel refuses
 * two filters with the same pref and a different protocol, so each shape
 * gets its own pref: pref = seq * ZEBRA_PBR_TC_PREF_STRIDE + variant.
 */
enum zebra_pbr_tc_variant {
	ZEBRA_PBR_TC_V_IPV4 = 0,  /* untagged IPv4 */
	ZEBRA_PBR_TC_V_IPV6,	  /* untagged IPv6 */
	ZEBRA_PBR_TC_V_VLAN_IPV4, /* 802.1Q, IPv4 inside */
	ZEBRA_PBR_TC_V_VLAN_IPV6, /* 802.1Q, IPv6 inside */
	ZEBRA_PBR_TC_V_VLAN,	  /* 802.1Q, any payload */
	ZEBRA_PBR_TC_V_ALL,	  /* any frame */
	ZEBRA_PBR_TC_V_MAX,
};

#define ZEBRA_PBR_TC_PREF_STRIDE 8

enum zebra_pbr_tc_state {
	ZEBRA_PBR_TC_NONE = 0,	   /* rule has no traffic-class */
	ZEBRA_PBR_TC_INSTALLED,	   /* filters handed to the dataplane */
	ZEBRA_PBR_TC_NO_INTERFACE, /* ingress interface unknown */
	ZEBRA_PBR_TC_REFUSED,	   /* interface type cannot carry a classifier */
	ZEBRA_PBR_TC_INVALID,	   /* match cannot be expressed as a classifier */
	ZEBRA_PBR_TC_UNSUPPORTED,  /* no tc dataplane on this platform */
};

/* Per-rule classifier state, kept in struct zebra_pbr_rule */
struct zebra_pbr_tc {
	enum zebra_pbr_tc_state state;
	ifindex_t ifindex;
	uint8_t variants; /* bit per enum zebra_pbr_tc_variant installed */
	const char *reason;
};

struct zebra_pbr_rule;
struct vty;

/*
 * Pure translation, no side effects: fill @out (ZEBRA_PBR_TC_V_MAX
 * entries) with the filters for @r on @ifindex.  @l2_port is true for
 * bridge ports, which also see 802.1Q-tagged frames.  Returns the number
 * of filters, or -1 if the match cannot be expressed (always -1 on
 * platforms without the Linux tc dataplane).
 */
extern int zebra_pbr_tc_derive(const struct pbr_rule *r, ifindex_t ifindex, bool l2_port,
			       struct tc_filter *out);

extern uint32_t zebra_pbr_tc_handle(uint32_t unique, enum zebra_pbr_tc_variant v);

/*
 * Install the classifier for @rule.  @old is the rule being replaced (an
 * update) or NULL: filters @old had and @rule still needs are updated in
 * place, the others are removed.
 */
extern void zebra_pbr_tc_rule_install(struct zebra_pbr_rule *rule, struct zebra_pbr_rule *old);
extern void zebra_pbr_tc_rule_uninstall(struct zebra_pbr_rule *rule);

extern void zebra_pbr_tc_show(struct vty *vty, const struct zebra_pbr_rule *rule);
extern const char *zebra_pbr_tc_state2str(enum zebra_pbr_tc_state state);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_PBR_TC_H */
