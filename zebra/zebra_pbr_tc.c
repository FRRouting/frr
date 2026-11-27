// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra PBR traffic class (QoS 2.21): PBR rule -> tc classifier
 * Copyright (C) 2026 Aviz Networks
 *
 * A pbr-map sequence with `set traffic-class N` reaches zebra as a PBR rule
 * with PBR_ACTION_TRAFFIC_CLASS.  The FIB rule (ip rule) part, if any, is
 * unchanged.  Here the match becomes tc flower filters on the clsact
 * ingress hook of the rule's interface, with a skbedit action that sets
 * skb->priority = N and, when a mark mask is configured, the TC into the
 * masked skb->mark bits.  The filters are zebra-owned TC objects
 * (zebra_tc.c), so non-kernel dataplanes still see the abstract rule.
 *
 * The classifier is Linux tc, so the implementation is built with
 * HAVE_NETLINK only.  Elsewhere the rule is kept and its classifier is
 * reported as unsupported; the FIB part is handled as before.
 */
#include <zebra.h>

#ifdef HAVE_NETLINK
#include <linux/if_ether.h>
#endif

#include "vty.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_ns.h"
#include "zebra/interface.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_pbr_tc.h"
#include "zebra/zebra_tc.h"
#include "zebra/debug.h"

#define PBR_L3_FILTERS                                                                            \
	(PBR_FILTER_SRC_IP | PBR_FILTER_DST_IP | PBR_FILTER_IP_PROTOCOL | PBR_FILTER_SRC_PORT |   \
	 PBR_FILTER_DST_PORT | PBR_FILTER_DSCP | PBR_FILTER_ECN)

const char *zebra_pbr_tc_state2str(enum zebra_pbr_tc_state state)
{
	switch (state) {
	case ZEBRA_PBR_TC_NONE:
		return "none";
	case ZEBRA_PBR_TC_INSTALLED:
		return "installed";
	case ZEBRA_PBR_TC_NO_INTERFACE:
		return "pending (interface unknown)";
	case ZEBRA_PBR_TC_REFUSED:
		return "refused";
	case ZEBRA_PBR_TC_INVALID:
		return "invalid";
	case ZEBRA_PBR_TC_UNSUPPORTED:
		return "unsupported";
	}

	return "unknown";
}

uint32_t zebra_pbr_tc_handle(uint32_t unique, enum zebra_pbr_tc_variant v)
{
	return TC_FILTER_HANDLE_ZEBRA | ((unique & 0x0fffffffu) << 3) | ((uint32_t)v & 0x7);
}

#ifdef HAVE_NETLINK

static bool tc_port_proto_ok(uint8_t ip_proto)
{
	return ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP || ip_proto == IPPROTO_SCTP;
}

static void tc_fill_l3(const struct pbr_filter *pf, int family, struct tc_flower *fl)
{
	if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_IP_PROTOCOL)) {
		fl->filter_bm |= TC_FLOWER_IP_PROTOCOL;
		fl->ip_proto = pf->ip_proto;
	}

	if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_SRC_IP) && pf->src_ip.family == family) {
		fl->filter_bm |= TC_FLOWER_SRC_IP;
		prefix_copy(&fl->src_ip, &pf->src_ip);
	}

	if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_DST_IP) && pf->dst_ip.family == family) {
		fl->filter_bm |= TC_FLOWER_DST_IP;
		prefix_copy(&fl->dst_ip, &pf->dst_ip);
	}

	if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_SRC_PORT)) {
		fl->filter_bm |= TC_FLOWER_SRC_PORT;
		fl->src_port_min = fl->src_port_max = pf->src_port;
	}

	if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_DST_PORT)) {
		fl->filter_bm |= TC_FLOWER_DST_PORT;
		fl->dst_port_min = fl->dst_port_max = pf->dst_port;
	}

	if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_DSCP)) {
		fl->filter_bm |= TC_FLOWER_DSFIELD;
		fl->dsfield |= pf->dsfield & PBR_DSFIELD_DSCP;
		fl->dsfield_mask |= PBR_DSFIELD_DSCP;
	}

	if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_ECN)) {
		fl->filter_bm |= TC_FLOWER_DSFIELD;
		fl->dsfield |= pf->dsfield & PBR_DSFIELD_ECN;
		fl->dsfield_mask |= PBR_DSFIELD_ECN;
	}
}

static void tc_fill_one(const struct pbr_rule *r, ifindex_t ifindex, enum zebra_pbr_tc_variant v,
			bool force_vid0, struct tc_filter *f)
{
	const struct pbr_filter *pf = &r->filter;
	const struct pbr_action *pa = &r->action;
	struct tc_flower *fl = &f->u.flower;
	uint32_t seq = r->seq ? r->seq : 1;

	memset(f, 0, sizeof(*f));
	f->ifindex = ifindex;
	f->kind = TC_FILTER_FLOWER;
	f->attach = TC_ATTACH_INGRESS;
	f->priority = seq * ZEBRA_PBR_TC_PREF_STRIDE + v;
	f->handle = zebra_pbr_tc_handle(r->unique, v);

	f->has_action = true;
	f->skbedit.set_priority = true;
	f->skbedit.priority = pa->traffic_class;
	if (pa->tc_mark_mask) {
		f->skbedit.set_mark = true;
		f->skbedit.mark = pbr_tc_mark(pa->traffic_class, pa->tc_mark_mask);
		f->skbedit.mark_mask = pa->tc_mark_mask;
	}

	switch (v) {
	case ZEBRA_PBR_TC_V_IPV4:
		f->protocol = ETH_P_IP;
		tc_fill_l3(pf, AF_INET, fl);
		break;
	case ZEBRA_PBR_TC_V_IPV6:
		f->protocol = ETH_P_IPV6;
		tc_fill_l3(pf, AF_INET6, fl);
		break;
	case ZEBRA_PBR_TC_V_VLAN_IPV4:
	case ZEBRA_PBR_TC_V_VLAN_IPV6:
	case ZEBRA_PBR_TC_V_VLAN:
		f->protocol = ETH_P_8021Q;
		if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_VLAN_ID) || force_vid0) {
			fl->filter_bm |= TC_FLOWER_VLAN_ID;
			fl->vlan_id = force_vid0 ? 0 : pf->vlan_id;
		}
		if (CHECK_FLAG(pf->filter_bm, PBR_FILTER_PCP)) {
			fl->filter_bm |= TC_FLOWER_VLAN_PRIO;
			fl->vlan_prio = pf->pcp & PBR_PCP;
		}
		if (v == ZEBRA_PBR_TC_V_VLAN)
			break;
		fl->filter_bm |= TC_FLOWER_VLAN_ETH_TYPE;
		fl->vlan_eth_type = (v == ZEBRA_PBR_TC_V_VLAN_IPV4) ? ETH_P_IP : ETH_P_IPV6;
		tc_fill_l3(pf, v == ZEBRA_PBR_TC_V_VLAN_IPV4 ? AF_INET : AF_INET6, fl);
		break;
	case ZEBRA_PBR_TC_V_ALL:
		f->protocol = ETH_P_ALL;
		break;
	case ZEBRA_PBR_TC_V_MAX:
		break;
	}
}

int zebra_pbr_tc_derive(const struct pbr_rule *r, ifindex_t ifindex, bool l2_port,
			struct tc_filter *out)
{
	const struct pbr_filter *pf = &r->filter;
	uint32_t bm = pf->filter_bm;
	bool has_l3 = CHECK_FLAG(bm, PBR_L3_FILTERS);
	bool has_vlan_key = CHECK_FLAG(bm, PBR_FILTER_PCP | PBR_FILTER_VLAN_ID);
	uint16_t vflags = CHECK_FLAG(bm, PBR_FILTER_VLAN_FLAGS) ? pf->vlan_flags
								: PBR_VLAN_FLAGS_NO_WILD;
	bool want4 = true, want6 = true;
	bool tagged, untagged, force_vid0 = false;
	int n = 0;

	if (!CHECK_FLAG(r->action.flags, PBR_ACTION_TRAFFIC_CLASS))
		return 0;

	/* flower has no fwmark key; L4 ports need the L4 protocol */
	if (CHECK_FLAG(bm, PBR_FILTER_FWMARK))
		return -1;
	if (CHECK_FLAG(bm, PBR_FILTER_SRC_PORT | PBR_FILTER_DST_PORT) &&
	    (!CHECK_FLAG(bm, PBR_FILTER_IP_PROTOCOL) || !tc_port_proto_ok(pf->ip_proto)))
		return -1;

	/*
	 * Which frame shapes can match.  The VLAN flags are checked first so
	 * that a PCP match never widens them: PCP exists only in a tag, so
	 * with "untagged-or-zero" it limits the match to priority-tagged
	 * (VID 0) frames, and with "untagged" nothing can match.  pbrd makes
	 * a VLAN ID match and VLAN flags mutually exclusive.
	 */
	if (vflags == PBR_VLAN_FLAGS_UNTAGGED) {
		if (CHECK_FLAG(bm, PBR_FILTER_PCP))
			return -1;
		tagged = false;
		untagged = true;
	} else if (vflags == PBR_VLAN_FLAGS_UNTAGGED_0) {
		tagged = force_vid0 = true;
		untagged = !CHECK_FLAG(bm, PBR_FILTER_PCP);
	} else if (has_vlan_key || vflags == PBR_VLAN_FLAGS_TAGGED) {
		tagged = true;
		untagged = false;
	} else {
		/* no VLAN constraint: bridge ports also see tagged frames */
		untagged = true;
		tagged = l2_port;
	}

	/* An address match pins the family */
	if (CHECK_FLAG(bm, PBR_FILTER_SRC_IP) || CHECK_FLAG(bm, PBR_FILTER_DST_IP)) {
		int fam = CHECK_FLAG(bm, PBR_FILTER_SRC_IP) ? pf->src_ip.family : pf->dst_ip.family;

		want4 = (fam == AF_INET);
		want6 = (fam == AF_INET6);
	}

	if (has_l3) {
		if (untagged && want4)
			tc_fill_one(r, ifindex, ZEBRA_PBR_TC_V_IPV4, false, &out[n++]);
		if (untagged && want6)
			tc_fill_one(r, ifindex, ZEBRA_PBR_TC_V_IPV6, false, &out[n++]);
		if (tagged && want4)
			tc_fill_one(r, ifindex, ZEBRA_PBR_TC_V_VLAN_IPV4, force_vid0, &out[n++]);
		if (tagged && want6)
			tc_fill_one(r, ifindex, ZEBRA_PBR_TC_V_VLAN_IPV6, force_vid0, &out[n++]);
		return n;
	}

	if (vflags == PBR_VLAN_FLAGS_NO_WILD && !has_vlan_key) {
		/* match everything */
		tc_fill_one(r, ifindex, ZEBRA_PBR_TC_V_ALL, false, &out[n++]);
		return n;
	}

	/*
	 * Untagged frames are recognised by their IPv4 / IPv6 ethertype, so
	 * "untagged, any payload" (no IP match) cannot be expressed: non-IP
	 * frames would miss the class.  pbrd rejects it; refuse it here too.
	 */
	if (untagged)
		return -1;

	if (tagged)
		tc_fill_one(r, ifindex, ZEBRA_PBR_TC_V_VLAN, force_vid0, &out[n++]);

	return n;
}

/*
 * Interface types that must not carry a classifier.  Returns true and sets
 * @reason to refuse.
 */
static bool tc_port_refused(const struct interface *ifp, const char **reason)
{
	return false;
}

static struct interface *tc_rule_ifp(const struct zebra_pbr_rule *rule)
{
	return if_lookup_by_name_per_ns(zebra_ns_lookup(NS_DEFAULT), rule->rule.ifname);
}

static bool tc_ifindex_gone(ifindex_t ifindex)
{
	return if_lookup_by_index_per_ns(zebra_ns_lookup(NS_DEFAULT), ifindex) == NULL;
}

static void tc_remove_variant(uint32_t unique, ifindex_t ifindex, enum zebra_pbr_tc_variant v,
			      bool ifp_gone)
{
	struct zebra_tc_filter *zf;

	zf = zebra_tc_filter_lookup(ifindex, zebra_pbr_tc_handle(unique, v), TC_ATTACH_INGRESS);
	if (!zf)
		return;

	if (ifp_gone)
		zebra_tc_filter_forget(zf);
	else
		zebra_tc_filter_delete(zf);

	zebra_tc_clsact_unref(ifindex, ifp_gone);
}

static void tc_remove_all(uint32_t unique, struct zebra_pbr_tc *st, uint8_t keep)
{
	bool gone;

	if (st->state != ZEBRA_PBR_TC_INSTALLED)
		return;

	gone = tc_ifindex_gone(st->ifindex);
	for (int v = 0; v < ZEBRA_PBR_TC_V_MAX; v++)
		if ((st->variants & (1u << v)) && !(keep & (1u << v)))
			tc_remove_variant(unique, st->ifindex, v, gone);
}

void zebra_pbr_tc_rule_install(struct zebra_pbr_rule *rule, struct zebra_pbr_rule *old)
{
	struct zebra_pbr_tc *st = &rule->tc;
	struct zebra_pbr_tc *prev = old ? &old->tc : NULL;
	struct tc_filter filters[ZEBRA_PBR_TC_V_MAX];
	struct interface *ifp;
	uint8_t have = 0;
	int n;

	memset(st, 0, sizeof(*st));

	/* Filters the old rule had on the same interface can be updated in place */
	ifp = tc_rule_ifp(rule);
	if (prev && prev->state == ZEBRA_PBR_TC_INSTALLED && ifp && ifp->ifindex == prev->ifindex)
		have = prev->variants;

	if (!CHECK_FLAG(rule->rule.action.flags, PBR_ACTION_TRAFFIC_CLASS))
		goto done;

	if (!ifp || ifp->ifindex == IFINDEX_INTERNAL) {
		st->state = ZEBRA_PBR_TC_NO_INTERFACE;
		goto done;
	}

	if (tc_port_refused(ifp, &st->reason)) {
		st->state = ZEBRA_PBR_TC_REFUSED;
		zlog_warn("PBR %s seq %u: traffic-class not installed on %s: %s",
			  rule->rule.ifname, rule->rule.seq, ifp->name, st->reason);
		goto done;
	}

	n = zebra_pbr_tc_derive(&rule->rule, ifp->ifindex, IS_ZEBRA_IF_BRIDGE_SLAVE(ifp), filters);
	if (n < 0) {
		st->state = ZEBRA_PBR_TC_INVALID;
		st->reason = "match cannot be expressed as a tc flower classifier or can never match";
		goto done;
	}

	st->state = ZEBRA_PBR_TC_INSTALLED;
	st->ifindex = ifp->ifindex;

	for (int i = 0; i < n; i++) {
		struct zebra_tc_filter zf = {};
		enum zebra_pbr_tc_variant v = filters[i].handle & 0x7;

		zf.sock = rule->sock;
		zf.owner = ZEBRA_TC_OWNER_PBR;
		zf.filter = filters[i];

		if (IS_ZEBRA_DEBUG_PBR)
			zlog_debug("%s: %s seq %u TC %u -> pref %u protocol 0x%04x handle 0x%08x",
				   __func__, ifp->name, rule->rule.seq,
				   rule->rule.action.traffic_class, zf.filter.priority,
				   zf.filter.protocol, zf.filter.handle);

		/* clsact first, so that it is queued ahead of the filter */
		if (!(have & (1u << v)))
			zebra_tc_clsact_ref(ifp->ifindex);
		zebra_tc_filter_add(&zf);
		st->variants |= 1u << v;
	}

done:
	if (prev)
		tc_remove_all(old->rule.unique, prev, have & st->variants);
	if (prev)
		prev->state = ZEBRA_PBR_TC_NONE;
}

void zebra_pbr_tc_rule_uninstall(struct zebra_pbr_rule *rule)
{
	tc_remove_all(rule->rule.unique, &rule->tc, 0);
	rule->tc.state = ZEBRA_PBR_TC_NONE;
	rule->tc.variants = 0;
}

static int tc_interface_update_walker(struct hash_bucket *b, void *arg)
{
	struct zebra_pbr_rule *rule = b->data;
	const struct interface *ifp = arg;
	struct zebra_pbr_rule old;

	if (!CHECK_FLAG(rule->rule.action.flags, PBR_ACTION_TRAFFIC_CLASS) ||
	    strcmp(rule->rule.ifname, ifp->name) != 0)
		return HASHWALK_CONTINUE;

	/*
	 * Re-derive against the new bridge membership.  The copy carries the
	 * current classifier state, so filters that are still needed are
	 * updated in place and the others (e.g. the 802.1Q shapes after
	 * leaving the bridge) are removed.
	 */
	old = *rule;
	zebra_pbr_tc_rule_install(rule, &old);

	return HASHWALK_CONTINUE;
}

void zebra_pbr_tc_interface_update(struct interface *ifp)
{
	if (IS_ZEBRA_DEBUG_PBR)
		zlog_debug("%s: %s bridge membership changed, rebuilding classifiers", __func__,
			   ifp->name);

	hash_walk(zrouter.rules_hash, tc_interface_update_walker, ifp);
}

#else /* !HAVE_NETLINK */

/*
 * No tc dataplane: nothing is programmed.  The rule (and any FIB part) is
 * handled as before; the classifier state says why there is none.
 */
int zebra_pbr_tc_derive(const struct pbr_rule *r, ifindex_t ifindex, bool l2_port,
			struct tc_filter *out)
{
	return CHECK_FLAG(r->action.flags, PBR_ACTION_TRAFFIC_CLASS) ? -1 : 0;
}

void zebra_pbr_tc_rule_install(struct zebra_pbr_rule *rule, struct zebra_pbr_rule *old)
{
	struct zebra_pbr_tc *st = &rule->tc;

	memset(st, 0, sizeof(*st));
	if (old)
		memset(&old->tc, 0, sizeof(old->tc));

	if (!CHECK_FLAG(rule->rule.action.flags, PBR_ACTION_TRAFFIC_CLASS))
		return;

	st->state = ZEBRA_PBR_TC_UNSUPPORTED;
	st->reason = "traffic-class needs the Linux tc dataplane";

	if (IS_ZEBRA_DEBUG_PBR)
		zlog_debug("%s: %s seq %u: %s", __func__, rule->rule.ifname, rule->rule.seq,
			   st->reason);
}

void zebra_pbr_tc_rule_uninstall(struct zebra_pbr_rule *rule)
{
	memset(&rule->tc, 0, sizeof(rule->tc));
}

void zebra_pbr_tc_interface_update(struct interface *ifp)
{
}

#endif /* HAVE_NETLINK */

void zebra_pbr_tc_show(struct vty *vty, const struct zebra_pbr_rule *rule)
{
	const struct zebra_pbr_tc *st = &rule->tc;

	if (!CHECK_FLAG(rule->rule.action.flags, PBR_ACTION_TRAFFIC_CLASS))
		return;

	vty_out(vty, "  Action: Set Traffic Class: %u", rule->rule.action.traffic_class);
	if (rule->rule.action.tc_mark_mask)
		vty_out(vty, " (mark 0x%x/0x%x)",
			pbr_tc_mark(rule->rule.action.traffic_class,
				    rule->rule.action.tc_mark_mask),
			rule->rule.action.tc_mark_mask);
	vty_out(vty, "\n");

	vty_out(vty, "  Classifier: %s", zebra_pbr_tc_state2str(st->state));
	if (st->reason)
		vty_out(vty, " (%s)", st->reason);
	if (st->state == ZEBRA_PBR_TC_INSTALLED) {
		vty_out(vty, ", ingress filter pref");
		for (int v = 0; v < ZEBRA_PBR_TC_V_MAX; v++)
			if (st->variants & (1u << v))
				vty_out(vty, " %u", rule->rule.seq * ZEBRA_PBR_TC_PREF_STRIDE + v);
	}
	vty_out(vty, "\n");

	if (!CHECK_FLAG(rule->rule.action.flags, PBR_ACTION_TABLE))
		vty_out(vty, "  Classify only: no FIB rule installed\n");
}
