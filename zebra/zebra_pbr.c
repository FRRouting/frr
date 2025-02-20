// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra Policy Based Routing (PBR) main handling.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 * Portions:
 *		Copyright (c) 2021 The MITRE Corporation.
 *		Copyright (c) 2023 LabN Consulting, L.L.C.
 */

#include <zebra.h>

#include <jhash.h>
#include <hash.h>
#include <memory.h>
#include <hook.h>

#include "zebra/zebra_router.h"
#include "zebra/zebra_pbr.h"
#include "zebra/rt.h"
#include "zebra/zapi_msg.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/zebra_neigh.h"

/* definitions */
DEFINE_MTYPE_STATIC(ZEBRA, PBR_IPTABLE_IFNAME, "PBR interface list");
DEFINE_MTYPE(ZEBRA, PBR_OBJ, "PBR");

/* definitions */
static const struct message ipset_type_msg[] = {
	{IPSET_NET_PORT_NET, "net,port,net"},
	{IPSET_NET_PORT, "net,port"},
	{IPSET_NET_NET, "net,net"},
	{IPSET_NET, "net"},
	{0}
};

const struct message icmp_typecode_str[] = {
	{ 0 << 8, "echo-reply"},
	{ 0 << 8, "pong"},
	{ 3 << 8, "network-unreachable"},
	{ (3 << 8) + 1, "host-unreachable"},
	{ (3 << 8) + 2, "protocol-unreachable"},
	{ (3 << 8) + 3, "port-unreachable"},
	{ (3 << 8) + 4, "fragmentation-needed"},
	{ (3 << 8) + 5, "source-route-failed"},
	{ (3 << 8) + 6, "network-unknown"},
	{ (3 << 8) + 7, "host-unknown"},
	{ (3 << 8) + 9, "network-prohibited"},
	{ (3 << 8) + 10, "host-prohibited"},
	{ (3 << 8) + 11, "TOS-network-unreachable"},
	{ (3 << 8) + 12, "TOS-host-unreachable"},
	{ (3 << 8) + 13, "communication-prohibited"},
	{ (3 << 8) + 14, "host-precedence-violation"},
	{ (3 << 8) + 15, "precedence-cutoff"},
	{ 4 << 8, "source-quench"},
	{ 5 << 8, "network-redirect"},
	{ (5 << 8) +  1, "host-redirect"},
	{ (5 << 8) +  2, "TOS-network-redirect"},
	{ (5 << 8) +  3, "TOS-host-redirect"},
	{ 8 << 8, "echo-request"},
	{ 8 << 8, "ping"},
	{ 9 << 8, "router-advertisement"},
	{ 10 << 8, "router-solicitation"},
	{ 11 << 8, "ttl-zero-during-transit"},
	{ (11 << 8) + 1, "ttl-zero-during-reassembly"},
	{ 12 << 8, "ip-header-bad"},
	{ (12 << 8) + 1, "required-option-missing"},
	{ 13 << 8, "timestamp-request"},
	{ 14 << 8, "timestamp-reply"},
	{ 17 << 8, "address-mask-request"},
	{ 18 << 8, "address-mask-reply"},
	{0}
};

const struct message icmpv6_typecode_str[] = {
	{ 128 << 8, "echo-request"},
	{ 129 << 8, "echo-reply"},
	{ 1 << 8, "no-route"},
	{ (1 << 8) + 1, "communication-prohibited"},
	{ (1 << 8) + 3, "address-unreachable"},
	{ (1 << 8) + 4, "port-unreachable"},
	{ (2 << 8), "packet-too-big"},
	{ 3 << 0, "ttl-zero-during-transit"},
	{ (3 << 8) + 1, "ttl-zero-during-reassembly"},
	{ 4 << 0, "bad-header"},
	{ (4 << 0) + 1, "unknown-header-type"},
	{ (4 << 0) + 2, "unknown-option"},
	{ 133 << 8, "router-solicitation"},
	{ 134 << 8, "router-advertisement"},
	{ 135 << 8, "neighbor-solicitation"},
	{ 136 << 8, "neighbor-advertisement"},
	{ 137 << 8, "redirect"},
	{0}
};

/* definitions */
static const struct message tcp_value_str[] = {
	{TCP_HEADER_FIN, "FIN"},
	{TCP_HEADER_SYN, "SYN"},
	{TCP_HEADER_RST, "RST"},
	{TCP_HEADER_PSH, "PSH"},
	{TCP_HEADER_ACK, "ACK"},
	{TCP_HEADER_URG, "URG"},
	{0}
};

static const struct message fragment_value_str[] = {
	{1, "dont-fragment"},
	{2, "is-fragment"},
	{4, "first-fragment"},
	{8, "last-fragment"},
	{0}
};

struct zebra_pbr_env_display {
	struct zebra_ns *zns;
	struct vty *vty;
	char *name;
};

/* static function declarations */
DEFINE_HOOK(zebra_pbr_ipset_entry_get_stat,
	    (struct zebra_pbr_ipset_entry *ipset, uint64_t *pkts,
	     uint64_t *bytes),
	    (ipset, pkts, bytes));

DEFINE_HOOK(zebra_pbr_iptable_get_stat,
	    (struct zebra_pbr_iptable *iptable, uint64_t *pkts,
	     uint64_t *bytes),
	    (iptable, pkts, bytes));

DEFINE_HOOK(zebra_pbr_iptable_update,
	    (int cmd, struct zebra_pbr_iptable *iptable), (cmd, iptable));

DEFINE_HOOK(zebra_pbr_ipset_entry_update,
	    (int cmd, struct zebra_pbr_ipset_entry *ipset), (cmd, ipset));

DEFINE_HOOK(zebra_pbr_ipset_update,
	    (int cmd, struct zebra_pbr_ipset *ipset), (cmd, ipset));

/* resolve nexthop for dataplane (dpdk) programming */
static bool zebra_pbr_expand_action;

/* Private functions */

/* Public functions */
void zebra_pbr_rules_free(void *arg)
{
	struct zebra_pbr_rule *rule;

	rule = (struct zebra_pbr_rule *)arg;

	(void)dplane_pbr_rule_delete(rule);
	XFREE(MTYPE_PBR_OBJ, rule);
}

uint32_t zebra_pbr_rules_hash_key(const void *arg)
{
	const struct zebra_pbr_rule *rule;
	uint32_t key;

	rule = arg;
	key = jhash_3words(rule->rule.seq, rule->rule.priority,
			   rule->rule.action.table,
			   prefix_hash_key(&rule->rule.filter.src_ip));

	key = jhash_3words(rule->rule.filter.fwmark, rule->vrf_id,
			   rule->rule.filter.ip_proto, key);

	key = jhash(rule->ifname, strlen(rule->ifname), key);

	key = jhash_3words(rule->rule.filter.pcp, rule->rule.filter.vlan_id,
			   rule->rule.filter.vlan_flags, key);

	key = jhash_3words(rule->rule.filter.src_port,
			   rule->rule.filter.dst_port,
			   prefix_hash_key(&rule->rule.filter.dst_ip), key);

	key = jhash_2words(rule->rule.unique, rule->sock, key);

	return key;
}

bool zebra_pbr_rules_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_rule *r1, *r2;

	r1 = (const struct zebra_pbr_rule *)arg1;
	r2 = (const struct zebra_pbr_rule *)arg2;

	if (r1->rule.seq != r2->rule.seq)
		return false;

	if (r1->rule.priority != r2->rule.priority)
		return false;

	if (r1->sock != r2->sock)
		return false;

	if (r1->rule.unique != r2->rule.unique)
		return false;

	if (r1->rule.action.table != r2->rule.action.table)
		return false;

	if (r1->rule.filter.src_port != r2->rule.filter.src_port)
		return false;

	if (r1->rule.filter.dst_port != r2->rule.filter.dst_port)
		return false;

	if (r1->rule.filter.fwmark != r2->rule.filter.fwmark)
		return false;

	if (r1->rule.filter.ip_proto != r2->rule.filter.ip_proto)
		return false;

	if (!prefix_same(&r1->rule.filter.src_ip, &r2->rule.filter.src_ip))
		return false;

	if (!prefix_same(&r1->rule.filter.dst_ip, &r2->rule.filter.dst_ip))
		return false;

	if (strcmp(r1->rule.ifname, r2->rule.ifname) != 0)
		return false;

	if (r1->vrf_id != r2->vrf_id)
		return false;

	return true;
}

struct pbr_rule_unique_lookup {
	struct zebra_pbr_rule *rule;
	int sock;
	uint32_t unique;
	char ifname[IFNAMSIZ + 1];
	vrf_id_t vrf_id;
};

static int pbr_rule_lookup_unique_walker(struct hash_bucket *b, void *data)
{
	struct pbr_rule_unique_lookup *pul = data;
	struct zebra_pbr_rule *rule = b->data;

	if (pul->sock == rule->sock && pul->unique == rule->rule.unique &&
	    strmatch(pul->ifname, rule->rule.ifname) &&
	    pul->vrf_id == rule->vrf_id) {
		pul->rule = rule;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

static struct zebra_pbr_rule *
pbr_rule_lookup_unique(struct zebra_pbr_rule *zrule)
{
	struct pbr_rule_unique_lookup pul;

	pul.unique = zrule->rule.unique;
	strlcpy(pul.ifname, zrule->rule.ifname, IFNAMSIZ);
	pul.rule = NULL;
	pul.vrf_id = zrule->vrf_id;
	pul.sock = zrule->sock;
	hash_walk(zrouter.rules_hash, &pbr_rule_lookup_unique_walker, &pul);

	return pul.rule;
}

void zebra_pbr_ipset_free(void *arg)
{
	struct zebra_pbr_ipset *ipset;

	ipset = (struct zebra_pbr_ipset *)arg;
	hook_call(zebra_pbr_ipset_update, 0, ipset);
	XFREE(MTYPE_PBR_OBJ, ipset);
}

uint32_t zebra_pbr_ipset_hash_key(const void *arg)
{
	const struct zebra_pbr_ipset *ipset = arg;
	uint32_t *pnt = (uint32_t *)&ipset->ipset_name;
	uint32_t key = jhash_1word(ipset->vrf_id, 0x63ab42de);

	key =  jhash_1word(ipset->family, key);

	return jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE, key);
}

bool zebra_pbr_ipset_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset *r1, *r2;

	r1 = (const struct zebra_pbr_ipset *)arg1;
	r2 = (const struct zebra_pbr_ipset *)arg2;

	if (r1->type != r2->type)
		return false;
	if (r1->unique != r2->unique)
		return false;
	if (r1->vrf_id != r2->vrf_id)
		return false;
	if (r1->family != r2->family)
		return false;

	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return false;
	return true;
}

void zebra_pbr_ipset_entry_free(void *arg)
{
	struct zebra_pbr_ipset_entry *ipset;

	ipset = (struct zebra_pbr_ipset_entry *)arg;

	hook_call(zebra_pbr_ipset_entry_update, 0, ipset);

	XFREE(MTYPE_PBR_OBJ, ipset);
}

uint32_t zebra_pbr_ipset_entry_hash_key(const void *arg)
{
	const struct zebra_pbr_ipset_entry *ipset;
	uint32_t key;

	ipset = arg;
	key = prefix_hash_key(&ipset->src);
	key = jhash_1word(ipset->unique, key);
	key = jhash_1word(prefix_hash_key(&ipset->dst), key);
	key = jhash(&ipset->dst_port_min, 2, key);
	key = jhash(&ipset->dst_port_max, 2, key);
	key = jhash(&ipset->src_port_min, 2, key);
	key = jhash(&ipset->src_port_max, 2, key);
	key = jhash(&ipset->proto, 1, key);

	return key;
}

bool zebra_pbr_ipset_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset_entry *r1, *r2;

	r1 = (const struct zebra_pbr_ipset_entry *)arg1;
	r2 = (const struct zebra_pbr_ipset_entry *)arg2;

	if (r1->unique != r2->unique)
		return false;

	if (!prefix_same(&r1->src, &r2->src))
		return false;

	if (!prefix_same(&r1->dst, &r2->dst))
		return false;

	if (r1->src_port_min != r2->src_port_min)
		return false;

	if (r1->src_port_max != r2->src_port_max)
		return false;

	if (r1->dst_port_min != r2->dst_port_min)
		return false;

	if (r1->dst_port_max != r2->dst_port_max)
		return false;

	if (r1->proto != r2->proto)
		return false;
	return true;
}

/* this function gives option to flush plugin memory contexts
 * with all parameter. set it to true to flush all
 * set it to false to flush only passed arg argument
 */
static void _zebra_pbr_iptable_free_all(void *arg, bool all)
{
	struct zebra_pbr_iptable *iptable;
	struct listnode *node, *nnode;
	char *name;

	iptable = (struct zebra_pbr_iptable *)arg;

	if (all)
		hook_call(zebra_pbr_iptable_update, 0, iptable);

	if (iptable->interface_name_list) {
		for (ALL_LIST_ELEMENTS(iptable->interface_name_list, node,
				       nnode, name)) {
			XFREE(MTYPE_PBR_IPTABLE_IFNAME, name);
			list_delete_node(iptable->interface_name_list, node);
		}
		list_delete(&iptable->interface_name_list);
	}
	XFREE(MTYPE_PBR_OBJ, iptable);
}

void zebra_pbr_iptable_free(void *arg)
{
	_zebra_pbr_iptable_free_all(arg, false);
}

uint32_t zebra_pbr_iptable_hash_key(const void *arg)
{
	const struct zebra_pbr_iptable *iptable = arg;
	uint32_t *pnt = (uint32_t *)&(iptable->ipset_name);
	uint32_t key;

	key = jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE,
		     0x63ab42de);
	key = jhash_1word(iptable->fwmark, key);
	key = jhash_1word(iptable->family, key);
	key = jhash_1word(iptable->flow_label, key);
	key = jhash_1word(iptable->pkt_len_min, key);
	key = jhash_1word(iptable->pkt_len_max, key);
	key = jhash_1word(iptable->tcp_flags, key);
	key = jhash_1word(iptable->tcp_mask_flags, key);
	key = jhash_1word(iptable->dscp_value, key);
	key = jhash_1word(iptable->protocol, key);
	key = jhash_1word(iptable->fragment, key);
	key = jhash_1word(iptable->vrf_id, key);

	return jhash_3words(iptable->filter_bm, iptable->type,
			    iptable->unique, key);
}

bool zebra_pbr_iptable_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_iptable *r1, *r2;

	r1 = (const struct zebra_pbr_iptable *)arg1;
	r2 = (const struct zebra_pbr_iptable *)arg2;

	if (r1->vrf_id != r2->vrf_id)
		return false;
	if (r1->type != r2->type)
		return false;
	if (r1->unique != r2->unique)
		return false;
	if (r1->filter_bm != r2->filter_bm)
		return false;
	if (r1->fwmark != r2->fwmark)
		return false;
	if (r1->action != r2->action)
		return false;
	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return false;
	if (r1->family != r2->family)
		return false;
	if (r1->flow_label != r2->flow_label)
		return false;
	if (r1->pkt_len_min != r2->pkt_len_min)
		return false;
	if (r1->pkt_len_max != r2->pkt_len_max)
		return false;
	if (r1->tcp_flags != r2->tcp_flags)
		return false;
	if (r1->tcp_mask_flags != r2->tcp_mask_flags)
		return false;
	if (r1->dscp_value != r2->dscp_value)
		return false;
	if (r1->fragment != r2->fragment)
		return false;
	if (r1->protocol != r2->protocol)
		return false;
	return true;
}

static void *pbr_rule_alloc_intern(void *arg)
{
	struct zebra_pbr_rule *zpr;
	struct zebra_pbr_rule *new;

	zpr = (struct zebra_pbr_rule *)arg;

	new = XCALLOC(MTYPE_PBR_OBJ, sizeof(*new));

	memcpy(new, zpr, sizeof(*zpr));

	return new;
}

static struct zebra_pbr_rule *pbr_rule_free(struct zebra_pbr_rule *hash_data,
					    bool free_data)
{
	if (hash_data->action.neigh)
		zebra_neigh_deref(hash_data);
	hash_release(zrouter.rules_hash, hash_data);
	if (free_data) {
		XFREE(MTYPE_PBR_OBJ, hash_data);
		return NULL;
	}

	return hash_data;
}

static struct zebra_pbr_rule *pbr_rule_release(struct zebra_pbr_rule *rule,
					       bool free_data)
{
	struct zebra_pbr_rule *lookup;

	lookup = hash_lookup(zrouter.rules_hash, rule);

	if (!lookup)
		return NULL;

	return pbr_rule_free(lookup, free_data);
}

void zebra_pbr_show_rule_unit(struct zebra_pbr_rule *rule, struct vty *vty)
{
	struct pbr_rule *prule = &rule->rule;
	struct zebra_pbr_action *zaction = &rule->action;
	struct pbr_action *pa = &prule->action;

	vty_out(vty, "Rules if %s\n", rule->ifname);
	vty_out(vty, "  Seq %u pri %u\n", prule->seq, prule->priority);
	if (prule->filter.filter_bm & PBR_FILTER_SRC_IP)
		vty_out(vty, "  SRC IP Match: %pFX\n", &prule->filter.src_ip);
	if (prule->filter.filter_bm & PBR_FILTER_DST_IP)
		vty_out(vty, "  DST IP Match: %pFX\n", &prule->filter.dst_ip);
	if (prule->filter.filter_bm & PBR_FILTER_IP_PROTOCOL)
		vty_out(vty, "  IP protocol Match: %u\n",
			prule->filter.ip_proto);
	if (prule->filter.filter_bm & PBR_FILTER_SRC_PORT)
		vty_out(vty, "  SRC Port Match: %u\n", prule->filter.src_port);
	if (prule->filter.filter_bm & PBR_FILTER_DST_PORT)
		vty_out(vty, "  DST Port Match: %u\n", prule->filter.dst_port);

	if (prule->filter.filter_bm & PBR_FILTER_DSCP)
		vty_out(vty, "  DSCP Match: %u\n",
			(prule->filter.dsfield & PBR_DSFIELD_DSCP) >> 2);
	if (prule->filter.filter_bm & PBR_FILTER_ECN)
		vty_out(vty, "  ECN Match: %u\n",
			prule->filter.dsfield & PBR_DSFIELD_ECN);

	if (prule->filter.filter_bm & PBR_FILTER_FWMARK)
		vty_out(vty, "  MARK Match: %u\n", prule->filter.fwmark);
	if (prule->filter.filter_bm & PBR_FILTER_PCP)
		vty_out(vty, "  PCP Match: %u\n", prule->filter.pcp);
	if (prule->filter.filter_bm & PBR_FILTER_VLAN_ID)
		vty_out(vty, "  VLAN ID Match: %u\n", prule->filter.vlan_id);
	if (prule->filter.filter_bm & PBR_FILTER_VLAN_FLAGS) {
		vty_out(vty, "  VLAN Flags Match:");
		if (CHECK_FLAG(prule->filter.vlan_flags, PBR_VLAN_FLAGS_TAGGED))
			vty_out(vty, " tagged");
		if (CHECK_FLAG(prule->filter.vlan_flags,
			       PBR_VLAN_FLAGS_UNTAGGED))
			vty_out(vty, " untagged");
		if (CHECK_FLAG(prule->filter.vlan_flags,
			       PBR_VLAN_FLAGS_UNTAGGED_0))
			vty_out(vty, " untagged-or-zero");
		vty_out(vty, "\n");
	}

	if (CHECK_FLAG(pa->flags, PBR_ACTION_ECN))
		vty_out(vty, "  Action: Set ECN: %u\n", pa->ecn);
	if (CHECK_FLAG(pa->flags, PBR_ACTION_DSCP))
		vty_out(vty, "  Action: Set DSCP: %u\n", pa->dscp >> 2);

	if (CHECK_FLAG(pa->flags, PBR_ACTION_SRC_IP))
		vty_out(vty, "  Action: Set SRC IP: %pSU\n", &pa->src_ip);
	if (CHECK_FLAG(pa->flags, PBR_ACTION_DST_IP))
		vty_out(vty, "  Action: Set DST IP: %pSU\n", &pa->dst_ip);
	if (CHECK_FLAG(pa->flags, PBR_ACTION_SRC_PORT))
		vty_out(vty, "  Action: Set SRC PORT: %u\n", pa->src_port);
	if (CHECK_FLAG(pa->flags, PBR_ACTION_DST_PORT))
		vty_out(vty, "  Action: Set DST PORT: %u\n", pa->dst_port);

	if (CHECK_FLAG(pa->flags, PBR_ACTION_QUEUE_ID))
		vty_out(vty, "  Action: Set Queue ID: %u\n", pa->queue_id);

	if (CHECK_FLAG(pa->flags, PBR_ACTION_PCP))
		vty_out(vty, "  Action: Set PCP: %u\n", pa->pcp);
	if (CHECK_FLAG(pa->flags, PBR_ACTION_VLAN_ID))
		vty_out(vty, "  Action: Set VLAN ID: %u\n", pa->vlan_id);
	if (CHECK_FLAG(pa->flags, PBR_ACTION_VLAN_STRIP_INNER_ANY))
		vty_out(vty, "  Action: Strip VLAN ID\n");

	vty_out(vty, "  Tableid: %u\n", prule->action.table);
	if (zaction->afi == AFI_IP)
		vty_out(vty, "  Action: nh: %pI4 intf: %s\n",
			&zaction->gate.ipv4,
			ifindex2ifname(zaction->ifindex, rule->vrf_id));
	if (zaction->afi == AFI_IP6)
		vty_out(vty, "  Action: nh: %pI6 intf: %s\n",
			&zaction->gate.ipv6,
			ifindex2ifname(zaction->ifindex, rule->vrf_id));
	if (zaction->neigh && (zaction->neigh->flags & ZEBRA_NEIGH_ENT_ACTIVE))
		vty_out(vty, "  Action: mac: %pEA\n", &zaction->neigh->mac);
}

static int zebra_pbr_show_rules_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_pbr_rule *rule = (struct zebra_pbr_rule *)bucket->data;
	struct zebra_pbr_env_display *env = (struct zebra_pbr_env_display *)arg;
	struct vty *vty = env->vty;

	zebra_pbr_show_rule_unit(rule, vty);

	return HASHWALK_CONTINUE;
}

void zebra_pbr_show_rule(struct vty *vty)
{
	struct zebra_pbr_env_display env;

	env.vty = vty;
	hash_walk(zrouter.rules_hash, zebra_pbr_show_rules_walkcb, &env);
}

void zebra_pbr_config_write(struct vty *vty)
{
	if (zebra_pbr_expand_action)
		vty_out(vty, "pbr nexthop-resolve\n");
}

void zebra_pbr_expand_action_update(bool enable)
{
	zebra_pbr_expand_action = enable;
}

static void zebra_pbr_expand_rule(struct zebra_pbr_rule *rule)
{
	struct prefix p;
	struct route_table *table;
	struct route_node *rn;
	rib_dest_t *dest;
	struct route_entry *re;
	const struct nexthop_group *nhg;
	const struct nexthop *nexthop;
	struct zebra_pbr_action *action = &rule->action;
	struct ipaddr ip;

	if (!zebra_pbr_expand_action)
		return;

	table = zebra_vrf_get_table_with_table_id(
		AFI_IP, SAFI_UNICAST, VRF_DEFAULT, rule->rule.action.table);
	if (!table)
		return;

	memset(&p, 0, sizeof(p));
	p.family = AF_INET;

	rn = route_node_lookup(table, &p);
	if (!rn)
		return;

	dest = rib_dest_from_rnode(rn);
	re = dest->selected_fib;
	if (!re) {
		route_unlock_node(rn);
		return;
	}

	nhg = rib_get_fib_nhg(re);
	if (!nhg) {
		route_unlock_node(rn);
		return;
	}

	nexthop = nhg->nexthop;
	if (nexthop) {
		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			action->afi = AFI_IP;
			action->gate.ipv4 = nexthop->gate.ipv4;
			action->ifindex = nexthop->ifindex;
			ip.ipa_type = AF_INET;
			ip.ipaddr_v4 = action->gate.ipv4;
			zebra_neigh_ref(action->ifindex, &ip, rule);
			break;

		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			action->afi = AFI_IP6;
			action->gate.ipv6 = nexthop->gate.ipv6;
			action->ifindex = nexthop->ifindex;
			ip.ipa_type = AF_INET6;
			ip.ipaddr_v6 = action->gate.ipv6;
			zebra_neigh_ref(action->ifindex, &ip, rule);
			break;

		case NEXTHOP_TYPE_BLACKHOLE:
		case NEXTHOP_TYPE_IFINDEX:
			action->afi = AFI_UNSPEC;
		}
	}

	route_unlock_node(rn);
}

void zebra_pbr_add_rule(struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *found;
	struct zebra_pbr_rule *old;
	struct zebra_pbr_rule *new;

	/**
	 * Check if we already have it (this checks via a unique ID, walking
	 * over the hash table, not via a hash operation).
	 */
	found = pbr_rule_lookup_unique(rule);

	/* If found, this is an update */
	if (found) {
		if (IS_ZEBRA_DEBUG_PBR)
			zlog_debug(
				"%s: seq: %d, prior: %d, unique: %d, ifname: %s -- update",
				__func__, rule->rule.seq, rule->rule.priority,
				rule->rule.unique, rule->rule.ifname);

		/* remove the old entry from the hash but don't free the hash
		 * data yet as we need it for the dplane update
		 */
		old = pbr_rule_release(found, false);

		/* insert new entry into hash */
		new = hash_get(zrouter.rules_hash, rule, pbr_rule_alloc_intern);
		/* expand the action if needed */
		zebra_pbr_expand_rule(new);
		/* update dataplane */
		(void)dplane_pbr_rule_update(found, new);
		/* release the old hash data */
		if (old)
			XFREE(MTYPE_PBR_OBJ, old);
	} else {
		if (IS_ZEBRA_DEBUG_PBR)
			zlog_debug(
				"%s: seq: %d, prior: %d, unique: %d, ifname: %s -- new",
				__func__, rule->rule.seq, rule->rule.priority,
				rule->rule.unique, rule->rule.ifname);

		/* insert new entry into hash */
		new = hash_get(zrouter.rules_hash, rule, pbr_rule_alloc_intern);
		/* expand the action if needed */
		zebra_pbr_expand_rule(new);
		(void)dplane_pbr_rule_add(new);
	}

}

void zebra_pbr_del_rule(struct zebra_pbr_rule *rule)
{
	if (IS_ZEBRA_DEBUG_PBR)
		zlog_debug("%s: seq: %d, prior: %d, unique: %d, ifname: %s",
			   __func__, rule->rule.seq, rule->rule.priority,
			   rule->rule.unique, rule->rule.ifname);

	(void)dplane_pbr_rule_delete(rule);

	if (pbr_rule_release(rule, true))
		zlog_debug("%s: Rule being deleted we know nothing about",
			   __func__);
}

void zebra_pbr_process_iptable(struct zebra_dplane_ctx *ctx)
{
	int mode, ret = 0;
	struct zebra_pbr_iptable ipt;

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_IPTABLE_ADD)
		mode = 1;
	else
		mode = 0;

	dplane_ctx_get_pbr_iptable(ctx, &ipt);

	ret = hook_call(zebra_pbr_iptable_update, mode, &ipt);
	if (ret)
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
	else
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
}

void zebra_pbr_process_ipset(struct zebra_dplane_ctx *ctx)
{
	int mode, ret = 0;
	struct zebra_pbr_ipset ipset;

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_IPSET_ADD)
		mode = 1;
	else
		mode = 0;

	dplane_ctx_get_pbr_ipset(ctx, &ipset);

	ret = hook_call(zebra_pbr_ipset_update, mode, &ipset);
	if (ret)
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
	else
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
}

void zebra_pbr_process_ipset_entry(struct zebra_dplane_ctx *ctx)
{
	int mode, ret = 0;
	struct zebra_pbr_ipset_entry ipset_entry;
	struct zebra_pbr_ipset ipset;

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_IPSET_ENTRY_ADD)
		mode = 1;
	else
		mode = 0;

	dplane_ctx_get_pbr_ipset_entry(ctx, &ipset_entry);
	dplane_ctx_get_pbr_ipset(ctx, &ipset);

	ipset_entry.backpointer = &ipset;

	ret = hook_call(zebra_pbr_ipset_entry_update, mode, &ipset_entry);
	if (ret)
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
	else
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
}

static void zebra_pbr_cleanup_rules(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_rule *rule = b->data;
	int *sock = data;

	if (rule->sock == *sock) {
		(void)dplane_pbr_rule_delete(rule);
		pbr_rule_free(rule, true);
	}
}

static void zebra_pbr_cleanup_ipset(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_ipset *ipset = b->data;
	int *sock = data;

	if (ipset->sock == *sock) {
		if (hash_release(zrouter.ipset_hash, ipset))
			zebra_pbr_ipset_free(ipset);
		else
			hook_call(zebra_pbr_ipset_update, 0, ipset);
	}
}

static void zebra_pbr_cleanup_ipset_entry(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_ipset_entry *ipset = b->data;
	int *sock = data;

	if (ipset->sock == *sock) {
		if (hash_release(zrouter.ipset_entry_hash, ipset))
			zebra_pbr_ipset_entry_free(ipset);
		else
			hook_call(zebra_pbr_ipset_entry_update, 0, ipset);
	}
}

static void zebra_pbr_cleanup_iptable(struct hash_bucket *b, void *data)
{
	struct zebra_pbr_iptable *iptable = b->data;
	int *sock = data;

	if (iptable->sock == *sock) {
		if (hash_release(zrouter.iptable_hash, iptable))
			_zebra_pbr_iptable_free_all(iptable, true);
		else
			hook_call(zebra_pbr_iptable_update, 0, iptable);
	}
}

static int zebra_pbr_client_close_cleanup(struct zserv *client)
{
	int sock = client->sock;

	if (!sock)
		return 0;
	hash_iterate(zrouter.rules_hash, zebra_pbr_cleanup_rules, &sock);
	hash_iterate(zrouter.iptable_hash, zebra_pbr_cleanup_iptable, &sock);
	hash_iterate(zrouter.ipset_entry_hash, zebra_pbr_cleanup_ipset_entry,
		     &sock);
	hash_iterate(zrouter.ipset_hash, zebra_pbr_cleanup_ipset, &sock);
	return 1;
}

void zebra_pbr_init(void)
{
	hook_register(zserv_client_close, zebra_pbr_client_close_cleanup);
}

static void *pbr_ipset_alloc_intern(void *arg)
{
	struct zebra_pbr_ipset *zpi;
	struct zebra_pbr_ipset *new;

	zpi = (struct zebra_pbr_ipset *)arg;

	new = XCALLOC(MTYPE_PBR_OBJ, sizeof(struct zebra_pbr_ipset));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_create_ipset(struct zebra_pbr_ipset *ipset)
{
	(void)hash_get(zrouter.ipset_hash, ipset, pbr_ipset_alloc_intern);
	(void)dplane_pbr_ipset_add(ipset);
}

void zebra_pbr_destroy_ipset(struct zebra_pbr_ipset *ipset)
{
	struct zebra_pbr_ipset *lookup;

	lookup = hash_lookup(zrouter.ipset_hash, ipset);
	(void)dplane_pbr_ipset_delete(ipset);
	if (lookup) {
		hash_release(zrouter.ipset_hash, lookup);
		XFREE(MTYPE_PBR_OBJ, lookup);
	} else
		zlog_debug(
			"%s: IPSet Entry being deleted we know nothing about",
			__func__);
}

struct pbr_ipset_name_lookup {
	struct zebra_pbr_ipset *ipset;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};

const char *zebra_pbr_ipset_type2str(uint32_t type)
{
	return lookup_msg(ipset_type_msg, type,
			  "Unrecognized IPset Type");
}

static int zebra_pbr_ipset_pername_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct pbr_ipset_name_lookup *pinl =
		(struct pbr_ipset_name_lookup *)arg;
	struct zebra_pbr_ipset *zpi = (struct zebra_pbr_ipset *)bucket->data;

	if (!strncmp(pinl->ipset_name, zpi->ipset_name,
		     ZEBRA_IPSET_NAME_SIZE)) {
		pinl->ipset = zpi;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct zebra_pbr_ipset *zebra_pbr_lookup_ipset_pername(char *ipsetname)
{
	struct pbr_ipset_name_lookup pinl;
	struct pbr_ipset_name_lookup *ptr = &pinl;

	if (!ipsetname)
		return NULL;
	memset(ptr, 0, sizeof(struct pbr_ipset_name_lookup));
	snprintf((char *)ptr->ipset_name, ZEBRA_IPSET_NAME_SIZE, "%s",
		ipsetname);
	hash_walk(zrouter.ipset_hash, zebra_pbr_ipset_pername_walkcb, ptr);
	return ptr->ipset;
}

static void *pbr_ipset_entry_alloc_intern(void *arg)
{
	struct zebra_pbr_ipset_entry *zpi;
	struct zebra_pbr_ipset_entry *new;

	zpi = (struct zebra_pbr_ipset_entry *)arg;

	new = XCALLOC(MTYPE_PBR_OBJ, sizeof(struct zebra_pbr_ipset_entry));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_add_ipset_entry(struct zebra_pbr_ipset_entry *ipset)
{
	(void)hash_get(zrouter.ipset_entry_hash, ipset,
		       pbr_ipset_entry_alloc_intern);
	(void)dplane_pbr_ipset_entry_add(ipset);
}

void zebra_pbr_del_ipset_entry(struct zebra_pbr_ipset_entry *ipset)
{
	struct zebra_pbr_ipset_entry *lookup;

	lookup = hash_lookup(zrouter.ipset_entry_hash, ipset);
	(void)dplane_pbr_ipset_entry_delete(ipset);
	if (lookup) {
		hash_release(zrouter.ipset_entry_hash, lookup);
		XFREE(MTYPE_PBR_OBJ, lookup);
	} else
		zlog_debug("%s: IPSet being deleted we know nothing about",
			   __func__);
}

static void *pbr_iptable_alloc_intern(void *arg)
{
	struct zebra_pbr_iptable *zpi;
	struct zebra_pbr_iptable *new;
	struct listnode *ln;
	char *ifname;

	zpi = (struct zebra_pbr_iptable *)arg;

	new = XCALLOC(MTYPE_PBR_OBJ, sizeof(struct zebra_pbr_iptable));

	/* Deep structure copy */
	memcpy(new, zpi, sizeof(*zpi));
	new->interface_name_list = list_new();

	if (zpi->interface_name_list) {
		for (ALL_LIST_ELEMENTS_RO(zpi->interface_name_list, ln, ifname))
			listnode_add(new->interface_name_list,
				     XSTRDUP(MTYPE_PBR_IPTABLE_IFNAME, ifname));
	}

	return new;
}

void zebra_pbr_add_iptable(struct zebra_pbr_iptable *iptable)
{
	struct zebra_pbr_iptable *ipt_hash;

	ipt_hash = hash_get(zrouter.iptable_hash, iptable,
			    pbr_iptable_alloc_intern);
	(void)dplane_pbr_iptable_add(ipt_hash);
}

void zebra_pbr_del_iptable(struct zebra_pbr_iptable *iptable)
{
	struct zebra_pbr_iptable *lookup;

	lookup = hash_lookup(zrouter.iptable_hash, iptable);
	(void)dplane_pbr_iptable_delete(iptable);
	if (lookup) {
		struct listnode *node, *nnode;
		char *name;

		hash_release(zrouter.iptable_hash, lookup);
		for (ALL_LIST_ELEMENTS(iptable->interface_name_list,
				       node, nnode, name)) {
			XFREE(MTYPE_PBR_IPTABLE_IFNAME, name);
			list_delete_node(iptable->interface_name_list,
					 node);
		}
		list_delete(&iptable->interface_name_list);
		XFREE(MTYPE_PBR_OBJ, lookup);
	} else
		zlog_debug("%s: IPTable being deleted we know nothing about",
			   __func__);
}

/*
 * Handle success or failure of rule (un)install in the kernel.
 */
void zebra_pbr_dplane_result(struct zebra_dplane_ctx *ctx)
{
	enum zebra_dplane_result res;
	enum dplane_op_e op;

	res = dplane_ctx_get_status(ctx);
	op = dplane_ctx_get_op(ctx);
	if (op == DPLANE_OP_RULE_ADD || op == DPLANE_OP_RULE_UPDATE)
		zsend_rule_notify_owner(ctx, res == ZEBRA_DPLANE_REQUEST_SUCCESS
						     ? ZAPI_RULE_INSTALLED
						     : ZAPI_RULE_FAIL_INSTALL);
	else if (op == DPLANE_OP_RULE_DELETE)
		zsend_rule_notify_owner(ctx, res == ZEBRA_DPLANE_REQUEST_SUCCESS
						     ? ZAPI_RULE_REMOVED
						     : ZAPI_RULE_FAIL_REMOVE);
	else if (op == DPLANE_OP_IPTABLE_ADD)
		zsend_iptable_notify_owner(ctx,
					   res == ZEBRA_DPLANE_REQUEST_SUCCESS
						? ZAPI_IPTABLE_INSTALLED
						: ZAPI_IPTABLE_FAIL_INSTALL);
	else if (op == DPLANE_OP_IPTABLE_DELETE)
		zsend_iptable_notify_owner(ctx,
					   res == ZEBRA_DPLANE_REQUEST_SUCCESS
						? ZAPI_IPTABLE_REMOVED
						: ZAPI_IPTABLE_FAIL_REMOVE);
	else if (op == DPLANE_OP_IPSET_ADD)
		zsend_ipset_notify_owner(ctx,
					 res == ZEBRA_DPLANE_REQUEST_SUCCESS
						 ? ZAPI_IPSET_INSTALLED
						 : ZAPI_IPSET_FAIL_INSTALL);
	else if (op == DPLANE_OP_IPSET_DELETE)
		zsend_ipset_notify_owner(ctx,
					 res == ZEBRA_DPLANE_REQUEST_SUCCESS
						 ? ZAPI_IPSET_REMOVED
						 : ZAPI_IPSET_FAIL_REMOVE);
	else if (op == DPLANE_OP_IPSET_ENTRY_ADD)
		zsend_ipset_entry_notify_owner(
			ctx, res == ZEBRA_DPLANE_REQUEST_SUCCESS
				     ? ZAPI_IPSET_ENTRY_INSTALLED
				     : ZAPI_IPSET_ENTRY_FAIL_INSTALL);
	else if (op == DPLANE_OP_IPSET_ENTRY_DELETE)
		zsend_ipset_entry_notify_owner(
			ctx, res == ZEBRA_DPLANE_REQUEST_SUCCESS
				     ? ZAPI_IPSET_ENTRY_REMOVED
				     : ZAPI_IPSET_ENTRY_FAIL_REMOVE);
	else
		flog_err(
			EC_ZEBRA_PBR_RULE_UPDATE,
			"Context received in pbr rule dplane result handler with incorrect OP code (%u)",
			op);
}

/*
 * Handle rule delete notification from kernel.
 */
int kernel_pbr_rule_del(struct zebra_pbr_rule *rule)
{
	return 0;
}

struct zebra_pbr_ipset_entry_unique_display {
	struct zebra_pbr_ipset *zpi;
	struct vty *vty;
	struct zebra_ns *zns;
};


static const char *zebra_pbr_prefix2str(union prefixconstptr pu,
					char *str, int size)
{
	const struct prefix *p = pu.p;
	char buf[PREFIX2STR_BUFFER];

	if ((p->family == AF_INET && p->prefixlen == IPV4_MAX_BITLEN)
	    || (p->family == AF_INET6 && p->prefixlen == IPV6_MAX_BITLEN)) {
		snprintf(str, size, "%s", inet_ntop(p->family, &p->u.prefix,
						    buf, PREFIX2STR_BUFFER));
		return str;
	}
	return prefix2str(pu, str, size);
}

static void zebra_pbr_display_icmp(struct vty *vty,
				   struct zebra_pbr_ipset_entry *zpie)
{
	char decoded_str[20];
	uint16_t port;
	struct zebra_pbr_ipset *zpi;

	zpi = zpie->backpointer;

	/* range icmp type */
	if (zpie->src_port_max || zpie->dst_port_max) {
		vty_out(vty, ":icmp:[type <%u:%u>;code <%u:%u>",
			zpie->src_port_min, zpie->src_port_max,
			zpie->dst_port_min, zpie->dst_port_max);
	} else {
		port = ((zpie->src_port_min << 8) & 0xff00) +
			(zpie->dst_port_min & 0xff);
		memset(decoded_str, 0, sizeof(decoded_str));
		snprintf(decoded_str, sizeof(decoded_str), "%u/%u",
			 zpie->src_port_min, zpie->dst_port_min);
		vty_out(vty, ":%s:%s",
			zpi->family == AF_INET6 ? "ipv6-icmp" : "icmp",
			lookup_msg(zpi->family == AF_INET6 ?
				   icmpv6_typecode_str : icmp_typecode_str,
				   port, decoded_str));
	}
}

static void zebra_pbr_display_port(struct vty *vty, uint32_t filter_bm,
			    uint16_t port_min, uint16_t port_max,
			    uint8_t proto)
{
	if (!(filter_bm & PBR_FILTER_IP_PROTOCOL)) {
		if (port_max)
			vty_out(vty, ":udp/tcp:%d-%d",
				port_min, port_max);
		else
			vty_out(vty, ":udp/tcp:%d",
				port_min);
	} else {
		if (port_max)
			vty_out(vty, ":proto %d:%d-%d",
				proto, port_min, port_max);
		else
			vty_out(vty, ":proto %d:%d",
				proto, port_min);
	}
}

static int zebra_pbr_show_ipset_entry_walkcb(struct hash_bucket *bucket,
					     void *arg)
{
	struct zebra_pbr_ipset_entry_unique_display *unique =
		(struct zebra_pbr_ipset_entry_unique_display *)arg;
	struct zebra_pbr_ipset *zpi = unique->zpi;
	struct vty *vty = unique->vty;
	struct zebra_pbr_ipset_entry *zpie =
		(struct zebra_pbr_ipset_entry *)bucket->data;
	uint64_t pkts = 0, bytes = 0;
	int ret = 0;

	if (zpie->backpointer != zpi)
		return HASHWALK_CONTINUE;

	if ((zpi->type == IPSET_NET_NET) ||
	    (zpi->type == IPSET_NET_PORT_NET)) {
		char buf[PREFIX_STRLEN];

		zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
		vty_out(vty, "\tfrom %s", buf);
		if (zpie->filter_bm & PBR_FILTER_SRC_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->src_port_min,
					       zpie->src_port_max,
					       zpie->proto);
		vty_out(vty, " to ");
		zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		if (zpie->filter_bm & PBR_FILTER_DST_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->dst_port_min,
					       zpie->dst_port_max,
					       zpie->proto);
		if (zpie->proto == IPPROTO_ICMP)
			zebra_pbr_display_icmp(vty, zpie);
	} else if ((zpi->type == IPSET_NET) ||
		   (zpi->type == IPSET_NET_PORT)) {
		char buf[PREFIX_STRLEN];

		if (zpie->filter_bm & PBR_FILTER_SRC_IP) {
			zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
			vty_out(vty, "\tfrom %s", buf);
		}
		if (zpie->filter_bm & PBR_FILTER_SRC_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->src_port_min,
					       zpie->src_port_max,
					       zpie->proto);
		if (zpie->filter_bm & PBR_FILTER_DST_IP) {
			zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
			vty_out(vty, "\tto %s", buf);
		}
		if (zpie->filter_bm & PBR_FILTER_DST_PORT &&
		    zpie->proto != IPPROTO_ICMP)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->dst_port_min,
					       zpie->dst_port_max,
					       zpie->proto);
		if (zpie->proto == IPPROTO_ICMP)
			zebra_pbr_display_icmp(vty, zpie);
	}
	vty_out(vty, " (%u)\n", zpie->unique);

	ret = hook_call(zebra_pbr_ipset_entry_get_stat, zpie, &pkts,
			&bytes);
	if (ret && pkts > 0)
		vty_out(vty, "\t pkts %" PRIu64 ", bytes %" PRIu64"\n",
			pkts, bytes);
	return HASHWALK_CONTINUE;
}

static int zebra_pbr_show_ipset_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_pbr_env_display *uniqueipset =
		(struct zebra_pbr_env_display *)arg;
	struct zebra_pbr_ipset *zpi = (struct zebra_pbr_ipset *)bucket->data;
	struct zebra_pbr_ipset_entry_unique_display unique;
	struct vty *vty = uniqueipset->vty;
	struct zebra_ns *zns = uniqueipset->zns;

	vty_out(vty, "IPset %s type %s family %s\n", zpi->ipset_name,
		zebra_pbr_ipset_type2str(zpi->type),
		family2str(zpi->family));
	unique.vty = vty;
	unique.zpi = zpi;
	unique.zns = zns;
	hash_walk(zrouter.ipset_entry_hash, zebra_pbr_show_ipset_entry_walkcb,
		  &unique);
	vty_out(vty, "\n");
	return HASHWALK_CONTINUE;
}

size_t zebra_pbr_tcpflags_snprintf(char *buffer, size_t len,
				   uint16_t tcp_val)
{
	size_t len_written = 0;
	static struct message nt = {0};
	const struct message *pnt;
	int incr = 0;

	for (pnt = tcp_value_str;
	     memcmp(pnt, &nt, sizeof(struct message)); pnt++)
		if (pnt->key & tcp_val) {
			len_written += snprintf(buffer + len_written,
						len - len_written,
						"%s%s", incr ?
						",":"", pnt->str);
			incr++;
		}
	return len_written;
}

/*
 */
void zebra_pbr_show_ipset_list(struct vty *vty, char *ipsetname)
{
	struct zebra_pbr_ipset *zpi;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_ipset_entry_unique_display unique;
	struct zebra_pbr_env_display uniqueipset;

	if (ipsetname) {
		zpi = zebra_pbr_lookup_ipset_pername(ipsetname);
		if (!zpi) {
			vty_out(vty, "No IPset %s found\n", ipsetname);
			return;
		}
		vty_out(vty, "IPset %s type %s family %s\n", ipsetname,
			zebra_pbr_ipset_type2str(zpi->type),
			family2str(zpi->family));
		unique.vty = vty;
		unique.zpi = zpi;
		unique.zns = zns;
		hash_walk(zrouter.ipset_entry_hash,
			  zebra_pbr_show_ipset_entry_walkcb, &unique);
		return;
	}
	uniqueipset.zns = zns;
	uniqueipset.vty = vty;
	uniqueipset.name = NULL;
	hash_walk(zrouter.ipset_hash, zebra_pbr_show_ipset_walkcb,
		  &uniqueipset);
}

struct pbr_rule_fwmark_lookup {
	struct zebra_pbr_rule *ptr;
	uint32_t fwmark;
};

static int zebra_pbr_rule_lookup_fwmark_walkcb(struct hash_bucket *bucket,
					       void *arg)
{
	struct pbr_rule_fwmark_lookup *iprule =
		(struct pbr_rule_fwmark_lookup *)arg;
	struct zebra_pbr_rule *zpr = (struct zebra_pbr_rule *)bucket->data;

	if (iprule->fwmark == zpr->rule.filter.fwmark) {
		iprule->ptr = zpr;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static void zebra_pbr_show_iptable_unit(struct zebra_pbr_iptable *iptable,
				       struct vty *vty,
				       struct zebra_ns *zns)
{
	int ret;
	uint64_t pkts = 0, bytes = 0;

	vty_out(vty, "IPtable %s family %s action %s (%u)\n",
		iptable->ipset_name,
		family2str(iptable->family),
		iptable->action == ZEBRA_IPTABLES_DROP ? "drop" : "redirect",
		iptable->unique);
	if (iptable->type == IPSET_NET_PORT ||
	    iptable->type == IPSET_NET_PORT_NET) {
		if (!(iptable->filter_bm & MATCH_ICMP_SET)) {
			if (iptable->filter_bm & PBR_FILTER_DST_PORT)
				vty_out(vty, "\t lookup dst port\n");
			else if (iptable->filter_bm & PBR_FILTER_SRC_PORT)
				vty_out(vty, "\t lookup src port\n");
		}
	}
	if (iptable->pkt_len_min || iptable->pkt_len_max) {
		if (!iptable->pkt_len_max)
			vty_out(vty, "\t pkt len %u\n",
				iptable->pkt_len_min);
		else
			vty_out(vty, "\t pkt len [%u;%u]\n",
				iptable->pkt_len_min,
				iptable->pkt_len_max);
	}
	if (iptable->tcp_flags || iptable->tcp_mask_flags) {
		char tcp_flag_str[64];
		char tcp_flag_mask_str[64];

		zebra_pbr_tcpflags_snprintf(tcp_flag_str,
					    sizeof(tcp_flag_str),
					    iptable->tcp_flags);
		zebra_pbr_tcpflags_snprintf(tcp_flag_mask_str,
					    sizeof(tcp_flag_mask_str),
					    iptable->tcp_mask_flags);
		vty_out(vty, "\t tcpflags [%s/%s]\n",
			tcp_flag_str, tcp_flag_mask_str);
	}
	if (iptable->filter_bm & (MATCH_DSCP_SET | MATCH_DSCP_INVERSE_SET)) {
		vty_out(vty, "\t dscp %s %d\n",
			iptable->filter_bm & MATCH_DSCP_INVERSE_SET ?
			"not" : "", iptable->dscp_value);
	}
	if (iptable->filter_bm & (MATCH_FLOW_LABEL_SET |
				  MATCH_FLOW_LABEL_INVERSE_SET)) {
		vty_out(vty, "\t flowlabel %s %d\n",
			iptable->filter_bm & MATCH_FLOW_LABEL_INVERSE_SET ?
			"not" : "", iptable->flow_label);
	}
	if (iptable->fragment) {
		char val_str[10];

		snprintf(val_str, sizeof(val_str), "%d", iptable->fragment);
		vty_out(vty, "\t fragment%s %s\n",
			iptable->filter_bm & MATCH_FRAGMENT_INVERSE_SET ?
			" not" : "", lookup_msg(fragment_value_str,
					       iptable->fragment, val_str));
	}
	if (iptable->protocol) {
		vty_out(vty, "\t protocol %d\n",
			iptable->protocol);
	}
	ret = hook_call(zebra_pbr_iptable_get_stat, iptable, &pkts,
			&bytes);
	if (ret && pkts > 0)
		vty_out(vty, "\t pkts %" PRIu64 ", bytes %" PRIu64"\n",
			pkts, bytes);
	if (iptable->action != ZEBRA_IPTABLES_DROP) {
		struct pbr_rule_fwmark_lookup prfl;

		prfl.fwmark = iptable->fwmark;
		prfl.ptr = NULL;
		hash_walk(zrouter.rules_hash,
			  &zebra_pbr_rule_lookup_fwmark_walkcb, &prfl);
		if (prfl.ptr) {
			struct zebra_pbr_rule *zpr = prfl.ptr;

			vty_out(vty, "\t table %u, fwmark %u\n",
				zpr->rule.action.table,
				prfl.fwmark);
		}
	}
}

static int zebra_pbr_show_iptable_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct zebra_pbr_iptable *iptable =
		(struct zebra_pbr_iptable *)bucket->data;
	struct zebra_pbr_env_display *env = (struct zebra_pbr_env_display *)arg;
	struct vty *vty = env->vty;
	struct zebra_ns *zns = env->zns;
	char *iptable_name = env->name;

	if (!iptable_name)
		zebra_pbr_show_iptable_unit(iptable, vty, zns);
	else if (!strncmp(iptable_name,
			  iptable->ipset_name,
			  ZEBRA_IPSET_NAME_SIZE))
		zebra_pbr_show_iptable_unit(iptable, vty, zns);
	return HASHWALK_CONTINUE;
}

void zebra_pbr_show_iptable(struct vty *vty, char *iptable_name)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_env_display env;

	env.vty = vty;
	env.zns = zns;
	env.name = iptable_name;
	hash_walk(zrouter.iptable_hash, zebra_pbr_show_iptable_walkcb, &env);
}

void zebra_pbr_iptable_update_interfacelist(struct stream *s,
					    struct zebra_pbr_iptable *zpi)
{
	uint32_t i = 0, index;
	struct interface *ifp;
	char *name;

	for (i = 0; i < zpi->nb_interface; i++) {
		STREAM_GETL(s, index);
		ifp = if_lookup_by_index(index, zpi->vrf_id);
		if (!ifp)
			continue;
		name = XSTRDUP(MTYPE_PBR_IPTABLE_IFNAME, ifp->name);
		listnode_add(zpi->interface_name_list, name);
	}
stream_failure:
	return;
}
