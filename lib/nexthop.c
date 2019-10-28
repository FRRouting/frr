/* A generic nexthop structure
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "prefix.h"
#include "nexthop.h"
#include "mpls.h"
#include "jhash.h"
#include "printfrr.h"

DEFINE_MTYPE_STATIC(LIB, NEXTHOP, "Nexthop")
DEFINE_MTYPE_STATIC(LIB, NH_LABEL, "Nexthop label")

static int _nexthop_labels_cmp(const struct nexthop *nh1,
			       const struct nexthop *nh2)
{
	const struct mpls_label_stack *nhl1 = NULL;
	const struct mpls_label_stack *nhl2 = NULL;

	nhl1 = nh1->nh_label;
	nhl2 = nh2->nh_label;

	/* No labels is a match */
	if (!nhl1 && !nhl2)
		return 0;

	if (nhl1 && !nhl2)
		return 1;

	if (nhl2 && !nhl1)
		return -1;

	if (nhl1->num_labels > nhl2->num_labels)
		return 1;

	if (nhl1->num_labels < nhl2->num_labels)
		return -1;

	return memcmp(nhl1->label, nhl2->label, nhl1->num_labels);
}

int nexthop_g_addr_cmp(enum nexthop_types_t type, const union g_addr *addr1,
		       const union g_addr *addr2)
{
	int ret = 0;

	switch (type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		ret = IPV4_ADDR_CMP(&addr1->ipv4, &addr2->ipv4);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		ret = IPV6_ADDR_CMP(&addr1->ipv6, &addr2->ipv6);
		break;
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		/* No addr here */
		break;
	}

	return ret;
}

static int _nexthop_gateway_cmp(const struct nexthop *nh1,
				const struct nexthop *nh2)
{
	return nexthop_g_addr_cmp(nh1->type, &nh1->gate, &nh2->gate);
}

static int _nexthop_source_cmp(const struct nexthop *nh1,
			       const struct nexthop *nh2)
{
	return nexthop_g_addr_cmp(nh1->type, &nh1->src, &nh2->src);
}

static int _nexthop_cmp_no_labels(const struct nexthop *next1,
				  const struct nexthop *next2)
{
	int ret = 0;

	if (next1->vrf_id < next2->vrf_id)
		return -1;

	if (next1->vrf_id > next2->vrf_id)
		return 1;

	if (next1->type < next2->type)
		return -1;

	if (next1->type > next2->type)
		return 1;

	switch (next1->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV6:
		ret = _nexthop_gateway_cmp(next1, next2);
		if (ret != 0)
			return ret;
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		ret = _nexthop_gateway_cmp(next1, next2);
		if (ret != 0)
			return ret;
		/* Intentional Fall-Through */
	case NEXTHOP_TYPE_IFINDEX:
		if (next1->ifindex < next2->ifindex)
			return -1;

		if (next1->ifindex > next2->ifindex)
			return 1;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		if (next1->bh_type < next2->bh_type)
			return -1;

		if (next1->bh_type > next2->bh_type)
			return 1;
		break;
	}

	ret = _nexthop_source_cmp(next1, next2);

	return ret;
}

int nexthop_cmp(const struct nexthop *next1, const struct nexthop *next2)
{
	int ret = 0;

	ret = _nexthop_cmp_no_labels(next1, next2);
	if (ret != 0)
		return ret;

	ret = _nexthop_labels_cmp(next1, next2);

	return ret;
}

int nexthop_same_firsthop(struct nexthop *next1, struct nexthop *next2)
{
	int type1 = NEXTHOP_FIRSTHOPTYPE(next1->type);
	int type2 = NEXTHOP_FIRSTHOPTYPE(next2->type);

	if (type1 != type2)
		return 0;
	switch (type1) {
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		if (!IPV4_ADDR_SAME(&next1->gate.ipv4, &next2->gate.ipv4))
			return 0;
		if (next1->ifindex != next2->ifindex)
			return 0;
		break;
	case NEXTHOP_TYPE_IFINDEX:
		if (next1->ifindex != next2->ifindex)
			return 0;
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (!IPV6_ADDR_SAME(&next1->gate.ipv6, &next2->gate.ipv6))
			return 0;
		if (next1->ifindex != next2->ifindex)
			return 0;
		break;
	default:
		/* do nothing */
		break;
	}
	return 1;
}

/*
 * nexthop_type_to_str
 */
const char *nexthop_type_to_str(enum nexthop_types_t nh_type)
{
	static const char *desc[] = {
		"none",		 "Directly connected",
		"IPv4 nexthop",  "IPv4 nexthop with ifindex",
		"IPv6 nexthop",  "IPv6 nexthop with ifindex",
		"Null0 nexthop",
	};

	return desc[nh_type];
}

/*
 * Check if the labels match for the 2 nexthops specified.
 */
bool nexthop_labels_match(const struct nexthop *nh1, const struct nexthop *nh2)
{
	if (_nexthop_labels_cmp(nh1, nh2) != 0)
		return false;

	return true;
}

struct nexthop *nexthop_new(void)
{
	return XCALLOC(MTYPE_NEXTHOP, sizeof(struct nexthop));
}

/* Free nexthop. */
void nexthop_free(struct nexthop *nexthop)
{
	nexthop_del_labels(nexthop);
	if (nexthop->resolved)
		nexthops_free(nexthop->resolved);
	XFREE(MTYPE_NEXTHOP, nexthop);
}

/* Frees a list of nexthops */
void nexthops_free(struct nexthop *nexthop)
{
	struct nexthop *nh, *next;

	for (nh = nexthop; nh; nh = next) {
		next = nh->next;
		nexthop_free(nh);
	}
}

bool nexthop_same(const struct nexthop *nh1, const struct nexthop *nh2)
{
	if (nh1 && !nh2)
		return false;

	if (!nh1 && nh2)
		return false;

	if (nh1 == nh2)
		return true;

	if (nexthop_cmp(nh1, nh2) != 0)
		return false;

	return true;
}

bool nexthop_same_no_labels(const struct nexthop *nh1,
			    const struct nexthop *nh2)
{
	if (nh1 && !nh2)
		return false;

	if (!nh1 && nh2)
		return false;

	if (nh1 == nh2)
		return true;

	if (_nexthop_cmp_no_labels(nh1, nh2) != 0)
		return false;

	return true;
}

/* Update nexthop with label information. */
void nexthop_add_labels(struct nexthop *nexthop, enum lsp_types_t type,
			uint8_t num_labels, mpls_label_t *label)
{
	struct mpls_label_stack *nh_label;
	int i;

	nexthop->nh_label_type = type;
	nh_label = XCALLOC(MTYPE_NH_LABEL,
			   sizeof(struct mpls_label_stack)
				   + num_labels * sizeof(mpls_label_t));
	nh_label->num_labels = num_labels;
	for (i = 0; i < num_labels; i++)
		nh_label->label[i] = *(label + i);
	nexthop->nh_label = nh_label;
}

/* Free label information of nexthop, if present. */
void nexthop_del_labels(struct nexthop *nexthop)
{
	if (nexthop->nh_label) {
		XFREE(MTYPE_NH_LABEL, nexthop->nh_label);
		nexthop->nh_label_type = ZEBRA_LSP_NONE;
	}
}

const char *nexthop2str(const struct nexthop *nexthop, char *str, int size)
{
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		snprintf(str, size, "if %u", nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		snprintf(str, size, "%s if %u", inet_ntoa(nexthop->gate.ipv4),
			 nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		snprintf(str, size, "%s if %u", inet6_ntoa(nexthop->gate.ipv6),
			 nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		snprintf(str, size, "blackhole");
		break;
	default:
		snprintf(str, size, "unknown");
		break;
	}

	return str;
}

/*
 * Iteration step for ALL_NEXTHOPS macro:
 * This is the tricky part. Check if `nexthop' has
 * NEXTHOP_FLAG_RECURSIVE set. If yes, this implies that `nexthop' has
 * at least one nexthop attached to `nexthop->resolved', which will be
 * the next one.
 *
 * If NEXTHOP_FLAG_RECURSIVE is not set, `nexthop' will progress in its
 * current chain. In case its current chain end is reached, it will move
 * upwards in the recursion levels and progress there. Whenever a step
 * forward in a chain is done, recursion will be checked again.
 * In a nustshell, it's equivalent to a pre-traversal order assuming that
 * left branch is 'resolved' and right branch is 'next':
 * https://en.wikipedia.org/wiki/Tree_traversal#/media/File:Sorted_binary_tree_preorder.svg
 */
struct nexthop *nexthop_next(const struct nexthop *nexthop)
{
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
		return nexthop->resolved;

	if (nexthop->next)
		return nexthop->next;

	for (struct nexthop *par = nexthop->rparent; par; par = par->rparent)
		if (par->next)
			return par->next;

	return NULL;
}

/* Return the next nexthop in the tree that is resolved and active */
struct nexthop *nexthop_next_active_resolved(const struct nexthop *nexthop)
{
	struct nexthop *next = nexthop_next(nexthop);

	while (next
	       && (CHECK_FLAG(next->flags, NEXTHOP_FLAG_RECURSIVE)
		   || !CHECK_FLAG(next->flags, NEXTHOP_FLAG_ACTIVE)))
		next = nexthop_next(next);

	return next;
}

unsigned int nexthop_level(struct nexthop *nexthop)
{
	unsigned int rv = 0;

	for (struct nexthop *par = nexthop->rparent; par; par = par->rparent)
		rv++;

	return rv;
}

/* Only hash word-sized things, let cmp do the rest. */
uint32_t nexthop_hash_quick(const struct nexthop *nexthop)
{
	uint32_t key = 0x45afe398;

	key = jhash_3words(nexthop->type, nexthop->vrf_id,
			   nexthop->nh_label_type, key);

	if (nexthop->nh_label) {
		int labels = nexthop->nh_label->num_labels;
		int i = 0;

		while (labels >= 3) {
			key = jhash_3words(nexthop->nh_label->label[i],
					   nexthop->nh_label->label[i + 1],
					   nexthop->nh_label->label[i + 2],
					   key);
			labels -= 3;
			i += 3;
		}

		if (labels >= 2) {
			key = jhash_2words(nexthop->nh_label->label[i],
					   nexthop->nh_label->label[i + 1],
					   key);
			labels -= 2;
			i += 2;
		}

		if (labels >= 1)
			key = jhash_1word(nexthop->nh_label->label[i], key);
	}

	key = jhash_2words(nexthop->ifindex,
			   CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ONLINK),
			   key);

	return key;
}


#define GATE_SIZE 4 /* Number of uint32_t words in struct g_addr */

/* For a more granular hash */
uint32_t nexthop_hash(const struct nexthop *nexthop)
{
	uint32_t gate_src_rmap_raw[GATE_SIZE * 3] = {};
	/* Get all the quick stuff */
	uint32_t key = nexthop_hash_quick(nexthop);

	assert(((sizeof(nexthop->gate) + sizeof(nexthop->src)
		 + sizeof(nexthop->rmap_src))
		/ 3)
	       == (GATE_SIZE * sizeof(uint32_t)));

	memcpy(gate_src_rmap_raw, &nexthop->gate, GATE_SIZE);
	memcpy(gate_src_rmap_raw + GATE_SIZE, &nexthop->src, GATE_SIZE);
	memcpy(gate_src_rmap_raw + (2 * GATE_SIZE), &nexthop->rmap_src,
	       GATE_SIZE);

	key = jhash2(gate_src_rmap_raw, (GATE_SIZE * 3), key);

	return key;
}

void nexthop_copy(struct nexthop *copy, const struct nexthop *nexthop,
		  struct nexthop *rparent)
{
	copy->vrf_id = nexthop->vrf_id;
	copy->ifindex = nexthop->ifindex;
	copy->type = nexthop->type;
	copy->flags = nexthop->flags;
	memcpy(&copy->gate, &nexthop->gate, sizeof(nexthop->gate));
	memcpy(&copy->src, &nexthop->src, sizeof(nexthop->src));
	memcpy(&copy->rmap_src, &nexthop->rmap_src, sizeof(nexthop->rmap_src));
	copy->rparent = rparent;
	if (nexthop->nh_label)
		nexthop_add_labels(copy, nexthop->nh_label_type,
				   nexthop->nh_label->num_labels,
				   &nexthop->nh_label->label[0]);
}

struct nexthop *nexthop_dup(const struct nexthop *nexthop,
			    struct nexthop *rparent)
{
	struct nexthop *new = nexthop_new();

	nexthop_copy(new, nexthop, rparent);
	return new;
}

/*
 * nexthop printing variants:
 *	%pNHvv
 *		via 1.2.3.4
 *		via 1.2.3.4, eth0
 *		is directly connected, eth0
 *		unreachable (blackhole)
 *	%pNHv
 *		1.2.3.4
 *		1.2.3.4, via eth0
 *		directly connected, eth0
 *		unreachable (blackhole)
 *	%pNHs
 *		nexthop2str()
 */
printfrr_ext_autoreg_p("NH", printfrr_nh)
static ssize_t printfrr_nh(char *buf, size_t bsz, const char *fmt,
			   int prec, const void *ptr)
{
	const struct nexthop *nexthop = ptr;
	struct fbuf fb = { .buf = buf, .pos = buf, .len = bsz - 1 };
	bool do_ifi = false;
	const char *s, *v_is = "", *v_via = "", *v_viaif = "via ";
	ssize_t ret = 3;

	switch (fmt[2]) {
	case 'v':
		if (fmt[3] == 'v') {
			v_is = "is ";
			v_via = "via ";
			v_viaif = "";
			ret++;
		}

		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			bprintfrr(&fb, "%s%pI4", v_via, &nexthop->gate.ipv4);
			do_ifi = true;
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			bprintfrr(&fb, "%s%pI6", v_via, &nexthop->gate.ipv6);
			do_ifi = true;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			bprintfrr(&fb, "%sdirectly connected, %s", v_is,
				ifindex2ifname(nexthop->ifindex,
					       nexthop->vrf_id));
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			switch (nexthop->bh_type) {
			case BLACKHOLE_REJECT:
				s = " (ICMP unreachable)";
				break;
			case BLACKHOLE_ADMINPROHIB:
				s = " (ICMP admin-prohibited)";
				break;
			case BLACKHOLE_NULL:
				s = " (blackhole)";
				break;
			default:
				s = "";
				break;
			}
			bprintfrr(&fb, "unreachable%s", s);
			break;
		default:
			break;
		}
		if (do_ifi && nexthop->ifindex)
			bprintfrr(&fb, ", %s%s", v_viaif, ifindex2ifname(
					nexthop->ifindex,
					nexthop->vrf_id));

		*fb.pos = '\0';
		return ret;
	case 's':
		nexthop2str(nexthop, buf, bsz);
		return 3;
	}
	return 0;
}
