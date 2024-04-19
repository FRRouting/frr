// SPDX-License-Identifier: GPL-2.0-or-later
/* A generic nexthop structure
 * Copyright (C) 2013 Cumulus Networks, Inc.
 */
#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "prefix.h"
#include "nexthop.h"
#include "mpls.h"
#include "jhash.h"
#include "printfrr.h"
#include "vrf.h"
#include "nexthop_group.h"

DEFINE_MTYPE_STATIC(LIB, NEXTHOP, "Nexthop");
DEFINE_MTYPE_STATIC(LIB, NH_LABEL, "Nexthop label");
DEFINE_MTYPE_STATIC(LIB, NH_SRV6, "Nexthop srv6");

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

	return memcmp(nhl1->label, nhl2->label,
		      (nhl1->num_labels * sizeof(mpls_label_t)));
}

static int _nexthop_srv6_cmp(const struct nexthop *nh1,
			     const struct nexthop *nh2)
{
	int ret = 0;
	int i = 0;

	if (!nh1->nh_srv6 && !nh2->nh_srv6)
		return 0;

	if (nh1->nh_srv6 && !nh2->nh_srv6)
		return 1;

	if (!nh1->nh_srv6 && nh2->nh_srv6)
		return -1;

	if (nh1->nh_srv6->seg6local_action > nh2->nh_srv6->seg6local_action)
		return 1;

	if (nh2->nh_srv6->seg6local_action < nh1->nh_srv6->seg6local_action)
		return -1;

	ret = memcmp(&nh1->nh_srv6->seg6local_ctx,
		     &nh2->nh_srv6->seg6local_ctx,
		     sizeof(struct seg6local_context));
	if (ret != 0)
		return ret;

	if (!nh1->nh_srv6->seg6_segs && !nh2->nh_srv6->seg6_segs)
		return 0;

	if (!nh1->nh_srv6->seg6_segs && nh2->nh_srv6->seg6_segs)
		return -1;

	if (nh1->nh_srv6->seg6_segs && !nh2->nh_srv6->seg6_segs)
		return 1;

	if (nh1->nh_srv6->seg6_segs->num_segs !=
	    nh2->nh_srv6->seg6_segs->num_segs)
		return -1;

	for (i = 0; i < nh1->nh_srv6->seg6_segs->num_segs; i++) {
		ret = memcmp(&nh1->nh_srv6->seg6_segs->seg[i],
			     &nh2->nh_srv6->seg6_segs->seg[i],
			     sizeof(struct in6_addr));
		if (ret != 0)
			break;
	}

	return ret;
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

	if (next1->weight < next2->weight)
		return -1;

	if (next1->weight > next2->weight)
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
		fallthrough;
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

	if (next1->srte_color < next2->srte_color)
		return -1;
	if (next1->srte_color > next2->srte_color)
		return 1;

	ret = _nexthop_source_cmp(next1, next2);
	if (ret != 0)
		goto done;

	if (!CHECK_FLAG(next1->flags, NEXTHOP_FLAG_HAS_BACKUP) &&
	    !CHECK_FLAG(next2->flags, NEXTHOP_FLAG_HAS_BACKUP))
		return 0;

	if (!CHECK_FLAG(next1->flags, NEXTHOP_FLAG_HAS_BACKUP) &&
	    CHECK_FLAG(next2->flags, NEXTHOP_FLAG_HAS_BACKUP))
		return -1;

	if (CHECK_FLAG(next1->flags, NEXTHOP_FLAG_HAS_BACKUP) &&
	    !CHECK_FLAG(next2->flags, NEXTHOP_FLAG_HAS_BACKUP))
		return 1;

	if (next1->backup_num == 0 && next2->backup_num == 0)
		goto done;

	if (next1->backup_num < next2->backup_num)
		return -1;

	if (next1->backup_num > next2->backup_num)
		return 1;

	ret = memcmp(next1->backup_idx,
		     next2->backup_idx, next1->backup_num);

done:
	return ret;
}

int nexthop_cmp(const struct nexthop *next1, const struct nexthop *next2)
{
	int ret = 0;

	ret = _nexthop_cmp_no_labels(next1, next2);
	if (ret != 0)
		return ret;

	ret = _nexthop_labels_cmp(next1, next2);
	if (ret != 0)
		return ret;

	ret = _nexthop_srv6_cmp(next1, next2);

	return ret;
}

/*
 * More-limited comparison function used to detect duplicate
 * nexthops. This is used in places where we don't need the full
 * comparison of 'nexthop_cmp()'.
 */
int nexthop_cmp_basic(const struct nexthop *nh1,
		      const struct nexthop *nh2)
{
	int ret = 0;
	const struct mpls_label_stack *nhl1 = NULL;
	const struct mpls_label_stack *nhl2 = NULL;

	if (nh1 == NULL && nh2 == NULL)
		return 0;

	if (nh1 && !nh2)
		return 1;

	if (!nh1 && nh2)
		return -1;

	if (nh1->vrf_id < nh2->vrf_id)
		return -1;

	if (nh1->vrf_id > nh2->vrf_id)
		return 1;

	if (nh1->type < nh2->type)
		return -1;

	if (nh1->type > nh2->type)
		return 1;

	if (nh1->weight < nh2->weight)
		return -1;

	if (nh1->weight > nh2->weight)
		return 1;

	switch (nh1->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV6:
		ret = nexthop_g_addr_cmp(nh1->type, &nh1->gate, &nh2->gate);
		if (ret != 0)
			return ret;
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		ret = nexthop_g_addr_cmp(nh1->type, &nh1->gate, &nh2->gate);
		if (ret != 0)
			return ret;
		fallthrough;
	case NEXTHOP_TYPE_IFINDEX:
		if (nh1->ifindex < nh2->ifindex)
			return -1;

		if (nh1->ifindex > nh2->ifindex)
			return 1;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		if (nh1->bh_type < nh2->bh_type)
			return -1;

		if (nh1->bh_type > nh2->bh_type)
			return 1;
		break;
	}

	/* Compare source addr */
	ret = nexthop_g_addr_cmp(nh1->type, &nh1->src, &nh2->src);
	if (ret != 0)
		goto done;

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

	ret = memcmp(nhl1->label, nhl2->label,
		     (nhl1->num_labels * sizeof(mpls_label_t)));

done:
	return ret;
}

/*
 * nexthop_type_to_str
 */
const char *nexthop_type_to_str(enum nexthop_types_t nh_type)
{
	static const char *const desc[] = {
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
	struct nexthop *nh;

	nh = XCALLOC(MTYPE_NEXTHOP, sizeof(struct nexthop));

	/*
	 * Default the weight to 1 here for all nexthops.
	 * The linux kernel does some weird stuff with adding +1 to
	 * all nexthop weights it gets over netlink.
	 * To handle this, just default everything to 1 right from
	 * the beginning so we don't have to special case
	 * default weights in the linux netlink code.
	 *
	 * 1 should be a valid on all platforms anyway.
	 */
	nh->weight = 1;

	return nh;
}

/* Free nexthop. */
void nexthop_free(struct nexthop *nexthop)
{
	nexthop_del_labels(nexthop);
	nexthop_del_srv6_seg6local(nexthop);
	nexthop_del_srv6_seg6(nexthop);
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

/*
 * Allocate a new nexthop object and initialize it from various args.
 */
struct nexthop *nexthop_from_ifindex(ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IFINDEX;
	nexthop->ifindex = ifindex;
	nexthop->vrf_id = vrf_id;

	return nexthop;
}

struct nexthop *nexthop_from_ipv4(const struct in_addr *ipv4,
				  const struct in_addr *src,
				  vrf_id_t vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IPV4;
	nexthop->vrf_id = vrf_id;
	nexthop->gate.ipv4 = *ipv4;
	if (src)
		nexthop->src.ipv4 = *src;

	return nexthop;
}

struct nexthop *nexthop_from_ipv4_ifindex(const struct in_addr *ipv4,
					  const struct in_addr *src,
					  ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
	nexthop->vrf_id = vrf_id;
	nexthop->gate.ipv4 = *ipv4;
	if (src)
		nexthop->src.ipv4 = *src;
	nexthop->ifindex = ifindex;

	return nexthop;
}

struct nexthop *nexthop_from_ipv6(const struct in6_addr *ipv6,
				  vrf_id_t vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->vrf_id = vrf_id;
	nexthop->type = NEXTHOP_TYPE_IPV6;
	nexthop->gate.ipv6 = *ipv6;

	return nexthop;
}

struct nexthop *nexthop_from_ipv6_ifindex(const struct in6_addr *ipv6,
					  ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->vrf_id = vrf_id;
	nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
	nexthop->gate.ipv6 = *ipv6;
	nexthop->ifindex = ifindex;

	return nexthop;
}

struct nexthop *nexthop_from_blackhole(enum blackhole_type bh_type,
				       vrf_id_t nh_vrf_id)
{
	struct nexthop *nexthop;

	nexthop = nexthop_new();
	nexthop->vrf_id = nh_vrf_id;
	nexthop->type = NEXTHOP_TYPE_BLACKHOLE;
	nexthop->bh_type = bh_type;

	return nexthop;
}

/* Update nexthop with label information. */
void nexthop_add_labels(struct nexthop *nexthop, enum lsp_types_t ltype,
			uint8_t num_labels, const mpls_label_t *labels)
{
	struct mpls_label_stack *nh_label;
	int i;

	if (num_labels == 0)
		return;

	/* Enforce limit on label stack size */
	if (num_labels > MPLS_MAX_LABELS)
		num_labels = MPLS_MAX_LABELS;

	nexthop->nh_label_type = ltype;

	nh_label = XCALLOC(MTYPE_NH_LABEL,
			   sizeof(struct mpls_label_stack)
				   + num_labels * sizeof(mpls_label_t));
	nh_label->num_labels = num_labels;
	for (i = 0; i < num_labels; i++)
		nh_label->label[i] = *(labels + i);
	nexthop->nh_label = nh_label;
}

/* Free label information of nexthop, if present. */
void nexthop_del_labels(struct nexthop *nexthop)
{
	XFREE(MTYPE_NH_LABEL, nexthop->nh_label);
	nexthop->nh_label_type = ZEBRA_LSP_NONE;
}

void nexthop_add_srv6_seg6local(struct nexthop *nexthop, uint32_t action,
				const struct seg6local_context *ctx)
{
	if (action == ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
		return;

	if (!nexthop->nh_srv6)
		nexthop->nh_srv6 = XCALLOC(MTYPE_NH_SRV6,
					   sizeof(struct nexthop_srv6));

	nexthop->nh_srv6->seg6local_action = action;
	nexthop->nh_srv6->seg6local_ctx = *ctx;
}

void nexthop_del_srv6_seg6local(struct nexthop *nexthop)
{
	if (!nexthop->nh_srv6)
		return;

	if (nexthop->nh_srv6->seg6local_action == ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
		return;

	nexthop->nh_srv6->seg6local_action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;

	if (nexthop->nh_srv6->seg6_segs &&
	    (nexthop->nh_srv6->seg6_segs->num_segs == 0 ||
	     sid_zero(nexthop->nh_srv6->seg6_segs)))
		XFREE(MTYPE_NH_SRV6, nexthop->nh_srv6->seg6_segs);

	if (nexthop->nh_srv6->seg6_segs == NULL)
		XFREE(MTYPE_NH_SRV6, nexthop->nh_srv6);
}

void nexthop_add_srv6_seg6(struct nexthop *nexthop, const struct in6_addr *segs,
			   int num_segs)
{
	int i;

	if (!segs)
		return;

	if (!nexthop->nh_srv6)
		nexthop->nh_srv6 = XCALLOC(MTYPE_NH_SRV6,
					   sizeof(struct nexthop_srv6));

	/* Enforce limit on srv6 seg stack size */
	if (num_segs > SRV6_MAX_SIDS)
		num_segs = SRV6_MAX_SIDS;

	if (!nexthop->nh_srv6->seg6_segs) {
		nexthop->nh_srv6->seg6_segs =
			XCALLOC(MTYPE_NH_SRV6,
				sizeof(struct seg6_seg_stack) +
					num_segs * sizeof(struct in6_addr));
	}

	nexthop->nh_srv6->seg6_segs->num_segs = num_segs;

	for (i = 0; i < num_segs; i++)
		memcpy(&nexthop->nh_srv6->seg6_segs->seg[i], &segs[i],
		       sizeof(struct in6_addr));
}

void nexthop_del_srv6_seg6(struct nexthop *nexthop)
{
	if (!nexthop->nh_srv6)
		return;

	if (nexthop->nh_srv6->seg6local_action == ZEBRA_SEG6_LOCAL_ACTION_UNSPEC &&
			nexthop->nh_srv6->seg6_segs) {
		memset(nexthop->nh_srv6->seg6_segs->seg, 0,
		       sizeof(struct in6_addr) *
			       nexthop->nh_srv6->seg6_segs->num_segs);
		XFREE(MTYPE_NH_SRV6, nexthop->nh_srv6->seg6_segs);
	}
	XFREE(MTYPE_NH_SRV6, nexthop->nh_srv6);
}

const char *nexthop2str(const struct nexthop *nexthop, char *str, int size)
{
	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		snprintf(str, size, "if %u", nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		snprintfrr(str, size, "%pI4 if %u", &nexthop->gate.ipv4,
			   nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		snprintfrr(str, size, "%pI6 if %u", &nexthop->gate.ipv6,
			   nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		snprintf(str, size, "blackhole");
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

unsigned int nexthop_level(const struct nexthop *nexthop)
{
	unsigned int rv = 0;

	for (const struct nexthop *par = nexthop->rparent;
	     par; par = par->rparent)
		rv++;

	return rv;
}

/* Only hash word-sized things, let cmp do the rest. */
uint32_t nexthop_hash_quick(const struct nexthop *nexthop)
{
	uint32_t key = 0x45afe398;
	int i;

	key = jhash_3words(nexthop->type, nexthop->vrf_id,
			   nexthop->nh_label_type, key);

	if (nexthop->nh_label) {
		int labels = nexthop->nh_label->num_labels;

		i = 0;

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

	/* Include backup nexthops, if present */
	if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_HAS_BACKUP)) {
		int backups = nexthop->backup_num;

		i = 0;

		while (backups >= 3) {
			key = jhash_3words(nexthop->backup_idx[i],
					   nexthop->backup_idx[i + 1],
					   nexthop->backup_idx[i + 2], key);
			backups -= 3;
			i += 3;
		}

		while (backups >= 2) {
			key = jhash_2words(nexthop->backup_idx[i],
					   nexthop->backup_idx[i + 1], key);
			backups -= 2;
			i += 2;
		}

		if (backups >= 1)
			key = jhash_1word(nexthop->backup_idx[i], key);
	}

	if (nexthop->nh_srv6) {
		int segs_num = 0;
		int i = 0;

		if (nexthop->nh_srv6->seg6local_action !=
		    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC) {
			key = jhash_1word(nexthop->nh_srv6->seg6local_action,
					  key);
			key = jhash(&nexthop->nh_srv6->seg6local_ctx,
				    sizeof(nexthop->nh_srv6->seg6local_ctx),
				    key);
			if (nexthop->nh_srv6->seg6_segs)
				key = jhash(&nexthop->nh_srv6->seg6_segs->seg[0],
					    sizeof(struct in6_addr), key);
		} else {
			if (nexthop->nh_srv6->seg6_segs) {
				segs_num = nexthop->nh_srv6->seg6_segs->num_segs;
				while (segs_num >= 1) {
					key = jhash(&nexthop->nh_srv6->seg6_segs
							    ->seg[i],
						    sizeof(struct in6_addr),
						    key);
					segs_num -= 1;
					i += 1;
				}
			}
		}
	}

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

void nexthop_copy_no_recurse(struct nexthop *copy,
			     const struct nexthop *nexthop,
			     struct nexthop *rparent)
{
	copy->vrf_id = nexthop->vrf_id;
	copy->ifindex = nexthop->ifindex;
	copy->type = nexthop->type;
	copy->flags = nexthop->flags;
	copy->weight = nexthop->weight;

	assert(nexthop->backup_num < NEXTHOP_MAX_BACKUPS);
	copy->backup_num = nexthop->backup_num;
	if (copy->backup_num > 0)
		memcpy(copy->backup_idx, nexthop->backup_idx, copy->backup_num);

	copy->srte_color = nexthop->srte_color;
	memcpy(&copy->gate, &nexthop->gate, sizeof(nexthop->gate));
	memcpy(&copy->src, &nexthop->src, sizeof(nexthop->src));
	memcpy(&copy->rmap_src, &nexthop->rmap_src, sizeof(nexthop->rmap_src));
	memcpy(&copy->rmac, &nexthop->rmac, sizeof(nexthop->rmac));
	copy->rparent = rparent;
	if (nexthop->nh_label)
		nexthop_add_labels(copy, nexthop->nh_label_type,
				   nexthop->nh_label->num_labels,
				   &nexthop->nh_label->label[0]);

	if (nexthop->nh_srv6) {
		if (nexthop->nh_srv6->seg6local_action !=
		    ZEBRA_SEG6_LOCAL_ACTION_UNSPEC)
			nexthop_add_srv6_seg6local(copy,
				nexthop->nh_srv6->seg6local_action,
				&nexthop->nh_srv6->seg6local_ctx);
		if (nexthop->nh_srv6->seg6_segs &&
		    nexthop->nh_srv6->seg6_segs->num_segs &&
		    !sid_zero(nexthop->nh_srv6->seg6_segs))
			nexthop_add_srv6_seg6(copy,
					      &nexthop->nh_srv6->seg6_segs->seg[0],
					      nexthop->nh_srv6->seg6_segs
						      ->num_segs);
	}
}

void nexthop_copy(struct nexthop *copy, const struct nexthop *nexthop,
		  struct nexthop *rparent)
{
	nexthop_copy_no_recurse(copy, nexthop, rparent);

	/* Bit of a special case here, we need to handle the case
	 * of a nexthop resolving to a group. Hence, we need to
	 * use a nexthop_group API.
	 */
	if (CHECK_FLAG(copy->flags, NEXTHOP_FLAG_RECURSIVE))
		copy_nexthops(&copy->resolved, nexthop->resolved, copy);
}

struct nexthop *nexthop_dup_no_recurse(const struct nexthop *nexthop,
				       struct nexthop *rparent)
{
	struct nexthop *new = nexthop_new();

	nexthop_copy_no_recurse(new, nexthop, rparent);
	return new;
}

struct nexthop *nexthop_dup(const struct nexthop *nexthop,
			    struct nexthop *rparent)
{
	struct nexthop *new = nexthop_new();

	nexthop_copy(new, nexthop, rparent);
	return new;
}

/*
 * Parse one or more backup index values, as comma-separated numbers,
 * into caller's array of uint8_ts. The array must be NEXTHOP_MAX_BACKUPS
 * in size. Mails back the number of values converted, and returns 0 on
 * success, <0 if an error in parsing.
 */
int nexthop_str2backups(const char *str, int *num_backups,
			uint8_t *backups)
{
	char *ostr;			  /* copy of string (start) */
	char *lstr;			  /* working copy of string */
	char *nump;			  /* pointer to next segment */
	char *endp;			  /* end pointer */
	int i, ret;
	uint8_t tmp[NEXTHOP_MAX_BACKUPS];
	uint32_t lval;

	/* Copy incoming string; the parse is destructive */
	lstr = ostr = XSTRDUP(MTYPE_TMP, str);
	*num_backups = 0;
	ret = 0;

	for (i = 0; i < NEXTHOP_MAX_BACKUPS && lstr; i++) {
		nump = strsep(&lstr, ",");
		lval = strtoul(nump, &endp, 10);

		/* Format check */
		if (*endp != '\0') {
			ret = -1;
			break;
		}

		/* Empty value */
		if (endp == nump) {
			ret = -1;
			break;
		}

		/* Limit to one octet */
		if (lval > 255) {
			ret = -1;
			break;
		}

		tmp[i] = lval;
	}

	/* Excess values */
	if (ret == 0 && i == NEXTHOP_MAX_BACKUPS && lstr)
		ret = -1;

	if (ret == 0) {
		*num_backups = i;
		memcpy(backups, tmp, i);
	}

	XFREE(MTYPE_TMP, ostr);

	return ret;
}

ssize_t printfrr_nhs(struct fbuf *buf, const struct nexthop *nexthop)
{
	ssize_t ret = 0;

	if (!nexthop)
		return bputs(buf, "(null)");

	switch (nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		ret += bprintfrr(buf, "if %u", nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		ret += bprintfrr(buf, "%pI4 if %u", &nexthop->gate.ipv4,
				 nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		ret += bprintfrr(buf, "%pI6 if %u", &nexthop->gate.ipv6,
				 nexthop->ifindex);
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		ret += bputs(buf, "blackhole");
		break;
	}

	ret += bprintfrr(buf, " vrfid %u", nexthop->vrf_id);
	return ret;
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
 *	%pNHcg
 *		1.2.3.4
 *		(0-length if no IP address present)
 *	%pNHci
 *		eth0
 *		(0-length if no interface present)
 */
printfrr_ext_autoreg_p("NH", printfrr_nh);
static ssize_t printfrr_nh(struct fbuf *buf, struct printfrr_eargs *ea,
			   const void *ptr)
{
	const struct nexthop *nexthop = ptr;
	bool do_ifi = false;
	const char *v_is = "", *v_via = "", *v_viaif = "via ";
	ssize_t ret = 0;

	switch (*ea->fmt) {
	case 'v':
		ea->fmt++;
		if (*ea->fmt == 'v') {
			v_is = "is ";
			v_via = "via ";
			v_viaif = "";
			ea->fmt++;
		}

		if (!nexthop)
			return bputs(buf, "(null)");

		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			ret += bprintfrr(buf, "%s%pI4", v_via,
					 &nexthop->gate.ipv4);
			do_ifi = true;
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			ret += bprintfrr(buf, "%s%pI6", v_via,
					 &nexthop->gate.ipv6);
			do_ifi = true;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			ret += bprintfrr(buf, "%sdirectly connected, %s", v_is,
					 ifindex2ifname(nexthop->ifindex,
							nexthop->vrf_id));
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			ret += bputs(buf, "unreachable");

			switch (nexthop->bh_type) {
			case BLACKHOLE_REJECT:
				ret += bputs(buf, " (ICMP unreachable)");
				break;
			case BLACKHOLE_ADMINPROHIB:
				ret += bputs(buf, " (ICMP admin-prohibited)");
				break;
			case BLACKHOLE_NULL:
				ret += bputs(buf, " (blackhole)");
				break;
			case BLACKHOLE_UNSPEC:
				break;
			}
			break;
		}
		if (do_ifi && nexthop->ifindex)
			ret += bprintfrr(buf, ", %s%s", v_viaif,
					 ifindex2ifname(nexthop->ifindex,
							nexthop->vrf_id));

		return ret;
	case 's':
		ea->fmt++;

		ret += printfrr_nhs(buf, nexthop);
		return ret;
	case 'c':
		ea->fmt++;
		if (*ea->fmt == 'g') {
			ea->fmt++;
			if (!nexthop)
				return bputs(buf, "(null)");
			switch (nexthop->type) {
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
				ret += bprintfrr(buf, "%pI4",
						 &nexthop->gate.ipv4);
				break;
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				ret += bprintfrr(buf, "%pI6",
						 &nexthop->gate.ipv6);
				break;
			case NEXTHOP_TYPE_IFINDEX:
			case NEXTHOP_TYPE_BLACKHOLE:
				break;
			}
		} else if (*ea->fmt == 'i') {
			ea->fmt++;
			if (!nexthop)
				return bputs(buf, "(null)");
			switch (nexthop->type) {
			case NEXTHOP_TYPE_IFINDEX:
				ret += bprintfrr(
					buf, "%s",
					ifindex2ifname(nexthop->ifindex,
						       nexthop->vrf_id));
				break;
			case NEXTHOP_TYPE_IPV4:
			case NEXTHOP_TYPE_IPV4_IFINDEX:
			case NEXTHOP_TYPE_IPV6:
			case NEXTHOP_TYPE_IPV6_IFINDEX:
				if (nexthop->ifindex)
					ret += bprintfrr(
						buf, "%s",
						ifindex2ifname(
							nexthop->ifindex,
							nexthop->vrf_id));
				break;
			case NEXTHOP_TYPE_BLACKHOLE:
				break;
			}
		}
		return ret;
	}
	return -1;
}

bool nexthop_is_blackhole(const struct nexthop *nh)
{
	return nh->type == NEXTHOP_TYPE_BLACKHOLE;
}
