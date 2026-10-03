// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MLD packet handling implementation.
 * Copyright (C) 2024 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "lib/checksum.h"
#include "lib/linklist.h"
#include "pimd/pim6_mld.h"
#include "pimd/pim6_mld_packet.h"
#include "pimd/pim6_mld_protocol.h"
#include "pimd/pim_iface.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_memory.h"
#include "pimd/pimd.h"

/**
 * Minimum expected MTU to generate the multicast packets is the IPv6
 * recommendation of 1280 bytes (otherwise the underlying layer must
 * provide fragmentation/assembly).
 *
 * See "RFC 2460 Section 5. Packet Size Issues".
 */
static const size_t multicast_minimum_mtu = 1280;

/**
 * Headers in front of the MLD message: IPv6 header and the hop-by-hop
 * options header carrying the Router Alert (see "RFC 3810 Section 5").
 */
static const size_t mld_headers_size = 40 + 8;

DEFINE_MTYPE_STATIC(PIMD, PIM6_MLD_PACKET, "PIMv6 MLD generated packet");
DEFINE_MTYPE_STATIC(PIMD, PIM6_MLD_PACKET_GROUP, "PIMv6 MLD generated packet group");

struct mld_group_source {
	SLIST_ENTRY(mld_group_source) entry;

	struct in6_addr source;
};
SLIST_HEAD(mld_group_source_list, mld_group_source);

struct mld_group {
	SLIST_ENTRY(mld_group) entry;

	bool star_source;
	/*
	 * (MLDv2 leave only) Change to include mode with the listed sources:
	 * the ones still joined after leaving `(*,G)`.
	 */
	bool to_include;
	size_t source_count;
	struct in6_addr group;
	struct mld_group_source_list source_list;
};
SLIST_HEAD(mld_group_list, mld_group);

static struct mld_group_source *mld_group_source_get(struct mld_group *group,
						     const struct in6_addr *source)
{
	struct mld_group_source *group_source;

	if (pim_addr_is_any(*source)) {
		group->star_source = true;
		return NULL;
	}

	SLIST_FOREACH (group_source, &group->source_list, entry)
		if (pim_addr_cmp(*source, group_source->source) == 0)
			return group_source;

	group->source_count++;

	group_source = XCALLOC(MTYPE_PIM6_MLD_PACKET_GROUP, sizeof(struct mld_group_source));
	group_source->source = *source;
	SLIST_INSERT_HEAD(&group->source_list, group_source, entry);

	return group_source;
}

static struct mld_group *mld_group_get(struct mld_group_list *groups, const struct in6_addr *group)
{
	struct mld_group *mld_group;

	SLIST_FOREACH (mld_group, groups, entry)
		if (pim_addr_cmp(*group, mld_group->group) == 0)
			return mld_group;

	mld_group = XCALLOC(MTYPE_PIM6_MLD_PACKET_GROUP, sizeof(struct mld_group));
	mld_group->group = *group;
	SLIST_INSERT_HEAD(groups, mld_group, entry);

	return mld_group;
}

/**
 * Collects the static joins matching `source`/`group` into `group_list`.
 *
 * \param remaining if not `NULL`, gets the other static joins of `group`.
 */
static void mld_group_list_get(const struct in6_addr *source, const struct in6_addr *group,
			       const struct list *gm_list, struct mld_group_list *group_list,
			       struct mld_group *remaining)
{
	const struct gm_join *gm_join;
	const struct listnode *node;
	struct mld_group *mld_group;

	if (gm_list == NULL || list_isempty(gm_list))
		return;

	for (ALL_LIST_ELEMENTS_RO(gm_list, node, gm_join)) {
		if (group && pim_addr_cmp(*group, gm_join->group_addr))
			continue;
		if (source && pim_addr_cmp(*source, gm_join->source_addr)) {
			if (remaining)
				mld_group_source_get(remaining, &gm_join->source_addr);
			continue;
		}

		mld_group = mld_group_get(group_list, &gm_join->group_addr);
		mld_group_source_get(mld_group, &gm_join->source_addr);
	}
}

/** Releases the source list of `group`. */
static void mld_group_free_sources(struct mld_group *group)
{
	struct mld_group_source *group_source;

	while (!SLIST_EMPTY(&group->source_list)) {
		group_source = SLIST_FIRST(&group->source_list);
		SLIST_REMOVE(&group->source_list, group_source, mld_group_source, entry);
		XFREE(MTYPE_PIM6_MLD_PACKET_GROUP, group_source);
	}

	group->source_count = 0;
}

static void mld_group_list_free(struct mld_group_list *group_list)
{
	struct mld_group *group;

	while (!SLIST_EMPTY(group_list)) {
		group = SLIST_FIRST(group_list);

		mld_group_free_sources(group);
		SLIST_REMOVE(group_list, group, mld_group, entry);
		XFREE(MTYPE_PIM6_MLD_PACKET_GROUP, group);
	}
}

struct mld_packet_params {
	/** Selected packet source address */
	const struct in6_addr *packet_source;
	/** Packet list to append packets */
	struct mld_packet_list *list;
	/** Maximum packet size */
	size_t size;
	/** MLD version */
	enum gm_version version;
	/** Action type: `true` join, `false` leave */
	bool join;
	/** List of group/source to act on. */
	struct mld_group_list groups;
};

/**
 * Leaving a single static join must not leave what the group keeps joined:
 * the interface listening state is the union of all memberships (see "RFC
 * 3810 Section 4.2. Per-Interface State").
 *
 * \param params leave parameters, with the leaving join as the only entry.
 * \param remaining the other static joins of the same group.
 * \param source the leaving join source.
 */
static void mld_leave_adjust(struct mld_packet_params *params, struct mld_group *remaining,
			     const struct in6_addr *source)
{
	struct mld_group *group = SLIST_FIRST(&params->groups);

	/* Nothing else stays joined: plain leave. */
	if (group == NULL || (!remaining->star_source && remaining->source_count == 0))
		return;

	if (params->version == GM_MLDV2) {
		/* Leaving `(*,G)`: EXCLUDE{} becomes INCLUDE{remaining sources}. */
		if (pim_addr_is_any(*source)) {
			group->star_source = false;
			group->to_include = true;
			group->source_list = remaining->source_list;
			group->source_count = remaining->source_count;
			SLIST_INIT(&remaining->source_list);
			remaining->source_count = 0;
			return;
		}

		/* Leaving `(S,G)`: BLOCK{S}, unless `(*,G)` keeps S joined. */
		if (!remaining->star_source)
			return;
	}

	/* The group stays joined (MLDv1 has no sources): send nothing. */
	SLIST_REMOVE(&params->groups, group, mld_group, entry);
	mld_group_free_sources(group);
	XFREE(MTYPE_PIM6_MLD_PACKET_GROUP, group);
}

static struct mld_packet *mld_new_packet(struct mld_packet_params *params)
{
	struct mld_packet *packet;
	size_t packet_size = sizeof(struct mld_packet) + sizeof(struct ipv6_ph) + params->size;

	packet = XCALLOC(MTYPE_PIM6_MLD_PACKET, packet_size);
	SLIST_INSERT_HEAD(params->list, packet, entry);
	packet->max_size = params->size;

	packet->ip6 = (struct ipv6_ph *)packet->data;
	packet->icmp6 = (struct icmp6_plain_hdr *)&packet->data[sizeof(struct ipv6_ph)];
	packet->size = sizeof(struct icmp6_plain_hdr);
	packet->ip6->src = *params->packet_source;
	/* Pseudo header for the ICMPv6 checksum (the encapsulation is not). */
	packet->ip6->next_hdr = IPPROTO_ICMPV6;

	switch (params->version) {
	case GM_MLDV1:
		/*
		 * Reports go to the group (set by the caller) and Done to all
		 * routers, see "RFC 2710 Section 5. Node State Transition Diagram".
		 */
		if (params->join) {
			packet->icmp6->icmp6_type = ICMP6_MLD_V1_REPORT;
		} else {
			packet->icmp6->icmp6_type = ICMP6_MLD_V1_DONE;
			packet->ip6->dst = qpim_all_routers_addr;
		}

		packet->mldv1 = (struct mld_v1_pkt *)(packet->icmp6 + 1);
		packet->size += sizeof(struct mld_v1_pkt);
		break;
	case GM_MLDV2:
		/* See "RFC 3810 Section 5.2.14. Destination Addresses". */
		packet->ip6->dst = qpim_all_gmp_routers_addr;
		packet->icmp6->icmp6_type = ICMP6_MLD_V2_REPORT;
		packet->mldv2 = (struct mld_v2_report_hdr *)(packet->icmp6 + 1);
		packet->size += sizeof(struct mld_v2_report_hdr);
		break;

	case GM_NONE:
	default:
		break;
	}

	return packet;
}

static void mld_packet_finish(struct mld_packet *packet)
{
	packet->ip6->ulpl = htonl((uint32_t)packet->size);
	packet->icmp6->icmp6_cksum = in_cksum_with_ph6(packet->ip6, packet->icmp6, packet->size);
}

static inline bool mldv2_packet_group_fit(const struct mld_packet *packet)
{
	size_t total_size;

	total_size = sizeof(struct mld_v2_rec_hdr) + sizeof(struct in6_addr);
	if ((packet->size + total_size) > packet->max_size)
		return false;

	return true;
}

/**
 * Appends a multicast record to a MLDv2 report. The caller must make sure the
 * record header and at least one source fit (`mldv2_packet_group_fit`).
 *
 * \returns the first source that didn't fit (to continue in a new packet) or
 *          `NULL` when the record is complete.
 */
static const struct mld_group_source *
mldv2_packet_add_record(struct mld_packet *packet, bool join, const struct mld_group *group,
			const struct mld_group_source *source_head)
{
	const struct mld_group_source *source = NULL;
	struct mld_v2_rec_hdr *record;
	const uint16_t records_number = ntohs(packet->mldv2->n_records);
	/* (*,G) is EXCLUDE{} (join) or INCLUDE{} (leave): no sources. */
	const bool no_sources = group->star_source || group->source_count == 0;
	size_t source_index;

	packet->size += sizeof(struct mld_v2_rec_hdr);
	if (packet->cur_record)
		record = (struct mld_v2_rec_hdr *)packet->cur_record;
	else
		record = (struct mld_v2_rec_hdr *)(packet->mldv2 + 1);

	packet->mldv2->n_records = htons(records_number + 1);
	record->grp = group->group;
	if (group->to_include)
		record->type = MLD_RECTYPE_CHANGE_TO_INCLUDE;
	else if (join)
		record->type = no_sources ? MLD_RECTYPE_CHANGE_TO_EXCLUDE
					  : MLD_RECTYPE_ALLOW_NEW_SOURCES;
	else
		record->type = no_sources ? MLD_RECTYPE_CHANGE_TO_INCLUDE
					  : MLD_RECTYPE_BLOCK_OLD_SOURCES;

	source_index = 0;
	if (!no_sources) {
		if (source_head == NULL)
			source_head = SLIST_FIRST(&group->source_list);

		for (source = source_head; source; source = SLIST_NEXT(source, entry)) {
			if (packet->size + sizeof(struct in6_addr) > packet->max_size)
				break;

			record->srcs[source_index] = source->source;
			source_index++;
			packet->size += sizeof(struct in6_addr);
		}
	}

	record->n_src = htons((uint16_t)source_index);
	packet->cur_record = (uint8_t *)&record->srcs[source_index];

	return source;
}

static void mldv2_generate_packets(struct mld_packet_params *params)
{
	const struct mld_group_source *last_group_source = NULL;
	const struct mld_group *group;
	struct mld_packet *packet;

	/* Nothing to report: don't send an empty report. */
	if (SLIST_EMPTY(&params->groups))
		return;

	packet = mld_new_packet(params);

	SLIST_FOREACH (group, &params->groups, entry) {
		do {
			if (!mldv2_packet_group_fit(packet)) {
				mld_packet_finish(packet);
				packet = mld_new_packet(params);
			}

			last_group_source = mldv2_packet_add_record(packet, params->join, group,
								    last_group_source);
		} while (last_group_source);
	}

	mld_packet_finish(packet);
}

static void mldv1_generate_packets(struct mld_packet_params *params)
{
	struct mld_group *group;
	struct mld_packet *packet;
	struct mld_v1_pkt *mld;

	SLIST_FOREACH (group, &params->groups, entry) {
		packet = mld_new_packet(params);
		if (params->join)
			packet->ip6->dst = group->group;
		mld = packet->mldv1;
		mld->grp = group->group;
		mld_packet_finish(packet);
	}
}

static inline void mld_generate_packets(struct mld_packet_params *params)
{
	switch (params->version) {
	case GM_MLDV1:
		params->list = XCALLOC(MTYPE_PIM6_MLD_PACKET, sizeof(struct mld_packet_list));
		mldv1_generate_packets(params);
		break;
	case GM_MLDV2:
		params->list = XCALLOC(MTYPE_PIM6_MLD_PACKET, sizeof(struct mld_packet_list));
		mldv2_generate_packets(params);
		break;

	default:
	case GM_NONE:
		break;
	}

	if (params->list && SLIST_EMPTY(params->list))
		XFREE(MTYPE_PIM6_MLD_PACKET, params->list);
}

struct mld_packet_list *mld_generate_packet_list(const struct interface *interface, bool join,
						 const struct in6_addr *source,
						 const struct in6_addr *group)
{
	const struct pim_interface *pim_interface = interface->info;
	const bool single_leave = !join && source != NULL && group != NULL;
	struct mld_packet_params packet_params;
	struct mld_group remaining = {};

	memset(&packet_params, 0, sizeof(packet_params));
	packet_params.join = join;
	packet_params.version = (enum gm_version)pim_interface->mld_version;
	packet_params.packet_source = &pim_interface->ll_lowest;

	/* MLD messages must come from a link-local address: wait for one. */
	if (IN6_IS_ADDR_UNSPECIFIED(packet_params.packet_source))
		return NULL;

	if (interface->mtu6 < multicast_minimum_mtu) {
		/* Generated on every query: don't flood the logs. */
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("Interface %s IPv6 MTU is too low (%u bytes)", interface->name,
				   interface->mtu6);
		packet_params.size = multicast_minimum_mtu - mld_headers_size;
	} else {
		/* The IPv6 payload length field limits the packet too. */
		packet_params.size = MIN(interface->mtu6, UINT16_MAX + sizeof(struct ip6_hdr)) -
				     mld_headers_size;
	}

	mld_group_list_get(source, group, pim_interface->gm_join_list, &packet_params.groups,
			   single_leave ? &remaining : NULL);
	if (single_leave)
		mld_leave_adjust(&packet_params, &remaining, source);
	mld_group_free_sources(&remaining);

	mld_generate_packets(&packet_params);
	mld_group_list_free(&packet_params.groups);

	return packet_params.list;
}

void mld_free_packet_list(struct mld_packet_list *packet_list)
{
	struct mld_packet *packet;

	while (!SLIST_EMPTY(packet_list)) {
		packet = SLIST_FIRST(packet_list);
		SLIST_REMOVE(packet_list, packet, mld_packet, entry);
		XFREE(MTYPE_PIM6_MLD_PACKET, packet);
	}

	XFREE(MTYPE_PIM6_MLD_PACKET, packet_list);
}
