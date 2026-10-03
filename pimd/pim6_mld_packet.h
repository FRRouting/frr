// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MLD packet handling implementation.
 * Copyright (C) 2024 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#ifndef PIM6_MLD_PACKET_H
#define PIM6_MLD_PACKET_H

#include <netinet/in.h>

#include <stdbool.h>

#include "lib/openbsd-queue.h"

/*
 * Data structures
 */
struct mld_packet {
	SLIST_ENTRY(mld_packet) entry;

	/** IPv6 pseudo header for checksum */
	struct ipv6_ph *ip6;

	/** ICMPv6 header pointer */
	struct icmp6_plain_hdr *icmp6;

	/** Current MLD header */
	union {
		struct mld_v1_pkt *mldv1;
		struct mld_v2_report_hdr *mldv2;
	};

	/** Current MLD record */
	uint8_t *cur_record;

	/** Packet maximum size */
	size_t max_size;
	/** Packet size */
	size_t size;
	/** Packet data */
	uint8_t data[];
};
SLIST_HEAD(mld_packet_list, mld_packet);

/* Forward declaration for struct in `pimd/pim_iface.h`. */
struct interface;

/*
 * Functions
 */

/**
 * Generates a packet list of pseudo-IPv6+ICMP+MLD to send.
 *
 * Returns `NULL` if no packets were generated.
 */
extern struct mld_packet_list *mld_generate_packet_list(const struct interface *interface,
							bool join, const struct in6_addr *source,
							const struct in6_addr *group);

/** Free memory allocated by generated packet list */
extern void mld_free_packet_list(struct mld_packet_list *packets);

#endif /* PIM6_MLD_PACKET_H */
