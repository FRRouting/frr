// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IGMP packet handling implementation.
 * Copyright (C) 2022-2023 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#ifndef PIM_IGMP_PACKET_H
#define PIM_IGMP_PACKET_H

#include "lib/openbsd-queue.h"
#include "lib/network.h"

#include <stdint.h>
#include <stdlib.h>

/*
 * IGMP packet definitions
 */

/** IGMPv3 host endian all routers address (224.0.0.22). */
#define IGMPV3_ALL_ROUTERS_ADDRESS ((in_addr_t)0xE0000016)

/** IGMP version. */
enum igmp_version {
	IGMP_VERSION_1 = 1,
	IGMP_VERSION_2 = 2,
	IGMP_VERSION_3 = 3,
};

/** IGMP message types. */
enum igmp_message_type {
	IGMP_TYPE_QUERY = 0x11,
	IGMP_TYPE_MEMBERSHIP_REPORT_V1 = 0x12,
	IGMP_TYPE_MEMBERSHIP_REPORT_V2 = 0x16,
	IGMP_TYPE_LEAVE_GROUP = 0x17,
	IGMP_TYPE_MEMBERSHIP_REPORT_V3 = 0x22,
};

/** Multicast operation modes. */
enum multicast_record_type {
	MULTICAST_MODE_IS_INCLUDE = 1,
	MULTICAST_MODE_IS_EXCLUDE = 2,
	MULTICAST_MODE_CHANGE_TO_INCLUDE = 3,
	MULTICAST_MODE_CHANGE_TO_EXCLUDE = 4,
	MULTICAST_MODE_ALLOW_NEW_SOURCES = 5,
	MULTICAST_MODE_BLOCK_OLD_SOURCES = 6,
};

/** IGMP common header. */
struct igmp_header {
	/**
	 * IGMP message type: query, report (v1, v2, v3), leave (v2).
	 * See `igmp_message_type`.
	 */
	uint8_t type;
	/**
	 * Maximum response "code" (see below) for a report.
	 *
	 * When value is less than 128 then maximum response time is
	 * `code` / 10 of seconds.
	 *
	 * When value is >= 128 then the following formula:
	 *
	 *   +-+-----+-------+
	 *   |1| exp | mant  |
	 *   +-+-----+-------+
	 *          ||
	 *          V
	 *
	 *   Response time = (mantissa | 0x10) << (exponential + 3)
	 *
	 * This field is used in IGMP query, but not on other message types.
	 */
	uint8_t max_resp_code;
	/** 16bit one complement sum of all IGMP message. */
	uint16_t checksum;
};

/** IGMP v1 and v2 membership report header. */
struct igmp_membership_report {
	/** Common IGMP header. */
	struct igmp_header header;
	/** Multicast group address. */
	struct in_addr group;
};

/** IGMP version 3 query header. */
struct igmpv3_query {
	/** Common IGMP header. */
	struct igmp_header header;
	/** Group address. This is zero when sending general query. */
	struct in_addr group;
	/**
	 * Flags and querier robustness variable.
	 *
	 *       4    1   3
	 *   +-------+-+-----+
	 *   | Resv  |S| QRV |
	 *   +-------+-+-----+
	 */
	uint8_t flags;
	/**
	 * Queriers Query Interval code.
	 *
	 * Translates using same rule as `max_resp_code`.
	 */
	uint8_t qqic;
	/** Number of sources. */
	uint16_t sources_number;
	/** Source(s). */
	struct in_addr sources[];
};

/** Multicast record. */
struct igmpv3_multicast_record {
	/** Multicast record type. See `multicast_record_type`. */
	uint8_t type;
	/** Auxiliary data length. */
	uint8_t auxiliary_length;
	/** Number of sources. */
	uint16_t sources_number;
	/** Multicast address. */
	struct in_addr multicast_address;
	/** Source address(es). */
	struct in_addr sources[];
};

/** IGMP v3 report message. */
struct igmpv3_membership_report {
	/** Common IGMP header. */
	struct igmp_header header;
	/** Unused/reserved. */
	uint16_t reserved;
	/** Number of records. */
	uint16_t records_number;
	/** Multicast records. */
	struct igmpv3_multicast_record records[];
};

/*
 * IGMP functions
 */

/** Multicast IGMP source parameters. */
struct igmp_packet_group_source_params {
	SLIST_ENTRY(igmp_packet_group_source_params) entry;

	/** Source address. */
	struct in_addr source;
};
SLIST_HEAD(igmp_packet_group_source_params_list, igmp_packet_group_source_params);

/** Multicast IGMP group parameters. */
struct igmp_packet_group_params {
	SLIST_ENTRY(igmp_packet_group_params) entry;

	/** Group address. */
	struct in_addr group;
	/** Star source is true when one of the sources is `0.0.0.0`. */
	bool star_source;
	/**
	 * (IGMPv3 leave only) Change to include mode with the listed sources:
	 * the ones still joined after leaving `(*,G)`.
	 */
	bool to_include;
	/** Source list size. */
	size_t sources_number;
	/** Source list. */
	struct igmp_packet_group_source_params_list sources;
};
SLIST_HEAD(igmp_packet_group_params_list, igmp_packet_group_params);

/** IGMP packet parameters. */
struct igmp_packet_params {
	/** IGMP version packet to generate. */
	enum igmp_version version;
	/** IGMP groups list. */
	struct igmp_packet_group_params_list groups;
	/** IPv4 header source address. */
	struct in_addr source;
	/** Maximum payload size. */
	size_t maximum_size;
	/** Message type. `true` if join else `false` if leave. */
	bool join;
};

/** IGMP generated packet list. */
struct igmp_packet {
	SLIST_ENTRY(igmp_packet) entry;

	/** (IGMPv3 only) Current record position. */
	uint8_t *current_record;
	/** (IGMPv3 only) Current message size. */
	size_t current_size;

	/** Packet size. */
	size_t size;
	/** Packet data. */
	uint8_t data[];
};
SLIST_HEAD(igmp_packet_list, igmp_packet);

/* Forward declaration for struct in `pimd/pim_iface.h`. */
struct interface;

/**
 * Generates IGMP packet parameters for all multicast groups in the interface
 * static group list.
 *
 * The returned value is allocated and must be freed with `igmp_join_params_free`.
 *
 * \param pim_interface the interface to get information from.
 * \param join if `true` will generate IGMP join otherwise the leave
 *             equivalent.
 * \param source if non `NULL` will generate IGMP for specific source.
 * \param group if non `NULL` will generate IGMP for specific group.
 * \return IGMP packet parameters.
 */
extern struct igmp_packet_params *
pim_interface_generate_igmp_static_params(const struct interface *interface, bool join,
					  const struct in_addr *source,
					  const struct in_addr *group);

/** Releases resources allocated for IGMP join parameters. */
extern void igmp_join_params_free(struct igmp_packet_params *params);

/**
 * Generates a packet list of IPv4+IGMP to send.
 *
 * Returns `NULL` if there are no groups or nothing to send (IGMPv1 has no leave
 * message).
 */
extern struct igmp_packet_list *igmp_generate_packets(const struct igmp_packet_params *params);

/** Release resources allocated for packet list. */
extern void igmp_packet_list_free(struct igmp_packet_list *packets);

#endif /* PIM_IGMP_PACKET_H */
