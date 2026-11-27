// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Network library.
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <sys/un.h>

#include <fcntl.h>
#include "log.h"
#include "command.h"
#include "memory.h"
#include "monotime.h"
#include "network.h"
#include "lib_errors.h"
#include "checksum.h"
#include "openbsd-queue.h"
#include "frrevent.h"

/* Read nbytes from fd and store into ptr. */
int readn(int fd, uint8_t *ptr, int nbytes)
{
	int nleft;
	int nread;

	nleft = nbytes;

	while (nleft > 0) {
		nread = read(fd, ptr, nleft);

		if (nread < 0)
			return (nread);
		else if (nread == 0)
			break;

		nleft -= nread;
		ptr += nread;
	}

	return nbytes - nleft;
}

/* Write nbytes from ptr to fd. */
int writen(int fd, const uint8_t *ptr, int nbytes)
{
	int nleft;
	int nwritten;

	nleft = nbytes;

	while (nleft > 0) {
		nwritten = write(fd, ptr, nleft);

		if (nwritten < 0) {
			if (!ERRNO_IO_RETRY(errno))
				return nwritten;
		}
		if (nwritten == 0)
			return (nwritten);

		nleft -= nwritten;
		ptr += nwritten;
	}
	return nbytes - nleft;
}

int set_nonblocking(int fd)
{
	int flags;

	/* According to the Single UNIX Spec, the return value for F_GETFL
	   should
	   never be negative. */
	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "fcntl(F_GETFL) failed for fd %d: %s", fd,
			 safe_strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "fcntl failed setting fd %d non-blocking: %s", fd,
			 safe_strerror(errno));
		return -1;
	}
	return 0;
}

int set_cloexec(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFD, 0);
	if (flags == -1)
		return -1;

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1)
		return -1;
	return 0;
}

float htonf(float host)
{
	uint32_t lu1, lu2;
	float convert;

	memcpy(&lu1, &host, sizeof(uint32_t));
	lu2 = htonl(lu1);
	memcpy(&convert, &lu2, sizeof(uint32_t));
	return convert;
}

float ntohf(float net)
{
	return htonf(net);
}

uint64_t frr_sequence_next(void)
{
	static uint64_t last_sequence;
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	if (last_sequence == (uint64_t)ts.tv_sec) {
		last_sequence++;
		return last_sequence;
	}

	last_sequence = ts.tv_sec;
	return last_sequence;
}

uint32_t frr_sequence32_next(void)
{
	/* coverity[Y2K38_SAFETY] */
	return (uint32_t)frr_sequence_next();
}


/*
 * IPv4 fragmentation handling.
 */

DEFINE_MTYPE_STATIC(LIB, PACKET_FRAGMENT, "IP packet fragment");
DEFINE_MTYPE_STATIC(LIB, PACKET_DATA, "IP packet assembled data");

/**
 * A packet fragment holder data structure.
 *
 * NOTE: Fragments don't contain the IP header.
 */
struct packet_fragment {
	/** List pointer. */
	SLIST_ENTRY(packet_fragment) entry;
	/** Data offset. */
	uint16_t offset;
	/** Fragment size. */
	uint16_t size;
	/** Fragment data (allocated dinamically during *alloc). */
	uint8_t data[];
};

/** Packet fragment list definition. */
SLIST_HEAD(packet_fragment_list, packet_fragment);

/**
 * IP packet identification.
 *
 * In order for a fragment to belong to this packet it must match
 * the following criteria: it must have the same source address,
 * destination address, identification and protocol.
 *
 * RFC 791 Section 3.2. Discussion.
 */
struct ipv4_identification {
	/** Identification field. */
	uint16_t id;
	/** Protocol. */
	uint16_t protocol;
	/** Source address. */
	struct in_addr source;
	/** Destination address. */
	struct in_addr destination;
	/** Receiving interface index (the addresses are only unique within a VRF). */
	int32_t ifindex;
};

enum ip_packet_flag {
	/** Data structure is in use. */
	IP_PACKET_IN_USE = (1 << 0),
	/** Currently being used to assemble IPv4 packet. */
	IP_PACKET_IPV4 = (1 << 1),
	/** Packet is complete. */
	IP_PACKET_COMPLETE = (1 << 2),
	/**
	 * Ignore this packet:
	 * This packet has been flagged to be ignored for one on the reasons:
	 *  1. Its too fragmented so only account it once for statistics.
	 *  2. Its a huge packet and should not be accounted more than once.
	 *  3. Its a repeated packet.
	 *
	 *  The packet will be ignored until it ceases its activity and gets
	 *  cleaned up by the periodic timer.
	 */
	IP_PACKET_IGNORE = (1 << 3),
};

/**
 * Data structure that symbolizes the entire packet.
 *
 * It holds all fragments and can be used to build the whole packet.
 */
struct ip_packet {
	/** Packet identification. */
	struct ipv4_identification id;
	/** Amount of fragments. */
	uint16_t total_fragments;
	/** Data structure flags. \see ip_packet_flag. */
	uint16_t flags;
	/**
	 * Amount of payload data currently held in the fragments list.
	 *
	 * Payload only: the header is kept apart in `header`, so this can be
	 * compared against `total_size` directly.
	 */
	uint32_t current_size;
	/**
	 * Total payload size of the datagram.
	 *
	 * Only known (and only non zero) after the last fragment, the one
	 * without the more fragments bit, has been accepted.
	 */
	uint32_t total_size;
	/** Final header size. */
	uint32_t header_size;
	/** Final header contents, taken from the first fragment. */
	uint8_t header[IPV4_MAXIMUM_HEADER_SIZE];
	/** Fragments list. */
	struct packet_fragment_list fragments;
	/** Last access. */
	time_t last_usage;
	/** Packet complete data. */
	uint8_t *data;
	/** Clean up event for the assembled packet data. */
	struct event *cleanup_event;
};

/** Encapsulation ToS value. */
#define IPV4_ENCAP_TOS 0xC0
/** Encapsulation magic value. */
#define IP_ENCAP_MAGIC_VALUE 0x676F6C64


static struct ip_packet packet_list[PACKET_ASSEMBLY_IN_PROGRESS_MAX];
static struct event_loop *packet_event_loop;
static struct event *packet_cleanup_timer;
struct ip_packet_statistics ip_packet_stats;

/**
 * Statistic counters for IP assembly/fragmentation.
 */
struct ip_encap_packet_statistics {
	/** Invalid IP header version. */
	uint64_t invalid_version;
	/** Invalid header length: less than 5 octets (or 20 bytes). */
	uint64_t invalid_header_length;
	/** Invalid packet length: header says X but packet data is Y. */
	uint64_t invalid_packet_length;
	/** Invalid checksum. */
	uint64_t invalid_checksum;
	/** IP encapsulation fragment detected: no fragmentation used. */
	uint64_t fragmented;
	/** Invalid IP encapsulation version. */
	uint64_t invalid_encapsulation_version;
	/** Invalid IP encapsulation magic number. */
	uint64_t invalid_encapsulation_magic;
	/** Valid packets. */
	uint64_t valid_packets;
} ip_encap_packet_stats;

/** Free packet resources. */
static void ip_packet_reset(struct ip_packet *packet)
{
	struct packet_fragment *pf;

	event_cancel(&packet->cleanup_event);

	/* Free resources. */
	while ((pf = SLIST_FIRST(&packet->fragments)) != NULL) {
		SLIST_REMOVE(&packet->fragments, pf, packet_fragment, entry);
		XFREE(MTYPE_PACKET_FRAGMENT, pf);
	}
	XFREE(MTYPE_PACKET_DATA, packet->data);

	/* Reset variables. */
	memset(packet, 0, sizeof(*packet));
}

/** Clean up a packet after usage. */
static void ip_packet_cleanup_event(struct event *event)
{
	struct ip_packet *packet = EVENT_ARG(event);

	ip_packet_reset(packet);
}

/** Gets an existing context or an unused one. */
static struct ip_packet *ip_packet_find(const struct ipv4_header *ipv4, int32_t ifindex)
{
	struct ip_packet *packet = NULL;
	int first_available = -1;
	int index;

	for (index = 0; index < PACKET_ASSEMBLY_IN_PROGRESS_MAX; index++) {
		/* Figure out the first available slot or just skip. */
		if (!CHECK_FLAG(packet_list[index].flags, IP_PACKET_IN_USE)) {
			if (first_available != -1)
				continue;

			first_available = index;
			continue;
		}

		/* Skip used IPv6 packet. */
		if (!CHECK_FLAG(packet_list[index].flags, IP_PACKET_IPV4))
			continue;

		/* Match identification. */
		if (ipv4->id != packet_list[index].id.id)
			continue;
		if (ipv4->protocol != packet_list[index].id.protocol)
			continue;
		if (ipv4->source.s_addr != packet_list[index].id.source.s_addr)
			continue;
		if (ipv4->destination.s_addr != packet_list[index].id.destination.s_addr)
			continue;
		if (ifindex != packet_list[index].id.ifindex)
			continue;

		packet = &packet_list[index];
		break;
	}
	if (packet)
		return packet;

	if (first_available == -1)
		return NULL;

	/* Use the new context. */
	packet = &packet_list[first_available];
	packet->flags = IP_PACKET_IN_USE | IP_PACKET_IPV4;
	packet->id.id = ipv4->id;
	packet->id.protocol = ipv4->protocol;
	packet->id.source = ipv4->source;
	packet->id.destination = ipv4->destination;
	packet->id.ifindex = ifindex;

	return packet;
}

/**
 * Allocates memory for the whole packet and assemble it.
 *
 * \returns `true` when the packet was assembled, otherwise `false` when the
 *          fragment set turned out to be inconsistent.
 */
static bool ip_packet_assemble(struct ip_packet *packet)
{
	struct packet_fragment *pf, *pfn;
	struct ipv4_header *ipv4;

	/* Verification: every fragment must fit within the datagram */
	SLIST_FOREACH (pf, &packet->fragments, entry) {
		if (((uint32_t)pf->offset + pf->size) > packet->total_size)
			return false;
	}

	/* Allocate packet data and assemble it. */
	packet->data = XCALLOC(MTYPE_PACKET_DATA, packet->header_size + packet->total_size);
	memcpy(packet->data, packet->header, packet->header_size);
	SLIST_FOREACH_SAFE (pf, &packet->fragments, entry, pfn) {
		memcpy(packet->data + packet->header_size + pf->offset, pf->data, pf->size);

		SLIST_REMOVE(&packet->fragments, pf, packet_fragment, entry);
		XFREE(MTYPE_PACKET_FRAGMENT, pf);
	}

	/* Fix final IP header fields. */
	ipv4 = (struct ipv4_header *)packet->data;
	ipv4->total_length = htons((uint16_t)(packet->header_size + packet->total_size));
	ipv4->fragmentation = 0;
	ipv4->checksum = 0;
	ipv4->checksum = in_cksum(packet->data, packet->header_size);

	return true;
}

/**
 * Allocates memory for fragment and register it.
 *
 * \returns `IPA_OK` when the datagram got completed by this fragment,
 *          `IPA_OK_INCOMPLETE` when more fragments are still expected,
 *          otherwise the reason the fragment was rejected.
 */
static enum ip_packet_assemble_result ip_packet_add_fragment(struct ip_packet *packet,
							     uint16_t offset, bool more_fragments,
							     const void *data, uint16_t datalen)
{
	struct packet_fragment *pf;
	struct packet_fragment *pfpos, *pfprev;
	uint32_t offset_end = (uint32_t)offset + datalen;

	/*
	 * Find fragment position.
	 *
	 * Handling:
	 *
	 *  * Fragment already exists:
	 *    The fragment is probably duplicated. If we want to be paranoiac
	 *    we could `memcmp` the data to detect tampering attempts.
	 *
	 *  * Fragment overlaps:
	 *    abort, it is possible someone is trying to tamper with our data.
	 *
	 *  * First fragment:
	 *    Just accept it.
	 *
	 * `pfpos` is the current iteration position and `pflast` is the last
	 * greater element before current. So if `!pflast` insert at the
	 * head of the list, otherwise after `pflast`.
	 */
	pfpos = NULL;
	pfprev = NULL;
	SLIST_FOREACH (pfpos, &packet->fragments, entry) {
		/* Repeated fragment: do nothing. */
		if (pfpos->offset == offset) {
			ip_packet_stats.repeated_fragment++;
			return IPA_REPEATED_PACKET;
		}
		/* Higher offset, we want to insert before it. */
		if (pfpos->offset > offset)
			break;

		/* Keep the current position. */
		pfprev = pfpos;
		continue;
	}

	/*
	 * Detect overlaps and other inconsistencies.
	 *
	 * Both neighbors have to be checked: a fragment that only overlaps
	 * the one that follows it would otherwise be accepted and leave a
	 * hole somewhere else while still summing up to the expected size.
	 *
	 * All of these mean someone is either retransmitting with different
	 * bounds or trying to tamper with the data we assemble, so they are
	 * accounted together.
	 */
	if (pfprev && ((uint32_t)pfprev->offset + pfprev->size) > offset) {
		ip_packet_stats.fragment_overlap++;
		return IPA_FRAGMENT_OVERLAP;
	}
	if (pfpos && offset_end > pfpos->offset) {
		ip_packet_stats.fragment_overlap++;
		return IPA_FRAGMENT_OVERLAP;
	}

	/*
	 * The last fragment fixes the datagram size, so nothing may claim
	 * data past its end and nothing may follow it.
	 */
	if (packet->total_size && offset_end > packet->total_size) {
		ip_packet_stats.fragment_overlap++;
		return IPA_FRAGMENT_OVERLAP;
	}
	if (!more_fragments && pfpos) {
		ip_packet_stats.fragment_overlap++;
		return IPA_FRAGMENT_OVERLAP;
	}

	/*
	 * Detect packets that are quickly accumulating more than expected or
	 * that reach past the biggest datagram we are willing to assemble.
	 */
	if ((packet->current_size + datalen) > IPV4_MAXIMUM_PACKET_SIZE ||
	    offset_end > IPV4_MAXIMUM_PACKET_SIZE) {
		SET_FLAG(packet->flags, IP_PACKET_IGNORE);
		ip_packet_stats.huge_packets++;
		return IPA_PACKET_TOO_BIG;
	}

	/* Allocate resources. */
	pf = XCALLOC(MTYPE_PACKET_FRAGMENT, sizeof(*pf) + datalen);
	pf->offset = offset;
	pf->size = datalen;
	memcpy(pf->data, data, datalen);

	/* Insert item in the correct position. */
	if (pfprev)
		SLIST_INSERT_AFTER(pfprev, pf, entry);
	else
		SLIST_INSERT_HEAD(&packet->fragments, pf, entry);

	/* Update packet counters. */
	packet->total_fragments++;
	packet->current_size += datalen;
	if (!more_fragments)
		packet->total_size = offset_end;

	/*
	 * Check for completion.
	 *
	 * The fragments are known not to overlap and to all live inside
	 * `[0, total_size)`, so their sizes adding up to `total_size` means
	 * they tile the datagram exactly with no hole left.
	 */
	if (packet->header_size && packet->total_size &&
	    packet->total_size == packet->current_size) {
		/*
		 * The header counts towards the datagram size limit and its
		 * length is only known for sure once the first fragment has
		 * been seen, so the total is checked here.
		 */
		if ((packet->header_size + packet->total_size) > IPV4_MAXIMUM_PACKET_SIZE) {
			SET_FLAG(packet->flags, IP_PACKET_IGNORE);
			ip_packet_stats.huge_packets++;
			return IPA_PACKET_TOO_BIG;
		}

		if (!ip_packet_assemble(packet)) {
			SET_FLAG(packet->flags, IP_PACKET_IGNORE);
			ip_packet_stats.fragment_overlap++;
			return IPA_FRAGMENT_OVERLAP;
		}

		SET_FLAG(packet->flags, IP_PACKET_COMPLETE);
		ip_packet_stats.assembled_packets++;

		return IPA_OK;
	}

	return IPA_OK_INCOMPLETE;
}

enum ip_packet_assemble_result ipv4_packet_assemble(const uint8_t *data, size_t datalen,
						    int32_t ifindex, const uint8_t **packetp,
						    size_t *packetlen)
{
	const struct ipv4_header *ipv4 = (const struct ipv4_header *)data;
	struct ip_packet *packet;
	uint16_t fragment_length;
	uint16_t header_length;
	int checksum;

	*packetp = NULL;
	*packetlen = 0;

	/* Basic check: data size is at least the header. */
	if (datalen < sizeof(struct ipv4_header)) {
		ip_packet_stats.invalid_header_length++;
		return IPA_INVALID_HEADER_LENGTH;
	}

	/* Check version. */
	if (ipv4_version(ipv4) != 4) {
		ip_packet_stats.invalid_version++;
		return IPA_INVALID_VERSION;
	}

	/* Check header length. */
	header_length = (uint16_t)ipv4_header_length(ipv4);
	if (header_length < sizeof(struct ipv4_header) || header_length > datalen) {
		ip_packet_stats.invalid_header_length++;
		return IPA_INVALID_HEADER_LENGTH;
	}

	/* Verify checksum. */
	checksum = in_cksum(data, header_length);
	if (checksum) {
		ip_packet_stats.invalid_checksum++;
		return IPA_INVALID_CHECKSUM;
	}

	/* Check packet length. */
	fragment_length = ntohs(ipv4->total_length);
	if (datalen < fragment_length || fragment_length < header_length) {
		ip_packet_stats.invalid_packet_length++;
		return IPA_INVALID_LENGTH;
	}

	/*
	 * Check if this packet is fragmented.
	 *
	 * Only `fragment_length` bytes belong to this packet: the read may
	 * have returned more (e.g. link layer padding) and the caller must
	 * not be told to look at it.
	 */
	if (!ipv4_more_fragments(ipv4) && ipv4_fragment_offset(ipv4) == 0) {
		*packetp = data;
		*packetlen = fragment_length;
		ip_packet_stats.whole_packets++;
		return IPA_NOT_FRAGMENTED;
	}

	/*
	 * From here on the packet claims to be a fragment. Reject the ones
	 * whose fragmentation fields don't make sense:
	 *
	 *  * `DF` (don't fragment) together with `MF` (more fragments) or a
	 *    non zero offset is contradictory. Such a packet was mangled or
	 *    crafted, and treating it as whole would make the caller parse
	 *    fragment payload as protocol headers.
	 *
	 *  * A fragment without payload would take up the offset slot in the
	 *    fragment list and lock out the real fragment for that offset,
	 *    which would then be seen as a repeat.
	 */
	if (ipv4_dont_fragment(ipv4) || fragment_length == header_length) {
		ip_packet_stats.invalid_fragmentation++;
		return IPA_INVALID_FRAGMENTATION;
	}

	/* Find an existing context or start a new one. */
	packet = ip_packet_find(ipv4, ifindex);
	if (!packet) {
		ip_packet_stats.too_many_packets++;
		return IPA_NO_MEMORY;
	}

	packet->last_usage = monotime(NULL);

	/* Don't attempt to assemble or account this packet anymore. */
	if (CHECK_FLAG(packet->flags, IP_PACKET_IGNORE))
		return IPA_IGNORED;

	/*
	 * Someone is trying to DoS us, so don't allocate more memory and wait
	 * them to go away. The periodic timer will clean up this memory later.
	 */
	if (packet->total_fragments >= IPV4_MAXIMUM_FRAGMENTS_AMOUNT) {
		SET_FLAG(packet->flags, IP_PACKET_IGNORE);
		ip_packet_stats.too_many_fragments++;
		return IPA_TOO_MANY_FRAGMENTS;
	}

	/*
	 * Attempt to receive and assemble packet fragments.
	 *
	 * If the packet was already assembled it means we've got a repeated
	 * fragment and we should not bother the caller with it.
	 */
	if (!CHECK_FLAG(packet->flags, IP_PACKET_COMPLETE)) {
		uint16_t offset = ipv4_fragment_offset(ipv4) << 3;
		enum ip_packet_assemble_result result;

		/*
		 * The first fragment carries the IP header with the options
		 * (if any), so keep it aside to build the final packet with.
		 * The headers of the remaining fragments are discarded.
		 *
		 * Only the first one seen is kept: a repeated first fragment
		 * announcing a different header length would otherwise make
		 * the assembled size disagree with the data we hold.
		 */
		if (offset == 0 && packet->header_size == 0) {
			memcpy(packet->header, data, header_length);
			packet->header_size = header_length;
		}

		result = ip_packet_add_fragment(packet, offset, ipv4_more_fragments(ipv4),
						data + header_length,
						fragment_length - header_length);
		if (result != IPA_OK)
			return result;
	} else {
		ip_packet_stats.repeated_packet++;
		return IPA_REPEATED_PACKET;
	}

	*packetp = packet->data;
	*packetlen = packet->header_size + packet->total_size;

	/* Schedule clean up. */
	event_add_event(packet_event_loop, ip_packet_cleanup_event, packet, 0,
			&packet->cleanup_event);

	return IPA_OK;
}

/** Removes completed and used packets. */
static void ip_packet_periodic(struct event *event __attribute__((unused)))
{
	time_t now;
	int index;

	/* Cache current time. */
	now = monotime(NULL);

	for (index = 0; index < PACKET_ASSEMBLY_IN_PROGRESS_MAX; index++) {
		/* Skip unused slots. */
		if (!CHECK_FLAG(packet_list[index].flags, IP_PACKET_IN_USE))
			continue;

		/* Skip packet with recent activity. */
		if (packet_list[index].last_usage + IP_PACKET_INACTIVE_INTERVAL >= now)
			continue;

		ip_packet_reset(&packet_list[index]);
	}

	/* Schedule next periodic clean up. */
	event_add_timer(packet_event_loop, ip_packet_periodic, NULL, IP_PACKET_INACTIVE_INTERVAL,
			&packet_cleanup_timer);
}

DEFUN(show_ip_packet_statistics, show_ip_packet_statistics_cmd,
      "show ip assembly",
      SHOW_STR
      IP_STR
      "IP fragmentation assembly statistics\n")
{
	vty_out(vty, "IP Assembly Statistics\n");
	vty_out(vty, "======================\n");
	vty_out(vty, "Invalid version: %" PRIu64 "\n", ip_packet_stats.invalid_version);
	vty_out(vty, "Invalid header length: %" PRIu64 "\n", ip_packet_stats.invalid_header_length);
	vty_out(vty, "Invalid packet length: %" PRIu64 "\n", ip_packet_stats.invalid_packet_length);
	vty_out(vty, "Invalid fragmentation: %" PRIu64 "\n", ip_packet_stats.invalid_fragmentation);
	vty_out(vty, "Invalid checksum: %" PRIu64 "\n", ip_packet_stats.invalid_checksum);
	vty_out(vty, "Fragment overlap: %" PRIu64 "\n", ip_packet_stats.fragment_overlap);
	vty_out(vty, "Too many packets (no slots): %" PRIu64 "\n",
		ip_packet_stats.too_many_packets);
	vty_out(vty, "Too many fragments: %" PRIu64 "\n", ip_packet_stats.too_many_fragments);
	vty_out(vty, "Whole packets: %" PRIu64 "\n", ip_packet_stats.whole_packets);
	vty_out(vty, "Assembled packets: %" PRIu64 "\n", ip_packet_stats.assembled_packets);
	vty_out(vty, "Repeated packets: %" PRIu64 "\n", ip_packet_stats.repeated_packet);
	vty_out(vty, "Repeated fragments: %" PRIu64 "\n", ip_packet_stats.repeated_fragment);
	vty_out(vty, "Huge packets: %" PRIu64 "\n", ip_packet_stats.huge_packets);

	return CMD_SUCCESS;
}

DEFUN(show_ip_encap_packet_statistics, show_ip_encap_packet_statistics_cmd,
      "show ip-encap assembly",
      SHOW_STR
      "IP encapsulation information\n"
      "IP encapsulation statistics\n")
{
	vty_out(vty, "IP Encapsulation Statistics\n");
	vty_out(vty, "===========================\n");
	vty_out(vty, "Invalid version: %" PRIu64 "\n", ip_encap_packet_stats.invalid_version);
	vty_out(vty, "Invalid header length: %" PRIu64 "\n",
		ip_encap_packet_stats.invalid_header_length);
	vty_out(vty, "Invalid packet length: %" PRIu64 "\n",
		ip_encap_packet_stats.invalid_packet_length);
	vty_out(vty, "Invalid checksum: %" PRIu64 "\n", ip_encap_packet_stats.invalid_checksum);
	vty_out(vty, "Fragmented encapsulation packets (invalid): %" PRIu64 "\n",
		ip_encap_packet_stats.fragmented);
	vty_out(vty, "Invalid encapsulation version: %" PRIu64 "\n",
		ip_encap_packet_stats.invalid_encapsulation_version);
	vty_out(vty, "Invalid encapsulation magic: %" PRIu64 "\n",
		ip_encap_packet_stats.invalid_encapsulation_magic);
	vty_out(vty, "Valid packets: %" PRIu64 "\n", ip_encap_packet_stats.valid_packets);

	return CMD_SUCCESS;
}

void ip_fragmentation_handler_init(struct event_loop *event_loop)
{
	packet_event_loop = event_loop;
	event_add_timer(packet_event_loop, ip_packet_periodic, NULL, IP_PACKET_INACTIVE_INTERVAL,
			&packet_cleanup_timer);

	install_element(ENABLE_NODE, &show_ip_packet_statistics_cmd);
	install_element(ENABLE_NODE, &show_ip_encap_packet_statistics_cmd);
}

void ip_fragmentation_handler_stop(void)
{
	int index;

	event_cancel(&packet_cleanup_timer);

	for (index = 0; index < PACKET_ASSEMBLY_IN_PROGRESS_MAX; index++)
		ip_packet_reset(&packet_list[index]);
}

const char *ip_packet_assemble_result_str(enum ip_packet_assemble_result result)
{
	switch (result) {
	case IPA_OK:
		return "IPA_OK";
	case IPA_OK_INCOMPLETE:
		return "IPA_OK_INCOMPLETE";
	case IPA_INVALID_VERSION:
		return "IPA_INVALID_VERSION";
	case IPA_INVALID_HEADER_LENGTH:
		return "IPA_INVALID_HEADER_LENGTH";
	case IPA_INVALID_LENGTH:
		return "IPA_INVALID_LENGTH";
	case IPA_INVALID_FRAGMENTATION:
		return "IPA_INVALID_FRAGMENTATION";
	case IPA_INVALID_CHECKSUM:
		return "IPA_INVALID_CHECKSUM";
	case IPA_FRAGMENT_OVERLAP:
		return "IPA_FRAGMENT_OVERLAP";
	case IPA_NO_MEMORY:
		return "IPA_NO_MEMORY";
	case IPA_TOO_MANY_FRAGMENTS:
		return "IPA_TOO_MANY_FRAGMENTS";
	case IPA_PACKET_TOO_BIG:
		return "IPA_PACKET_TOO_BIG";
	case IPA_NOT_FRAGMENTED:
		return "IPA_NOT_FRAGMENTED";
	case IPA_REPEATED_PACKET:
		return "IPA_REPEATED_PACKET";
	case IPA_IGNORED:
		return "IPA_IGNORED";
	default:
		return "unknown";
	}
}

enum ip_encap_packet_assemble_result ipv4_encap_parse(const void *data, size_t datalen,
						      struct ipv4_encap_result *rv)
{
	const struct ipv4_header *ipv4 = (const struct ipv4_header *)data;
	const struct encap_header *encap;
	uint16_t header_length;
	uint16_t packet_length;
	int checksum;

	/* Reset result data structure. */
	memset(rv, 0, sizeof(*rv));

	/* Basic check: data size is at least the header. */
	if (datalen < sizeof(struct ipv4_encap_header)) {
		ip_encap_packet_stats.invalid_header_length++;
		return IEPA_INVALID_HEADER_LENGTH;
	}

	/* Check version. */
	if (ipv4_version(ipv4) != 4) {
		ip_encap_packet_stats.invalid_version++;
		return IEPA_INVALID_VERSION;
	}

	/* Check header length. */
	header_length = (uint16_t)ipv4_header_length(ipv4);
	if (header_length < sizeof(struct ipv4_header) ||
	    datalen < ((size_t)header_length + sizeof(struct encap_header))) {
		ip_encap_packet_stats.invalid_header_length++;
		return IEPA_INVALID_HEADER_LENGTH;
	}

	/* Verify checksum. */
	checksum = in_cksum(data, header_length);
	if (checksum) {
		ip_encap_packet_stats.invalid_checksum++;
		return IEPA_INVALID_CHECKSUM;
	}

	/* Check packet length. */
	packet_length = ntohs(ipv4->total_length);
	if (datalen < packet_length) {
		ip_encap_packet_stats.invalid_packet_length++;
		return IEPA_INVALID_LENGTH;
	}

	/* Check if this packet is fragmented. */
	if (ipv4_more_fragments(ipv4) || ipv4_fragment_offset(ipv4)) {
		ip_encap_packet_stats.fragmented++;
		return IEPA_FRAGMENTED;
	}

	encap = (const struct encap_header *)((const uint8_t *)data + header_length);

	/* Encapsulation check: version. */
	if (encap->version != 0) {
		ip_encap_packet_stats.invalid_encapsulation_version++;
		return IEPA_INVALID_ENCAPSULATION_VERSION;
	}
	/* Encapsulation check: magic number. */
	if (encap->magic != htonl(IP_ENCAP_MAGIC_VALUE)) {
		ip_encap_packet_stats.invalid_encapsulation_magic++;
		return IEPA_INVALID_ENCAPSULATION_MAGIC;
	}

	/* Set and return results. */
	rv->ifindex = ntohs(encap->ifindex);
	rv->protocol = ipv4->protocol;
	rv->encap_length = header_length + IP_ENCAP_DATA_SIZE;
	rv->destination.s_addr = ipv4->destination.s_addr;

	/* Statistics. */
	ip_encap_packet_stats.valid_packets++;

	return IEPA_OK;
}

void ipv4_encap_output(const struct ipv4_encap_params *params, void *data, size_t datalen)
{
	struct ipv4_encap_header *ipv4e = data;

	/* Fix static analyzer warning about garbage values. */
	memset(ipv4e, 0, sizeof(*ipv4e));

	ipv4_set_version(&ipv4e->ipv4);
	/*
	 * NOTE: the encapsulation header does not count the encapsulation
	 *       data as part of the header.
	 */
	ipv4_set_header_length(&ipv4e->ipv4, sizeof(ipv4e->ipv4));
	ipv4e->ipv4.tos = IPV4_ENCAP_TOS;
	ipv4e->ipv4.id = htons(((uint16_t)frr_weak_random()));
	ipv4e->ipv4.total_length = htons(sizeof(*ipv4e) + datalen);
	ipv4e->ipv4.ttl = 1;
	ipv4e->ipv4.protocol = IP_ENCAP_ROUTING;
	ipv4e->ipv4.source = params->source;
	ipv4e->ipv4.destination.s_addr = htonl(IPV4_ENCAP_DST);
	ipv4e->ipv4.checksum = 0;
	ipv4e->ipv4.checksum = (uint16_t)in_cksum(ipv4e, ipv4_header_length(&ipv4e->ipv4));

	ipv4e->version = 0;
	ipv4e->ifindex = htons((uint16_t)params->ifindex);
	ipv4e->magic = htonl(IP_ENCAP_MAGIC_VALUE);
}

ssize_t ipv4_output(const struct ipv4_output_params *params, const void *data, size_t datalen)
{
	const uint8_t *packet_p = data;
	struct ipv4_header *ipv4e;
	struct ipv4_header *ipv4;
	struct udp_header *uh;
	size_t remaining = datalen;
	size_t data_size;
	size_t payload_size;
	size_t data_offset = 0;
	size_t fragment_offset = 0;
	size_t headers_size;
	ssize_t bytes_sent;
	uint16_t more_fragments;
	bool first_fragment = true;
	struct sockaddr_in sin = {};
	struct msghdr msg = {};
	struct iovec iov[2] = {};
	uint8_t headers[128] = {};

	/*
	 * The fragment offset field only has 13 bits (in octet groups), so
	 * the whole datagram has to fit `IPV4_MAXIMUM_PACKET_SIZE` for the
	 * offsets below to be representable.
	 */
	if (datalen >
	    (IPV4_MAXIMUM_PACKET_SIZE - IPV4_MAXIMUM_HEADER_SIZE - sizeof(struct udp_header))) {
		zlog_warn("%s: payload too big to fragment: %zu bytes", __func__, datalen);
		return -1;
	}

	/* Encapsulation header. */
	ipv4_encap_output(&params->encap, headers, datalen);
	ipv4e = (struct ipv4_header *)&headers[0];
	headers_size = ipv4_header_length(ipv4e) + sizeof(struct encap_header);

	/* Encapsulated header. */
	ipv4 = (struct ipv4_header *)&headers[headers_size];

	/* Fix static analyzer warning about garbage values. */
	memset(ipv4, 0, sizeof(*ipv4));

	ipv4_set_version(ipv4);
	ipv4_set_header_length(ipv4, sizeof(struct ipv4_header));
	ipv4->tos = params->tos;
	ipv4->id = htons(((uint16_t)frr_weak_random()));
	ipv4->ttl = params->ttl;
	ipv4->protocol = params->protocol;
	ipv4->source = params->source;
	ipv4->destination = params->destination;
	ipv4->checksum = 0;

	headers_size += ipv4_header_length(ipv4);

	if (params->router_alert) {
		struct ipv4_router_alert *router_alert =
			(struct ipv4_router_alert *)&headers[headers_size];

		router_alert->identifier = htons(IPV4_ROUTER_ALERT_IDENTIFIER);
		router_alert->value = htons(IPV4_ROUTER_ALERT_VALUE_EXAMINE);

		ipv4_set_header_length(ipv4, sizeof(struct ipv4_header) +
						     sizeof(struct ipv4_router_alert));

		headers_size += sizeof(struct ipv4_router_alert);
	}

	/* Encapsulated UDP. */
	if (params->protocol == IPPROTO_UDP) {
		uh = (struct udp_header *)&headers[headers_size];
		uh->source = params->udp_source;
		uh->destination = params->udp_destination;

		headers_size += sizeof(struct udp_header);
	} else
		uh = NULL;

	/* Destination: loopback. */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(IPV4_ENCAP_DST);

	/*
	 * Bail out when the MTU can't fit the headers plus one octet group
	 * of payload: the loop below would either never terminate (zero
	 * sized fragments) or compute a bogus size (underflow).
	 */
	if ((size_t)params->mtu < (headers_size + 8)) {
		zlog_debug("%s: MTU %u is too small for %zu bytes of headers", __func__,
			   params->mtu, headers_size);
		return -1;
	}

	payload_size = params->mtu - headers_size;
	payload_size = payload_size - (payload_size % 8);

	while (remaining) {
		if (remaining > payload_size) {
			data_size = payload_size;
			more_fragments = IPV4_MORE_FRAGMENTS;
		} else {
			data_size = remaining;
			more_fragments = 0;
		}

		ipv4e->total_length = htons((uint16_t)(headers_size + (uint16_t)data_size));

		ipv4->fragmentation = htons(more_fragments | (uint16_t)(fragment_offset >> 3));
		if (uh && first_fragment) {
			ipv4->total_length = htons(ipv4_header_length(ipv4) +
						   sizeof(struct udp_header) + data_size);
			uh->length = htons(sizeof(struct udp_header) + datalen);
		} else
			ipv4->total_length =
				htons((uint16_t)(ipv4_header_length(ipv4) + data_size));

		ipv4e->checksum = 0;
		ipv4e->checksum = in_cksum(ipv4e, ipv4_header_length(ipv4e));
		ipv4->checksum = 0;
		ipv4->checksum = in_cksum(ipv4, ipv4_header_length(ipv4));

		iov[0].iov_base = headers;
		iov[0].iov_len = headers_size;
		iov[1].iov_base = (void *)(size_t)(packet_p + data_offset);
		iov[1].iov_len = data_size;

		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
		msg.msg_name = &sin;
		msg.msg_namelen = sizeof(struct sockaddr_in);

		bytes_sent = sendmsg(params->socket, &msg, 0);
		if (bytes_sent == -1) {
			if (errno == EINTR)
				continue;

			return -1;
		}
		if (bytes_sent == 0)
			return 0;

		remaining -= data_size;
		data_offset += data_size;
		fragment_offset += data_size;

		if (params->protocol == IPPROTO_UDP && first_fragment) {
			first_fragment = false;
			/* Only the first fragment has UDP header. */
			fragment_offset += sizeof(struct udp_header);
			headers_size -= sizeof(struct udp_header);
			payload_size += sizeof(struct udp_header);
		}
	}

	return datalen;
}

/**
 * Parses an address port from string and validates its format.
 *
 * If `error` parameter is `NULL` no error explanation will be returned.
 *
 * \param port_string the port in string format.
 * \param error pointer to buffer to write errors.
 * \param error_size error buffer size.
 * \returns port value on success otherwise `0`.
 */
static uint16_t parse_port(const char *port_string, char *error, size_t error_size)
{
	char *nullbyte;
	long rv;

	/*
	 * `strtol` silently accepts leading white space and a '+'/'-' sign:
	 * only allow plain decimal numbers here.
	 */
	if (!isdigit((unsigned char)*port_string)) {
		if (error)
			snprintfrr(error, error_size, "invalid format: %s", port_string);
		return 0;
	}

	errno = 0;
	rv = strtol(port_string, &nullbyte, 10);
	/* Invalid number range. */
	if ((rv <= 0 || rv > UINT16_MAX) || errno == ERANGE) {
		if (error)
			snprintfrr(error, error_size, "outside valid range: %s", port_string);
		return 0;
	}
	/* There was garbage at the end of the string. */
	if (*nullbyte != 0) {
		if (error)
			snprintfrr(error, error_size, "unexpected ending: %s", nullbyte);
		return 0;
	}

	return (uint16_t)rv;
}

bool network_address_parse(const char *address_string, struct network_address *address,
			   uint16_t default_port)
{
	const char *addr_start;
	char *str_pos, *str_pos_aux;
	size_t str_len;
	char addr[128];
	char type[64];
	char port_error[64];

	memset(address, 0, sizeof(*address));

	/* e.g. a module loaded without arguments. */
	if (address_string == NULL) {
		snprintfrr(address->error, sizeof(address->error),
			   "missing address (expected <type>:<address>[:<port>])");
		return false;
	}

	/* Basic parsing: find ':' to figure out type part and address part. */
	addr_start = strchr(address_string, ':');
	if (!addr_start) {
		snprintfrr(address->error, sizeof(address->error), "invalid address format: %s",
			   address_string);
		return false;
	}

	/* Calculate type string length. */
	str_len = (size_t)(addr_start - address_string);

	/* Copy the address part. */
	addr_start++;
	strlcpy(addr, addr_start, sizeof(addr));

	if (strlen(addr) == 0) {
		snprintfrr(address->error, sizeof(address->error), "address part is empty");
		return false;
	}

	/* Copy type part. */
	strlcpy(type, address_string, MIN(str_len + 1, sizeof(type)));

	/* Fill the address information. */
	if (strcmp(type, "unix") == 0 || strcmp(type, "unixc") == 0) {
		struct sockaddr_un *sunp = (struct sockaddr_un *)&address->address;

		address->listen = (strcmp(type, "unixc") != 0);

		sunp->sun_family = AF_UNIX;
		if (strlcpy(sunp->sun_path, addr, sizeof(sunp->sun_path)) >=
		    sizeof(sunp->sun_path)) {
			snprintfrr(address->error, sizeof(address->error), "unix path is too long");
			return false;
		}
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
		sunp->sun_len = SUN_LEN(sunp);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */
		address->address_size = sizeof(struct sockaddr_un);
	} else if (strcmp(type, "ipv4") == 0 || strcmp(type, "ipv4c") == 0) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&address->address;

		address->listen = (strcmp(type, "ipv4c") != 0);

		sin->sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		sin->sin_len = sizeof(*sin);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
		sin->sin_port = htons(default_port);

		address->address_size = sizeof(struct sockaddr_in);

		/* Parse port if any. */
		str_pos = strchr(addr, ':');
		if (str_pos != NULL) {
			uint16_t port;

			*str_pos = 0;
			port = parse_port(str_pos + 1, port_error, sizeof(port_error));
			if (port == 0) {
				snprintfrr(address->error, sizeof(address->error),
					   "invalid port: %s", port_error);
				return false;
			}

			sin->sin_port = htons(port);
		}

		if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv4 address: %s", addr);
			return false;
		}
	} else if (strcmp(type, "ipv6") == 0 || strcmp(type, "ipv6c") == 0) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&address->address;

		address->listen = (strcmp(type, "ipv6c") != 0);

		sin6->sin6_family = AF_INET6;
#ifdef SIN6_LEN
		sin6->sin6_len = sizeof(*sin6);
#endif /* SIN6_LEN */
		sin6->sin6_port = htons(default_port);

		address->address_size = sizeof(struct sockaddr_in6);

		/* Check for IPv6 enclosures '[]' */
		str_pos = &addr[0];
		if (*str_pos != '[') {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv6 format (expected '['): %s", addr);
			return false;
		}

		str_pos_aux = strrchr(addr, ']');
		if (!str_pos_aux) {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv6 format (expected ']'): %s", addr);
			return false;
		}

		/* Consume the '[]:' part. */
		str_len = (size_t)(str_pos_aux - str_pos);
		memmove(addr, addr + 1, str_len);
		addr[str_len - 1] = 0;

		/*
		 * Parse port if any: only a port or the end of the string may
		 * follow the ']'.
		 */
		str_pos_aux++;
		if (*str_pos_aux == ':') {
			uint16_t port;

			port = parse_port(str_pos_aux + 1, port_error, sizeof(port_error));
			if (port == 0) {
				snprintfrr(address->error, sizeof(address->error),
					   "invalid port: %s", port_error);
				return false;
			}
			sin6->sin6_port = htons(port);
		} else if (*str_pos_aux != 0) {
			snprintfrr(address->error, sizeof(address->error),
				   "expected port or nothing, got: %s", str_pos_aux);
			return false;
		}

		/* Parse the scope/zone identifier if any. */
		str_pos = strchr(addr, '%');
		if (str_pos != NULL) {
			*str_pos = 0;
			sin6->sin6_scope_id = if_nametoindex(str_pos + 1);
			if (sin6->sin6_scope_id == 0) {
				snprintfrr(address->error, sizeof(address->error),
					   "invalid IPv6 scope: %s", str_pos + 1);
				return false;
			}
		}

		if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) != 1) {
			snprintfrr(address->error, sizeof(address->error),
				   "invalid IPv6 address: %s", addr);
			return false;
		}
	} else {
		snprintfrr(address->error, sizeof(address->error), "invalid address type: %s",
			   type);
		return false;
	}

	return true;
}
