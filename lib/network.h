// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Network library header.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_NETWORK_H
#define _ZEBRA_NETWORK_H

#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#include <endian.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Both readn and writen are deprecated and will be removed.  They are not
   suitable for use with non-blocking file descriptors.
 */
extern int readn(int fd, uint8_t *ptr, int nbytes);
extern int writen(int fd, const uint8_t *ptr, int nbytes);

/* Set the file descriptor to use non-blocking I/O.  Returns 0 for success,
   -1 on error. */
extern int set_nonblocking(int fd);

extern int set_cloexec(int fd);

/* Does the I/O error indicate that the operation should be retried later? */
#define ERRNO_IO_RETRY(EN)                                                     \
	(((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

extern float htonf(float host);
extern float ntohf(float net);

/* force type for be64toh/htobe64 to be uint64_t, *without* a direct cast
 *
 * this is a workaround for false-positive printfrr warnings from FRR's
 * frr-format GCC plugin that would be triggered from
 * { printfrr("%"PRIu64, (uint64_t)be64toh(...)); }
 *
 * the key element here is that "(uint64_t)expr" causes the warning, while
 * "({ uint64_t x = expr; x; })" does not.  (The cast is the trigger, a
 * variable of the same type works correctly.)
 */

/* zap system definitions... */
#ifdef be64toh
#undef be64toh
#endif
#ifdef htobe64
#undef htobe64
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define be64toh(x)	({ uint64_t r = __builtin_bswap64(x); r; })
#define htobe64(x)	({ uint64_t r = __builtin_bswap64(x); r; })
#elif BYTE_ORDER == BIG_ENDIAN
#define be64toh(x)	({ uint64_t r = (x); r; })
#define htobe64(x)	({ uint64_t r = (x); r; })
#else
#error nobody expects the endianish inquisition. check OS endian.h headers.
#endif

/**
 * Generate a sequence number using monotonic clock with a same second call
 * protection to help guarantee a unique incremental sequence number that never
 * goes back (except when wrapping/overflow).
 *
 * **NOTE** this function is not thread safe since it uses `static` variable.
 *
 * This function and `frr_sequence32_next` should be used to initialize
 * sequence numbers without directly calling other `time_t` returning
 * functions because of `time_t` truncation warnings.
 *
 * \returns `uint64_t` number based on the monotonic clock.
 */
extern uint64_t frr_sequence_next(void);

/** Same as `frr_sequence_next` but returns truncated number. */
extern uint32_t frr_sequence32_next(void);

/**
 * Helper function that returns a random long value. The main purpose of
 * this function is to hide a `random()` call that gets flagged by coverity
 * scan and put it into one place.
 *
 * The main usage of this function should be for generating jitter or weak
 * random values for simple purposes.
 *
 * See 'man 3 random' for more information.
 *
 * \returns random long integer.
 */
static inline long frr_weak_random(void)
{
	/* coverity[dont_call] */
	return random();
}

/*
 * IP fragmentation/assembly API.
 */

/**
 * RFC 791 Section 3.1. Internet Header Format.
 *
 * Hosts must be prepared to accept datagrams of up to 576 octets.
 */
#define IPV4_MINIMUM_FRAGMENT_SIZE 576

/** Maximum IPv4 header size (including options). */
#define IPV4_MAXIMUM_HEADER_SIZE 60

/** Maximum allowed IPv4 packet size (reassembled). */
#define IPV4_MAXIMUM_PACKET_SIZE 65535

/**
 * Maximum amount of fragments allowed to be queued for a single IPv4 packet.
 *
 * Reasoning:
 *
 *  Maximum packet size
 * --------------------- = 113.77
 * Minimum fragment size
 */
#define IPV4_MAXIMUM_FRAGMENTS_AMOUNT 113

/**
 * Maximum number of allowed in progress fragmented packets.
 */
#define PACKET_ASSEMBLY_IN_PROGRESS_MAX 12

/**
 * Maximum inactive interval before getting free'd.
 */
#define IP_PACKET_INACTIVE_INTERVAL 4

/**
 * Possible IP assembly outcomes.
 */
enum ip_packet_assemble_result {
	/** Packet was successfully assembled. */
	IPA_OK = 0,
	/** Packet is still being assembled. */
	IPA_OK_INCOMPLETE,
	/** Invalid IP packet version. */
	IPA_INVALID_VERSION,
	/** Packet part has invalid length. */
	IPA_INVALID_HEADER_LENGTH,
	/** Packet part has invalid length. */
	IPA_INVALID_LENGTH,
	/** Fragmentation fields are contradictory. */
	IPA_INVALID_FRAGMENTATION,
	/** Packet checksum invalid. */
	IPA_INVALID_CHECKSUM,
	/** Fragment overlapped existing part. */
	IPA_FRAGMENT_OVERLAP,
	/** Not enough resources to reassemble packet. */
	IPA_NO_MEMORY,
	/** Too many IP fragments. */
	IPA_TOO_MANY_FRAGMENTS,
	/** Packet is too big (>65k) and can't be assembled. */
	IPA_PACKET_TOO_BIG,
	/** Not fragmented. */
	IPA_NOT_FRAGMENTED,
	/** Packet already got read. */
	IPA_REPEATED_PACKET,
	/** Ignored packet (its too big or too fragmented). */
	IPA_IGNORED,
};

/**
 * Possible IP encapsulation parse outcomes.
 */
enum ip_encap_packet_assemble_result {
	/** Packet was successfully assembled. */
	IEPA_OK = 0,
	/** Invalid IP packet version. */
	IEPA_INVALID_VERSION,
	/** Packet part has invalid length. */
	IEPA_INVALID_HEADER_LENGTH,
	/** Packet part has invalid length. */
	IEPA_INVALID_LENGTH,
	/** Packet checksum invalid. */
	IEPA_INVALID_CHECKSUM,
	/** Fragmented encapsulated packet. */
	IEPA_FRAGMENTED,
	/** Invalid encapsulation version. */
	IEPA_INVALID_ENCAPSULATION_VERSION,
	/** Invalid encapsulation magic. */
	IEPA_INVALID_ENCAPSULATION_MAGIC,
};

/**
 * Statistic counters for IP assembly/fragmentation.
 */
struct ip_packet_statistics {
	/** Invalid IP header version. */
	uint64_t invalid_version;
	/** Invalid header length: less than 5 octets (or 20 bytes). */
	uint64_t invalid_header_length;
	/** Invalid packet length: header says X but packet data is Y. */
	uint64_t invalid_packet_length;
	/**
	 * Fragments with contradictory fragmentation fields: `DF` set along
	 * with `MF`/an offset, or a fragment carrying no payload at all.
	 */
	uint64_t invalid_fragmentation;
	/** Invalid checksum. */
	uint64_t invalid_checksum;
	/** IP fragment overlaps detected: possible malicious user. */
	uint64_t fragment_overlap;
	/**
	 * We exceeded the amount of parallel packets being assembled.
	 *
	 * This is possible in two situations:
	 *  1. We are receiving too much traffic and most of it is fragmented.
	 *  2. We are being DDoS with fragmented packets using randomized IDs.
	 */
	uint64_t too_many_packets;
	/**
	 * Packets with fragment count exceeding IPV4_MAXIMUM_FRAGMENTS_AMOUNT.
	 */
	uint64_t too_many_fragments;
	/** Packets that were not fragmented. */
	uint64_t whole_packets;
	/** Total amount of assembled packets. */
	uint64_t assembled_packets;
	/**
	 * Amount of packets repeated.
	 *
	 * This situation is either:
	 *  1. When repeated fragments were received.
	 *  2. We exceeded the transfer rate causing ID collision.
	 */
	uint64_t repeated_packet;
	/**
	 * Amount of duplicated fragments received for a datagram that is
	 * still being assembled.
	 */
	uint64_t repeated_fragment;
	/** Amount of packets that exceeded 65k size. */
	uint64_t huge_packets;
};

extern struct ip_packet_statistics ip_packet_stats;

/**
 * Parses and assembles the passed IPv4 packet (if fragmented).
 *
 * NOTE:
 * Don't keep the pointer to `packet` because it will be `free()`d once the
 * FRR event loop is called.
 *
 * Fragments are only assembled with the ones received on the same interface:
 * the IP identification fields (source, destination, protocol and ID) are
 * only unique within an address space, so different VRFs (or links) may use
 * the same ones at the same time.
 *
 * \param data the IPv4 packet raw data (with header).
 * \param datalen the IPv4 packet read length as returned by syscall.
 * \param ifindex the index of the interface the packet was received on.
 * \param packet pointer to return the assembled packet (only set if return
 *               value is `IPA_OK`).
 * \param packetlen pointer to return total packet length (header + data).
 * \returns one of `enum ip_packet_assemble_result` values.
 */
extern enum ip_packet_assemble_result ipv4_packet_assemble(const uint8_t *data, size_t datalen,
							   int32_t ifindex, const uint8_t **packet,
							   size_t *packetlen);

/** Converts enum value to string. */
extern const char *ip_packet_assemble_result_str(enum ip_packet_assemble_result result);

/* Forward declaration. */
struct event_loop;

/** Initialize packet assembler API/periodic timers.  */
extern void ip_fragmentation_handler_init(struct event_loop *event_loop);

/** Stop packet assembler API/periodic timers. */
extern void ip_fragmentation_handler_stop(void);

/*
 * IP encapsulation.
 */

/** IP encapsulation protocol number for sending packets. */
#define IP_ENCAP_ROUTING 249

/** IP encapsulation protocol for receiving OSPFv2 SPF packets. */
#define OSPF_IP_ENCAP_SPF 248
/** IP encapsulation protocol for receiving other OSPFv2 packets. */
#define OSPF_IP_ENCAP_OTHER IP_ENCAP_ROUTING
/** IP encapsulation protocol for receiving OSPFv2 DR packets. */
#define OSPF_IP_ENCAP_DR 250

/** IP encapsulation protocol for receiving IGMP packets. */
#define PIM_IP_ENCAP_IGMP 251
/** IP encapsulation protocol for receiving PIM packets. */
#define PIM_IP_ENCAP_PIM 252

/** Encapsulation parse results.  */
struct ipv4_encap_result {
	/** Interface index the packet came from. */
	int32_t ifindex;
	/** Encapsulation header length. */
	uint16_t encap_length;
	/** Encapsulation protocol. */
	uint8_t protocol;
	/** Destination address header value. */
	struct in_addr destination;
};

/**
 * Parses a raw packet and returns whether the encapsulated data is valid or
 * not.
 *
 * \param data raw packet pointer.
 * \param datalen raw packet length.
 * \param rv the results output.
 * \returns `IEPA_OK` on success otherwise one of the codes in
 *          `enum ip_encap_packet_assemble_result`.
 */
extern enum ip_encap_packet_assemble_result ipv4_encap_parse(const void *data, size_t datalen,
							     struct ipv4_encap_result *rv);

/** Encapsulation parameters. */
struct ipv4_encap_params {
	/** Source address for the packet. */
	struct in_addr source;
	/** Interface index. */
	int32_t ifindex;
};

/**
 * Encapsulation data size.
 *
 * Use this value to reserve the appropriated buffer size to use with
 * `ip_encap_output`.
 */
#define IPV4_ENCAP_DATA_SIZE 28

/** Encapsulation destination address. */
#define IPV4_ENCAP_DST 0x7F8201FE

/**
 * Generates an encapsulation header and sets it in the packet pointed by
 * `data`.
 *
 * \param params the encapsulation data parameters.
 * \param data pointer to the data packet.
 * \param datalen the amount of data in the packet.
 */
extern void ipv4_encap_output(const struct ipv4_encap_params *params, void *data, size_t datalen);

/** Parameters for function `ipv4_output`. */
struct ipv4_output_params {
	/** Socket descriptor to use. */
	int socket;

	/** Interface MTU. */
	uint16_t mtu;

	/** IPv4 protocol. */
	uint8_t protocol;
	/** IPv4 TTL. */
	uint8_t ttl;
	/** IPv4 ToS. */
	uint8_t tos;
	/** IPv4 source address. */
	struct in_addr source;
	/** IPv4 destination address. */
	struct in_addr destination;

	/** UDP source port (if protocol == IPPROTO_UDP). */
	uint16_t udp_source;
	/** UDP destination port (if protocol == IPPROTO_UDP). */
	uint16_t udp_destination;

	/** Include router alert. */
	bool router_alert;

	/** Encapsulation parameters. */
	struct ipv4_encap_params encap;
};

/**
 * Sends packet using parameters for generating the encapsulation.
 * This function will fragment the packet if necessary.
 *
 * \param params the packets parameters.
 * \param data the packet data payload.
 * \param datalen the packet data payload length.
 */
extern ssize_t ipv4_output(const struct ipv4_output_params *params, const void *data,
			   size_t datalen);

/**
 * Regular IPv4 header (simplified) from RFC 791 Section 3.1..
 */
struct ipv4_header {
	uint8_t version_ihl;
#define IPV4_VERSION 4
	uint8_t tos;
	uint16_t total_length;
	uint16_t id;
	uint16_t fragmentation;
#define IPV4_MORE_FRAGMENTS 0x2000
#define IPV4_DONT_FRAGMENT  0x4000
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	struct in_addr source;
	struct in_addr destination;
};

/** IPv4 ToS field value for IGMP packets: internetwork control. */
#define IPV4_TOS_INTERNET_PROTOCOL 0xC0

static inline uint8_t ipv4_version(const struct ipv4_header *ipv4)
{
	return ipv4->version_ihl >> 4;
}

static inline void ipv4_set_version(struct ipv4_header *ipv4)
{
	ipv4->version_ihl = (ipv4->version_ihl & 0x0F) | (4 << 4);
}

static inline uint8_t ipv4_header_length(const struct ipv4_header *ipv4)
{
	return (ipv4->version_ihl & 0x0F) << 2;
}

static inline void ipv4_set_header_length(struct ipv4_header *ipv4, size_t header_length)
{
	ipv4->version_ihl = (ipv4->version_ihl & 0xF0) | ((header_length >> 2) & 0x0F);
}

static inline bool ipv4_more_fragments(const struct ipv4_header *ipv4)
{
	return (ntohs(ipv4->fragmentation) & IPV4_MORE_FRAGMENTS) == IPV4_MORE_FRAGMENTS;
}

static inline bool ipv4_dont_fragment(const struct ipv4_header *ipv4)
{
	return (ntohs(ipv4->fragmentation) & IPV4_DONT_FRAGMENT) == IPV4_DONT_FRAGMENT;
}

static inline uint16_t ipv4_fragment_offset(const struct ipv4_header *ipv4)
{
	return ntohs(ipv4->fragmentation) & 0x1FFF;
}

/* Magic encapsulation header. */
struct ipv4_encap_header {
	struct ipv4_header ipv4;

	/** Encapsulation version. */
	uint16_t version;
	/** Interface index. */
	uint16_t ifindex;
	/** Magic version. */
	uint32_t magic;
};

/** UDP header as described in RFC 768. */
struct udp_header {
	/** UDP source port. */
	uint16_t source;
	/** UDP destination port. */
	uint16_t destination;
	/** UDP packet length. */
	uint16_t length;
	/** UDP checksum. */
	uint16_t checksum;
};

/* Encapsulation data (without IP part). */
struct encap_header {
	/** Encapsulation version. */
	uint16_t version;
	/** Interface index. */
	uint16_t ifindex;
	/** Magic version. */
	uint32_t magic;
};

/** IPv4 router alert option (RFC 2113 IP Router Alert Option). */
struct ipv4_router_alert {
	/** Fixed identifier value. */
	uint16_t identifier;
	/** Router alert value. */
	uint16_t value;
};

/** Fixed value used in the identifier field. */
#define IPV4_ROUTER_ALERT_IDENTIFIER ((uint16_t)0x9404)
/** Router alert value to ask router to inspect packet. */
#define IPV4_ROUTER_ALERT_VALUE_EXAMINE ((uint16_t)0)

/** Encapsulation data length. */
#define IP_ENCAP_DATA_SIZE (sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t))

/** Parsed network address information. */
struct network_address {
	/** Address storage. */
	struct sockaddr_storage address;
	/** Used address storage. */
	socklen_t address_size;
	/** Listen mode otherwise connect. */
	bool listen;
	/** Error string (if function returned false). */
	char error[256];
};

/**
 * Parses a string and returns the formatted network address if successful.
 *
 * When the parse fails the function returns `false` and the parameter
 * `address` member `error` is set with the error message that occurred.
 *
 * When no port is present on the string the corresponding `sockaddr` port
 * field will be set to the provided `default_port`.  `default_port` is used
 * as-is and is not validated: a port explicitly written as `0` is rejected
 * (it is most likely a typo), but callers that have no meaningful default
 * may pass `0` to get the wildcard port.
 *
 * IPv6 addresses must be enclosed in `[]` and may carry a scope/zone
 * identifier (e.g. `ipv6:[fe80::1%eth0]:1234`), which is resolved with
 * `if_nametoindex()` and stored in `sin6_scope_id`.
 *
 * \param address_string the string to parse
 * \param address the formatted address output
 * \param default_port port to use if none found in string (IPv4/IPv6 only).
 * \returns `true` on success with address set in `address` members, otherwise
 *          `false` and error message in `address.error`.
 */
extern bool network_address_parse(const char *address_string, struct network_address *address,
				  uint16_t default_port);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NETWORK_H */
