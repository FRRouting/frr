// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IPv4 fragment reassembly tests.
 *
 * Exercises `ipv4_packet_assemble` and `ipv4_encap_parse` with the malformed
 * and hostile fragment patterns they are meant to reject. Every case here
 * guards a defect that was found in the assembler, so a failure means one of
 * them came back rather than that the test needs adjusting.
 *
 * Run under AddressSanitizer whenever possible: several cases only show up as
 * an out of bounds read, and the fragments are deliberately allocated with
 * the exact length that "arrived" so any over read is caught.
 *
 * Copyright (C) 2026 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/checksum.h"
#include "lib/command.h"
#include "lib/frrevent.h"
#include "lib/monotime.h"
#include "lib/network.h"

static struct event_loop *master;
static int failures;
static uint16_t next_id = 1;

/** Receiving interface of the fragments, unless a test says otherwise. */
#define TEST_IFINDEX 1

#define CHECK(cond, ...)                                                                          \
	do {                                                                                      \
		if (!(cond)) {                                                                    \
			printf("  FAIL: ");                                                       \
			printf(__VA_ARGS__);                                                      \
			printf("\n");                                                             \
			failures++;                                                               \
		}                                                                                 \
	} while (0)

/*
 * Builds one fragment in an allocation sized exactly to the amount of data
 * that "arrived", so reading past it trips the sanitizer.
 *
 * `total_length` is written to the header as is (it is one of the fields
 * under test) and may disagree with `datalen` on purpose.
 */
static uint8_t *fragment_new(uint8_t ihl, uint16_t total_length, uint16_t offset, bool mf,
			     uint8_t fill, size_t datalen, uint16_t id)
{
	uint8_t *buf = malloc(datalen);
	struct ipv4_header *ip;

	assert(buf);
	assert(datalen >= sizeof(struct ipv4_header));

	memset(buf, fill, datalen);

	ip = (struct ipv4_header *)buf;
	memset(ip, 0, sizeof(*ip));
	ipv4_set_version(ip);
	ipv4_set_header_length(ip, ihl);
	ip->total_length = htons(total_length);
	ip->id = htons(id);
	ip->fragmentation = htons((mf ? IPV4_MORE_FRAGMENTS : 0) | (offset >> 3));
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->source.s_addr = htonl(0x0A000001);
	ip->destination.s_addr = htonl(0x0A000002);
	ip->checksum = 0;
	/* Clamped: `ihl` may deliberately claim more than we allocated. */
	ip->checksum = in_cksum(ip, ihl < datalen ? ihl : datalen);

	return buf;
}

/*
 * Feeds one fragment received on `ifindex` and releases the input buffer
 * before returning, so the assembler keeping a pointer into it would show up
 * as a use after free.
 *
 * `out` is therefore only meaningful for `IPA_OK`, where it points at the
 * assembler's own buffer: it is cleared otherwise.
 */
static enum ip_packet_assemble_result feed_on(int32_t ifindex, uint8_t ihl, uint16_t total_length,
					      uint16_t offset, bool mf, uint8_t fill,
					      size_t datalen, uint16_t id, const uint8_t **out,
					      size_t *outlen)
{
	uint8_t *buf = fragment_new(ihl, total_length, offset, mf, fill, datalen, id);
	enum ip_packet_assemble_result result;

	result = ipv4_packet_assemble(buf, datalen, ifindex, out, outlen);
	free(buf);

	if (result != IPA_OK)
		*out = NULL;

	return result;
}

/* Feeds one fragment received on `TEST_IFINDEX` (see `feed_on`). */
static enum ip_packet_assemble_result feed(uint8_t ihl, uint16_t total_length, uint16_t offset,
					   bool mf, uint8_t fill, size_t datalen, uint16_t id,
					   const uint8_t **out, size_t *outlen)
{
	return feed_on(TEST_IFINDEX, ihl, total_length, offset, mf, fill, datalen, id, out, outlen);
}

/*
 * Runs up to `count` queued events and returns how many actually ran.
 *
 * `event_fetch` serves the immediate queue before polling, so queued clean up
 * events come back without blocking. It does block when that queue runs dry,
 * and the periodic clean up timer keeps rescheduling itself, so bail out once
 * time has clearly passed rather than pay `IP_PACKET_INACTIVE_INTERVAL` for
 * every event that was expected but never scheduled.
 */
static int run_events(int count)
{
	time_t deadline = monotime(NULL) + 2;
	struct event event;
	int i;

	for (i = 0; i < count; i++) {
		if (monotime(NULL) > deadline)
			break;

		if (!event_fetch(master, &event))
			break;

		event_call(&event);
	}

	return i;
}

/*
 * Returns the index of the first byte in the range that does not hold
 * `value`, or `len` when they all do.
 */
static size_t payload_mismatch(const uint8_t *data, size_t offset, size_t len, uint8_t value)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (data[offset + i] != value)
			break;
	}

	return i;
}

/*
 * Every completed datagram must get its own clean up event.
 *
 * A single shared event pointer only ever schedules one of them (the others
 * are dropped by `event_add_event`), leaving the remaining slots occupied
 * until the periodic timer runs.
 *
 * NOTE: this has to run before the tests that park incomplete datagrams,
 *       since those hold on to a slot until the periodic timer reaps them.
 */
static void test_cleanup_recycles_slots(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	int ran;
	int i;

	printf("clean up recycles every slot\n");

	/* Fill and complete every slot without running the event loop. */
	for (i = 0; i < PACKET_ASSEMBLY_IN_PROGRESS_MAX; i++) {
		uint16_t id = next_id++;

		feed(20, 44, 0, true, 0xAA, 44, id, &out, &outlen);
		result = feed(20, 44, 24, false, 0xBB, 44, id, &out, &outlen);
		CHECK(result == IPA_OK, "datagram %d: %s (must run before the other tests)", i,
		      ip_packet_assemble_result_str(result));
	}

	/*
	 * Every completion must have queued a clean up of its own, so draining
	 * them has to yield exactly one event per datagram.
	 */
	ran = run_events(PACKET_ASSEMBLY_IN_PROGRESS_MAX);
	CHECK(ran == PACKET_ASSEMBLY_IN_PROGRESS_MAX, "%d of %d clean up events were scheduled",
	      ran, PACKET_ASSEMBLY_IN_PROGRESS_MAX);

	/* So every slot has to be usable again. */
	for (i = 0; i < PACKET_ASSEMBLY_IN_PROGRESS_MAX; i++) {
		uint16_t id = next_id++;

		feed(20, 44, 0, true, 0xAA, 44, id, &out, &outlen);
		result = feed(20, 44, 24, false, 0xBB, 44, id, &out, &outlen);
		CHECK(result == IPA_OK, "datagram %d: %s (slot was not released)", i,
		      ip_packet_assemble_result_str(result));
	}

	run_events(PACKET_ASSEMBLY_IN_PROGRESS_MAX);
}

/*
 * A two fragment datagram, fed in both orders.
 *
 * Besides reassembly this checks the rebuilt header: `total_length` used to
 * be written in host byte order and the checksum was zeroed instead of being
 * recomputed.
 */
static void test_reassemble(bool reverse)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	const struct ipv4_header *ip;
	uint16_t id = next_id++;
	size_t bad;

	printf("reassembly, %s order\n", reverse ? "reverse" : "in");

	if (!reverse) {
		result = feed(20, 44, 0, true, 0xAA, 44, id, &out, &outlen);
		CHECK(result == IPA_OK_INCOMPLETE, "first fragment: %s",
		      ip_packet_assemble_result_str(result));
		result = feed(20, 44, 24, false, 0xBB, 44, id, &out, &outlen);
	} else {
		result = feed(20, 44, 24, false, 0xBB, 44, id, &out, &outlen);
		CHECK(result == IPA_OK_INCOMPLETE, "last fragment: %s",
		      ip_packet_assemble_result_str(result));
		result = feed(20, 44, 0, true, 0xAA, 44, id, &out, &outlen);
	}

	CHECK(result == IPA_OK, "datagram did not complete: %s",
	      ip_packet_assemble_result_str(result));
	if (result != IPA_OK)
		return;

	CHECK(outlen == 68, "length %zu, expected 68", outlen);

	ip = (const struct ipv4_header *)out;
	printf("  outlen=%zu total_length=%u checksum=%s\n", outlen, ntohs(ip->total_length),
	       in_cksum(out, ipv4_header_length(ip)) == 0 ? "valid" : "INVALID");

	CHECK(ntohs(ip->total_length) == outlen, "total_length is %u (raw 0x%04x), expected %zu",
	      ntohs(ip->total_length), ip->total_length, outlen);
	CHECK(in_cksum(out, ipv4_header_length(ip)) == 0,
	      "rebuilt header checksum does not validate");
	CHECK(!ipv4_more_fragments(ip) && ipv4_fragment_offset(ip) == 0,
	      "fragmentation field was not cleared");

	/* Payload must land at the offset each fragment announced. */
	bad = payload_mismatch(out, 20, 24, 0xAA);
	CHECK(bad == 24, "first fragment payload differs at byte %zu", bad);
	bad = payload_mismatch(out, 44, 24, 0xBB);
	CHECK(bad == 24, "second fragment payload differs at byte %zu", bad);

	run_events(1);
}

/*
 * Overlapping fragments must be refused in both directions. Checking only
 * the preceding fragment lets a fragment that overlaps the following one
 * through, which leaves a hole elsewhere while the sizes still add up.
 */
static void test_overlap(const char *name, uint16_t off1, uint16_t len1, uint16_t off2,
			 uint16_t len2)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	uint16_t id = next_id++;
	uint64_t before = ip_packet_stats.fragment_overlap;

	printf("%s: [%u,%u) then [%u,%u)\n", name, off1, off1 + len1, off2, off2 + len2);

	feed(20, 20 + len1, off1, true, 0xAA, 20 + len1, id, &out, &outlen);
	result = feed(20, 20 + len2, off2, true, 0xBB, 20 + len2, id, &out, &outlen);

	printf("  -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_FRAGMENT_OVERLAP, "expected IPA_FRAGMENT_OVERLAP, got %s",
	      ip_packet_assemble_result_str(result));
	CHECK(ip_packet_stats.fragment_overlap > before, "overlap was not accounted");
}

/*
 * A fragment reaching past the end announced by the last fragment, arranged
 * so the fragment sizes still add up to the announced total while leaving a
 * hole. Completing on the size sum alone would hand over a datagram with a
 * gap in the middle of its payload.
 */
static void test_beyond_end(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	uint16_t id = next_id++;

	printf("fragment past the announced end\n");

	/* Payload [200, 300). */
	feed(20, 120, 200, true, 0xCC, 120, id, &out, &outlen);
	/* Payload [0, 48). */
	feed(20, 68, 0, true, 0xAA, 68, id, &out, &outlen);
	/* Last fragment [48, 150): announces 150 while 250 bytes are held. */
	result = feed(20, 122, 48, false, 0xBB, 122, id, &out, &outlen);

	printf("  -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_FRAGMENT_OVERLAP, "expected IPA_FRAGMENT_OVERLAP, got %s",
	      ip_packet_assemble_result_str(result));
}

/*
 * A fragment carrying no payload (`total_length` equal to the header length)
 * must be refused: accepting it claims the offset in the fragment list and
 * locks out the real fragment for that offset, which is then taken for a
 * repeat. One such packet is enough to block a datagram.
 */
static void test_empty_fragment(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	uint16_t id = next_id++;

	printf("empty fragment must not claim an offset\n");

	result = feed(20, 20, 24, true, 0x00, 20, id, &out, &outlen);
	printf("  empty fragment at offset 24 -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_INVALID_FRAGMENTATION, "expected IPA_INVALID_FRAGMENTATION, got %s",
	      ip_packet_assemble_result_str(result));

	/* The real datagram, using that same offset, must still assemble. */
	feed(20, 44, 0, true, 0xAA, 44, id, &out, &outlen);
	feed(20, 44, 24, true, 0xBB, 44, id, &out, &outlen);
	result = feed(20, 44, 48, false, 0xCC, 44, id, &out, &outlen);

	printf("  real datagram -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_OK, "datagram was blocked by the empty fragment: %s",
	      ip_packet_assemble_result_str(result));

	run_events(1);
}

/*
 * `DF` together with `MF` or a non zero offset is contradictory. Such a
 * packet used to be handed over as not fragmented with its fragmentation
 * fields intact, which makes the caller parse fragment payload as protocol
 * headers.
 */
static void test_dont_fragment_with_more_fragments(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	struct ipv4_header *ip;
	uint8_t *buf;

	printf("DF together with MF/offset\n");

	buf = fragment_new(20, 44, 48, true, 0xAA, 44, next_id++);
	ip = (struct ipv4_header *)buf;
	ip->fragmentation = htons(IPV4_DONT_FRAGMENT | IPV4_MORE_FRAGMENTS | (48 >> 3));
	ip->checksum = 0;
	ip->checksum = in_cksum(ip, 20);

	result = ipv4_packet_assemble(buf, 44, TEST_IFINDEX, &out, &outlen);
	free(buf);

	printf("  -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_INVALID_FRAGMENTATION, "expected IPA_INVALID_FRAGMENTATION, got %s",
	      ip_packet_assemble_result_str(result));
}

/*
 * Fragments with the same identification received on different interfaces
 * belong to different datagrams: two VRFs may use the same addresses (and IP
 * IDs) at the same time, so they must neither complete nor spoil each other.
 */
static void test_interfaces_kept_apart(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	uint16_t id = next_id++;

	printf("same identification on different interfaces\n");

	result = feed_on(TEST_IFINDEX, 20, 44, 0, true, 0xAA, 44, id, &out, &outlen);
	CHECK(result == IPA_OK_INCOMPLETE, "first fragment: %s",
	      ip_packet_assemble_result_str(result));

	/* The last fragment from another interface must not complete it. */
	result = feed_on(TEST_IFINDEX + 1, 20, 44, 24, false, 0xCC, 44, id, &out, &outlen);
	CHECK(result == IPA_OK_INCOMPLETE, "other interface fragment: %s",
	      ip_packet_assemble_result_str(result));

	/* Nor take the offset slot of the datagram's own last fragment. */
	result = feed_on(TEST_IFINDEX, 20, 44, 24, false, 0xBB, 44, id, &out, &outlen);
	CHECK(result == IPA_OK, "datagram did not complete: %s",
	      ip_packet_assemble_result_str(result));
	if (result == IPA_OK)
		CHECK(payload_mismatch(out, 20 + 24, 24, 0xBB) == 24,
		      "second half holds the other interface's data");

	run_events(1);
}

/*
 * An un-fragmented packet must be reported with the length its header
 * announces, not the length of the read: a raw socket can hand us link layer
 * padding, and the caller would otherwise be pointed at it.
 */
static void test_trailing_bytes(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;

	printf("un-fragmented packet with trailing bytes\n");

	/* Header announces 28 bytes, 64 were read. */
	result = feed(20, 28, 0, false, 0xAA, 64, next_id++, &out, &outlen);

	printf("  -> %s outlen=%zu\n", ip_packet_assemble_result_str(result), outlen);
	CHECK(result == IPA_NOT_FRAGMENTED, "expected IPA_NOT_FRAGMENTED, got %s",
	      ip_packet_assemble_result_str(result));
	CHECK(outlen == 28, "length %zu, expected 28 (the announced packet length)", outlen);
}

/* Duplicated fragments must be reported and accounted, not dropped silently. */
static void test_duplicate_fragment(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;
	uint16_t id = next_id++;
	uint64_t before = ip_packet_stats.repeated_fragment;

	printf("duplicated fragment\n");

	feed(20, 44, 0, true, 0xAA, 44, id, &out, &outlen);
	result = feed(20, 44, 0, true, 0xAA, 44, id, &out, &outlen);

	printf("  -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_REPEATED_PACKET, "expected IPA_REPEATED_PACKET, got %s",
	      ip_packet_assemble_result_str(result));
	CHECK(ip_packet_stats.repeated_fragment > before, "duplicate was not accounted");
}

/*
 * A header length larger than what was read must be refused before the
 * checksum is computed over it, otherwise the checksum reads past the
 * received data.
 */
static void test_header_longer_than_read(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;

	printf("header length beyond the read length\n");

	/* Announces a 60 byte header, only 20 bytes arrived. */
	result = feed(60, 100, 8, true, 0xAA, 20, next_id++, &out, &outlen);

	printf("  -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_INVALID_HEADER_LENGTH, "expected IPA_INVALID_HEADER_LENGTH, got %s",
	      ip_packet_assemble_result_str(result));
}

/*
 * `total_length` smaller than the header length must be refused: the payload
 * length is derived from the difference and used to be an unsigned underflow
 * straight into a 64k `memcpy` from a much smaller buffer.
 */
static void test_length_below_header(void)
{
	const uint8_t *out = NULL;
	size_t outlen = 0;
	enum ip_packet_assemble_result result;

	printf("announced length below the header length\n");

	result = feed(20, 8, 8, true, 0xAA, 40, next_id++, &out, &outlen);

	printf("  -> %s\n", ip_packet_assemble_result_str(result));
	CHECK(result == IPA_INVALID_LENGTH, "expected IPA_INVALID_LENGTH, got %s",
	      ip_packet_assemble_result_str(result));
}

/*
 * Same class of problem in the encapsulation parser: the header plus the
 * encapsulation data that follows it must both be covered by what was read.
 */
static void test_encap_short_read(void)
{
	struct ipv4_encap_result rv;
	enum ip_encap_packet_assemble_result result;
	struct ipv4_header *ip;
	uint8_t whole[IPV4_MAXIMUM_HEADER_SIZE];
	uint8_t *truncated;

	printf("encapsulation header beyond the read length\n");

	memset(whole, 0, sizeof(whole));
	ip = (struct ipv4_header *)whole;
	ipv4_set_version(ip);
	ipv4_set_header_length(ip, sizeof(whole));
	ip->total_length = htons(sizeof(whole));
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->checksum = in_cksum(whole, sizeof(whole));

	/* Announces a 60 byte header, only 28 bytes arrived. */
	truncated = malloc(28);
	assert(truncated);
	memcpy(truncated, whole, 28);

	result = ipv4_encap_parse(truncated, 28, &rv);
	free(truncated);

	printf("  -> %d\n", result);
	CHECK(result == IEPA_INVALID_HEADER_LENGTH, "expected IEPA_INVALID_HEADER_LENGTH, got %d",
	      result);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	cmd_init(1);
	master = event_master_create("test_ip_assembly");
	ip_fragmentation_handler_init(master);

	/* Keep first: needs every assembly slot to be free. */
	test_cleanup_recycles_slots();

	test_reassemble(false);
	test_reassemble(true);
	test_overlap("overlap with the preceding fragment", 0, 24, 16, 24);
	test_overlap("overlap with the following fragment", 32, 24, 8, 32);
	test_beyond_end();
	test_empty_fragment();
	test_dont_fragment_with_more_fragments();
	test_trailing_bytes();
	test_interfaces_kept_apart();
	test_duplicate_fragment();
	test_header_longer_than_read();
	test_length_below_header();
	test_encap_short_read();

	printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASS", failures);

	return failures ? 1 : 0;
}
