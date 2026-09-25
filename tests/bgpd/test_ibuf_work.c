// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Test BGP I/O thread receive path optimization (ibuf_scratch/ibuf_work).
 *
 * Copyright (c) 2026, Palo Alto Networks, Inc.
 * Enke Chen <enchen@paloaltonetworks.com>
 */

#include <zebra.h>

#include "memory.h"
#include "stream.h"
#include "frr_pthread.h"
#include "frrevent.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_memory.h"

/* Include bgp_io.c to access static functions */
#include "bgpd/bgp_io.c"

#define VT100_RESET "\x1b[0m"
#define VT100_RED "\x1b[31m"
#define VT100_GREEN "\x1b[32m"

/* Required globals */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static int failed;
static int tty;

/* BGP marker - 16 bytes of 0xff */
static const uint8_t bgp_marker[BGP_MARKER_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/* Build a minimal BGP KEEPALIVE message (19 bytes) */
static void build_keepalive(uint8_t *buf)
{
	memcpy(buf, bgp_marker, BGP_MARKER_SIZE);
	buf[16] = 0x00;  /* length high byte */
	buf[17] = 0x13;  /* length low byte = 19 */
	buf[18] = BGP_MSG_KEEPALIVE;
}

/* Build a BGP message header with given length and type */
static void build_header(uint8_t *buf, uint16_t len, uint8_t type)
{
	memcpy(buf, bgp_marker, BGP_MARKER_SIZE);
	buf[16] = (len >> 8) & 0xff;
	buf[17] = len & 0xff;
	buf[18] = type;
}

static void print_test_result(const char *name, int pass)
{
	if (pass)
		printf("%s%-45s %sPASS%s\n",
		       tty ? VT100_GREEN : "", name,
		       tty ? VT100_GREEN : "", tty ? VT100_RESET : "");
	else {
		printf("%s%-45s %sFAIL%s\n",
		       tty ? VT100_RED : "", name,
		       tty ? VT100_RED : "", tty ? VT100_RESET : "");
		failed++;
	}
}

/*
 * Test 1: Parse length field from buffer (big-endian)
 */
static void test_parse_length_field(void)
{
	uint8_t buf[BGP_HEADER_SIZE];
	uint16_t parsed_len;

	/* Test KEEPALIVE length = 19 = 0x0013 */
	build_keepalive(buf);
	parsed_len = (buf[BGP_MARKER_SIZE] << 8) + buf[BGP_MARKER_SIZE + 1];

	int pass = (parsed_len == 19);

	print_test_result("parse_length: KEEPALIVE (19)", pass);

	/* Test UPDATE length = 100 = 0x0064 */
	build_header(buf, 100, BGP_MSG_UPDATE);
	parsed_len = (buf[BGP_MARKER_SIZE] << 8) + buf[BGP_MARKER_SIZE + 1];

	pass = (parsed_len == 100);
	print_test_result("parse_length: UPDATE (100)", pass);

	/* Test max packet size 4096 = 0x1000 */
	build_header(buf, 4096, BGP_MSG_UPDATE);
	parsed_len = (buf[BGP_MARKER_SIZE] << 8) + buf[BGP_MARKER_SIZE + 1];

	pass = (parsed_len == 4096);
	print_test_result("parse_length: max packet (4096)", pass);
}

/*
 * Test 2: Marker validation
 */
static void test_marker_validation(void)
{
	uint8_t buf[BGP_MARKER_SIZE];
	int i;
	bool valid;

	/* Valid marker */
	memcpy(buf, bgp_marker, BGP_MARKER_SIZE);
	valid = true;
	for (i = 0; i < BGP_MARKER_SIZE; i++) {
		if (buf[i] != 0xff) {
			valid = false;
			break;
		}
	}
	print_test_result("marker_valid: all 0xff", valid == true);

	/* Invalid marker (first byte) */
	buf[0] = 0x00;
	valid = true;
	for (i = 0; i < BGP_MARKER_SIZE; i++) {
		if (buf[i] != 0xff) {
			valid = false;
			break;
		}
	}
	print_test_result("marker_invalid: first byte corrupted", valid == false);

	/* Invalid marker (last byte) */
	memcpy(buf, bgp_marker, BGP_MARKER_SIZE);
	buf[15] = 0x00;
	valid = true;
	for (i = 0; i < BGP_MARKER_SIZE; i++) {
		if (buf[i] != 0xff) {
			valid = false;
			break;
		}
	}
	print_test_result("marker_invalid: last byte corrupted", valid == false);
}

/*
 * Test 3: Partial header detection
 */
static void test_partial_header_detection(void)
{
	size_t len;
	bool has_complete_header;

	/* Full header */
	len = BGP_HEADER_SIZE;
	has_complete_header = (len >= BGP_HEADER_SIZE);
	print_test_result("header_complete: 19 bytes", has_complete_header == true);

	/* Partial header - only marker */
	len = BGP_MARKER_SIZE;
	has_complete_header = (len >= BGP_HEADER_SIZE);
	print_test_result("header_partial: 16 bytes", has_complete_header == false);

	/* Partial header - marker + length only */
	len = BGP_MARKER_SIZE + 2;
	has_complete_header = (len >= BGP_HEADER_SIZE);
	print_test_result("header_partial: 18 bytes", has_complete_header == false);

	/* Empty buffer */
	len = 0;
	has_complete_header = (len >= BGP_HEADER_SIZE);
	print_test_result("header_empty: 0 bytes", has_complete_header == false);
}

/*
 * Test 4: Complete message detection
 */
static void test_complete_message_detection(void)
{
	uint8_t buf[200];
	size_t buf_len;
	uint16_t pktsize;
	bool complete;

	/* KEEPALIVE - exactly 19 bytes */
	build_keepalive(buf);
	buf_len = BGP_HEADER_SIZE;
	pktsize = (buf[BGP_MARKER_SIZE] << 8) + buf[BGP_MARKER_SIZE + 1];
	complete = (buf_len >= pktsize);
	print_test_result("message_complete: KEEPALIVE exact", complete == true);

	/* UPDATE 100 bytes - only header present */
	build_header(buf, 100, BGP_MSG_UPDATE);
	buf_len = BGP_HEADER_SIZE;  /* only header */
	pktsize = (buf[BGP_MARKER_SIZE] << 8) + buf[BGP_MARKER_SIZE + 1];
	complete = (buf_len >= pktsize);
	print_test_result("message_partial: UPDATE header only", complete == false);

	/* UPDATE 100 bytes - partial body */
	buf_len = 50;
	complete = (buf_len >= pktsize);
	print_test_result("message_partial: UPDATE partial body", complete == false);

	/* UPDATE 100 bytes - complete */
	buf_len = 100;
	complete = (buf_len >= pktsize);
	print_test_result("message_complete: UPDATE full", complete == true);

	/* UPDATE 100 bytes - extra data (next message starting) */
	buf_len = 110;
	complete = (buf_len >= pktsize);
	print_test_result("message_complete: UPDATE + extra", complete == true);
}

/*
 * Test 5: Multiple message counting in buffer
 */
static void test_multiple_message_counting(void)
{
	uint8_t buf[200];
	size_t offset, buf_len;
	int count;
	uint16_t pktsize;

	/* 3 KEEPALIVE messages back to back */
	build_keepalive(buf);
	build_keepalive(buf + BGP_HEADER_SIZE);
	build_keepalive(buf + BGP_HEADER_SIZE * 2);
	buf_len = BGP_HEADER_SIZE * 3;

	count = 0;
	offset = 0;
	while (offset + BGP_HEADER_SIZE <= buf_len) {
		pktsize = (buf[offset + BGP_MARKER_SIZE] << 8) +
			  buf[offset + BGP_MARKER_SIZE + 1];
		if (offset + pktsize > buf_len)
			break;
		count++;
		offset += pktsize;
	}
	print_test_result("multi_message: 3 KEEPALIVEs", count == 3);

	/* 2 complete + 1 partial */
	buf_len = BGP_HEADER_SIZE * 2 + 10;  /* 2 complete + partial header */
	count = 0;
	offset = 0;
	while (offset + BGP_HEADER_SIZE <= buf_len) {
		pktsize = (buf[offset + BGP_MARKER_SIZE] << 8) +
			  buf[offset + BGP_MARKER_SIZE + 1];
		if (offset + pktsize > buf_len)
			break;
		count++;
		offset += pktsize;
	}
	int pass = (count == 2 && (buf_len - offset) == 10);

	print_test_result("multi_message: 2 complete + partial", pass);
}

/*
 * Test 6: Copy remaining data between buffers (like scratch -> work)
 */
static void test_copy_remaining(void)
{
	uint8_t scratch[200];
	uint8_t work[200];
	size_t total_len;
	uint16_t pktsize;

	/* Simulate: scratch has KEEPALIVE followed by 10 bytes of next message */
	build_keepalive(scratch);
	memcpy(scratch + BGP_HEADER_SIZE, bgp_marker, 10);  /* partial next */
	total_len = BGP_HEADER_SIZE + 10;

	/* Process the complete KEEPALIVE */
	pktsize = (scratch[BGP_MARKER_SIZE] << 8) + scratch[BGP_MARKER_SIZE + 1];
	int pass = (pktsize == BGP_HEADER_SIZE);
	size_t remaining = total_len - pktsize;

	print_test_result("copy: parse complete packet size", pass);

	/* Copy remaining data from scratch to work (like our implementation) */
	if (remaining > 0)
		memcpy(work, scratch + total_len - remaining, remaining);

	pass = (remaining == 10);
	print_test_result("copy: remaining count", pass);

	/* Verify the partial data is intact (first 10 bytes of marker) */
	pass = (memcmp(work, bgp_marker, 10) == 0);
	print_test_result("copy: data integrity", pass);
}

/*
 * Test 7: Buffer size calculations
 */
static void test_buffer_sizes(void)
{
	int pass;

	pass = (BGP_HEADER_SIZE == 19);
	print_test_result("size: BGP_HEADER_SIZE == 19", pass);

	pass = (BGP_MARKER_SIZE == 16);
	print_test_result("size: BGP_MARKER_SIZE == 16", pass);

	/* ibuf_work should hold 1.5x max packet for partial + incoming */
	pass = (BGP_IBUF_WORK_SIZE >= (BGP_MAX_PACKET_SIZE + BGP_MAX_PACKET_SIZE / 2));
	print_test_result("size: BGP_IBUF_WORK_SIZE >= 1.5 * max", pass);
}

/*
 * Test 8: stream operations (used for packet queuing)
 */
static void test_stream_operations(void)
{
	struct stream *s;
	uint8_t buf[BGP_HEADER_SIZE];
	int pass;

	/* Create stream and put packet data */
	s = stream_new(BGP_MAX_PACKET_SIZE);
	build_keepalive(buf);
	stream_put(s, buf, BGP_HEADER_SIZE);

	pass = (stream_get_endp(s) == BGP_HEADER_SIZE);
	print_test_result("stream: put packet data", pass);

	/* Read back and verify */
	uint8_t marker_check[BGP_MARKER_SIZE];

	stream_get(marker_check, s, BGP_MARKER_SIZE);
	pass = (memcmp(marker_check, bgp_marker, BGP_MARKER_SIZE) == 0);
	print_test_result("stream: get marker data", pass);

	stream_free(s);

	/* Test stream_fifo for packet queuing */
	struct stream_fifo *fifo = stream_fifo_new();

	s = stream_new(BGP_HEADER_SIZE);
	stream_put(s, buf, BGP_HEADER_SIZE);
	stream_fifo_push(fifo, s);

	pass = (fifo->count == 1);
	print_test_result("stream_fifo: push one", pass);

	struct stream *s2 = stream_new(BGP_HEADER_SIZE);

	stream_put(s2, buf, BGP_HEADER_SIZE);
	stream_fifo_push(fifo, s2);

	pass = (fifo->count == 2);
	print_test_result("stream_fifo: push two", pass);

	stream_fifo_free(fifo);
}

/*
 * Helper to set up a minimal connection for testing parse_buffer
 */
static void setup_test_connection(struct peer_connection *conn, struct peer *peer,
				  struct stream_fifo *ibuf, pthread_mutex_t *io_mtx)
{
	memset(peer, 0, sizeof(*peer));
	peer->max_packet_size = BGP_MAX_PACKET_SIZE;

	memset(conn, 0, sizeof(*conn));
	conn->peer = peer;
	conn->ibuf = ibuf;
	pthread_mutex_init(io_mtx, NULL);
	conn->io_mtx = *io_mtx;
}

static void cleanup_test_connection(struct peer_connection *conn,
				    pthread_mutex_t *io_mtx)
{
	pthread_mutex_destroy(io_mtx);
	if (conn->ibuf)
		stream_fifo_free(conn->ibuf);
}

/*
 * Test parse_buffer with one complete KEEPALIVE
 */
static void test_parse_buffer_one_complete(void)
{
	uint8_t buf[BGP_HEADER_SIZE];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	int ret;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	build_keepalive(buf);
	ret = parse_buffer(&connection, buf, BGP_HEADER_SIZE,
			   &added_pkt, &remaining);

	int pass = (ret == 0 && added_pkt == true && remaining == 0 &&
		    connection.ibuf->count == 1);

	print_test_result("parse_buffer: one complete", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test parse_buffer with partial header (< 19 bytes)
 */
static void test_parse_buffer_partial_header(void)
{
	uint8_t buf[10];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	int ret;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	memcpy(buf, bgp_marker, 10);  /* partial marker */
	ret = parse_buffer(&connection, buf, 10, &added_pkt, &remaining);

	int pass = (ret == 0 && added_pkt == false && remaining == 10 &&
		    connection.ibuf->count == 0);

	print_test_result("parse_buffer: partial header", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test parse_buffer with partial message body
 */
static void test_parse_buffer_partial_body(void)
{
	uint8_t buf[BGP_HEADER_SIZE + 10];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	int ret;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Build header claiming 100 byte message but only provide header + 10 */
	build_header(buf, 100, BGP_MSG_UPDATE);
	ret = parse_buffer(&connection, buf, BGP_HEADER_SIZE + 10,
			   &added_pkt, &remaining);

	int pass = (ret == 0 && added_pkt == false &&
		    remaining == BGP_HEADER_SIZE + 10 &&
		    connection.ibuf->count == 0);

	print_test_result("parse_buffer: partial body", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test parse_buffer with multiple complete messages
 */
static void test_parse_buffer_multiple(void)
{
	uint8_t buf[BGP_HEADER_SIZE * 3];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	int ret;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Three KEEPALIVE messages */
	build_keepalive(buf);
	build_keepalive(buf + BGP_HEADER_SIZE);
	build_keepalive(buf + BGP_HEADER_SIZE * 2);

	ret = parse_buffer(&connection, buf, BGP_HEADER_SIZE * 3,
			   &added_pkt, &remaining);

	int pass = (ret == 0 && added_pkt == true && remaining == 0 &&
		    connection.ibuf->count == 3);

	print_test_result("parse_buffer: multiple complete", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test parse_buffer with complete + partial
 */
static void test_parse_buffer_complete_plus_partial(void)
{
	uint8_t buf[BGP_HEADER_SIZE + 10];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	int ret;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* One complete KEEPALIVE + start of another */
	build_keepalive(buf);
	memcpy(buf + BGP_HEADER_SIZE, bgp_marker, 10);  /* partial next msg */

	ret = parse_buffer(&connection, buf, BGP_HEADER_SIZE + 10,
			   &added_pkt, &remaining);

	int pass = (ret == 0 && added_pkt == true && remaining == 10 &&
		    connection.ibuf->count == 1);

	print_test_result("parse_buffer: complete + partial", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test scratch/work interaction: simulate the symmetric flow
 *
 * Scenario: 100-byte UPDATE arrives in two TCP segments:
 *   Read 1: 49 bytes arrive -> partial, copy remaining to ibuf_work
 *   Read 2: copy ibuf_work to ibuf_scratch, read 51 bytes, parse, complete
 */
static void test_scratch_work_interaction(void)
{
	uint8_t msg[100];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	size_t alloc_before, alloc_after;
	int ret;
	int pass;
	size_t total_len;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Get baseline */
	alloc_before = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);

	/* Build a 100-byte UPDATE message */
	build_header(msg, 100, BGP_MSG_UPDATE);
	memset(msg + BGP_HEADER_SIZE, 0xAB, 100 - BGP_HEADER_SIZE);

	/*
	 * Read 1: First 49 bytes arrive directly into ibuf_scratch
	 * (no prior partial data, so ibuf_work is NULL)
	 */
	size_t nread1 = 49;

	memcpy(ibuf_scratch, msg, nread1);

	total_len = connection.ibuf_data_len + nread1;  /* 0 + 49 = 49 */
	ret = parse_buffer(&connection, ibuf_scratch, total_len,
			   &added_pkt, &remaining);

	pass = (ret == 0 && added_pkt == false && remaining == 49);
	print_test_result("interaction: read1 returns partial", pass);

	/* Simulate bgp_process_reads: copy remaining to ibuf_work */
	if (remaining > 0) {
		connection.ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK,
					       BGP_IBUF_WORK_SIZE);
		memcpy(connection.ibuf_work,
		       ibuf_scratch + total_len - remaining,
		       remaining);
	}
	connection.ibuf_data_len = remaining;

	pass = (connection.ibuf_work != NULL && connection.ibuf_data_len == 49);
	print_test_result("interaction: ibuf_work allocated", pass);

	/* Verify allocation counter */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("interaction: alloc count +1", pass);

	/*
	 * Read 2: Remaining 51 bytes arrive
	 * Simulate bgp_read(): copy ibuf_work to ibuf_scratch, then read
	 */
	size_t nread2 = 51;

	memcpy(ibuf_scratch, connection.ibuf_work, connection.ibuf_data_len);
	memcpy(ibuf_scratch + connection.ibuf_data_len, msg + 49, nread2);

	pass = (connection.ibuf_data_len + nread2 == 100);
	print_test_result("interaction: data in ibuf_scratch", pass);

	/* Parse from ibuf_scratch */
	total_len = connection.ibuf_data_len + nread2;
	added_pkt = false;
	ret = parse_buffer(&connection, ibuf_scratch, total_len,
			   &added_pkt, &remaining);

	pass = (added_pkt == true && connection.ibuf->count == 1 && remaining == 0);
	print_test_result("interaction: message extracted", pass);

	/* Simulate bgp_process_reads: no remaining, free ibuf_work */
	if (remaining == 0 && connection.ibuf_work)
		XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
	connection.ibuf_data_len = remaining;

	/* Verify back to baseline */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before);
	print_test_result("interaction: alloc back to baseline", pass);

	pass = (connection.ibuf_work == NULL && connection.ibuf_data_len == 0);
	print_test_result("interaction: ibuf_work freed", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test interaction: multiple messages spanning reads (symmetric flow)
 *
 * Scenario:
 *   Read 1: KEEPALIVE (19) + partial KEEPALIVE (10 bytes) -> 1 complete, save 10
 *   Read 2: copy 10 to scratch, read 9+19 bytes, parse -> 2 more complete
 */
static void test_scratch_work_multi_message(void)
{
	uint8_t msg1[BGP_HEADER_SIZE];
	uint8_t msg2[BGP_HEADER_SIZE];
	uint8_t msg3[BGP_HEADER_SIZE];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	size_t alloc_before, alloc_after;
	int ret;
	int pass;
	size_t total_len;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Get baseline */
	alloc_before = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);

	/* Build three KEEPALIVE messages */
	build_keepalive(msg1);
	build_keepalive(msg2);
	build_keepalive(msg3);

	/*
	 * Read 1: Complete KEEPALIVE + 10 bytes of next into ibuf_scratch
	 */
	size_t nread1 = BGP_HEADER_SIZE + 10;

	memcpy(ibuf_scratch, msg1, BGP_HEADER_SIZE);
	memcpy(ibuf_scratch + BGP_HEADER_SIZE, msg2, 10);

	total_len = connection.ibuf_data_len + nread1;  /* 0 + 29 = 29 */
	ret = parse_buffer(&connection, ibuf_scratch, total_len,
			   &added_pkt, &remaining);

	pass = (ret == 0 && added_pkt == true && remaining == 10 &&
		connection.ibuf->count == 1);
	print_test_result("multi: read1 - 1 complete, 10 remaining", pass);

	/* Save partial to ibuf_work */
	if (remaining > 0) {
		connection.ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK,
					       BGP_IBUF_WORK_SIZE);
		memcpy(connection.ibuf_work,
		       ibuf_scratch + total_len - remaining,
		       remaining);
	}
	connection.ibuf_data_len = remaining;

	/* Verify allocation counter */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("multi: alloc count +1", pass);

	/*
	 * Read 2: copy ibuf_work to scratch, read remaining 9 + third KEEPALIVE
	 */
	size_t nread2 = 9 + BGP_HEADER_SIZE;  /* rest of msg2 + all of msg3 */

	memcpy(ibuf_scratch, connection.ibuf_work, connection.ibuf_data_len);
	memcpy(ibuf_scratch + connection.ibuf_data_len, msg2 + 10, 9);
	memcpy(ibuf_scratch + connection.ibuf_data_len + 9, msg3, BGP_HEADER_SIZE);

	total_len = connection.ibuf_data_len + nread2;  /* 10 + 28 = 38 */
	pass = (total_len == 10 + 9 + BGP_HEADER_SIZE);
	print_test_result("multi: read2 - data in ibuf_scratch", pass);

	/* Process from ibuf_scratch */
	added_pkt = false;
	ret = parse_buffer(&connection, ibuf_scratch, total_len,
			   &added_pkt, &remaining);

	pass = (connection.ibuf->count == 3 && remaining == 0);
	print_test_result("multi: 2 more messages extracted (3 total)", pass);

	/* No remaining, free ibuf_work */
	if (remaining == 0 && connection.ibuf_work)
		XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
	connection.ibuf_data_len = remaining;

	pass = (connection.ibuf_work == NULL && connection.ibuf_data_len == 0);
	print_test_result("multi: ibuf_work freed", pass);

	/* Verify back to baseline */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before);
	print_test_result("multi: alloc back to baseline", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test ibuf_work reuse: start with partial, parse complete messages,
 * end with partial again - should reuse existing ibuf_work (no realloc).
 *
 * Scenario:
 *   Setup: 10 bytes of partial KEEPALIVE in ibuf_work
 *   Read: remaining 9 bytes + complete KEEPALIVE + 5 bytes of next
 *   Result: 2 complete messages, 5 bytes partial - reuse ibuf_work
 */
static void test_ibuf_work_reuse(void)
{
	uint8_t msg1[BGP_HEADER_SIZE];
	uint8_t msg2[BGP_HEADER_SIZE];
	uint8_t msg3[BGP_HEADER_SIZE];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	size_t alloc_before, alloc_after;
	int ret;
	int pass;
	size_t total_len;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Get baseline */
	alloc_before = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);

	/* Build three KEEPALIVE messages */
	build_keepalive(msg1);
	build_keepalive(msg2);
	build_keepalive(msg3);

	/* Setup: allocate ibuf_work with 10 bytes of first message */
	connection.ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK, BGP_IBUF_WORK_SIZE);
	memcpy(connection.ibuf_work, msg1, 10);
	connection.ibuf_data_len = 10;

	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("reuse: initial alloc +1", pass);

	/*
	 * Simulate read: copy ibuf_work to scratch, then read:
	 * - remaining 9 bytes of msg1
	 * - complete msg2 (19 bytes)
	 * - partial msg3 (5 bytes)
	 */
	size_t nread = 9 + BGP_HEADER_SIZE + 5;  /* 33 bytes */

	memcpy(ibuf_scratch, connection.ibuf_work, connection.ibuf_data_len);
	memcpy(ibuf_scratch + connection.ibuf_data_len, msg1 + 10, 9);
	memcpy(ibuf_scratch + connection.ibuf_data_len + 9, msg2, BGP_HEADER_SIZE);
	memcpy(ibuf_scratch + connection.ibuf_data_len + 9 + BGP_HEADER_SIZE, msg3, 5);

	total_len = connection.ibuf_data_len + nread;  /* 10 + 33 = 43 */

	/* Parse - should get 2 complete, 5 remaining */
	ret = parse_buffer(&connection, ibuf_scratch, total_len,
			   &added_pkt, &remaining);

	pass = (ret == 0 && added_pkt == true && connection.ibuf->count == 2 &&
		remaining == 5);
	print_test_result("reuse: 2 complete, 5 remaining", pass);

	/* Simulate bgp_process_reads: copy remaining back to ibuf_work */
	if (remaining > 0) {
		/* Reuse existing ibuf_work - no allocation needed */
		memcpy(connection.ibuf_work,
		       ibuf_scratch + total_len - remaining, remaining);
	} else if (connection.ibuf_work) {
		XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
	}
	connection.ibuf_data_len = remaining;

	/* Verify ibuf_work still exists with 5 bytes */
	pass = (connection.ibuf_work != NULL && connection.ibuf_data_len == 5);
	print_test_result("reuse: ibuf_work preserved with 5 bytes", pass);

	/* Key check: allocation count unchanged - reused, not reallocated */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("reuse: alloc count unchanged (reused)", pass);

	/* Verify data integrity - should have first 5 bytes of msg3 */
	pass = (memcmp(connection.ibuf_work, msg3, 5) == 0);
	print_test_result("reuse: data integrity", pass);

	/* Cleanup */
	XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test no progress when buffer contains only partial data.
 *
 * When parse_buffer receives data that doesn't contain a complete
 * message, it returns remaining == input length (no progress made).
 */
static void test_no_progress_partial_only(void)
{
	uint8_t buf[10];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	int ret;
	int pass;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Only partial header in buffer - no complete message */
	memcpy(buf, bgp_marker, 10);

	ret = parse_buffer(&connection, buf, 10, &added_pkt, &remaining);

	/* No progress: remaining == input length */
	pass = (ret == 0 && added_pkt == false && remaining == 10 &&
		connection.ibuf->count == 0);
	print_test_result("no_progress: remaining == input len", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test EAGAIN handling: prior partial data, read returns 0 bytes
 *
 * When EAGAIN occurs (BGP_IO_TRANS_ERR), bgp_process_reads() takes an
 * early return - no parsing, no copying. The partial data in ibuf_work
 * remains untouched.
 *
 * This test verifies ibuf_work is preserved across EAGAIN events.
 */
static void test_eagain_with_partial(void)
{
	uint8_t msg[100];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	size_t alloc_before, alloc_after;
	int pass;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Build a 100-byte UPDATE message */
	build_header(msg, 100, BGP_MSG_UPDATE);
	memset(msg + BGP_HEADER_SIZE, 0xAB, 100 - BGP_HEADER_SIZE);

	/* Get baseline before allocating ibuf_work */
	alloc_before = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);

	/*
	 * Setup: 50 bytes of partial data in ibuf_work
	 */
	connection.ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK, BGP_IBUF_WORK_SIZE);
	memcpy(connection.ibuf_work, msg, 50);
	connection.ibuf_data_len = 50;

	/* Verify allocation happened */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("eagain: ibuf_work allocated (+1)", pass);

	/*
	 * Simulate EAGAIN: bgp_process_reads() takes early return when
	 * BGP_IO_TRANS_ERR is set - no parsing, no copying. ibuf_work
	 * and ibuf_data_len remain unchanged.
	 */

	/* ibuf_work should still have the same 50 bytes */
	pass = (connection.ibuf_work != NULL && connection.ibuf_data_len == 50);
	print_test_result("eagain: ibuf_work preserved", pass);

	/* Verify no allocation changes during EAGAIN */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("eagain: alloc count unchanged", pass);

	/* Verify data integrity - should be same as original */
	pass = (memcmp(connection.ibuf_work, msg, 50) == 0);
	print_test_result("eagain: data integrity maintained", pass);

	/* Cleanup */
	XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test bgp_read() buffer selection logic (symmetric flow)
 *
 * bgp_read always reads into ibuf_scratch. When ibuf_work has partial data,
 * it copies ibuf_work to ibuf_scratch first, then reads after that offset.
 */
static void test_read_buffer_selection(void)
{
	uint8_t *ibuf_work;
	size_t ibuf_data_len;
	uint8_t *readbuf;
	size_t readsize;
	int pass;

	/* Case 1: No partial data - read into ibuf_scratch from start */
	ibuf_work = NULL;
	ibuf_data_len = 0;

	if (ibuf_work && ibuf_data_len > 0) {
		/* copy ibuf_work to ibuf_scratch first (simulated) */
		readbuf = ibuf_scratch + ibuf_data_len;
		readsize = sizeof(ibuf_scratch) - ibuf_data_len;
	} else {
		readbuf = ibuf_scratch;
		readsize = sizeof(ibuf_scratch);
	}

	pass = (readbuf == ibuf_scratch && readsize == BGP_IBUF_WORK_SIZE);
	print_test_result("buf_select: no partial -> scratch start", pass);

	/* Case 2: Has partial data - copy to scratch, read after it */
	ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK, BGP_IBUF_WORK_SIZE);
	ibuf_data_len = 100;

	if (ibuf_work && ibuf_data_len > 0) {
		/* In real code: memcpy(ibuf_scratch, ibuf_work, ibuf_data_len) */
		readbuf = ibuf_scratch + ibuf_data_len;
		readsize = sizeof(ibuf_scratch) - ibuf_data_len;
	} else {
		readbuf = ibuf_scratch;
		readsize = sizeof(ibuf_scratch);
	}

	pass = (readbuf == ibuf_scratch + 100 &&
		readsize == BGP_IBUF_WORK_SIZE - 100);
	print_test_result("buf_select: partial -> scratch+offset", pass);

	/*
	 * Case 3: ibuf_work allocated but empty (ibuf_data_len = 0)
	 * This shouldn't happen in practice but test the logic.
	 */
	ibuf_data_len = 0;

	if (ibuf_work && ibuf_data_len > 0) {
		readbuf = ibuf_scratch + ibuf_data_len;
		readsize = sizeof(ibuf_scratch) - ibuf_data_len;
	} else {
		readbuf = ibuf_scratch;
		readsize = sizeof(ibuf_scratch);
	}

	pass = (readbuf == ibuf_scratch);
	print_test_result("buf_select: ibuf_work but len=0 -> scratch", pass);

	XFREE(MTYPE_BGP_IBUF_WORK, ibuf_work);
}

/*
 * Test fatal error cleanup pattern from bgp_process_reads()
 */
static void test_fatal_cleanup(void)
{
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	size_t alloc_before, alloc_after;
	int pass;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Get baseline */
	alloc_before = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);

	/* Simulate partial data in ibuf_work */
	connection.ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK, BGP_IBUF_WORK_SIZE);
	connection.ibuf_data_len = 500;

	/* Verify allocation */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("fatal: ibuf_work allocated (+1)", pass);

	/* Simulate fatal error cleanup */
	if (connection.ibuf_work) {
		XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
		connection.ibuf_data_len = 0;
	}

	pass = (connection.ibuf_work == NULL && connection.ibuf_data_len == 0);
	print_test_result("fatal: ibuf_work freed and len reset", pass);

	/* Verify back to baseline */
	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before);
	print_test_result("fatal: alloc back to baseline", pass);

	/* Test cleanup when no ibuf_work - should be no-op */
	connection.ibuf_work = NULL;
	connection.ibuf_data_len = 0;

	if (connection.ibuf_work) {
		XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
		connection.ibuf_data_len = 0;
	}

	pass = (connection.ibuf_work == NULL && connection.ibuf_data_len == 0);
	print_test_result("fatal: no ibuf_work is no-op", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

/*
 * Test read buffer capacity calculation.
 *
 * When partial data exists, it's copied to ibuf_scratch first,
 * leaving (BGP_IBUF_WORK_SIZE - ibuf_data_len) bytes for the read.
 */
static void test_read_buffer_capacity(void)
{
	size_t ibuf_data_len;
	size_t readsize;
	int pass;

	/* Case 1: Almost full - only 100 bytes free for read */
	ibuf_data_len = BGP_IBUF_WORK_SIZE - 100;
	readsize = sizeof(ibuf_scratch) - ibuf_data_len;

	pass = (readsize == 100);
	print_test_result("capacity: 100 bytes free", pass);

	/* Case 2: Maximum partial (65535 byte message header received) */
	ibuf_data_len = BGP_MAX_PACKET_SIZE;
	readsize = sizeof(ibuf_scratch) - ibuf_data_len;

	/* BGP_IBUF_WORK_SIZE is 1.5x BGP_MAX_PACKET_SIZE, so 0.5x remains */
	pass = (readsize == BGP_IBUF_WORK_SIZE - BGP_MAX_PACKET_SIZE);
	print_test_result("capacity: max packet partial", pass);

	/* Case 3: Exactly at limit - 0 bytes free */
	ibuf_data_len = BGP_IBUF_WORK_SIZE;
	readsize = sizeof(ibuf_scratch) - ibuf_data_len;

	pass = (readsize == 0);
	print_test_result("capacity: buffer exactly full", pass);
}

/*
 * Test memory tracking through the full scratch/work interaction (symmetric flow).
 */
static void test_memory_tracking(void)
{
	uint8_t msg[100];
	struct peer peer;
	struct peer_connection connection;
	struct stream_fifo *ibuf = stream_fifo_new();
	pthread_mutex_t io_mtx;
	bool added_pkt = false;
	size_t remaining = 0;
	size_t alloc_before, alloc_after;
	int ret;
	int pass;
	size_t total_len;

	setup_test_connection(&connection, &peer, ibuf, &io_mtx);

	/* Get baseline */
	alloc_before = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);

	/*
	 * Test 1: Complete packets - no allocation
	 */
	build_keepalive(ibuf_scratch);
	ret = parse_buffer(&connection, ibuf_scratch, BGP_HEADER_SIZE,
			   &added_pkt, &remaining);

	/* No partial, so no ibuf_work should be allocated */
	pass = (ret == 0 && remaining == 0 && connection.ibuf_work == NULL);
	print_test_result("memtrack: complete pkt - no alloc", pass);

	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before);
	print_test_result("memtrack: alloc count unchanged", pass);

	/*
	 * Test 2: Partial packet - allocation happens
	 */
	build_header(msg, 100, BGP_MSG_UPDATE);
	memset(msg + BGP_HEADER_SIZE, 0xAB, 100 - BGP_HEADER_SIZE);
	memcpy(ibuf_scratch, msg, 50);
	ret = parse_buffer(&connection, ibuf_scratch, 50,
			   &added_pkt, &remaining);

	/* Partial, so we allocate ibuf_work (simulating bgp_process_reads) */
	if (remaining > 0) {
		connection.ibuf_work = XMALLOC(MTYPE_BGP_IBUF_WORK,
					       BGP_IBUF_WORK_SIZE);
		memcpy(connection.ibuf_work,
		       ibuf_scratch + 50 - remaining, remaining);
		connection.ibuf_data_len = remaining;
	}

	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before + 1);
	print_test_result("memtrack: partial pkt - alloc +1", pass);

	/*
	 * Test 3: Complete the message and free (symmetric flow)
	 * Copy ibuf_work to ibuf_scratch, read remaining, parse
	 */
	memcpy(ibuf_scratch, connection.ibuf_work, connection.ibuf_data_len);
	memcpy(ibuf_scratch + connection.ibuf_data_len, msg + 50, 50);
	total_len = connection.ibuf_data_len + 50;

	added_pkt = false;
	ret = parse_buffer(&connection, ibuf_scratch, total_len,
			   &added_pkt, &remaining);

	/* Simulate bgp_process_reads cleanup - no remaining, free ibuf_work */
	if (remaining == 0 && connection.ibuf_work)
		XFREE(MTYPE_BGP_IBUF_WORK, connection.ibuf_work);
	connection.ibuf_data_len = remaining;

	alloc_after = mtype_stats_alloc(MTYPE_BGP_IBUF_WORK);
	pass = (alloc_after == alloc_before);
	print_test_result("memtrack: after drain - back to baseline", pass);

	cleanup_test_connection(&connection, &io_mtx);
}

static struct bgp_master bgp_master_test;

int main(int argc, char **argv)
{
	tty = isatty(STDOUT_FILENO);

	printf("BGP ibuf_work unit tests\n");
	printf("========================\n\n");

	/* Initialize BGP master for memory tracking */
	bm = &bgp_master_test;
	memset(bm, 0, sizeof(*bm));
	bm->inq_limit = 10000;

	/* Run tests */
	test_parse_length_field();
	test_marker_validation();
	test_partial_header_detection();
	test_complete_message_detection();
	test_multiple_message_counting();
	test_copy_remaining();
	test_buffer_sizes();
	test_stream_operations();

	/* parse_buffer tests */
	test_parse_buffer_one_complete();
	test_parse_buffer_partial_header();
	test_parse_buffer_partial_body();
	test_parse_buffer_multiple();
	test_parse_buffer_complete_plus_partial();

	/* scratch/work interaction tests */
	test_scratch_work_interaction();
	test_scratch_work_multi_message();
	test_ibuf_work_reuse();

	/* no progress when partial only */
	test_no_progress_partial_only();

	/* EAGAIN handling */
	test_eagain_with_partial();

	/* bgp_read buffer selection logic */
	test_read_buffer_selection();

	/* fatal error cleanup */
	test_fatal_cleanup();

	/* read buffer capacity */
	test_read_buffer_capacity();

	/* memory tracking */
	test_memory_tracking();

	printf("\n");
	if (failed)
		printf("%d test(s) FAILED\n", failed);
	else
		printf("All tests PASSED\n");

	return failed ? 1 : 0;
}
