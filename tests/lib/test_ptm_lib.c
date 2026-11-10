// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ptm_lib key lookup unit test
 * Copyright (C) 2026  NVIDIA Corporation
 */

#include <zebra.h>

#include <sys/socket.h>

#include "lib/csv.h"
#include "lib/ptm_lib.h"
#include "lib/printfrr.h"

static void check_lookup(void *ctxt, const char *key, size_t val_len, int expected_rc,
			 const char *expected_value)
{
	struct {
		char value[128];
		unsigned char guard[16];
	} checked;
	size_t i;
	int rc;

	assert(val_len <= sizeof(checked.value));
	memset(&checked, 0xcc, sizeof(checked));

	rc = ptm_lib_find_key_in_msg(ctxt, key, checked.value, val_len);
	assert(rc == expected_rc);
	assert(strnlen(checked.value, val_len) < val_len);
	assert(!strcmp(checked.value, expected_value));

	for (i = val_len; i < sizeof(checked.value); i++)
		assert((unsigned char)checked.value[i] == 0xcc);
	for (i = 0; i < sizeof(checked.guard); i++)
		assert(checked.guard[i] == 0xcc);
}

static void test_find_key(ptm_lib_handle_t *hdl)
{
	char long_value[256];
	char truncated[32];
	void *ctxt = NULL;

	memset(long_value, 'A', sizeof(long_value) - 1);
	long_value[sizeof(long_value) - 1] = '\0';
	memset(truncated, 'A', sizeof(truncated) - 1);
	truncated[sizeof(truncated) - 1] = '\0';

	assert(ptm_lib_init_msg(hdl, 0, PTMLIB_MSG_TYPE_NOTIFICATION, NULL, &ctxt) == 0);
	assert(ctxt);
	assert(ptm_lib_append_msg(hdl, ctxt, "status", "pass") == 0);
	assert(ptm_lib_append_msg(hdl, ctxt, "long", long_value) == 0);
	assert(ptm_lib_append_msg(hdl, ctxt, "command", "short") == 0);
	assert(ptm_lib_append_msg(hdl, ctxt, "", "empty") == 0);

	check_lookup(ctxt, "status", 32, 0, "pass");
	check_lookup(ctxt, "long", sizeof(truncated), 0, truncated);
	check_lookup(ctxt, "long", 1, 0, "");

	check_lookup(ctxt, "command", 32, 0, "short");
	check_lookup(ctxt, "comm", 32, -1, "");
	check_lookup(ctxt, "command-extra", 32, -1, "");
	check_lookup(ctxt, "missing", 32, -1, "");

	assert(ptm_lib_find_key_in_msg(NULL, "status", long_value, 32) == -1);
	assert(ptm_lib_find_key_in_msg(ctxt, NULL, long_value, 32) == -1);
	assert(ptm_lib_find_key_in_msg(ctxt, "status", NULL, 32) == -1);
	assert(ptm_lib_find_key_in_msg(ctxt, "status", long_value, 0) == -1);

	assert(ptm_lib_cleanup_msg(hdl, ctxt) == 0);
}

static void test_empty_csv_record(void)
{
	csv_field_t *field = NULL;
	csv_record_t *record;
	csv_t *csv;

	csv = csv_init(NULL, NULL, PTMLIB_MSG_SZ);
	assert(csv);
	record = csv_append_record(csv, NULL, 0);
	assert(record);
	assert(csv_field_iter(record, &field) == NULL);
	assert(field == NULL);

	csv_clean(csv);
	csv_free(csv);
}

/*
 * Raw messages delivered over a socket, the way zebra receives them from
 * ptmd: a fixed-size header line followed by a header record and a data
 * record.  The lookup runs inside the notification callback.
 */
struct raw_case {
	const char *name;
	const char *body;
	const char *key;
	int expected_rc;
	const char *expected_value;
};

/* Mirrors ZEBRA_PTM_MAX_SOCKBUF, the buffer zebra reads PTM messages into. */
#define RAW_SOCKBUF 3200

static const struct raw_case *raw_current;
static int raw_notifications;

static int raw_notify_cb(void *arg, void *ctxt)
{
	assert(arg == &raw_notifications);
	assert(raw_current);
	raw_notifications++;
	check_lookup(ctxt, raw_current->key, 32, raw_current->expected_rc,
		     raw_current->expected_value);
	return 0;
}

static void send_raw(ptm_lib_handle_t *hdl, const struct raw_case *tc)
{
	char inbuf[RAW_SOCKBUF];
	char hdr[PTMLIB_MSG_HDR_LEN + 1];
	int fds[2];
	size_t body_len = strlen(tc->body);
	int before = raw_notifications;

	assert(body_len < sizeof(inbuf));
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

	snprintfrr(hdr, sizeof(hdr), "%4d,%4d,%4d,%4d,%16.16s\n",
		   (int)body_len, PTMLIB_MSG_VERSION, PTMLIB_MSG_TYPE_NOTIFICATION, 0, "ptmd");
	assert(strlen(hdr) == PTMLIB_MSG_HDR_LEN);
	assert(write(fds[0], hdr, PTMLIB_MSG_HDR_LEN) == PTMLIB_MSG_HDR_LEN);
	assert(write(fds[0], tc->body, body_len) == (ssize_t)body_len);

	/* stale content from an earlier message, as in a reused buffer */
	memset(inbuf, 'Z', sizeof(inbuf));

	raw_current = tc;
	printf("raw: %s\n", tc->name);
	assert(ptm_lib_process_msg(hdl, fds[1], inbuf, sizeof(inbuf),
				   &raw_notifications) > 0);
	assert(raw_notifications == before + 1);
	raw_current = NULL;

	close(fds[0]);
	close(fds[1]);
}

static void test_raw_messages(ptm_lib_handle_t *hdl)
{
	static char long_value[16 + 500 + 6 + 1];
	static char long_line[1100 + 3 + 1];
	char truncated[32];
	const struct raw_case cases[] = {
		{
			.name = "well-formed notification",
			.body = "cmd_status,port\npass,swp1\n",
			.key = "port",
			.expected_rc = 0,
			.expected_value = "swp1",
		},
		{
			.name = "500 byte value into a 32 byte buffer",
			.body = long_value,
			.key = "cmd_status",
			.expected_rc = 0,
			.expected_value = truncated,
		},
		{
			.name = "empty header field",
			.body = ",port\nx,swp1\n",
			.key = "cmd_status",
			.expected_rc = -1,
			.expected_value = "",
		},
		{
			.name = "1100 byte line without a comma",
			.body = long_line,
			.key = "cmd_status",
			.expected_rc = -1,
			.expected_value = "",
		},
	};
	size_t i;

	/* "cmd_status,port\n" + 500 x 'Y' + ",swp1\n" */
	memcpy(long_value, "cmd_status,port\n", 16);
	memset(long_value + 16, 'Y', 500);
	memcpy(long_value + 16 + 500, ",swp1\n", 7);
	memset(truncated, 'Y', sizeof(truncated) - 1);
	truncated[sizeof(truncated) - 1] = '\0';

	/*
	 * csv_decode() copies each record into a PTMLIB_MSG_SZ buffer, so a
	 * comma-less line this long loses its newline and decodes to a
	 * record without any field.
	 */
	memset(long_line, 'B', 1100);
	memcpy(long_line + 1100, "\nx\n", 4);

	for (i = 0; i < array_size(cases); i++)
		send_raw(hdl, &cases[i]);
}

/*
 * Message lengths that must be refused before any body is read.  A guard
 * byte right past the input buffer catches the NUL terminator that
 * ptm_lib_process_msg() writes at inbuf[len].
 */
#define GUARD_BYTE 0xa5

static void send_length(ptm_lib_handle_t *hdl, const char *name, int inlen, const char *hdr,
			const char *body, size_t body_len, int expected_errno)
{
	struct {
		char buf[RAW_SOCKBUF];
		unsigned char guard[16];
	} in;
	unsigned char *guard;
	int fds[2];
	int before = raw_notifications;
	int rc;

	assert(inlen > PTMLIB_MSG_HDR_LEN && inlen <= RAW_SOCKBUF);
	guard = inlen < RAW_SOCKBUF ? (unsigned char *)&in.buf[inlen] : in.guard;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	assert(write(fds[0], hdr, PTMLIB_MSG_HDR_LEN) == PTMLIB_MSG_HDR_LEN);
	if (body_len)
		assert(write(fds[0], body, body_len) == (ssize_t)body_len);

	memset(&in, 'Z', sizeof(in));
	*guard = GUARD_BYTE;

	printf("length: %s\n", name);
	errno = 0;
	rc = ptm_lib_process_msg(hdl, fds[1], in.buf, inlen, &raw_notifications);
	assert(rc == -1);
	/* 0 means errno is unspecified on this path, do not check it */
	if (expected_errno)
		assert(errno == expected_errno);
	assert(*guard == GUARD_BYTE);
	assert(raw_notifications == before);

	close(fds[0]);
	close(fds[1]);
}

static void test_bad_lengths(ptm_lib_handle_t *hdl)
{
	char hdr[PTMLIB_MSG_HDR_LEN + 1];
	static char body[RAW_SOCKBUF];
	static const int msglens[] = { -1, 0, RAW_SOCKBUF };
	static const char *const names[] = { "negative framed length", "zero framed length",
					     "buffer-sized framed length" };
	size_t i;

	memset(body, 'A', sizeof(body));

	/*
	 * Framed messages: the length in the header is rejected with
	 * EBADMSG so that zebra drops the connection.  The last case sends
	 * a body that fills the buffer exactly, which puts the terminator
	 * one byte past it when the length is accepted.
	 */
	for (i = 0; i < array_size(msglens); i++) {
		snprintfrr(hdr, sizeof(hdr), "%4d,%4d,%4d,%4d,%16.16s\n", msglens[i],
			   PTMLIB_MSG_VERSION, PTMLIB_MSG_TYPE_NOTIFICATION, 0, "ptmd");
		assert(strlen(hdr) == PTMLIB_MSG_HDR_LEN);
		send_length(hdl, names[i], RAW_SOCKBUF, hdr, body,
			    msglens[i] > 0 ? (size_t)msglens[i] : 0, EBADMSG);
	}

	/*
	 * Legacy command: a header that does not decode as CSV makes the
	 * rest of the buffer be read as a plain text command.  Send enough
	 * to fill a 64 byte buffer; the read must stop one byte short so the
	 * terminator stays inside it.  The command is unknown, so the result
	 * is -1; errno is not set by that path and allocator internals may
	 * leave anything in it, so it is not checked.
	 */
	memset(hdr, 'x', PTMLIB_MSG_HDR_LEN);
	hdr[PTMLIB_MSG_HDR_LEN - 1] = '\n';
	hdr[PTMLIB_MSG_HDR_LEN] = '\0';
	memset(body, 'x', 64 - PTMLIB_MSG_HDR_LEN);
	send_length(hdl, "legacy command filling the buffer", 64, hdr, body,
		    64 - PTMLIB_MSG_HDR_LEN, 0);
}

int main(int argc, char **argv)
{
	ptm_lib_handle_t *hdl;
	char client_name[] = "test";

	hdl = ptm_lib_register(client_name, NULL, raw_notify_cb, NULL);
	assert(hdl);

	test_find_key(hdl);
	test_empty_csv_record();
	test_raw_messages(hdl);
	test_bad_lengths(hdl);

	ptm_lib_deregister(hdl);
	printf("done\n");
	return 0;
}
