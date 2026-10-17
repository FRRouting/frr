// SPDX-License-Identifier: GPL-2.0-or-later
/* SRv6 SID notification decoder: caller buffers and stream boundaries. */

#include <zebra.h>

#include "stream.h"
#include "zclient.h"

static struct stream *notification(const char *name, size_t len)
{
	struct stream *s = stream_new(1024);
	struct srv6_sid_ctx ctx = {0};
	struct in6_addr sid;
	enum zapi_srv6_sid_notify note = ZAPI_SRV6_SID_ALLOCATED;

	ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_X;
	ctx.ifindex = 42;
	assert(inet_pton(AF_INET6, "2001:db8::1", &sid) == 1);
	stream_put(s, &note, sizeof(note));
	stream_put(s, &ctx, sizeof(ctx));
	stream_put(s, &sid, sizeof(sid));
	stream_putl(s, 0xe000);
	stream_putl(s, 0x12345678);
	stream_putw(s, len);
	stream_put(s, name, len);
	return s;
}

static bool decode(struct stream *s, char *name, size_t size)
{
	struct srv6_sid_ctx ctx;
	struct in6_addr sid, expected;
	enum zapi_srv6_sid_notify note;
	uint32_t func, wide_func;
	bool success;

	success = zapi_srv6_sid_notify_decode(s, &ctx, &sid, &func,
					    &wide_func, &note, name, size);
	if (success) {
		assert(ctx.behavior == ZEBRA_SEG6_LOCAL_ACTION_END_X);
		assert(ctx.ifindex == 42);
		assert(inet_pton(AF_INET6, "2001:db8::1", &expected) == 1);
		assert(IPV6_ADDR_SAME(&sid, &expected));
		assert(func == 0xe000 && wide_func == 0x12345678);
		assert(note == ZAPI_SRV6_SID_ALLOCATED);
		assert(STREAM_READABLE(s) == 0);
	}
	return success;
}

static void test_names(void)
{
	static const char *const names[] = {"CLASSIC_LONG", "USID", "USID", "CLASSIC_LONG", ""};
	char name[SRV6_LOCNAME_SIZE], second[SRV6_LOCNAME_SIZE];
	struct stream *s;

	memset(name, 0xa5, sizeof(name));
	memset(second, 0xa5, sizeof(second));
	for (size_t i = 0; i < array_size(names); i++) {
		s = notification(names[i], strlen(names[i]));
		assert(decode(s, name, sizeof(name)));
		assert(!memcmp(name, names[i], strlen(names[i]) + 1));
		stream_free(s);
	}
	printf("Names decode without stale suffixes.\n");

	s = notification("FIRST", 5);
	assert(decode(s, name, sizeof(name)));
	stream_free(s);
	s = notification("SECOND", 6);
	assert(decode(s, second, sizeof(second)));
	assert(!strcmp(name, "FIRST") && !strcmp(second, "SECOND"));
	stream_free(s);
	printf("Caller buffers retain independent names.\n");
}

static void assert_untouched_tail(const char *name, size_t size)
{
	for (size_t i = size; i < SRV6_LOCNAME_SIZE; i++)
		assert((unsigned char)name[i] == 0xa5);
}

static void test_boundaries(void)
{
	struct {
		uint8_t before;
		char name[SRV6_LOCNAME_SIZE];
		uint8_t after;
	} guarded;
	char payload[SRV6_LOCNAME_SIZE + 1];
	struct stream *s;

	memset(payload, 'A', sizeof(payload));
	memset(&guarded, 0xa5, sizeof(guarded));
	s = notification(payload, SRV6_LOCNAME_SIZE - 1);
	assert(decode(s, guarded.name, sizeof(guarded.name)));
	assert(!memcmp(guarded.name, payload, SRV6_LOCNAME_SIZE - 1));
	assert(guarded.name[SRV6_LOCNAME_SIZE - 1] == '\0');
	assert(guarded.before == 0xa5 && guarded.after == 0xa5);
	stream_free(s);

	for (size_t len = SRV6_LOCNAME_SIZE; len <= sizeof(payload); len++) {
		memset(&guarded, 0xa5, sizeof(guarded));
		s = notification(payload, len);
		assert(!decode(s, guarded.name, sizeof(guarded.name)));
		assert(guarded.before == 0xa5 && guarded.after == 0xa5);
		stream_free(s);
	}
	for (size_t size = 0; size <= 4; size += 4) {
		memset(&guarded, 0xa5, sizeof(guarded));
		s = notification("MAIN", 4);
		assert(!decode(s, guarded.name, size));
		assert_untouched_tail(guarded.name, size);
		assert(guarded.before == 0xa5 && guarded.after == 0xa5);
		stream_free(s);
	}
	memset(&guarded, 0xa5, sizeof(guarded));
	s = notification("MAIN", 4);
	assert(decode(s, guarded.name, 5));
	assert(!memcmp(guarded.name, "MAIN", 5));
	assert_untouched_tail(guarded.name, 5);
	assert(guarded.before == 0xa5 && guarded.after == 0xa5);
	stream_free(s);
	memset(&guarded, 0xa5, sizeof(guarded));
	s = notification("", 0);
	assert(!decode(s, guarded.name, 0));
	assert_untouched_tail(guarded.name, 0);
	assert(guarded.before == 0xa5 && guarded.after == 0xa5);
	stream_free(s);
	memset(&guarded, 0xa5, sizeof(guarded));
	s = notification("", 0);
	assert(decode(s, guarded.name, 1));
	assert(guarded.name[0] == '\0');
	assert_untouched_tail(guarded.name, 1);
	assert(guarded.before == 0xa5 && guarded.after == 0xa5);
	stream_free(s);
	printf("Buffer boundaries reserve space for the terminator.\n");
}

static void test_skip_and_truncation(void)
{
	char name[SRV6_LOCNAME_SIZE];
	struct stream *s;
	size_t end;

	for (size_t len = 0; len <= 4; len += 4) {
		s = notification("MAIN", len);
		assert(decode(s, NULL, 0));
		stream_free(s);
	}
	printf("Unused names are consumed.\n");

	s = notification("MAIN", 4);
	end = stream_get_endp(s);
	stream_free(s);
	for (size_t len = 0; len < end; len++) {
		for (unsigned int want_name = 0; want_name < 2; want_name++) {
			s = notification("MAIN", 4);
			stream_set_endp(s, len);
			assert(!decode(s, want_name ? name : NULL,
				       want_name ? sizeof(name) : 0));
			stream_free(s);
		}
	}
	s = notification("RECOVERED", 9);
	assert(decode(s, name, sizeof(name)));
	assert(!strcmp(name, "RECOVERED"));
	stream_free(s);
	printf("Truncated notifications fail and do not poison later decodes.\n");
}

int main(void)
{
	test_names();
	test_boundaries();
	test_skip_and_truncation();
	return 0;
}
