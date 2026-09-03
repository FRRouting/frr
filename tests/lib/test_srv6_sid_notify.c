// SPDX-License-Identifier: GPL-2.0-or-later
/* SRv6 SID notification representation flags. */

#include <zebra.h>

#include "stream.h"
#include "zclient.h"

static const char locator_name[] = "MAIN";

static struct stream *notification(bool with_flags)
{
	struct stream *s = stream_new(256);
	struct srv6_sid_ctx ctx = {0};
	struct in6_addr sid = IN6ADDR_ANY_INIT;
	enum zapi_srv6_sid_notify note = ZAPI_SRV6_SID_ALLOCATED;

	stream_put(s, &note, sizeof(note));
	stream_put(s, &ctx, sizeof(ctx));
	stream_put(s, &sid, sizeof(sid));
	stream_putl(s, 0xe000);
	stream_putl(s, 0);
	stream_putw(s, sizeof(locator_name) - 1);
	stream_put(s, locator_name, sizeof(locator_name) - 1);
	if (with_flags)
		stream_putc(s, ZAPI_SRV6_MANAGER_SID_FLAG_IS_LOCALONLY);

	return s;
}

int main(void)
{
	struct srv6_sid_ctx ctx;
	struct in6_addr sid;
	enum zapi_srv6_sid_notify note;
	char locator[sizeof(locator_name)];
	uint8_t flags = 0;
	struct stream *s;

	s = notification(true);
	assert(zapi_srv6_sid_notify_decode(s, &ctx, &sid, NULL, NULL, &note,
					   locator, sizeof(locator), &flags));
	assert(!strcmp(locator, locator_name));
	assert(flags == ZAPI_SRV6_MANAGER_SID_FLAG_IS_LOCALONLY);
	stream_free(s);
	printf("Local-only flag decoded after locator.\n");

	s = notification(false);
	flags = UINT8_MAX;
	assert(zapi_srv6_sid_notify_decode(s, &ctx, &sid, NULL, NULL, &note,
					   locator, sizeof(locator), &flags));
	assert(flags == 0);
	stream_free(s);
	printf("Legacy notification defaults to zero flags.\n");

	s = notification(true);
	assert(zapi_srv6_sid_notify_decode(s, &ctx, &sid, NULL, NULL, &note,
					   NULL, 0, NULL));
	assert(STREAM_READABLE(s) == 0);
	stream_free(s);
	printf("Unused locator and flags are consumed.\n");

	return 0;
}
