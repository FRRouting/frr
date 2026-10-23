// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-LS attribute encoding test
 * Copyright (C) 2026 Minghan Chan <mhchann082@gmail.com>
 *
 * Checks that a Link State edge from the TED is encoded with the IGP Metric
 * TLV (1095) length of its IGP (RFC 9552 section 5.3.2.4), whatever the
 * metric value.
 */

#include <zebra.h>

#include "privs.h"
#include "stream.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_ls_nlri.h"
#include "bgpd/bgp_ls_ted.h"

/* Satisfy link requirements from including bgpd.h */
struct zebra_privs_t bgpd_privs = {};

static int failed;

#define TLV_MAX 8

struct test_case {
	const char *name;
	const char *desc;
	enum ls_origin origin;
	uint32_t metric;
	uint8_t tlv[TLV_MAX];
	size_t tlv_len;
};

static const struct test_case tests[] = {
	{
		"OSPFv2-1",
		"OSPFv2 metric 1 is 2 octets",
		OSPFv2,
		1,
		{ 0x04, 0x47, 0x00, 0x02, 0x00, 0x01 },
		6,
	},
	{
		"OSPFv2-100",
		"OSPFv2 metric 100 is 2 octets",
		OSPFv2,
		100,
		{ 0x04, 0x47, 0x00, 0x02, 0x00, 0x64 },
		6,
	},
	{
		"OSPFv2-1000",
		"OSPFv2 metric 1000 is 2 octets",
		OSPFv2,
		1000,
		{ 0x04, 0x47, 0x00, 0x02, 0x03, 0xe8 },
		6,
	},
	{
		"OSPFv2-65535",
		"OSPFv2 metric 65535 is 2 octets",
		OSPFv2,
		65535,
		{ 0x04, 0x47, 0x00, 0x02, 0xff, 0xff },
		6,
	},
	{
		"ISIS-L2-10",
		"IS-IS L2 wide metric 10 is 3 octets",
		ISIS_L2,
		10,
		{ 0x04, 0x47, 0x00, 0x03, 0x00, 0x00, 0x0a },
		7,
	},
	{
		"ISIS-L1-1000",
		"IS-IS L1 wide metric 1000 is 3 octets",
		ISIS_L1,
		1000,
		{ 0x04, 0x47, 0x00, 0x03, 0x00, 0x03, 0xe8 },
		7,
	},
	{
		"ISIS-L2-16777215",
		"IS-IS L2 wide metric 16777215 is 3 octets",
		ISIS_L2,
		16777215,
		{ 0x04, 0x47, 0x00, 0x03, 0xff, 0xff, 0xff },
		7,
	},
};

static void dump(const char *what, const uint8_t *buf, size_t len)
{
	printf("  %s:", what);
	for (size_t i = 0; i < len; i++)
		printf(" %02x", buf[i]);
	printf("\n");
}

static void run_test(const struct test_case *t)
{
	struct ls_attributes ls_attr = {};
	struct bgp_ls_attr *attr;
	struct stream *s;
	int len;
	bool ok;

	printf("%s: %s\n", t->name, t->desc);

	ls_attr.adv.origin = t->origin;
	ls_attr.metric = t->metric;
	SET_FLAG(ls_attr.flags, LS_ATTR_METRIC);

	attr = bgp_ls_attr_alloc();
	s = stream_new(64);

	ok = bgp_ls_populate_link_attr(&ls_attr, attr) == 0;
	len = ok ? bgp_ls_encode_attr(s, attr) : -1;
	ok = len == (int)t->tlv_len && memcmp(STREAM_DATA(s), t->tlv, t->tlv_len) == 0;

	if (!ok) {
		dump("expected", t->tlv, t->tlv_len);
		dump("got     ", STREAM_DATA(s), stream_get_endp(s));
		failed++;
	}
	printf("%s\n", ok ? "OK" : "failed");

	stream_free(s);
	bgp_ls_attr_free(attr);
}

int main(void)
{
	for (size_t i = 0; i < array_size(tests); i++)
		run_test(&tests[i]);

	printf("failures: %d\n", failed);
	return failed;
}
