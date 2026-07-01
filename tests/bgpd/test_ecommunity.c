// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2007 Sun Microsystems, Inc.
 */
#include <zebra.h>

#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master = NULL;

static int failed = 0;

/* specification for a test - what the results should be */
struct test_spec {
	const char *shouldbe; /* the string the path should parse to */
};


/* test segments to parse and validate, and use for other tests */
static struct test_segment {
	const char *name;
	const char *desc;
	const uint8_t data[1024];
	int len;
	struct test_spec sp;
} test_segments[] = {{/* 0 */
		      "ipaddr",
		      "rt 1.2.3.4:257",
		      {ECOMMUNITY_ENCODE_IP, ECOMMUNITY_ROUTE_TARGET, 0x1, 0x2,
		       0x3, 0x4, 0x1, 0x1},
		      8,
		      {"rt 1.2.3.4:257"}},
		     {/* 1 */
		      "ipaddr-so",
		      "soo 1.2.3.4:257",
		      {ECOMMUNITY_ENCODE_IP, ECOMMUNITY_SITE_ORIGIN, 0x1, 0x2,
		       0x3, 0x4, 0x1, 0x1},
		      8,
		      {"soo 1.2.3.4:257"}},
		     {/* 2 */
		      "asn",
		      "rt 23456:987654321",
		      {ECOMMUNITY_ENCODE_AS, ECOMMUNITY_SITE_ORIGIN, 0x5b, 0xa0,
		       0x3a, 0xde, 0x68, 0xb1},
		      8,
		      {"soo 23456:987654321"}},
		     {/* 3 */
		      "asn4",
		      "rt 168450976:4321",
		      {ECOMMUNITY_ENCODE_AS4, ECOMMUNITY_SITE_ORIGIN, 0xa, 0xa,
		       0x5b, 0xa0, 0x10, 0xe1},
		      8,
		      {"soo 168450976:4321"}},
		     {NULL, NULL, {0}, 0, {NULL}}};


/* validate the given aspath */
static int validate(struct ecommunity *ecom, const struct test_spec *sp)
{
	int fails = 0;
	struct ecommunity *etmp;
	char *str1, *str2;

	printf("got:\n  %s\n", ecommunity_str(ecom));
	str1 = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_COMMUNITY_LIST, 0);
	etmp = ecommunity_str2com(str1, 0, 1);
	if (etmp)
		str2 = ecommunity_ecom2str(etmp,
					   ECOMMUNITY_FORMAT_COMMUNITY_LIST, 0);
	else
		str2 = NULL;

	if (strcmp(sp->shouldbe, str1)) {
		failed++;
		fails++;
		printf("shouldbe: %s\n%s\n", str1, sp->shouldbe);
	}
	if (!etmp || strcmp(str1, str2)) {
		failed++;
		fails++;
		printf("dogfood: in %s\n"
		       "    in->out %s\n",
		       str1, (etmp && str2) ? str2 : "NULL");
	}
	ecommunity_free(&etmp);
	XFREE(MTYPE_ECOMMUNITY_STR, str1);
	XFREE(MTYPE_ECOMMUNITY_STR, str2);

	return fails;
}

/* basic parsing test */
static void parse_test(struct test_segment *t)
{
	struct ecommunity *ecom;

	printf("%s: %s\n", t->name, t->desc);

	ecom = ecommunity_parse((uint8_t *)t->data, t->len, 0);

	printf("ecom: %s\nvalidating...:\n", ecommunity_str(ecom));

	if (!validate(ecom, &t->sp))
		printf("OK\n");
	else
		printf("failed\n");

	printf("\n");
	ecommunity_unintern(&ecom);
}

static bool keep_non_route_targets(uint8_t *val, uint8_t size, void *arg)
{
	(void)size;
	(void)arg;

	return val[1] != ECOMMUNITY_ROUTE_TARGET;
}

static void filter_disable_ieee_test(void)
{
	const uint64_t expected_bw = 125000000;
	struct ecommunity *source = ecommunity_new();
	struct ecommunity *filtered;
	struct ecommunity_val rt = {};
	struct ecommunity_val lb = {};
	uint64_t decoded_bw = 0;
	bool distinct;
	bool has_lb;
	bool mode_preserved;

	printf("filter-disable-ieee: preserve link-bandwidth encoding mode\n");
	source->disable_ieee_floating = true;
	encode_route_target_as(65000, 100, &rt, true);
	encode_lb_extcomm(65000, expected_bw, false, &lb, true);
	ecommunity_add_val(source, &rt, false, false);
	ecommunity_add_val(source, &lb, false, false);

	filtered = ecommunity_filter(source, keep_non_route_targets, NULL);
	distinct = filtered && filtered != source;
	has_lb = filtered && ecommunity_linkbw_present(filtered, &decoded_bw);
	mode_preserved = filtered && filtered->disable_ieee_floating;
	if (distinct && filtered->size == 1 && has_lb && mode_preserved &&
	    decoded_bw == expected_bw)
		printf("OK\n\n");
	else {
		printf("failed (distinct=%d size=%u mode=%d bandwidth=%" PRIu64 ")\n\n", distinct,
		       filtered ? filtered->size : 0, mode_preserved, decoded_bw);
		failed++;
	}

	if (filtered != source)
		ecommunity_free(&filtered);
	ecommunity_free(&source);
}

int main(void)
{
	int i = 0;
	ecommunity_init();
	while (test_segments[i].name)
		parse_test(&test_segments[i++]);
	filter_disable_ieee_test();

	printf("failures: %d\n", failed);
	// printf ("aspath count: %ld\n", aspath_count());
	return failed;
	// return (failed + aspath_count());
}
