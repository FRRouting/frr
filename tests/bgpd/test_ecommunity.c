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

/*
 * Link-bandwidth display: a rate that is not a whole number of Gbps / Mbps
 * must keep its fraction. The IPv4 values are raw (not IEEE floating point)
 * bytes per second; 187500000 is 1.5 Gbps and 312500 is 2.5 Mbps.
 */
static struct lb_segment {
	const char *name;
	const char *desc;
	bool ipv6;
	const uint8_t data[IPV6_ECOMMUNITY_SIZE];
	int len;
	const char *shouldbe;
} lb_segments[] = {
	{ "lb-gbps",
	  "LB 65000, 1.5 Gbps",
	  false,
	  { ECOMMUNITY_ENCODE_AS, ECOMMUNITY_LINK_BANDWIDTH, 0xfd, 0xe8, 0x0b, 0x2d, 0x05, 0xe0 },
	  ECOMMUNITY_SIZE,
	  "LB:65000:187500000 (1.500 Gbps)" },
	{ "lb-mbps",
	  "LB 65000, 2.5 Mbps",
	  false,
	  { ECOMMUNITY_ENCODE_AS, ECOMMUNITY_LINK_BANDWIDTH, 0xfd, 0xe8, 0x00, 0x04, 0xc4, 0xb4 },
	  ECOMMUNITY_SIZE,
	  "LB:65000:312500 (2.500 Mbps)" },
	{ "lb-ipv6-gbps",
	  "extended LB 65000, 1.5 Gbps",
	  true,
	  { ECOMMUNITY_ENCODE_AS4, ECOMMUNITY_EXTENDED_LINK_BANDWIDTH, 0x00, 0x00, /* reserved */
	    0x00, 0x00, 0x00, 0x00, 0x0b, 0x2d, 0x05, 0xe0,			   /* bandwidth */
	    0x00, 0x00, 0xfd, 0xe8 },						   /* AS */
	  IPV6_ECOMMUNITY_SIZE,
	  "LB:65000:187500000 (1.500 Gbps)" },
	{ NULL, NULL, false, { 0 }, 0, NULL }
};

static void lb_display_test(struct lb_segment *t)
{
	struct ecommunity *ecom;
	char *str = NULL;

	printf("%s: %s\n", t->name, t->desc);

	if (t->ipv6)
		ecom = ecommunity_parse_ipv6((uint8_t *)t->data, t->len);
	else
		ecom = ecommunity_parse((uint8_t *)t->data, t->len, true);
	if (ecom)
		str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);

	printf("got: %s\n", str ? str : "NULL");
	if (!str || strcmp(str, t->shouldbe)) {
		failed++;
		printf("shouldbe: %s\nfailed\n\n", t->shouldbe);
	} else {
		printf("OK\n\n");
	}

	XFREE(MTYPE_ECOMMUNITY_STR, str);
	if (ecom)
		ecommunity_unintern(&ecom);
}


/* Color extended-community formatting.
 *
 * COMMUNITY_LIST and ROUTE_MAP render config that has to parse again, so both
 * must emit "color CC:VALUE"; DISPLAY stays human-readable as "Color:CC:VALUE".
 * The CO field is two binary digits, hence 11 == 3.
 */
static struct color_segment {
	const char *name;
	const char *str;     /* input, extcommunity-list syntax */
	const char *reparse; /* expected COMMUNITY_LIST and ROUTE_MAP output */
	const char *display; /* expected DISPLAY output */
} color_segments[] = {
	{"color-format", "color 00:100", "color 00:100", "Color:00:100"},
	{"color-format-co", "color 11:55555", "color 11:55555",
	 "Color:11:55555"},
	{"color-format-max", "color 11:4294967295", "color 11:4294967295",
	 "Color:11:4294967295"},
	{NULL, NULL, NULL, NULL}};

static int check_format(const char *what, struct ecommunity *ecom, int format,
			const char *shouldbe)
{
	char *str = ecommunity_ecom2str(ecom, format, 0);
	int fails = 0;

	printf("  %-14s %s\n", what, str ? str : "NULL");
	if (!str || strcmp(str, shouldbe)) {
		printf("shouldbe: %s\n", shouldbe);
		fails++;
	}
	XFREE(MTYPE_ECOMMUNITY_STR, str);

	return fails;
}

static void color_test(struct color_segment *t)
{
	struct ecommunity *ecom, *etmp;
	char *str1, *str2;
	int fails = 0;

	printf("%s: %s\n", t->name, t->str);

	ecom = ecommunity_str2com(t->str, 0, 1);
	if (!ecom) {
		printf("shouldbe: %s\nparse returned NULL\n", t->reparse);
		failed++;
		printf("failed\n\n");
		return;
	}

	fails += check_format("COMMUNITY_LIST", ecom,
			      ECOMMUNITY_FORMAT_COMMUNITY_LIST, t->reparse);
	fails += check_format("ROUTE_MAP", ecom, ECOMMUNITY_FORMAT_ROUTE_MAP,
			      t->reparse);
	fails += check_format("DISPLAY", ecom, ECOMMUNITY_FORMAT_DISPLAY,
			      t->display);

	/* the re-parseable form must survive a round trip */
	str1 = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_COMMUNITY_LIST, 0);
	etmp = str1 ? ecommunity_str2com(str1, 0, 1) : NULL;
	if (etmp)
		str2 = ecommunity_ecom2str(etmp,
					   ECOMMUNITY_FORMAT_COMMUNITY_LIST, 0);
	else
		str2 = NULL;

	if (!str2 || strcmp(str1, str2)) {
		printf("dogfood: in %s\n"
		       "    in->out %s\n",
		       str1 ? str1 : "NULL", str2 ? str2 : "NULL");
		fails++;
	}

	ecommunity_free(&etmp);
	ecommunity_free(&ecom);
	XFREE(MTYPE_ECOMMUNITY_STR, str1);
	XFREE(MTYPE_ECOMMUNITY_STR, str2);

	failed += fails;
	printf(fails ? "failed\n\n" : "OK\n\n");
}

int main(void)
{
	int i = 0;
	ecommunity_init();
	while (test_segments[i].name)
		parse_test(&test_segments[i++]);
	for (i = 0; lb_segments[i].name; i++)
		lb_display_test(&lb_segments[i]);

	i = 0;
	while (color_segments[i].name)
		color_test(&color_segments[i++]);

	printf("failures: %d\n", failed);
	// printf ("aspath count: %ld\n", aspath_count());
	return failed;
	// return (failed + aspath_count());
}
