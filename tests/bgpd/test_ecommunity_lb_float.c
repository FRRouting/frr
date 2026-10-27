// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Check IEEE-754 link-bandwidth decoding and display at conversion boundaries.
 * Also check extended link-bandwidth display at UINT64_MAX.
 *
 * Copyright (C) 2026 Dave Seddon
 *
 * Each case runs in a child process so that a sanitizer abort fails only
 * that case.
 */

#include <zebra.h>

#include <float.h>
#include <math.h>
#include <sys/wait.h>

#include "memory.h"
#include "printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

/* Child exit codes, distinct from the sanitizers' error exit code (1). */
#define EXIT_MATCH    10
#define EXIT_MISMATCH 11

#define LB_MAX "LB:65000:18446744073709551615 (147573948416.000 Gbps)"
#define LB_0   "LB:65000:0 (0 bps)"

struct tcase {
	const char *description;
	enum kind kind;
	uint32_t ieee; /* IEEE-754 single precision bit pattern */
	bool extended; /* extended LB: 64-bit integer bandwidth = bw */
	/* expected */
	uint64_t bw;
	const char *str;
};

static const struct tcase tcases[] = {
	{ "1.5 Gbps (187500000.0)", POSITIVE, 0x4d32d05e, false, 187500000,
	  "LB:65000:187500000 (1.500 Gbps)" },
	{ "2.5 Mbps (312500.0)", POSITIVE, 0x48989680, false, 312500,
	  "LB:65000:312500 (2.500 Mbps)" },
	{ "1.0 byte/s", POSITIVE, 0x3f800000, false, 1, "LB:65000:1 (8 bps)" },
	{ "-1.0 gives 0", NEGATIVE, 0xbf800000, false, 0, LB_0 },
	{ "-inf gives 0", NEGATIVE, 0xff800000, false, 0, LB_0 },
	{ "quiet NaN gives 0", NEGATIVE, 0x7fc00000, false, 0, LB_0 },
	{ "negative NaN gives 0", NEGATIVE, 0xffc00000, false, 0, LB_0 },
	{ "0.0", BOUNDARY, 0x00000000, false, 0, LB_0 },
	{ "0.5 truncates to 0", BOUNDARY, 0x3f000000, false, 0, LB_0 },
	{ "2^63 is shown in full", BOUNDARY, 0x5f000000, false, 9223372036854775808ULL,
	  "LB:65000:9223372036854775808 (73786974208.000 Gbps)" },
	{ "largest float below 2^64", BOUNDARY, 0x5f7fffff, false, 18446742974197923840ULL,
	  "LB:65000:18446742974197923840 (147573948416.000 Gbps)" },
	{ "2^64 saturates", BOUNDARY, 0x5f800000, false, UINT64_MAX, LB_MAX },
	{ "FLT_MAX saturates", BOUNDARY, 0x7f7fffff, false, UINT64_MAX, LB_MAX },
	{ "+inf saturates", CORNER, 0x7f800000, false, UINT64_MAX, LB_MAX },
	{ "-0.0 gives 0", CORNER, 0x80000000, false, 0, LB_0 },
	{ "smallest denormal gives 0", CORNER, 0x00000001, false, 0, LB_0 },
	{ "extended LB at UINT64_MAX is shown in full", BOUNDARY, 0, true, UINT64_MAX, LB_MAX },
};

static bool display_matches(const char *actual, const char *expected)
{
	size_t prefix = strcspn(expected, "(");
	char *actual_end, *expected_end;
	double actual_rate, expected_rate;

	if (!strcmp(actual, expected))
		return true;
	if (strncmp(actual, expected, prefix) || expected[prefix] != '(')
		return false;

	/* x87 excess precision can change the rounded human-readable rate. */
	actual_rate = strtod(actual + prefix + 1, &actual_end);
	expected_rate = strtod(expected + prefix + 1, &expected_end);
	return actual_end != actual + prefix + 1 && expected_end != expected + prefix + 1 &&
	       !strcmp(actual_end, " Gbps)") && !strcmp(expected_end, " Gbps)") &&
	       fabs(actual_rate - expected_rate) <= FLT_EPSILON * expected_rate;
}

static int run_case(const struct tcase *tc)
{
	uint8_t data[ECOMMUNITY_SIZE] = { ECOMMUNITY_ENCODE_AS, ECOMMUNITY_LINK_BANDWIDTH, 0xfd,
					  0xe8 /* AS 65000 */ };
	uint8_t ext[IPV6_ECOMMUNITY_SIZE] = { ECOMMUNITY_ENCODE_AS4,
					      ECOMMUNITY_EXTENDED_LINK_BANDWIDTH };
	struct ecommunity *ecom;
	uint64_t bw = 0;
	char *str;
	int rc = EXIT_MATCH;

	data[4] = tc->ieee >> 24;
	data[5] = tc->ieee >> 16;
	data[6] = tc->ieee >> 8;
	data[7] = tc->ieee;

	if (tc->extended) {
		for (int i = 0; i < 8; i++)
			ext[4 + i] = tc->bw >> (56 - 8 * i);
		ext[14] = 0xfd; /* AS 65000 */
		ext[15] = 0xe8;
		ecom = ecommunity_parse_ipv6(ext, sizeof(ext));
	} else
		ecom = ecommunity_parse(data, sizeof(data), false);
	if (!ecom) {
		printf("    parse failed\n");
		return EXIT_MISMATCH;
	}

	str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);
	printf("    str: \"%s\"\n", str);
	if (!display_matches(str, tc->str))
		rc = EXIT_MISMATCH;

	if (!ecommunity_linkbw_present(ecom, &bw)) {
		printf("    link-bandwidth not found\n");
		rc = EXIT_MISMATCH;
	}
	printf("    bw: %" PRIu64 "\n", bw);
	if (bw != tc->bw)
		rc = EXIT_MISMATCH;

	XFREE(MTYPE_ECOMMUNITY_STR, str);
	ecommunity_unintern(&ecom);
	return rc;
}

int main(int argc, char **argv)
{
	int failures = 0;

	ecommunity_init();

	printf("BGP link-bandwidth IEEE float tests\n\n");

	for (size_t i = 0; i < array_size(tcases); i++) {
		const struct tcase *tc = &tcases[i];
		char why[128] = "";
		int status;
		pid_t pid, waited;

		fflush(stdout);
		pid = fork();
		if (pid < 0) {
			perror("fork");
			return 1;
		}
		if (pid == 0) {
			int rc = run_case(tc);

			fflush(stdout);
			_exit(rc);
		}

		do {
			waited = waitpid(pid, &status, 0);
		} while (waited < 0 && errno == EINTR);
		if (waited < 0) {
			perror("waitpid");
			return 1;
		}
		if (WIFSIGNALED(status))
			snprintfrr(why, sizeof(why), " (crashed: signal %d)", WTERMSIG(status));
		else if (WEXITSTATUS(status) == EXIT_MISMATCH)
			snprintfrr(why, sizeof(why), " (expected bw %" PRIu64 ", \"%s\")", tc->bw,
				   tc->str);
		else if (WEXITSTATUS(status) != EXIT_MATCH)
			snprintfrr(why, sizeof(why), " (abnormal exit %d)", WEXITSTATUS(status));

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}

	printf("\n%d of %zu cases failed\n", failures, array_size(tcases));
	return failures ? 1 : 0;
}
