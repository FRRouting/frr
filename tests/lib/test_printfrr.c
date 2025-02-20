// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * printfrr() unit test
 * Copyright (C) 2019  David Lamparter
 */

#include "zebra.h"

#include <math.h>

#include "lib/printfrr.h"
#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"
#include "lib/asn.h"

static int errors;

static void printcmp(const char *fmt, ...) PRINTFRR(1, 2);
static void printcmp(const char *fmt, ...)
{
	va_list ap;
	char buf[256], bufrr[256], *p;
	int cmp;
	memset(bufrr, 0xcc, sizeof(bufrr));

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	va_start(ap, fmt);
	vsnprintfrr(bufrr, sizeof(bufrr), fmt, ap);
	va_end(ap);

	cmp = strcmp(buf, bufrr);

	/* OS dependent "+nan" vs. "nan" */
	if (cmp && (p = strstr(bufrr, "+nan"))) {
		p[0] = ' ';
		if (!strcmp(buf, bufrr))
			cmp = 0;
		p[0] = '+';
	}
	printf("fmt: \"%s\"\nsys: \"%s\"\nfrr: \"%s\"\n%s\n\n",
	       fmt, buf, bufrr, cmp ? "ERROR" : "ok");

	if (cmp)
		errors++;
}

static int printchk(const char *ref, const char *fmt, ...) PRINTFRR(2, 3);
static int printchk(const char *ref, const char *fmt, ...)
{
	va_list ap;
	char bufrr[256];
	bool truncfail = false;
	size_t i;
	size_t expectlen;

	memset(bufrr, 0xcc, sizeof(bufrr));

	va_start(ap, fmt);
	expectlen = vsnprintfrr(NULL, 0, fmt, ap);
	va_end(ap);

	va_start(ap, fmt);
	vsnprintfrr(bufrr, 7, fmt, ap);
	va_end(ap);

	if (strnlen(bufrr, 7) == 7)
		truncfail = true;
	if (strnlen(bufrr, 7) < 7 && strncmp(ref, bufrr, 6) != 0)
		truncfail = true;
	for (i = 7; i < sizeof(bufrr); i++)
		if (bufrr[i] != (char)0xcc) {
			truncfail = true;
			break;
		}

	if (truncfail) {
		printf("truncation test FAILED:\n"
		       "fmt: \"%s\"\nref: \"%s\"\nfrr[:7]: \"%s\"\n%s\n\n",
		       fmt, ref, bufrr, strcmp(ref, bufrr) ? "ERROR" : "ok");
		errors++;
	}

	struct fmt_outpos outpos[16];
	struct fbuf fb = {
		.buf = bufrr,
		.pos = bufrr,
		.len = sizeof(bufrr) - 1,
		.outpos = outpos,
		.outpos_n = array_size(outpos),
	};

	va_start(ap, fmt);
	vbprintfrr(&fb, fmt, ap);
	fb.pos[0] = '\0';
	va_end(ap);

	printf("fmt: \"%s\"\nref: \"%s\"\nfrr: \"%s\"\n%s\n",
	       fmt, ref, bufrr, strcmp(ref, bufrr) ? "ERROR" : "ok");
	if (strcmp(ref, bufrr))
		errors++;
	if (strlen(bufrr) != expectlen) {
		printf("return value <> length mismatch\n");
		errors++;
	}

	for (size_t i = 0; i < fb.outpos_i; i++)
		printf("\t[%zu: %u..%u] = \"%.*s\"\n", i,
			outpos[i].off_start,
			outpos[i].off_end,
			(int)(outpos[i].off_end - outpos[i].off_start),
			bufrr + outpos[i].off_start);
	printf("\n");
	return 0;
}

static void test_va(const char *ref, const char *fmt, ...) PRINTFRR(2, 3);
static void test_va(const char *ref, const char *fmt, ...)
{
	struct va_format vaf;
	va_list ap;

	va_start(ap, fmt);
	vaf.fmt = fmt;
	vaf.va = &ap;

	printchk(ref, "VA [%pVA] %s", &vaf, "--");

	va_end(ap);
}

int main(int argc, char **argv)
{
	size_t i;
	float flts[] = {
		123.456789,
		23.456789e-30,
		3.456789e+30,
		INFINITY,
		NAN,
	};
	uint64_t ui64 = 0xfeed1278cafef00d;
	uint16_t i16 = -23456;
	int_fast8_t if8 = 123;
	struct in_addr ip;
	char *p;
	char buf[256];
	as_t asn;

	printcmp("%d %u %d %u", 123, 123, -456, -456);
	printcmp("%lld %llu %lld %llu", 123LL, 123LL, -456LL, -456LL);

	printcmp("%-20s,%20s,%.20s", "test", "test", "test");
	printcmp("%-3s,%3s,%.3s", "test", "test", "test");
	printcmp("%-6.3s,%6.3s,%6.3s", "test", "test", "test");
	printcmp("%*s,%*s,%.*s", -3, "test", 3, "test", 3, "test");

	for (i = 0; i < array_size(flts); i++) {
		printcmp("%-6.3e,%6.3e,%+06.3e", flts[i], flts[i], flts[i]);
		printcmp("%-6.3f,%6.3f,%+06.3f", flts[i], flts[i], flts[i]);
		printcmp("%-6.3g,%6.3g,%+06.3g", flts[i], flts[i], flts[i]);
		printcmp("%-6.3a,%6.3a,%+06.3a", flts[i], flts[i], flts[i]);
	}

	printchk("-77385308584349683 18369358765125201933 feed1278cafef00d",
		 "%Ld %Lu %Lx", ui64, ui64, ui64);

	FMT_NSTD(printchk("11110000000011111010010111000011", "%b", 0xf00fa5c3));
	FMT_NSTD(printchk("0b01011010", "%#010b", 0x5a));

/* FMT_NSTD is conditional on the frr-format plugin being NOT enabled.
 * However, the frr-format plugin does not support %wd/%wfd yet, so this needs
 * to be unconditional.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
	printchk("123 -23456 feed1278cafef00d 9876", "%wf8d %w16d %w64x %d",
		 if8, i16, ui64, 9876);
#pragma GCC diagnostic pop

	inet_aton("192.168.1.2", &ip);
	printchk("192.168.1.2", "%pI4", &ip);
	printchk("         192.168.1.2", "%20pI4", &ip);
	printchk("192.168.1.2         ", "%-20pI4", &ip);

	printcmp("%p", &ip);

	test_va("VA [192.168.1.2 1234] --", "%pI4 %u", &ip, 1234);

	inet_aton("0.0.0.0", &ip);
	printchk("0.0.0.0", "%pI4", &ip);
	printchk("*", "%pI4s", &ip);

	snprintfrr(buf, sizeof(buf), "test%s", "#1");
	csnprintfrr(buf, sizeof(buf), "test%s", "#2");
	assert(strcmp(buf, "test#1test#2") == 0);

	p = asnprintfrr(MTYPE_TMP, buf, sizeof(buf), "test%s", "#3");
	assert(p == buf);
	assert(strcmp(buf, "test#3") == 0);

	p = asnprintfrr(MTYPE_TMP, buf, 4, "test%s", "#4");
	assert(p != buf);
	assert(strcmp(p, "test#4") == 0);
	XFREE(MTYPE_TMP, p);

	p = asprintfrr(MTYPE_TMP, "test%s", "#5");
	assert(strcmp(p, "test#5") == 0);
	XFREE(MTYPE_TMP, p);

	struct prefix pfx;

	str2prefix("192.168.1.23/24", &pfx);
	printchk("192.168.1.23/24", "%pFX", &pfx);
	printchk("192.168.1.23", "%pFXh", &pfx);

	str2prefix("2001:db8::1234/64", &pfx);
	printchk("2001:db8::1234/64", "%pFX", &pfx);
	printchk("2001:db8::1234", "%pFXh", &pfx);

	pfx.family = AF_UNIX;
	printchk("UNK prefix", "%pFX", &pfx);
	printchk("{prefix.af=AF_UNIX}", "%pFXh", &pfx);

	str2prefix_eth("02:ca:fe:f0:0d:1e/48", (struct prefix_eth *)&pfx);
	printchk("02:ca:fe:f0:0d:1e/48", "%pFX", &pfx);
	printchk("02:ca:fe:f0:0d:1e", "%pFXh", &pfx);

	struct prefix_sg sg;
	SET_IPADDR_V4(&sg.src);
	sg.src.ipaddr_v4.s_addr = INADDR_ANY;
	sg.grp.s_addr = INADDR_ANY;
	printchk("(*,*)", "%pPSG4", &sg);

	inet_aton("192.168.1.2", &sg.src.ipaddr_v4);
	printchk("(192.168.1.2,*)", "%pPSG4", &sg);

	inet_aton("224.1.2.3", &sg.grp);
	printchk("(192.168.1.2,224.1.2.3)", "%pPSG4", &sg);

	SET_IPADDR_NONE(&sg.src);
	sg.src.ipaddr_v4.s_addr = INADDR_ANY;
	printchk("(*,224.1.2.3)", "%pPSG4", &sg);

	SET_IPADDR_V6(&sg.src);
	inet_pton(AF_INET6, "1:2:3:4::5", &sg.src.ipaddr_v6);
	printchk("(1:2:3:4::5,224.1.2.3)", "%pPSG4", &sg);

	uint8_t randhex[] = { 0x12, 0x34, 0x00, 0xca, 0xfe, 0x00, 0xaa, 0x55 };

	FMT_NSTD(printchk("12 34 00 ca fe 00 aa 55", "%.8pHX", randhex));
	FMT_NSTD(printchk("12 34 00 ca fe 00 aa 55", "%.*pHX",
		 (int)sizeof(randhex), randhex));
	FMT_NSTD(printchk("12 34 00 ca", "%.4pHX", randhex));

	printchk("12 34 00 ca fe 00 aa 55", "%8pHX", randhex);
	printchk("12 34 00 ca fe 00 aa 55", "%*pHX",
		 (int)sizeof(randhex), randhex);
	printchk("12 34 00 ca", "%4pHX", randhex);

	printchk("", "%pHX", randhex);

	printchk("12:34:00:ca:fe:00:aa:55", "%8pHXc", randhex);
	printchk("123400cafe00aa55", "%8pHXn", randhex);

	printchk("/test/pa\\ th/\\~spe\\ncial\\x01/file.name", "%pSE",
		 "/test/pa th/~spe\ncial\x01/file.name");
	printchk("/test/pa\\ th/\\~spe\\n", "%17pSE",
		 "/test/pa th/~spe\ncial\x01/file.name");

	char nulltest[] = { 'n', 'u', 0, 'l', 'l' };

	printchk("nu\\x00ll", "%5pSE", nulltest);
	printchk("nu\\x00ll", "%*pSE", 5, nulltest);

	printchk("bl\\\"ah\\x01te[st\\nab]c", "%pSQ",
		 "bl\"ah\x01te[st\nab]c");
	printchk("\"bl\\\"ah\\x01te[st\\nab]c\"", "%pSQq",
		 "bl\"ah\x01te[st\nab]c");
	printchk("\"bl\\\"ah\\x01te[st\\x0aab\\]c\"", "%pSQqs",
		 "bl\"ah\x01te[st\nab]c");
	printchk("\"\"", "%pSQqn", "");
	printchk("\"\"", "%pSQqn", (char *)NULL);
	printchk("(null)", "%pSQq", (char *)NULL);

	/*
	 * %pNH<foo> tests
	 *
	 * gateway addresses only for now: interfaces require more setup
	 */
	printchk("(null)", "%pNHcg", (struct nexthop *)NULL);
	printchk("(null)", "%pNHci", (struct nexthop *)NULL);

	struct nexthop nh;

	memset(&nh, 0, sizeof(nh));

	nh.type = NEXTHOP_TYPE_IPV4;
	inet_aton("3.2.1.0", &nh.gate.ipv4);
	printchk("3.2.1.0", "%pNHcg", &nh);

	nh.type = NEXTHOP_TYPE_IPV6;
	inet_pton(AF_INET6, "fe2c::34", &nh.gate.ipv6);
	printchk("fe2c::34", "%pNHcg", &nh);

	/* time printing */

	/* need a non-UTC timezone for testing */
	setenv("TZ", "TEST-01:00", 1);
	tzset();

	struct timespec ts;
	struct timeval tv;
	time_t tt;

	ts.tv_sec = tv.tv_sec = tt = 1642015880;
	ts.tv_nsec = 123456789;
	tv.tv_usec = 234567;

	printchk("Wed Jan 12 20:31:20 2022", "%pTSR", &ts);
	printchk("Wed Jan 12 20:31:20 2022", "%pTVR", &tv);
	printchk("Wed Jan 12 20:31:20 2022", "%pTTR", &tt);

	FMT_NSTD(printchk("Wed Jan 12 20:31:20 2022", "%.3pTSR", &ts));

	printchk("2022-01-12T20:31:20.123", "%pTSRi", &ts);
	printchk("2022-01-12 20:31:20.123", "%pTSRip", &ts);
	printchk("2022-01-12 20:31:20.123", "%pTSRpi", &ts);
	FMT_NSTD(printchk("2022-01-12T20:31:20", "%.0pTSRi", &ts));
	FMT_NSTD(printchk("2022-01-12T20:31:20.123456789", "%.9pTSRi", &ts));
	FMT_NSTD(printchk("2022-01-12T20:31:20", "%.3pTTRi", &tt));

	ts.tv_sec = tv.tv_sec = tt = 9 * 86400 + 12345;

	printchk("1w 2d 03:25:45.123", "%pTSIp", &ts);
	printchk("1w2d03:25:45.123", "%pTSI", &ts);
	printchk("1w2d03:25:45.234", "%pTVI", &tv);
	printchk("1w2d03:25:45", "%pTTI", &tt);

	printchk("1w 2d 03h", "%pTVItp", &tv);
	printchk("1w2d03h", "%pTSIt", &ts);

	printchk("219:25:45", "%pTVIh", &tv);
	printchk("13165:45", "%pTVIm", &tv);

	ts.tv_sec = tv.tv_sec = tt = 1 * 86400 + 12345;

	printchk("1d 03:25:45.123", "%pTSIp", &ts);
	printchk("1d03:25:45.234", "%pTVI", &tv);

	printchk("1d 03h 25m", "%pTVItp", &tv);
	printchk("1d03h25m", "%pTSIt", &ts);

	printchk("98745.234", "%pTVId", &tv);

	printchk("27:25:45", "%pTVIh", &tv);
	printchk("1645:45", "%pTVIm", &tv);

	ts.tv_sec = tv.tv_sec = tt = 12345;

	printchk("03:25:45.123", "%pTSIp", &ts);
	printchk("03:25:45.123", "%pTSI", &ts);
	printchk("03:25:45.234", "%pTVI", &tv);
	printchk("03:25:45", "%pTTI", &tt);

	printchk("03:25:45", "%pTSItp", &ts);
	printchk("03:25:45", "%pTVIt", &tv);

	printchk("12345.234", "%pTVId", &tv);

	printchk("03:25:45", "%pTVIh", &tv);
	printchk("205:45", "%pTVIm", &tv);

	ts.tv_sec = tv.tv_sec = tt = 0;

	printchk("00:00:00.123", "%pTSIp", &ts);
	printchk("00:00:00.123", "%pTSI", &ts);
	printchk("00:00:00.234", "%pTVI", &tv);
	printchk("00:00:00", "%pTTI", &tt);

	printchk("00:00:00", "%pTVItp", &tv);
	printchk("00:00:00", "%pTSIt", &ts);

	printchk("0.234", "%pTVId", &tv);
	printchk("0.234", "%pTVIdx", &tv);
	printchk("-", "%pTTIdx", &tt);

	printchk("00:00:00", "%pTVIhx", &tv);
	printchk("--:--:--", "%pTTIhx", &tt);
	printchk("00:00", "%pTVImx", &tv);
	printchk("--:--", "%pTTImx", &tt);

	ts.tv_sec = tv.tv_sec = tt = -10;

	printchk("-00:00:09.876", "%pTSIp", &ts);
	printchk("-00:00:09.876", "%pTSI", &ts);
	printchk("-00:00:09.765", "%pTVI", &tv);
	printchk("-00:00:10", "%pTTI", &tt);

	printchk("-00:00:09", "%pTSItp", &ts);
	printchk("-00:00:09", "%pTSIt", &ts);
	printchk("-00:00:09", "%pTVIt", &tv);
	printchk("-00:00:10", "%pTTIt", &tt);

	printchk("-9.765", "%pTVId", &tv);
	printchk("-", "%pTVIdx", &tv);

	printchk("-00:00:09", "%pTSIh", &ts);
	printchk("--:--:--", "%pTVIhx", &tv);
	printchk("--:--:--", "%pTTIhx", &tt);

	printchk("-00:09", "%pTSIm", &ts);
	printchk("--:--", "%pTVImx", &tv);
	printchk("--:--", "%pTTImx", &tt);
	/* ASN checks */
	asn = 65536;
	printchk("1.0", "%pASD", &asn);
	asn = 65400;
	printchk("65400", "%pASP", &asn);
	printchk("0.65400", "%pASE", &asn);
	printchk("65400", "%pASD", &asn);

	return !!errors;
}
