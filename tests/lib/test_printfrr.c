/*
 * printfrr() unit test
 * Copyright (C) 2019  David Lamparter
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "zebra.h"

#include <math.h>

#include "lib/printfrr.h"
#include "lib/memory.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"

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
	struct in_addr ip;
	char *p;
	char buf[256];

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

	inet_aton("192.168.1.2", &ip);
	printchk("192.168.1.2", "%pI4", &ip);
	printchk("         192.168.1.2", "%20pI4", &ip);
	printchk("192.168.1.2         ", "%-20pI4", &ip);

	printcmp("%p", &ip);

	test_va("VA [192.168.1.2 1234] --", "%pI4 %u", &ip, 1234);

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

	struct prefix_sg sg;
	sg.src.s_addr = INADDR_ANY;
	sg.grp.s_addr = INADDR_ANY;
	printchk("(*,*)", "%pSG4", &sg);

	inet_aton("192.168.1.2", &sg.src);
	printchk("(192.168.1.2,*)", "%pSG4", &sg);

	inet_aton("224.1.2.3", &sg.grp);
	printchk("(192.168.1.2,224.1.2.3)", "%pSG4", &sg);

	sg.src.s_addr = INADDR_ANY;
	printchk("(*,224.1.2.3)", "%pSG4", &sg);

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
	printchk("(null)", "%pNHcg", NULL);
	printchk("(null)", "%pNHci", NULL);

	struct nexthop nh;

	memset(&nh, 0, sizeof(nh));

	nh.type = NEXTHOP_TYPE_IPV4;
	inet_aton("3.2.1.0", &nh.gate.ipv4);
	printchk("3.2.1.0", "%pNHcg", &nh);

	nh.type = NEXTHOP_TYPE_IPV6;
	inet_pton(AF_INET6, "fe2c::34", &nh.gate.ipv6);
	printchk("fe2c::34", "%pNHcg", &nh);

	return !!errors;
}
