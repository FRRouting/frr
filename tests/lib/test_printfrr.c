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

static void printchk(const char *ref, const char *fmt, ...) PRINTFRR(2, 3);
static void printchk(const char *ref, const char *fmt, ...)
{
	va_list ap;
	char bufrr[256];
	memset(bufrr, 0xcc, sizeof(bufrr));

	va_start(ap, fmt);
	vsnprintfrr(bufrr, sizeof(bufrr), fmt, ap);
	va_end(ap);

	printf("fmt: \"%s\"\nref: \"%s\"\nfrr: \"%s\"\n%s\n\n",
	       fmt, ref, bufrr, strcmp(ref, bufrr) ? "ERROR" : "ok");
	if (strcmp(ref, bufrr))
		errors++;
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

	printcmp("%p", &ip);

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

	return !!errors;
}
