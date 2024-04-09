// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frr_version_cmp() tests
 * Copyright (C) 2018  David Lamparter for NetDEF, Inc.
 */
#include <zebra.h>
#include <defaults.h>

static const char *rel(int x)
{
	if (x < 0)
		return "<";
	if (x > 0)
		return ">";
	return "==";
}

static int fail;

static void compare(const char *a, const char *b, int expect)
{
	int result = frr_version_cmp(a, b);

	if (expect == result)
		printf("\"%s\" %s \"%s\"\n", a, rel(result), b);
	else {
		printf("\"%s\" %s \"%s\", expected %s!\n", a, rel(result), b,
				rel(expect));
		fail = 1;
	}
}

int main(int argc, char **argv)
{
	compare("", "", 0);
	compare("1", "1", 0);
	compare("1.0", "1.00", 0);
	compare("10.0", "1", 1);
	compare("10.0", "2", 1);
	compare("2.1", "10.0", -1);
	compare("1.1.1", "1.1.0", 1);
	compare("1.0a", "1.0", 1);
	compare("1.0a", "1.0b", -1);
	compare("1.0a10", "1.0a2", 1);
	compare("1.00a2", "1.0a2", 0);
	compare("1.00a2", "1.0a3", -1);
	compare("1.0-dev", "1.0", 1);
	compare("1.0~foo", "1.0", -1);
	compare("1.0~1", "1.0~0", 1);
	compare("1.00~1", "1.0~0", 1);
	printf("final tally: %s\n", fail ? "FAILED" : "ok");
	return fail;
}
