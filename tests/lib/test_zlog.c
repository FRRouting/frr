// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zlog tests.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
 */
#include <zebra.h>
#include <memory.h>
#include "log.h"
#include "network.h"

/* maximum amount of data to hexdump */
#define MAXDATA 16384

/*
 * Test hexdump functionality.
 *
 * At the moment, not crashing is considered success.
 */
static bool test_zlog_hexdump(void)
{
	unsigned int nl = 1;

	do {
		uint8_t d[nl];

		for (unsigned int i = 0; i < nl; i++)
			d[i] = frr_weak_random();
		zlog_hexdump(d, nl - 1);

		nl += 1 + (nl / 2);
	} while (nl <= MAXDATA);

	return true;
}

bool (*tests[])(void) = {
	test_zlog_hexdump,
};

int main(int argc, char **argv)
{
	zlog_aux_init("NONE: ", ZLOG_DISABLED);

	for (unsigned int i = 0; i < array_size(tests); i++)
		if (!tests[i]())
			return 1;
	return 0;
}
