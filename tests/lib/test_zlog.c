/*
 * Zlog tests.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
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
#include <zebra.h>
#include <memory.h>
#include "log.h"

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
		long d[nl];

		for (unsigned int i = 0; i < nl; i++)
			d[i] = random();
		zlog_hexdump(d, nl * sizeof(long));
	} while (++nl * sizeof(long) <= MAXDATA);

	return true;
}

bool (*tests[])(void) = {
	test_zlog_hexdump,
};

int main(int argc, char **argv)
{
	openzlog("testzlog", "NONE", 0, LOG_CONS | LOG_NDELAY | LOG_PID,
		 LOG_ERR);
	zlog_set_file("test_zlog.log", LOG_DEBUG);

	for (unsigned int i = 0; i < array_size(tests); i++)
		if (!tests[i]())
			return 1;
	return 0;
}
