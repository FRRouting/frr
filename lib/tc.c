/*
 * Traffic Control (TC) main library
 * Copyright (C) 2022  Shichu Yang
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

#include "tc.h"

int tc_getrate(const char *str, uint64_t *rate)
{
	char *endp;
	uint64_t raw = strtoull(str, &endp, 10);

	if (endp == str)
		return -1;

	/* if the string only contains a number, it must be valid rate (bps) */
	bool valid = (*endp == '\0');

	const char *p = endp;
	bool bytes = false, binary_base = false;
	int power = 0;

	while (*p) {
		if (strcmp(p, "Bps") == 0) {
			bytes = true;
			valid = true;
			break;
		} else if (strcmp(p, "bit") == 0) {
			valid = true;
			break;
		}
		switch (*p) {
		case 'k':
		case 'K':
			power = 1;
			break;
		case 'm':
		case 'M':
			power = 2;
			break;
		case 'g':
		case 'G':
			power = 3;
			break;
		case 't':
		case 'T':
			power = 4;
			break;
		case 'i':
		case 'I':
			if (power != 0)
				binary_base = true;
			else
				return -1;
			break;
		default:
			return -1;
		}
		p++;
	}

	if (!valid)
		return -1;

	for (int i = 0; i < power; i++)
		raw *= binary_base ? 1024ULL : 1000ULL;

	if (bytes)
		*rate = raw;
	else
		*rate = raw / 8ULL;

	return 0;
}
