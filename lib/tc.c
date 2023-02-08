// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Traffic Control (TC) main library
 * Copyright (C) 2022  Shichu Yang
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
