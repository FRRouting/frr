// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - iso_checksum.c
 *                             ISO checksum related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>
#include "iso_checksum.h"
#include "checksum.h"

/*
 * Calculations of the OSI checksum.
 * ISO/IEC 8473 defines the sum as
 *
 *     L
 *  sum  a (mod 255) = 0
 *     1  i
 *
 *     L
 *  sum (L-i+1)a (mod 255) = 0
 *     1        i
 *
 */

/*
 * Verifies that the checksum is correct.
 * Return 0 on correct and 1 on invalid checksum.
 * Based on Annex C.4 of ISO/IEC 8473
 */

int iso_csum_verify(uint8_t *buffer, int len, uint16_t csum, int offset)
{
	uint16_t checksum;
	uint32_t c0;
	uint32_t c1;

	c0 = csum & 0xff00;
	c1 = csum & 0x00ff;

	/*
	 * If both are zero return correct
	 */
	if (c0 == 0 && c1 == 0)
		return 0;

	/*
	 * If either, but not both are zero return incorrect
	 */
	if (c0 == 0 || c1 == 0)
		return 1;

	checksum = fletcher_checksum(buffer, len, offset);
	if (checksum == htons(csum))
		return 0;
	return 1;
}
