/*
 * IS-IS Rout(e)ing protocol - iso_checksum.c
 *                             ISO checksum related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>
#include "iso_checksum.h"

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

int
iso_csum_verify (u_char * buffer, int len, uint16_t * csum)
{
  u_int8_t *p;
  u_int32_t c0;
  u_int32_t c1;
  u_int16_t checksum;
  int i, partial_len;

  p = buffer;
  checksum = 0;
  c0 = *csum & 0xff00;
  c1 = *csum & 0x00ff;

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

  /*
   * Otherwise initialize to zero and calculate...
   */
  c0 = 0;
  c1 = 0;

  while (len)
    {
      partial_len = MIN(len, 5803);

      for (i = 0; i < partial_len; i++)
	{
	  c0 = c0 + *(p++);
	  c1 += c0;
	}

      c0 = c0 % 255;
      c1 = c1 % 255;

      len -= partial_len;
    }

  if (c0 == 0 && c1 == 0)
    return 0;

  return 1;
}

/*
 * Creates the checksum. *csum points to the position of the checksum in the 
 * PDU. 
 * Based on Annex C.4 of ISO/IEC 8473
 */
#define FIXED_CODE
u_int16_t
iso_csum_create (u_char * buffer, int len, u_int16_t n)
{

  u_int8_t *p;
  int x;
  int y;
  u_int32_t mul;
  u_int32_t c0;
  u_int32_t c1;
  u_int16_t checksum;
  u_int16_t *csum;
  int i, init_len, partial_len;

  checksum = 0;

  /*
   * Zero the csum in the packet.
   */
  csum = (u_int16_t *) (buffer + n);
  *(csum) = checksum;

  p = buffer;
  c0 = 0;
  c1 = 0;
  init_len = len;

  while (len != 0)
    {
      partial_len = MIN(len, 5803);

      for (i = 0; i < partial_len; i++)
	{
	  c0 = c0 + *(p++);
	  c1 += c0;
	}

      c0 = c0 % 255;
      c1 = c1 % 255;

      len -= partial_len;
    }

  mul = (init_len - n)*(c0);

#ifdef FIXED_CODE
  x = mul - c0 - c1;
  y = c1 - mul - 1;

  if (y > 0)
    y++;
  if (x < 0)
    x--;

  x %= 255;
  y %= 255;

  if (x == 0)
    x = 255;
  if (y == 0)
    y = 1;

  checksum = (y << 8) | (x & 0xFF);

#else
  x = mul - c0 - c1;
  x %= 255;

  y = c1 - mul - 1;
  y %= 255;

  if (x == 0)
    x = 255;
  if (y == 0)
    y = 255;

  checksum = ((y << 8) | x);
#endif

  /*
   * Now we write this to the packet
   */
  *(csum) = checksum;

  /* return the checksum for user usage */
  return checksum;
}

int
iso_csum_modify (u_char * buffer, int len, uint16_t * csum)
{
  return 0;
}
