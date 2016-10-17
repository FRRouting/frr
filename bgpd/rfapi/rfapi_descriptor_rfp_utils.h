/* 
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */


extern void *rfapi_create_generic (struct rfapi_ip_addr *vn,
                                   struct rfapi_ip_addr *un);

/*------------------------------------------
 * rfapi_free_generic
 *
 * Compare two generic rfapi descriptors.
 *
 * input: 
 *    grfd: rfapi descriptor returned by rfapi_open or rfapi_create_generic
 *
 * output:
 *
 * return value: 
 *
 *------------------------------------------*/
extern void rfapi_free_generic (void *grfd);
