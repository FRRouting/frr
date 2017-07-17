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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_RFAPI_NVE_ADDR_H
#define _QUAGGA_BGP_RFAPI_NVE_ADDR_H

#include "rfapi.h"

struct rfapi_nve_addr {
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	void *info;
};


extern int rfapi_nve_addr_cmp(void *k1, void *k2);

extern void rfapiNveAddr2Str(struct rfapi_nve_addr *na, char *buf, int bufsize);


#endif /* _QUAGGA_BGP_RFAPI_NVE_ADDR_H */
