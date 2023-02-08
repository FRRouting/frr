// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

#ifndef _QUAGGA_BGP_RFAPI_NVE_ADDR_H
#define _QUAGGA_BGP_RFAPI_NVE_ADDR_H

#include "rfapi.h"

struct rfapi_nve_addr {
	struct rfapi_ip_addr vn;
	struct rfapi_ip_addr un;
	void *info;
};


extern int rfapi_nve_addr_cmp(const void *k1, const void *k2);

extern void rfapiNveAddr2Str(struct rfapi_nve_addr *na, char *buf, int bufsize);


#endif /* _QUAGGA_BGP_RFAPI_NVE_ADDR_H */
