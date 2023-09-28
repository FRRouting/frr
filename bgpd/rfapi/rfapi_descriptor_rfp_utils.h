// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */


extern void *rfapi_create_generic(struct rfapi_ip_addr *vn,
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
extern void rfapi_free_generic(void *grfd);
